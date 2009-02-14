/*
 * $Id$
 *
 * Copyright (C) 2005 Marc Kleine-Budde, Pengutronix
 * Copyright (C) 2006 Andrey Volkov, Varma Electronics
 * Copyright (C) 2008 Wolfgang Grandegger <wg@grandegger.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the version 2 of the GNU General Public License
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/can.h>
#include <linux/can/dev.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#include <net/rtnetlink.h>
#endif

#include "sysfs.h"

#define MOD_DESC "CAN device driver interface"

MODULE_DESCRIPTION(MOD_DESC);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Wolfgang Grandegger <wg@grandegger.com>");

#ifdef CONFIG_CAN_CALC_BITTIMING
#define CAN_CALC_MAX_ERROR 50 /* in one-tenth of a percent */

/*
 * Bit-timing calculation derived from:
 *
 * Code based on LinCAN sources and H8S2638 project
 * Copyright 2004-2006 Pavel Pisa - DCE FELK CVUT cz
 * Copyright 2005      Stanislav Marek
 * email: pisa@cmp.felk.cvut.cz
 */
static int can_update_spt(const struct can_bittiming_const *btc,
			  int sampl_pt, int tseg, int *tseg1, int *tseg2)
{
	*tseg2 = tseg + 1 - (sampl_pt * (tseg + 1)) / 1000;
	if (*tseg2 < btc->tseg2_min)
		*tseg2 = btc->tseg2_min;
	if (*tseg2 > btc->tseg2_max)
		*tseg2 = btc->tseg2_max;
	*tseg1 = tseg - *tseg2;
	if (*tseg1 > btc->tseg1_max) {
		*tseg1 = btc->tseg1_max;
		*tseg2 = tseg - *tseg1;
	}
	return 1000 * (tseg + 1 - *tseg2) / (tseg + 1);
}

static int can_calc_bittiming(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);
	struct can_bittiming *bt = &priv->bittiming;
	const struct can_bittiming_const *btc = priv->bittiming_const;
	long rate, best_rate = 0;
	long best_error = 1000000000, error = 0;
	int best_tseg = 0, best_brp = 0, brp = 0;
	int tsegall, tseg = 0, tseg1 = 0, tseg2 = 0;
	int spt_error = 1000, spt = 0, sampl_pt;
	uint64_t v64;

	if (!priv->bittiming_const)
		return -ENOTSUPP;

	/* Use CIA recommended sample points */
	if (bt->sample_point) {
		sampl_pt = bt->sample_point;
	} else {
		if (bt->bitrate > 800000)
			sampl_pt = 750;
		else if (bt->bitrate > 500000)
			sampl_pt = 800;
		else
			sampl_pt = 875;
	}

	/* tseg even = round down, odd = round up */
	for (tseg = (btc->tseg1_max + btc->tseg2_max) * 2 + 1;
	     tseg >= (btc->tseg1_min + btc->tseg2_min) * 2; tseg--) {
		tsegall = 1 + tseg / 2;
		/* Compute all possible tseg choices (tseg=tseg1+tseg2) */
		brp = bt->clock / (tsegall * bt->bitrate) + tseg % 2;
		/* chose brp step which is possible in system */
		brp = (brp / btc->brp_inc) * btc->brp_inc;
		if ((brp < btc->brp_min) || (brp > btc->brp_max))
			continue;
		rate = bt->clock / (brp * tsegall);
		error = bt->bitrate - rate;
		/* tseg brp biterror */
		if (error < 0)
			error = -error;
		if (error > best_error)
			continue;
		best_error = error;
		if (error == 0) {
			spt = can_update_spt(btc, sampl_pt, tseg / 2,
					     &tseg1, &tseg2);
			error = sampl_pt - spt;
			if (error < 0)
				error = -error;
			if (error > spt_error)
				continue;
			spt_error = error;
		}
		best_tseg = tseg / 2;
		best_brp = brp;
		best_rate = rate;
		if (error == 0)
			break;
	}

	if (best_error) {
		/* Error in one-tenth of a percent */
		error = (best_error * 1000) / bt->bitrate;
		if (error > CAN_CALC_MAX_ERROR) {
			dev_err(ND2D(dev), "bitrate error %ld.%ld%% too high\n",
				error / 10, error % 10);
			return -EDOM;
		} else {
			dev_warn(ND2D(dev), "bitrate error %ld.%ld%%\n",
				 error / 10, error % 10);
		}
	}

	spt = can_update_spt(btc, sampl_pt, best_tseg, &tseg1, &tseg2);

	v64 = (u64)best_brp * 1000000000UL;
	do_div(v64, bt->clock);
	bt->tq = (u32)v64;
	bt->prop_seg = tseg1 / 2;
	bt->phase_seg1 = tseg1 - bt->prop_seg;
	bt->phase_seg2 = tseg2;
	bt->sjw = 1;
	bt->brp = best_brp;

	return 0;
}
#else /* !CONFIG_CAN_CALC_BITTIMING */
static int can_calc_bittiming(struct net_device *dev)
{
	dev_err(ND2D(dev), "bit-timing calculation not available\n");
	return -EINVAL;
}
#endif /* CONFIG_CAN_CALC_BITTIMING */

int can_sample_point(struct can_bittiming *bt)
{
	return ((bt->prop_seg + bt->phase_seg1 + 1) * 1000) /
		(bt->prop_seg + bt->phase_seg1 + bt->phase_seg2 + 1);
}

int can_fixup_bittiming(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);
	struct can_bittiming *bt = &priv->bittiming;
	const struct can_bittiming_const *btc = priv->bittiming_const;
	int tseg1, alltseg;
	u32 bitrate;
	u64 brp64;

	if (!priv->bittiming_const)
		return -ENOTSUPP;

	tseg1 = bt->prop_seg + bt->phase_seg1;
	if (bt->sjw > btc->sjw_max ||
	    tseg1 < btc->tseg1_min || tseg1 > btc->tseg1_max ||
	    bt->phase_seg2 < btc->tseg2_min || bt->phase_seg2 > btc->tseg2_max)
		return -EINVAL;

	brp64 = (u64)bt->clock * (u64)bt->tq;
	if (btc->brp_inc > 1)
		do_div(brp64, btc->brp_inc);
	brp64 += 500000000UL - 1;
	do_div(brp64, 1000000000UL); /* the practicable BRP */
	if (btc->brp_inc > 1)
		brp64 *= btc->brp_inc;
	bt->brp = (u32)brp64;

	if (bt->brp < btc->brp_min || bt->brp > btc->brp_max)
		return -EINVAL;

	alltseg = bt->prop_seg + bt->phase_seg1 + bt->phase_seg2 + 1;
	bitrate = bt->clock / (bt->brp * alltseg);
	bt->bitrate = bitrate;

	return 0;
}

/*
 * Set CAN bit-timing for the device
 *
 * This functions should be called in the open function of the device
 * driver to determine, check and set appropriate bit-timing parameters.
 */
int can_set_bittiming(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);
	int err;

	/* Check if bit-timing parameters have been pre-defined */
	if (!priv->bittiming.tq && !priv->bittiming.bitrate) {
		dev_err(ND2D(dev), "bit-timing not yet defined\n");
		return -EINVAL;
	}

	/* Check if the CAN device has bit-timing parameters */
	if (priv->bittiming_const) {

		/* Check if bit-timing parameters have already been set */
		if (priv->bittiming.tq && priv->bittiming.bitrate)
			return 0;

		/* Non-expert mode? Check if the bitrate has been pre-defined */
		if (!priv->bittiming.tq)
			/* Determine bit-timing parameters */
			err = can_calc_bittiming(dev);
		else
			/* Check bit-timing params and calculate proper brp */
			err = can_fixup_bittiming(dev);
		if (err)
			return err;
	}

	if (priv->do_set_bittiming) {
		/* Finally, set the bit-timing registers */
		err = priv->do_set_bittiming(dev);
		if (err)
			return err;
	}

	return 0;
}
EXPORT_SYMBOL(can_set_bittiming);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
struct net_device_stats *can_get_stats(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);

	return &priv->net_stats;
}
EXPORT_SYMBOL(can_get_stats);
#endif

static void can_setup(struct net_device *dev)
{
	dev->type = ARPHRD_CAN;
	dev->mtu = sizeof(struct can_frame);
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->tx_queue_len = 10;

	/* New-style flags. */
	dev->flags = IFF_NOARP;
	dev->features = NETIF_F_NO_CSUM;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	dev->get_stats = can_get_stats;
#endif
}

/*
 * Allocate and setup space for the CAN network device
 */
struct net_device *alloc_candev(int sizeof_priv)
{
	struct net_device *dev;
	struct can_priv *priv;

	dev = alloc_netdev(sizeof_priv, "can%d", can_setup);
	if (!dev)
		return NULL;

	priv = netdev_priv(dev);

	priv->state = CAN_STATE_STOPPED;
	spin_lock_init(&priv->irq_lock);

	init_timer(&priv->timer);
	priv->timer.expires = 0;

	return dev;
}
EXPORT_SYMBOL(alloc_candev);

/*
 * Allocate space of the CAN network device
 */
void free_candev(struct net_device *dev)
{
	free_netdev(dev);
}
EXPORT_SYMBOL(free_candev);

/*
 * Register the CAN network device
 */
int register_candev(struct net_device *dev)
{
	int err;

	err = register_netdev(dev);
	if (err)
		return err;

#ifdef CONFIG_SYSFS
	can_create_sysfs(dev);
#endif
	return 0;
}
EXPORT_SYMBOL(register_candev);

/*
 * Unregister the CAN network device
 */
void unregister_candev(struct net_device *dev)
{
#ifdef CONFIG_SYSFS
	can_remove_sysfs(dev);
#endif
	unregister_netdev(dev);
}
EXPORT_SYMBOL(unregister_candev);

/*
 * Local echo of CAN messages
 *
 * CAN network devices *should* support a local echo functionality
 * (see Documentation/networking/can.txt). To test the handling of CAN
 * interfaces that do not support the local echo both driver types are
 * implemented. In the case that the driver does not support the echo
 * the IFF_ECHO remains clear in dev->flags. This causes the PF_CAN core
 * to perform the echo as a fallback solution.
 */

void can_flush_echo_skb(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	struct net_device_stats *stats = can_get_stats(dev);
#else
	struct net_device_stats *stats = &dev->stats;
#endif
	int i;

	for (i = 0; i < CAN_ECHO_SKB_MAX; i++) {
		if (priv->echo_skb[i]) {
			kfree_skb(priv->echo_skb[i]);
			priv->echo_skb[i] = NULL;
			stats->tx_dropped++;
			stats->tx_aborted_errors++;
		}
	}
}

/*
 * Put the skb on the stack to be looped backed locally lateron
 *
 * The function is typically called in the start_xmit function
 * of the device driver.
 */
void can_put_echo_skb(struct sk_buff *skb, struct net_device *dev, int idx)
{
	struct can_priv *priv = netdev_priv(dev);

	/* set flag whether this packet has to be looped back */
	if (!(dev->flags & IFF_ECHO) || skb->pkt_type != PACKET_LOOPBACK) {
		kfree_skb(skb);
		return;
	}

	if (!priv->echo_skb[idx]) {
		struct sock *srcsk = skb->sk;

		if (atomic_read(&skb->users) != 1) {
			struct sk_buff *old_skb = skb;

			skb = skb_clone(old_skb, GFP_ATOMIC);
			kfree_skb(old_skb);
			if (!skb)
				return;
		} else
			skb_orphan(skb);

		skb->sk = srcsk;

		/* make settings for echo to reduce code in irq context */
		skb->protocol = htons(ETH_P_CAN);
		skb->pkt_type = PACKET_BROADCAST;
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		skb->dev = dev;

		/* save this skb for tx interrupt echo handling */
		priv->echo_skb[idx] = skb;
	} else {
		/* locking problem with netif_stop_queue() ?? */
		printk(KERN_ERR "%s: %s: BUG! echo_skb is occupied!\n",
		       dev->name, __func__);
		kfree_skb(skb);
	}
}
EXPORT_SYMBOL(can_put_echo_skb);

/*
 * Get the skb from the stack and loop it back locally
 *
 * The function is typically called when the TX done interrupt
 * is handled in the device driver.
 */
void can_get_echo_skb(struct net_device *dev, int idx)
{
	struct can_priv *priv = netdev_priv(dev);

	if ((dev->flags & IFF_ECHO) && priv->echo_skb[idx]) {
		netif_rx(priv->echo_skb[idx]);
		priv->echo_skb[idx] = NULL;
	}
}
EXPORT_SYMBOL(can_get_echo_skb);

/*
 * CAN device restart for bus-off recovery
 */
int can_restart_now(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	struct net_device_stats *stats = can_get_stats(dev);
#else
	struct net_device_stats *stats = &dev->stats;
#endif
	struct sk_buff *skb;
	struct can_frame *cf;
	int err;

	if (netif_carrier_ok(dev))
		netif_carrier_off(dev);

	/* Cancel restart in progress */
	if (priv->timer.expires) {
		del_timer(&priv->timer);
		priv->timer.expires = 0; /* mark inactive timer */
	}

	can_flush_echo_skb(dev);

	err = priv->do_set_mode(dev, CAN_MODE_START);
	if (err)
		return err;

	netif_carrier_on(dev);

	priv->can_stats.restarts++;

	/* send restart message upstream */
	skb = dev_alloc_skb(sizeof(struct can_frame));
	if (skb == NULL)
		return -ENOMEM;
	skb->dev = dev;
	skb->protocol = htons(ETH_P_CAN);
	cf = (struct can_frame *)skb_put(skb, sizeof(struct can_frame));
	memset(cf, 0, sizeof(struct can_frame));
	cf->can_id = CAN_ERR_FLAG | CAN_ERR_RESTARTED;
	cf->can_dlc = CAN_ERR_DLC;

	netif_rx(skb);

	dev->last_rx = jiffies;
	stats->rx_packets++;
	stats->rx_bytes += cf->can_dlc;

	return 0;
}

static void can_restart_after(unsigned long data)
{
	struct net_device *dev = (struct net_device *)data;
	struct can_priv *priv = netdev_priv(dev);

	priv->timer.expires = 0; /* mark inactive timer */
	can_restart_now(dev);
}

/*
 * CAN bus-off
 *
 * This functions should be called when the device goes bus-off to
 * tell the netif layer that no more packets can be sent or received.
 * If enabled, a timer is started to trigger bus-off recovery.
 */
void can_bus_off(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);

	netif_carrier_off(dev);

	if (priv->restart_ms > 0 && !priv->timer.expires) {

		priv->timer.function = can_restart_after;
		priv->timer.data = (unsigned long)dev;
		priv->timer.expires =
			jiffies + (priv->restart_ms * HZ) / 1000;
		add_timer(&priv->timer);
	}
}
EXPORT_SYMBOL(can_bus_off);

/*
 * Cleanup function before the device gets closed.
 *
 * This functions should be called in the close function of the device
 * driver.
 */
void can_close_cleanup(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);

	if (priv->timer.expires) {
		del_timer(&priv->timer);
		priv->timer.expires = 0;
	}

	can_flush_echo_skb(dev);
}
EXPORT_SYMBOL(can_close_cleanup);

static __init int can_dev_init(void)
{
	printk(KERN_INFO MOD_DESC "\n");

	return 0;
}
module_init(can_dev_init);

static __exit void can_dev_exit(void)
{
}
module_exit(can_dev_exit);
