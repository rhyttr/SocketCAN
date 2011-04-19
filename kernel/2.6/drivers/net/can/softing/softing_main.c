/*
* drivers/net/can/softing/softing_main.c
*
* Copyright (C) 2008
*
* - Kurt Van Dijck, EIA Electronics
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
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
*/

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/mutex.h>
#include <linux/io.h>

#include "softing.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
#error This driver does not support Kernel versions < 2.6.23
#endif

#define TX_ECHO_SKB_MAX 4

/*
 * test is a specific CAN netdev
 * is online (ie. up 'n running, not sleeping, not busoff
 */
static inline int canif_is_active(struct net_device *netdev)
{
	struct can_priv *can = netdev_priv(netdev);
	if (!netif_running(netdev))
		return 0;
	return (can->state <= CAN_STATE_ERROR_PASSIVE);
}

/* trigger the tx queue-ing */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
static int netdev_start_xmit(struct sk_buff *skb, struct net_device *dev)
#else
static netdev_tx_t netdev_start_xmit(struct sk_buff *skb,
			struct net_device *dev)
#endif
{
	struct softing_priv *priv = netdev_priv(dev);
	struct softing *card = priv->card;
	int ret;
	int bhlock;
	u8 *ptr;
	u8 cmd;
	unsigned int fifo_wr;
	struct can_frame msg;

	if (can_dropped_invalid_skb(dev, skb))
		return NETDEV_TX_OK;

	if (in_interrupt()) {
		bhlock = 0;
		spin_lock(&card->spin);
	} else {
		bhlock = 1;
		spin_lock_bh(&card->spin);
	}
	ret = NETDEV_TX_BUSY;
	if (!card->fw.up)
		goto xmit_done;
	if (card->tx.pending >= TXMAX)
		goto xmit_done;
	if (priv->tx.pending >= TX_ECHO_SKB_MAX)
		goto xmit_done;
	fifo_wr = card->dpram.tx->wr;
	if (fifo_wr == card->dpram.tx->rd)
		/*fifo full */
		goto xmit_done;
	memcpy(&msg, skb->data, sizeof(msg));
	ptr = &card->dpram.tx->fifo[fifo_wr][0];
	cmd = CMD_TX;
	if (msg.can_id & CAN_RTR_FLAG)
		cmd |= CMD_RTR;
	if (msg.can_id & CAN_EFF_FLAG)
		cmd |= CMD_XTD;
	if (priv->index)
		cmd |= CMD_BUS2;
	*ptr++ = cmd;
	*ptr++ = msg.can_dlc;
	*ptr++ = (msg.can_id >> 0);
	*ptr++ = (msg.can_id >> 8);
	if (msg.can_id & CAN_EFF_FLAG) {
		*ptr++ = (msg.can_id >> 16);
		*ptr++ = (msg.can_id >> 24);
	} else {
		/*increment 1, not 2 as you might think */
		ptr += 1;
	}
	if (!(msg.can_id & CAN_RTR_FLAG))
		memcpy_toio(ptr, &msg.data[0], msg.can_dlc);
	if (++fifo_wr >=
		 sizeof(card->dpram.tx->fifo) /
		 sizeof(card->dpram.tx->fifo[0]))
		fifo_wr = 0;
	card->dpram.tx->wr = fifo_wr;
	card->tx.last_bus = priv->index;
	++card->tx.pending;
	++priv->tx.pending;
	can_put_echo_skb(skb, dev, priv->tx.echo_put);
	++priv->tx.echo_put;
	if (priv->tx.echo_put >= TX_ECHO_SKB_MAX)
		priv->tx.echo_put = 0;
	/* can_put_echo_skb() saves the skb, safe to return TX_OK */
	ret = NETDEV_TX_OK;
xmit_done:
	if (bhlock)
		spin_unlock_bh(&card->spin);
	else
		spin_unlock(&card->spin);
	if (card->tx.pending >= TXMAX) {
		struct softing_priv *bus;
		int j;
		for (j = 0; j < card->nbus; ++j) {
			bus = card->bus[j];
			if (!bus)
				continue;
			netif_stop_queue(bus->netdev);
		}
	}
	if (ret != NETDEV_TX_OK)
		netif_stop_queue(dev);

	return ret;
}

int softing_rx(struct net_device *netdev, const struct can_frame *msg,
	ktime_t ktime)
{
	struct sk_buff *skb;
	struct can_frame *cf;
	int ret;
	struct net_device_stats *stats;

	skb = alloc_can_skb(netdev, &cf);
	if (!skb)
		return -ENOMEM;
	memcpy(cf, msg, sizeof(*msg));
	skb->tstamp = ktime;
	ret = netif_rx(skb);
	if (ret == NET_RX_DROP) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
		stats = can_get_stats(netdev);
#else
		stats = &netdev->stats;
#endif
		++stats->rx_dropped;
	}
	return ret;
}

static int softing_dev_svc_once(struct softing *card)
{
	int j;
	struct softing_priv *bus;
	ktime_t ktime;
	struct can_frame msg;

	unsigned int fifo_rd;
	unsigned int cnt = 0;
	struct net_device_stats *stats;
	u8 *ptr;
	u32 tmp;
	u8 cmd;

	memset(&msg, 0, sizeof(msg));
	if (card->dpram.rx->lost_msg) {
		/*reset condition */
		card->dpram.rx->lost_msg = 0;
		/* prepare msg */
		msg.can_id = CAN_ERR_FLAG | CAN_ERR_CRTL;
		msg.can_dlc = CAN_ERR_DLC;
		msg.data[1] = CAN_ERR_CRTL_RX_OVERFLOW;
		/*
		 * service to all busses, we don't know which it was applicable
		 * but only service busses that are online
		 */
		for (j = 0; j < card->nbus; ++j) {
			bus = card->bus[j];
			if (!bus)
				continue;
			if (!canif_is_active(bus->netdev))
				/* a dead bus has no overflows */
				continue;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
			stats = can_get_stats(bus->netdev);
#else
			stats = &bus->netdev->stats;
#endif
			++stats->rx_over_errors;
			softing_rx(bus->netdev, &msg, ktime_set(0, 0));
		}
		/* prepare for other use */
		memset(&msg, 0, sizeof(msg));
		++cnt;
	}

	fifo_rd = card->dpram.rx->rd;
	if (++fifo_rd >= ARRAY_SIZE(card->dpram.rx->fifo))
		fifo_rd = 0;

	if (card->dpram.rx->wr == fifo_rd)
		return cnt;

	ptr = &card->dpram.rx->fifo[fifo_rd][0];

	cmd = *ptr++;
	if (cmd == 0xff) {
		/*not quite useful, probably the card has got out */
		dev_alert(card->dev, "got cmd 0x%02x,"
			" I suspect the card is lost\n", cmd);
	}
	/*mod_trace("0x%02x", cmd);*/
	bus = card->bus[0];
	if (cmd & CMD_BUS2)
		bus = card->bus[1];

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	stats = can_get_stats(bus->netdev);
#else
	stats = &bus->netdev->stats;
#endif
	if (cmd & CMD_ERR) {
		u8 can_state;
		u8 state;
		state = *ptr++;

		msg.can_id = CAN_ERR_FLAG;
		msg.can_dlc = CAN_ERR_DLC;

		if (state & 0x80) {
			can_state = CAN_STATE_BUS_OFF;
			msg.can_id |= CAN_ERR_BUSOFF;
			state = 2;
		} else if (state & 0x60) {
			can_state = CAN_STATE_ERROR_PASSIVE;
			msg.can_id |= CAN_ERR_BUSERROR;
			msg.data[1] = CAN_ERR_CRTL_TX_PASSIVE;
			state = 1;
		} else {
			can_state = CAN_STATE_ERROR_ACTIVE;
			state = 0;
			msg.can_id |= CAN_ERR_BUSERROR;
		}
		/*update DPRAM */
		if (!bus->index)
			card->dpram.info->bus_state = state;
		else
			card->dpram.info->bus_state2 = state;
		/*timestamp */
		tmp = (ptr[0] <<  0) | (ptr[1] <<  8)
		    | (ptr[2] << 16) | (ptr[3] << 24);
		ptr += 4;
		ktime = softing_raw2ktime(card, tmp);
		/*trigger dual port RAM */
		mb();
		card->dpram.rx->rd = fifo_rd;

		++bus->can.can_stats.bus_error;
		++stats->rx_errors;
		/*update internal status */
		if (can_state != bus->can.state) {
			bus->can.state = can_state;
			if (can_state == CAN_STATE_ERROR_PASSIVE)
				++bus->can.can_stats.error_passive;
			if (can_state == CAN_STATE_BUS_OFF) {
				/* this calls can_close_cleanup() */
				can_bus_off(bus->netdev);
				netif_stop_queue(bus->netdev);
			}
			/*trigger socketcan */
			softing_rx(bus->netdev, &msg, ktime);
		}

	} else {
		if (cmd & CMD_RTR)
			msg.can_id |= CAN_RTR_FLAG;
		/* acknowledge, was tx msg
		 * no real tx flag to set
		if (cmd & CMD_ACK) {
		}
		 */
		msg.can_dlc = get_can_dlc(*ptr++);
		if (cmd & CMD_XTD) {
			msg.can_id |= CAN_EFF_FLAG;
			msg.can_id |= (ptr[0] <<  0) | (ptr[1] <<  8)
				    | (ptr[2] << 16) | (ptr[3] << 24);
			ptr += 4;
		} else {
			msg.can_id |= (ptr[0] << 0) | (ptr[1] << 8);
			ptr += 2;
		}
		tmp = (ptr[0] <<  0) | (ptr[1] <<  8)
		    | (ptr[2] << 16) | (ptr[3] << 24);
		ptr += 4;
		ktime = softing_raw2ktime(card, tmp);
		memcpy_fromio(&msg.data[0], ptr, 8);
		ptr += 8;
		/*trigger dual port RAM */
		mb();
		card->dpram.rx->rd = fifo_rd;
		/*update socket */
		if (cmd & CMD_ACK) {
			struct sk_buff *skb;
			skb = bus->can.echo_skb[bus->tx.echo_get];
			if (skb)
				skb->tstamp = ktime;
			can_get_echo_skb(bus->netdev, bus->tx.echo_get);
			++bus->tx.echo_get;
			if (bus->tx.echo_get >= TX_ECHO_SKB_MAX)
				bus->tx.echo_get = 0;
			if (bus->tx.pending)
				--bus->tx.pending;
			if (card->tx.pending)
				--card->tx.pending;
			++stats->tx_packets;
			stats->tx_bytes += msg.can_dlc;
		} else {
			++stats->rx_packets;
			stats->rx_bytes += msg.can_dlc;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
			bus->netdev->last_rx = jiffies;
#endif
			softing_rx(bus->netdev, &msg, ktime);
		}
	}
	++cnt;
	return cnt;
}

static void softing_dev_svc(unsigned long param)
{
	struct softing *card = (struct softing *)param;
	struct softing_priv *bus;
	int j;
	int offset;

	spin_lock(&card->spin);
	while (softing_dev_svc_once(card) > 0)
		++card->irq.svc_count;
	spin_unlock(&card->spin);
	/*resume tx queue's */
	offset = card->tx.last_bus;
	for (j = 0; j < card->nbus; ++j) {
		if (card->tx.pending >= TXMAX)
			break;
		bus = card->bus[(j + offset + 1) % card->nbus];
		if (!bus)
			continue;
		if (!canif_is_active(bus->netdev))
			/* it makes no sense to wake dead busses */
			continue;
		if (bus->tx.pending >= TX_ECHO_SKB_MAX)
			continue;
		netif_wake_queue(bus->netdev);
	}
}

static
irqreturn_t dev_interrupt_shared(int irq, void *dev_id)
{
	struct softing *card = (struct softing *)dev_id;
	unsigned char ir;
	ir = card->dpram.virt[0xe02];
	card->dpram.virt[0xe02] = 0;
	if (card->dpram.rx->rd == 0xffff) {
		dev_alert(card->dev, "I think the card is gone\n");
		return IRQ_NONE;
	}
	if (ir == 1) {
		tasklet_schedule(&card->irq.bh);
		return IRQ_HANDLED;
	} else if (ir == 0x10) {
		return IRQ_NONE;
	} else {
		return IRQ_NONE;
	}
}

static
irqreturn_t dev_interrupt_nshared(int irq, void *dev_id)
{
	struct softing *card = (struct softing *)dev_id;
	unsigned char irq_host;
	irq_host = card->dpram.irq->to_host;
	/* make sure we have a copy, before clearing the variable in DPRAM */
	rmb();
	card->dpram.irq->to_host = 0;
	/* make sure we cleared it */
	wmb();
	if (card->dpram.rx->rd == 0xffff) {
		dev_alert(card->dev, "I think the card is gone\n");
		return IRQ_NONE;
	}
	tasklet_schedule(&card->irq.bh);
	return IRQ_HANDLED;
}

static int netdev_open(struct net_device *ndev)
{
	struct softing_priv *priv = netdev_priv(ndev);
	struct softing *card = priv->card;
	int ret;

	/* check or determine and set bittime */
	ret = open_candev(ndev);
	if (ret)
		goto failed;
	ret = softing_cycle(card, priv, 1);
	if (ret)
		goto failed;
	return 0;
failed:
	return ret;
}

static int netdev_stop(struct net_device *ndev)
{
	struct softing_priv *priv = netdev_priv(ndev);
	struct softing *card = priv->card;
	int ret;

	netif_stop_queue(ndev);

	/* softing cycle does close_candev() */
	ret = softing_cycle(card, priv, 0);
	return ret;
}

static int candev_set_mode(struct net_device *ndev, enum can_mode mode)
{
	struct softing_priv *priv = netdev_priv(ndev);
	struct softing *card = priv->card;
	int ret;

	switch (mode) {
	case CAN_MODE_START:
		/* softing cycle does close_candev() */
		ret = softing_cycle(card, priv, 1);
		return ret;
	case CAN_MODE_STOP:
	case CAN_MODE_SLEEP:
		return -EOPNOTSUPP;
	}
	return 0;
}

/*assume the card->lock is held*/

int softing_card_irq(struct softing *card, int enable)
{
	int ret;
	if (!enable) {
		if (card->irq.requested && card->irq.nr) {
			free_irq(card->irq.nr, card);
			card->irq.requested = 0;
		}
		return 0;
	}
	if (!card->irq.requested && (card->irq.nr)) {
		irqreturn_t(*fn) (int, void *);
		fn = dev_interrupt_nshared;
		if (card->desc->generation >= 2)
			fn = dev_interrupt_shared;
		ret = request_irq(card->irq.nr, fn, IRQF_SHARED,
				card->id.name, card);
		if (ret) {
			dev_alert(card->dev, "%s, request_irq(%u) failed\n",
				card->id.name, card->irq.nr);
			return ret;
		}
		card->irq.requested = 1;
	}
	return 0;
}

static void shutdown_card(struct softing *card)
{
	int fw_up = 0;
	dev_dbg(card->dev, "%s()\n", __func__);
	if (mutex_lock_interruptible(&card->fw.lock))
		/* return -ERESTARTSYS*/;
	fw_up = card->fw.up;
	card->fw.up = 0;

	if (card->irq.requested && card->irq.nr) {
		free_irq(card->irq.nr, card);
		card->irq.requested = 0;
	}
	if (fw_up) {
		if (card->fn.enable_irq)
			card->fn.enable_irq(card, 0);
		if (card->fn.reset)
			card->fn.reset(card, 1);
	}
	mutex_unlock(&card->fw.lock);
	tasklet_kill(&card->irq.bh);
}

static int boot_card(struct softing *card)
{
	unsigned char *lp;
	static const unsigned char stream[] =
		{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, };
	unsigned char back[sizeof(stream)];
	dev_dbg(card->dev, "%s()\n", __func__);

	if (mutex_lock_interruptible(&card->fw.lock))
		return -ERESTARTSYS;
	if (card->fw.up) {
		mutex_unlock(&card->fw.lock);
		return 0;
	}
	/*reset board */

	if (card->fn.enable_irq)
		card->fn.enable_irq(card, 1);
	/*boot card */
	if (card->fn.reset)
		card->fn.reset(card, 1);
	/*test dp ram */
	if (!card->dpram.virt)
		goto open_failed;
	for (lp = card->dpram.virt; &lp[sizeof(stream)] <= card->dpram.end;
		lp += sizeof(stream)) {

		memcpy_toio(lp, stream, sizeof(stream));
		/* flush IO cache */
		mb();
		memcpy_fromio(back, lp, sizeof(stream));

		if (!memcmp(back, stream, sizeof(stream)))
			continue;
		/* memory is not equal */
		dev_alert(card->dev, "write to dpram failed at 0x%04lx\n",
			(unsigned long)(lp - card->dpram.virt));
		goto open_failed;
	}
	wmb();
	/*load boot firmware */
	if (softing_load_fw(card->desc->boot.fw, card, card->dpram.virt,
				 card->dpram.size,
				 card->desc->boot.offs -
				 card->desc->boot.addr))
		goto open_failed;
	/*load load firmware */
	if (softing_load_fw(card->desc->load.fw, card, card->dpram.virt,
				 card->dpram.size,
				 card->desc->load.offs -
				 card->desc->load.addr))
		goto open_failed;

	if (card->fn.reset)
		card->fn.reset(card, 0);
	if (softing_bootloader_command(card, 0, "card boot"))
		goto open_failed;
	if (softing_load_app_fw(card->desc->app.fw, card))
		goto open_failed;
	/*reset chip */
	card->dpram.info->reset_rcv_fifo = 0;
	card->dpram.info->reset = 1;
	/*sync */
	if (softing_fct_cmd(card, 99, 0x55, "sync-a"))
		goto open_failed;
	if (softing_fct_cmd(card, 99, 0xaa, "sync-a"))
		goto open_failed;
	/*reset chip */
	if (softing_fct_cmd(card, 0, 0, "reset_chip"))
		goto open_failed;
	/*get_serial */
	if (softing_fct_cmd(card, 43, 0, "get_serial_number"))
		goto open_failed;
	card->id.serial =
		 (u16) card->dpram.fct->param[1] +
		 (((u16) card->dpram.fct->param[2]) << 16);
	/*get_version */
	if (softing_fct_cmd(card, 12, 0, "get_version"))
		goto open_failed;
	card->id.fw = (u16) card->dpram.fct->param[1];
	card->id.hw = (u16) card->dpram.fct->param[2];
	card->id.lic = (u16) card->dpram.fct->param[3];
	card->id.chip[0] = (u16) card->dpram.fct->param[4];
	card->id.chip[1] = (u16) card->dpram.fct->param[5];

	dev_info(card->dev, "card booted, type %s, "
			"serial %u, fw %u, hw %u, lic %u, chip (%u,%u)\n",
		  card->id.name, card->id.serial, card->id.fw, card->id.hw,
		  card->id.lic, card->id.chip[0], card->id.chip[1]);

	card->fw.up = 1;
	mutex_unlock(&card->fw.lock);
	return 0;
open_failed:
	card->fw.up = 0;
	if (card->fn.enable_irq)
		card->fn.enable_irq(card, 0);
	if (card->fn.reset)
		card->fn.reset(card, 1);
	mutex_unlock(&card->fw.lock);
	return EINVAL;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,28)
static const struct net_device_ops softing_netdev_ops = {
	.ndo_open 	= netdev_open,
	.ndo_stop	= netdev_stop,
	.ndo_start_xmit	= netdev_start_xmit,
};
#endif

static const struct can_bittiming_const softing_btr_const = {
	.tseg1_min = 1,
	.tseg1_max = 16,
	.tseg2_min = 1,
	.tseg2_max = 8,
	.sjw_max = 4, /* overruled */
	.brp_min = 1,
	.brp_max = 32, /* overruled */
	.brp_inc = 1,
};


static struct softing_priv *mk_netdev(struct softing *card, u16 chip_id)
{
	struct net_device *ndev;
	struct softing_priv *priv;

	ndev = alloc_candev(sizeof(*priv), TX_ECHO_SKB_MAX);
	if (!ndev) {
		dev_alert(card->dev, "alloc_candev failed\n");
		return 0;
	}
	priv = netdev_priv(ndev);
	priv->netdev		= ndev;
	priv->card		= card;
	memcpy(&priv->btr_const, &softing_btr_const, sizeof(priv->btr_const));
	priv->btr_const.brp_max = card->desc->max_brp;
	priv->btr_const.sjw_max = card->desc->max_sjw;
	priv->can.bittiming_const = &priv->btr_const;
	priv->can.clock.freq	= 8000000;
	priv->chip 		= chip_id;
	priv->output = softing_default_output(card, priv);
	SET_NETDEV_DEV(ndev, card->dev);

	ndev->flags |= IFF_ECHO;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,28)
	ndev->netdev_ops	= &softing_netdev_ops;
#else
	ndev->open		= netdev_open;
	ndev->stop		= netdev_stop;
	ndev->hard_start_xmit	= netdev_start_xmit;
#endif
	priv->can.do_set_mode	= candev_set_mode;
	priv->can.ctrlmode_supported = CAN_CTRLMODE_3_SAMPLES;

	return priv;
}

static int reg_netdev(struct softing_priv *priv)
{
	int ret;
	ret = register_candev(priv->netdev);
	if (ret) {
		dev_alert(priv->card->dev, "%s, register failed\n",
			priv->card->id.name);
		goto reg_failed;
	}
	ret = softing_bus_sysfs_create(priv);
	if (ret) {
		dev_alert(priv->card->dev, "%s, sysfs failed\n",
			priv->card->id.name);
		goto sysfs_failed;
	}
	return 0;
sysfs_failed:
	unregister_candev(priv->netdev);
reg_failed:
	return EINVAL;
}

void rm_softing(struct softing *card)
{
	int j;

	/*first, disable card*/
	shutdown_card(card);

	for (j = 0; j < card->nbus; ++j) {
		if (!card->bus[j])
			continue;
		softing_bus_sysfs_remove(card->bus[j]);
		unregister_candev(card->bus[j]->netdev);
		free_candev(card->bus[j]->netdev);
		card->bus[j] = 0;
	}

	softing_card_sysfs_remove(card);

	iounmap(card->dpram.virt);
}
EXPORT_SYMBOL(rm_softing);

int mk_softing(struct softing *card)
{
	int j;

	/* try_module_get(THIS_MODULE); */
	mutex_init(&card->fw.lock);
	spin_lock_init(&card->spin);
	tasklet_init(&card->irq.bh, softing_dev_svc, (unsigned long)card);

	if (!card->desc) {
		dev_alert(card->dev, "no card description\n");
		goto lookup_failed;
	}
	card->id.name = card->desc->name;

	card->dpram.virt = ioremap(card->dpram.phys, card->dpram.size);
	if (!card->dpram.virt) {
		dev_alert(card->dev, "dpram ioremap failed\n");
		goto ioremap_failed;
	}

	card->dpram.size = card->desc->dpram_size;
	card->dpram.end = &card->dpram.virt[card->dpram.size];
	/*initialize_board */
	card->dpram.rx = (struct softing_rx *)&card->dpram.virt[0x0000];
	card->dpram.tx = (struct softing_tx *)&card->dpram.virt[0x0400];
	card->dpram.fct = (struct softing_fct *)&card->dpram.virt[0x0300];
	card->dpram.info = (struct softing_info *)&card->dpram.virt[0x0330];
	card->dpram.command = (unsigned short *)&card->dpram.virt[0x07e0];
	card->dpram.receipt = (unsigned short *)&card->dpram.virt[0x07f0];
	card->dpram.irq = (struct softing_irq *)&card->dpram.virt[0x07fe];

	/*reset card */
	if (card->fn.reset)
		card->fn.reset(card, 1);
	if (boot_card(card)) {
		dev_alert(card->dev, "failed to boot\n");
		goto boot_failed;
	}

	/*only now, the chip's are known */
	card->id.freq = card->desc->freq * 1000000UL;

	if (softing_card_sysfs_create(card)) {
		dev_alert(card->dev, "sysfs failed\n");
		goto sysfs_failed;
	}

	if (card->nbus > (sizeof(card->bus) / sizeof(card->bus[0]))) {
		card->nbus = sizeof(card->bus) / sizeof(card->bus[0]);
		dev_alert(card->dev, "have %u busses\n", card->nbus);
	}

	for (j = 0; j < card->nbus; ++j) {
		card->bus[j] = mk_netdev(card, card->id.chip[j]);
		if (!card->bus[j]) {
			dev_alert(card->dev, "failed to make can[%i]", j);
			goto netdev_failed;
		}
		card->bus[j]->index = j;
	}
	for (j = 0; j < card->nbus; ++j) {
		if (reg_netdev(card->bus[j])) {
			dev_alert(card->dev,
				"failed to register can[%i]\n", j);
			goto reg_failed;
		}
	}
	dev_info(card->dev, "card initialised\n");
	return 0;

reg_failed:
	for (j = 0; j < card->nbus; ++j) {
		if (!card->bus[j])
			continue;
		softing_bus_sysfs_remove(card->bus[j]);
		unregister_candev(card->bus[j]->netdev);
	}
netdev_failed:
	for (j = 0; j < card->nbus; ++j) {
		if (!card->bus[j])
			continue;
		free_candev(card->bus[j]->netdev);
		card->bus[j] = 0;
	}
	softing_card_sysfs_remove(card);
sysfs_failed:
	shutdown_card(card);
boot_failed:
	iounmap(card->dpram.virt);
	card->dpram.virt = 0;
	card->dpram.end = 0;
ioremap_failed:
lookup_failed:
	tasklet_kill(&card->irq.bh);
	return EINVAL;
}
EXPORT_SYMBOL(mk_softing);

static int __init mod_start(void)
{
	printk(KERN_INFO "[%s] start\n", THIS_MODULE->name);
	return 0;
}

static void __exit mod_stop(void)
{
	printk(KERN_INFO "[%s] stop\n", THIS_MODULE->name);
}

module_init(mod_start);
module_exit(mod_stop);

MODULE_DESCRIPTION("socketcan softing driver");
MODULE_AUTHOR("Kurt Van Dijck <kurt.van.dijck@eia.be>");
MODULE_LICENSE("GPL");

int softing_debug = 1;
EXPORT_SYMBOL(softing_debug);
module_param(softing_debug, int , S_IRUGO | S_IWUSR | S_IWGRP);
MODULE_PARM_DESC(softing_debug, "trace softing functions");
