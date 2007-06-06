/*
 * vcan.c - Virtual CAN interface
 *
 * Copyright (c) 2002-2007 Volkswagen Group Electronic Research
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, the following disclaimer and
 *    the referenced file 'COPYING'.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Volkswagen nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2 as distributed in the 'COPYING'
 * file from the main directory of the linux kernel source.
 *
 * The provided data structures and external interfaces from this code
 * are not restricted to be used by modules with a GPL compatible license.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * Send feedback to <socketcan-users@lists.berlios.de>
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/can.h>

#include <linux/can/version.h> /* for RCSID. Removed by mkpatch script */
RCSID("$Id$");

static __initdata const char banner[] =
	KERN_INFO "vcan: Virtual CAN interface driver\n";

MODULE_DESCRIPTION("virtual CAN interface");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Urs Thuermann <urs.thuermann@volkswagen.de>");

#ifdef CONFIG_CAN_DEBUG_DEVICES
static int debug = 0;
module_param(debug, int, S_IRUGO);
#endif

/* To be moved to linux/can/dev.h */
#ifdef CONFIG_CAN_DEBUG_DEVICES
#define DBG(args...)       (debug & 1 ? \
			       (printk(KERN_DEBUG "vcan %s: ", __func__), \
				printk(args)) : 0)
#else
#define DBG(args...)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
static void *kzalloc(size_t size, unsigned int __nocast flags)
{
	void *ret = kmalloc(size, flags);

	if (ret)
		memset(ret, 0, size);

	return ret;
}
#endif

#define STATSIZE sizeof(struct net_device_stats)

static int numdev = 4; /* default number of virtual CAN interfaces */
module_param(numdev, int, S_IRUGO);
MODULE_PARM_DESC(numdev, "Number of virtual CAN devices");

/*
 * CAN network devices *should* support a local loopback functionality
 * (see Documentation/networking/can.txt). To test the handling of CAN
 * interfaces that do not support the loopback both driver types are
 * implemented inside this vcan driver. In the case that the driver does
 * not support the loopback the IFF_LOOPBACK remains clear in dev->flags.
 * This causes the PF_CAN core to perform the loopback as a fallback solution.
 */

static int loopback = 0; /* vcan default: no loopback, just free the skb */
module_param(loopback, int, S_IRUGO);
MODULE_PARM_DESC(loopback, "Loop back sent frames. vcan default: 0 (Off)");

static struct net_device **vcan_devs; /* root pointer to netdevice structs */

static int vcan_open(struct net_device *dev)
{
	DBG("%s: interface up\n", dev->name);

	netif_start_queue(dev);
	return 0;
}

static int vcan_stop(struct net_device *dev)
{
	DBG("%s: interface down\n", dev->name);

	netif_stop_queue(dev);
	return 0;
}

static void vcan_rx(struct sk_buff *skb, struct net_device *dev)
{
	struct net_device_stats *stats = netdev_priv(dev);

	stats->rx_packets++;
	stats->rx_bytes += skb->len;

	skb->protocol  = htons(ETH_P_CAN);
	skb->pkt_type  = PACKET_BROADCAST;
	skb->dev       = dev;
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	DBG("received skbuff on interface %d\n", dev->ifindex);

	netif_rx(skb);
}

static int vcan_tx(struct sk_buff *skb, struct net_device *dev)
{
	struct net_device_stats *stats = netdev_priv(dev);
	int loop;

	DBG("sending skbuff on interface %s\n", dev->name);

	stats->tx_packets++;
	stats->tx_bytes += skb->len;

	/* tx socket reference pointer: Loopback required if not NULL */
	loop = *(struct sock **)skb->cb != NULL;

	if (!loopback) {
		/* no loopback handling available inside this driver */

		if (loop) {
			/*
			 * only count the packets here, because the
			 * CAN core already did the loopback for us
			 */
			stats->rx_packets++;
			stats->rx_bytes += skb->len;
		}
		kfree_skb(skb);
		return 0;
	}

	/* perform standard loopback handling for CAN network interfaces */

	if (loop) {
		if (atomic_read(&skb->users) != 1) {
			struct sk_buff *old_skb = skb;

			skb = skb_clone(old_skb, GFP_ATOMIC);
			DBG(KERN_INFO "%s: %s: freeing old skbuff %p, "
			    "using new skbuff %p\n",
			    dev->name, __FUNCTION__, old_skb, skb);
			kfree_skb(old_skb);
			if (!skb)
				return 0;
		} else
			skb_orphan(skb);

		/* receive with packet counting */
		vcan_rx(skb, dev);
	} else {
		/* no looped packets => no counting */
		kfree_skb(skb);
	}
	return 0;
}

static struct net_device_stats *vcan_get_stats(struct net_device *dev)
{
	struct net_device_stats *stats = netdev_priv(dev);

	return stats;
}

static void vcan_init(struct net_device *dev)
{
	DBG("dev %s\n", dev->name);

	ether_setup(dev);

	memset(dev->priv, 0, STATSIZE);

	dev->type              = ARPHRD_CAN;
	dev->mtu               = sizeof(struct can_frame);
	dev->flags             = IFF_NOARP;

	/* set flags according to driver capabilities */
	if (loopback)
		dev->flags |= IFF_LOOPBACK;

	dev->open              = vcan_open;
	dev->stop              = vcan_stop;
	dev->hard_start_xmit   = vcan_tx;
	dev->get_stats         = vcan_get_stats;

	SET_MODULE_OWNER(dev);
}

static __init int vcan_init_module(void)
{
	int i, result;

	printk(banner);

	/* register at least one interface */
	if (numdev < 1)
		numdev = 1;

	printk(KERN_INFO
	       "vcan: registering %d virtual CAN interfaces. (loopback %s)\n",
	       numdev, loopback ? "enabled" : "disabled");

	vcan_devs = kzalloc(numdev * sizeof(struct net_device *), GFP_KERNEL);
	if (!vcan_devs) {
		printk(KERN_ERR "vcan: Can't allocate vcan devices array!\n");
		return -ENOMEM;
	}

	for (i = 0; i < numdev; i++) {
		vcan_devs[i] = alloc_netdev(STATSIZE, "vcan%d", vcan_init);
		if (!vcan_devs[i]) {
			printk(KERN_ERR "vcan: error allocating net_device\n");
			result = -ENOMEM;
			goto out;
		}

		result = register_netdev(vcan_devs[i]);
		if (result < 0) {
			printk(KERN_ERR
			       "vcan: error %d registering interface %s\n",
			       result, vcan_devs[i]->name);
			free_netdev(vcan_devs[i]);
			vcan_devs[i] = NULL;
			goto out;

		} else {
			DBG("successfully registered interface %s\n",
			    vcan_devs[i]->name);
		}
	}

	return 0;

 out:
	for (i = 0; i < numdev; i++) {
		if (vcan_devs[i]) {
			unregister_netdev(vcan_devs[i]);
			free_netdev(vcan_devs[i]);
		}
	}

	kfree(vcan_devs);

	return result;
}

static __exit void vcan_cleanup_module(void)
{
	int i;

	for (i = 0; i < numdev; i++) {
		if (vcan_devs[i]) {
			unregister_netdev(vcan_devs[i]);
			free_netdev(vcan_devs[i]);
		}
	}

	kfree(vcan_devs);
}

module_init(vcan_init_module);
module_exit(vcan_cleanup_module);
