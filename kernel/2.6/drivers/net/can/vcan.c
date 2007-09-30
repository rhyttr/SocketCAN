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
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Volkswagen nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23)
#include <net/rtnetlink.h>
#endif

#include <linux/can/version.h> /* for RCSID. Removed by mkpatch script */
RCSID("$Id$");

static __initdata const char banner[] =
	KERN_INFO "vcan: Virtual CAN interface driver\n";

MODULE_DESCRIPTION("virtual CAN interface");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Urs Thuermann <urs.thuermann@volkswagen.de>");

#ifdef CONFIG_CAN_DEBUG_DEVICES
static int debug;
module_param(debug, int, S_IRUGO);
#endif

/* To be moved to linux/can/dev.h */
#ifdef CONFIG_CAN_DEBUG_DEVICES
#define DBG(fmt, args...)  (debug & 1 ? \
				printk(KERN_DEBUG "vcan %s: " fmt, \
				__func__, ##args) : 0)
#else
#define DBG(fmt, args...)
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
static int numdev = 4; /* default number of virtual CAN interfaces */
module_param(numdev, int, S_IRUGO);
MODULE_PARM_DESC(numdev, "Number of virtual CAN devices");
#endif

/*
 * CAN test feature:
 * Enable the echo on driver level for testing the CAN core echo modes.
 * See Documentation/networking/can.txt for details.
 */

static int echo; /* echo testing. Default: 0 (Off) */
module_param(echo, int, S_IRUGO);
MODULE_PARM_DESC(echo, "Echo sent frames (for testing). Default: 0 (Off)");

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
static struct net_device **vcan_devs; /* root pointer to netdevice structs */
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
#define PRIVSIZE sizeof(struct net_device_stats)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define PRIVSIZE 0
#endif

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23)
	struct net_device_stats *stats = &dev->stats;
#else
	struct net_device_stats *stats = netdev_priv(dev);
#endif

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23)
	struct net_device_stats *stats = &dev->stats;
#else
	struct net_device_stats *stats = netdev_priv(dev);
#endif
	int loop;

	DBG("sending skbuff on interface %s\n", dev->name);

	stats->tx_packets++;
	stats->tx_bytes += skb->len;

	/* set flag whether this packet has to be looped back */
	loop = skb->pkt_type == PACKET_LOOPBACK;

	if (!echo) {
		/* no echo handling available inside this driver */

		if (loop) {
			/*
			 * only count the packets here, because the
			 * CAN core already did the echo for us
			 */
			stats->rx_packets++;
			stats->rx_bytes += skb->len;
		}
		kfree_skb(skb);
		return 0;
	}

	/* perform standard echo handling for CAN network interfaces */

	if (loop) {
		struct sock *srcsk = skb->sk;

		skb = skb_share_check(skb, GFP_ATOMIC);
		if (!skb)
			return 0;

		/* receive with packet counting */
		skb->sk = srcsk;
		vcan_rx(skb, dev);
	} else {
		/* no looped packets => no counting */
		kfree_skb(skb);
	}
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
static struct net_device_stats *vcan_get_stats(struct net_device *dev)
{
	struct net_device_stats *stats = netdev_priv(dev);

	return stats;
}
#endif

static void vcan_setup(struct net_device *dev)
{
	DBG("dev %s\n", dev->name);

	dev->type              = ARPHRD_CAN;
	dev->mtu               = sizeof(struct can_frame);
	dev->hard_header_len   = 0;
	dev->addr_len          = 0;
	dev->tx_queue_len      = 0;
	dev->flags             = IFF_NOARP;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define IFF_ECHO IFF_LOOPBACK
#endif
	/* set flags according to driver capabilities */
	if (echo)
		dev->flags |= IFF_ECHO;

	dev->open              = vcan_open;
	dev->stop              = vcan_stop;
	dev->hard_start_xmit   = vcan_tx;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	dev->destructor        = free_netdev;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	dev->get_stats         = vcan_get_stats;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	SET_MODULE_OWNER(dev);
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
static struct rtnl_link_ops vcan_link_ops __read_mostly = {
       .kind           = "vcan",
       .setup          = vcan_setup,
};

static __init int vcan_init_module(void)
{
	printk(banner);

	if (echo)
		printk(KERN_INFO "vcan: enabled echo on driver level.\n");

	return rtnl_link_register(&vcan_link_ops);
}

static __exit void vcan_cleanup_module(void)
{
	rtnl_link_unregister(&vcan_link_ops);
}
#else
static __init int vcan_init_module(void)
{
	int i, result;

	printk(banner);

	/* register at least one interface */
	if (numdev < 1)
		numdev = 1;

	printk(KERN_INFO
	       "vcan: registering %d virtual CAN interfaces. (echo %s)\n",
	       numdev, echo ? "enabled" : "disabled");

	vcan_devs = kzalloc(numdev * sizeof(struct net_device *), GFP_KERNEL);
	if (!vcan_devs) {
		printk(KERN_ERR "vcan: Can't allocate vcan devices array!\n");
		return -ENOMEM;
	}

	for (i = 0; i < numdev; i++) {
		vcan_devs[i] = alloc_netdev(PRIVSIZE, "vcan%d", vcan_setup);
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
#endif

module_init(vcan_init_module);
module_exit(vcan_cleanup_module);
