/*
 * vcan.c
 *
 * Copyright (c) 2002-2005 Volkswagen Group Electronic Research
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
 * Send feedback to <llcf@volkswagen.de>
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>

#include <net/can/af_can.h>
#include <net/can/version.h>

RCSID("$Id$");


#define NAME "VCAN loopback interface for LLCF"
static __initdata const char banner[] = BANNER(NAME);

MODULE_DESCRIPTION(NAME);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Urs Thuermann <urs.thuermann@volkswagen.de>");

#ifdef DEBUG
static int debug = 0;
module_param(debug, int, S_IRUGO);
#define DBG(args...)       (debug & 1 ? \
	                       (printk(KERN_DEBUG "VCAN %s: ", __func__), \
			        printk(args)) : 0)
#define DBG_FRAME(args...) (debug & 2 ? can_debug_cframe(args) : 0)
#define DBG_SKB(skb)       (debug & 4 ? can_debug_skb(skb) : 0)
#else
#define DBG(args...)
#define DBG_FRAME(args...)
#define DBG_SKB(skb)
#endif

/* This 'undef' makes the vcan a kind of NULL device.  Since LLCF v0.6  */
/* the local loopback is implemented in af_can.c for all interfaces.    */
#undef  DO_LOOPBACK

#define NDEVICES 4

static struct net_device *vcan_devs[NDEVICES];

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

#ifdef DO_LOOPBACK

static void vcan_rx(struct sk_buff *skb, struct net_device *dev)
{
    struct net_device_stats *stats = netdev_priv(dev);
    stats->rx_packets++;
    stats->rx_bytes += skb->len;

    skb->protocol  = htons(ETH_P_CAN);
    skb->dev       = dev;
    skb->ip_summed = CHECKSUM_UNNECESSARY;

    DBG("received skbuff on interface %d\n", dev->ifindex);
    DBG_SKB(skb);

    netif_rx(skb);
}

#endif


static int vcan_tx(struct sk_buff *skb, struct net_device *dev)
{
    struct net_device_stats *stats = netdev_priv(dev);

    DBG("sending skbuff on interface %s\n", dev->name);
    DBG_SKB(skb);
    DBG_FRAME("VCAN: transmit CAN frame", (struct can_frame *)skb->data);

#ifdef DO_LOOPBACK
    if (atomic_read(&skb->users) != 1) {
	struct sk_buff *old_skb = skb;
	skb = skb_clone(old_skb, GFP_ATOMIC);
	DBG("  freeing old skbuff %p, using new skbuff %p\n", old_skb, skb);
	kfree_skb(old_skb);
	if (!skb) {
	    return 0;
	}
    } else
	skb_orphan(skb);
#endif

    stats->tx_packets++;
    stats->tx_bytes += skb->len;
#ifdef DO_LOOPBACK
    vcan_rx(skb, dev);
#else
    stats->rx_packets++;
    stats->rx_bytes += skb->len;
    kfree_skb(skb);
#endif
    return 0;
}

static int vcan_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
    return -EOPNOTSUPP;
}

static int vcan_rebuild_header(struct sk_buff *skb)
{
    DBG("called on skbuff %p\n", skb);
    DBG_SKB(skb);
    return 0;
}

static int vcan_header(struct sk_buff *skb, struct net_device *dev,
		       unsigned short type, void *daddr, void *saddr,
		       unsigned int len)
{
    DBG("called skbuff %p device %p\n", skb, dev);
    DBG_SKB(skb);
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

    memset(dev->priv, 0, sizeof(struct net_device_stats));

    dev->open              = vcan_open;
    dev->stop              = vcan_stop;
    dev->set_config        = NULL;
    dev->hard_start_xmit   = vcan_tx;
    dev->do_ioctl          = vcan_ioctl;
    dev->get_stats         = vcan_get_stats;

    dev->mtu               = sizeof(struct can_frame);
    dev->flags             = IFF_LOOPBACK;
    dev->hard_header       = vcan_header;
    dev->rebuild_header    = vcan_rebuild_header;
    dev->hard_header_cache = NULL;
    dev->type              = ARPHRD_LOOPBACK;

    SET_MODULE_OWNER(dev);
}

static __init int vcan_init_module(void)
{
    int i, ndev = 0, result;

    printk(banner);

    for (i = 0; i < NDEVICES; i++) {
	if (!(vcan_devs[i] = alloc_netdev(sizeof(struct net_device_stats),
					  "vcan%d", vcan_init)))
	    printk(KERN_ERR "vcan: error allocating net_device\n");
	else if (result = register_netdev(vcan_devs[i])) {
	    printk(KERN_ERR "vcan: error %d registering interface %s\n",
		   result, vcan_devs[i]->name);
	    free_netdev(vcan_devs[i]);
	} else {
	    DBG("successfully registered interface %s\n", vcan_devs[i]->name);
	    ndev++;
	}
    }
    return ndev ? 0 : -ENODEV;
}

static __exit void vcan_cleanup_module(void)
{
    int i;
    for (i = 0; i < NDEVICES; i++) {
	unregister_netdev(vcan_devs[i]);
	free_netdev(vcan_devs[i]);
    }
}

module_init(vcan_init_module);
module_exit(vcan_cleanup_module);
