/*
 * af_can.c - Protocol family CAN core module
 *            (used by different CAN protocol modules)
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
#include <linux/version.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/uaccess.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <linux/can.h>
#include <linux/can/core.h>
#include <net/sock.h>

#include "af_can.h"

#include <linux/can/version.h> /* for RCSID. Removed by mkpatch script */
RCSID("$Id$");

#define IDENT "core"
static __initdata const char banner[] = KERN_INFO
	"can: controller area network core (" CAN_VERSION_STRING ")\n";

MODULE_DESCRIPTION("Controller Area Network PF_CAN core");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Urs Thuermann <urs.thuermann@volkswagen.de>, "
	      "Oliver Hartkopp <oliver.hartkopp@volkswagen.de>");

MODULE_ALIAS_NETPROTO(PF_CAN);

int stats_timer = 1; /* default: on */
module_param(stats_timer, int, S_IRUGO);
MODULE_PARM_DESC(stats_timer, "enable timer for statistics (default:on)");

#ifdef CONFIG_CAN_DEBUG_CORE
static int debug;
module_param(debug, int, S_IRUGO);
MODULE_PARM_DESC(debug, "debug print mask: 1:debug, 2:frames, 4:skbs");
#endif

HLIST_HEAD(rx_dev_list);
static struct dev_rcv_lists rx_alldev_list;
static DEFINE_SPINLOCK(rcv_lists_lock);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
static struct kmem_cache *rcv_cache __read_mostly;
#else
static kmem_cache_t *rcv_cache;
#endif

/* table of registered CAN protocols */
static struct can_proto *proto_tab[CAN_NPROTO];

struct timer_list stattimer; /* timer for statistics update */
struct s_stats  stats;       /* packet statistics */
struct s_pstats pstats;      /* receive list statistics */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
static void *kzalloc(size_t size, unsigned int __nocast flags)
{
	void *ret = kmalloc(size, flags);
	if (ret)
		memset(ret, 0, size);
	return ret;
}
#endif

/*
 * af_can socket functions
 */

static int can_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sock *sk = sock->sk;

	switch (cmd) {

	case SIOCGSTAMP:
		return sock_get_timestamp(sk, (struct timeval __user *)arg);

	default:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
		return -ENOIOCTLCMD;
#else
		return dev_ioctl(cmd, (void __user *)arg);
#endif
	}
}

static void can_sock_destruct(struct sock *sk)
{
	DBG("called for sock %p\n", sk);

	skb_queue_purge(&sk->sk_receive_queue);
	if (sk->sk_protinfo)
		kfree(sk->sk_protinfo);
}

static int can_create(struct socket *sock, int protocol)
{
	struct sock *sk;
	struct can_proto *cp;
	char module_name[sizeof("can-proto-000")];
	int ret = 0;

	DBG("socket %p, type %d, proto %d\n", sock, sock->type, protocol);

	sock->state = SS_UNCONNECTED;

	if (protocol < 0 || protocol >= CAN_NPROTO)
		return -EINVAL;

	DBG("looking up proto %d in proto_tab[]\n", protocol);

	/* try to load protocol module, when CONFIG_KMOD is defined */
	if (!proto_tab[protocol]) {
		sprintf(module_name, "can-proto-%d", protocol);
		ret = request_module(module_name);

		/*
		 * In case of error we only print a message but don't
		 * return the error code immediately.  Below we will
		 * return -EPROTONOSUPPORT
		 */
		if (ret == -ENOSYS)
			printk(KERN_INFO "can: request_module(%s) not"
			       " implemented.\n", module_name);
		else if (ret)
			printk(KERN_ERR "can: request_module(%s) failed\n",
			       module_name);
	}

	/* check for success and correct type */
	cp = proto_tab[protocol];
	if (!cp || cp->type != sock->type)
		return -EPROTONOSUPPORT;

	if (cp->capability >= 0 && !capable(cp->capability))
		return -EPERM;

	sock->ops = cp->ops;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
	sk = sk_alloc(PF_CAN, GFP_KERNEL, cp->prot, 1);
	if (!sk)
		return -ENOMEM;
#else
	sk = sk_alloc(PF_CAN, GFP_KERNEL, 1, 0);
	if (!sk)
		return -ENOMEM;

	if (cp->obj_size) {
		sk->sk_protinfo = kmalloc(cp->obj_size, GFP_KERNEL);
		if (!sk->sk_protinfo) {
			sk_free(sk);
			return -ENOMEM;
		}
	}
	sk_set_owner(sk, proto_tab[protocol]->owner);
#endif

	sock_init_data(sock, sk);
	sk->sk_destruct = can_sock_destruct;

	DBG("created sock: %p\n", sk);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
	if (sk->sk_prot->init)
		ret = sk->sk_prot->init(sk);
#else
	if (cp->init)
		ret = cp->init(sk);
#endif

	if (ret) {
		/* release sk on errors */
		sock_orphan(sk);
		sock_put(sk);
	}

	return ret;
}

/*
 * af_can tx path
 */

/**
 * can_send - transmit a CAN frame (optional with local loopback)
 * @skb: pointer to socket buffer with CAN frame in data section
 * @loop: loopback for listeners on local CAN sockets (recommended default!)
 *
 * Return:
 *  0 on success
 *  -ENETDOWN when the selected interface is down
 *  -ENOBUFS on full driver queue (see net_xmit_errno())
 *  -ENOMEM when local loopback failed at calling skb_clone()
 */
int can_send(struct sk_buff *skb, int loop)
{
	int err;

	if (skb->dev->type != ARPHRD_CAN) {
		kfree_skb(skb);
		return -EPERM;
	}

	if (!(skb->dev->flags & IFF_UP)) {
		kfree_skb(skb);
		return -ENETDOWN;
	}

	skb->protocol = htons(ETH_P_CAN);

	if (loop) {
		/* local loopback of sent CAN frames */

		/* indication for the CAN driver: do loopback */
		skb->pkt_type = PACKET_LOOPBACK;

		/*
		 * The reference to the originating sock may be required
		 * by the receiving socket to check whether the frame is
		 * its own. Example: can_raw sockopt CAN_RAW_RECV_OWN_MSGS
		 * Therefore we have to ensure that skb->sk remains the
		 * reference to the originating sock by restoring skb->sk
		 * after each skb_clone() or skb_orphan() usage.
		 */

		if (!(skb->dev->flags & IFF_LOOPBACK)) {
			/*
			 * If the interface is not capable to do loopback
			 * itself, we do it here.
			 */
			struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);

			if (!newskb) {
				kfree_skb(skb);
				return -ENOMEM;
			}

			newskb->sk = skb->sk;
			newskb->ip_summed = CHECKSUM_UNNECESSARY;
			newskb->pkt_type = PACKET_BROADCAST;
			netif_rx(newskb);
		}
	} else {
		/* indication for the CAN driver: no loopback required */
		skb->pkt_type = PACKET_HOST;
	}

	/* send to netdevice */
	err = dev_queue_xmit(skb);
	if (err > 0)
		err = net_xmit_errno(err);

	/* update statistics */
	stats.tx_frames++;
	stats.tx_frames_delta++;

	return err;
}
EXPORT_SYMBOL(can_send);

/*
 * af_can rx path
 */

static struct dev_rcv_lists *find_dev_rcv_lists(struct net_device *dev)
{
	struct dev_rcv_lists *d;
	struct hlist_node *n;

	/*
	 * find receive list for this device
	 *
	 * The hlist_for_each_entry*() macros curse through the list
	 * using the pointer variable n and set d to the containing
	 * struct in each list iteration.  Therefore, after list
	 * iteration, d is unmodified when the list is empty, and it
	 * points to last list element, when the list is non-empty
	 * but no match in the loop body is found.  I.e. d is *not*
	 * NULL when no match is found.  We can, however, use the
	 * cursor variable n to decide if a match was found.
	 */

	hlist_for_each_entry(d, n, &rx_dev_list, list) {
		if (d->dev == dev)
			break;
	}

	return n ? d : NULL;
}

static struct hlist_head *find_rcv_list(canid_t *can_id, canid_t *mask,
					struct dev_rcv_lists *d)
{
	canid_t inv = *can_id & CAN_INV_FILTER; /* save flag before masking */

	/* filter error frames */
	if (*mask & CAN_ERR_FLAG) {
		/* clear CAN_ERR_FLAG in list entry */
		*mask &= CAN_ERR_MASK;
		return &d->rx[RX_ERR];
	}

	/* ensure valid values in can_mask */
	if (*mask & CAN_EFF_FLAG)
		*mask &= (CAN_EFF_MASK | CAN_EFF_FLAG | CAN_RTR_FLAG);
	else
		*mask &= (CAN_SFF_MASK | CAN_RTR_FLAG);

	/* reduce condition testing at receive time */
	*can_id &= *mask;

	/* inverse can_id/can_mask filter */
	if (inv)
		return &d->rx[RX_INV];

	/* mask == 0 => no condition testing at receive time */
	if (!(*mask))
		return &d->rx[RX_ALL];

	/* use extra filterset for the subscription of exactly *ONE* can_id */
	if (*can_id & CAN_EFF_FLAG) {
		if (*mask == (CAN_EFF_MASK | CAN_EFF_FLAG)) {
			/* RFC: a use-case for hash-tables in the future? */
			return &d->rx[RX_EFF];
		}
	} else {
		if (*mask == CAN_SFF_MASK)
			return &d->rx_sff[*can_id];
	}

	/* default: filter via can_id/can_mask */
	return &d->rx[RX_FIL];
}

/**
 * can_rx_register - subscribe CAN frames from a specific interface
 * @dev: pointer to netdevice (NULL => subcribe from 'all' CAN devices list)
 * @can_id: CAN identifier (see description)
 * @mask: CAN mask (see description)
 * @func: callback function on filter match
 * @data: returned parameter for callback function
 * @ident: string for calling module indentification
 *
 * Description:
 *  Invokes the callback function with the received sk_buff and the given
 *  parameter 'data' on a matching receive filter. A filter matches, when
 *
 *          <received_can_id> & mask == can_id & mask
 *
 *  The filter can be inverted (CAN_INV_FILTER bit set in can_id) or it can
 *  filter for error frames (CAN_ERR_FLAG bit set in mask).
 *
 * Return:
 *  0 on success
 *  -ENOMEM on missing cache mem to create subscription entry
 *  -ENODEV unknown device
 */
int can_rx_register(struct net_device *dev, canid_t can_id, canid_t mask,
		    void (*func)(struct sk_buff *, void *), void *data,
		    char *ident)
{
	struct receiver *r;
	struct hlist_head *rl;
	struct dev_rcv_lists *d;
	int ret = 0;

	/* insert new receiver  (dev,canid,mask) -> (func,data) */

	DBG("dev %p (%s), id %03X, mask %03X, callback %p, data %p, "
	    "ident %s\n", dev, DNAME(dev), can_id, mask, func, data, ident);

	r = kmem_cache_alloc(rcv_cache, GFP_KERNEL);
	if (!r)
		return -ENOMEM;

	spin_lock_bh(&rcv_lists_lock);

	d = find_dev_rcv_lists(dev);
	if (d) {
		rl = find_rcv_list(&can_id, &mask, d);

		r->can_id  = can_id;
		r->mask    = mask;
		r->matches = 0;
		r->func    = func;
		r->data    = data;
		r->ident   = ident;

		hlist_add_head_rcu(&r->list, rl);
		d->entries++;

		pstats.rcv_entries++;
		if (pstats.rcv_entries_max < pstats.rcv_entries)
			pstats.rcv_entries_max = pstats.rcv_entries;
	} else {
		DBG("receive list not found for dev %s, id %03X, mask %03X\n",
		    DNAME(dev), can_id, mask);
		kmem_cache_free(rcv_cache, r);
		ret = -ENODEV;
	}

	spin_unlock_bh(&rcv_lists_lock);

	return ret;
}
EXPORT_SYMBOL(can_rx_register);

/*
 * can_rx_delete_device - rcu callback for dev_rcv_lists structure removal
 */
static void can_rx_delete_device(struct rcu_head *rp)
{
	struct dev_rcv_lists *d = container_of(rp, struct dev_rcv_lists, rcu);

	DBG("removing dev_rcv_list at %p\n", d);
	kfree(d);
}

/*
 * can_rx_delete_receiver - rcu callback for single receiver entry removal
 */
static void can_rx_delete_receiver(struct rcu_head *rp)
{
	struct receiver *r = container_of(rp, struct receiver, rcu);

	DBG("removing receiver at %p\n", r);
	kmem_cache_free(rcv_cache, r);
}

/**
 * can_rx_unregister - unsubscribe CAN frames from a specific interface
 * @dev: pointer to netdevice (NULL => unsubcribe from 'all' CAN devices list)
 * @can_id: CAN identifier
 * @mask: CAN mask
 * @func: callback function on filter match
 * @data: returned parameter for callback function
 *
 * Description:
 *  Removes subscription entry depending on given (subscription) values.
 *
 * Return:
 *  0 on success
 *  -EINVAL on missing subscription entry
 *  -ENODEV unknown device
 */
int can_rx_unregister(struct net_device *dev, canid_t can_id, canid_t mask,
		      void (*func)(struct sk_buff *, void *), void *data)
{
	struct receiver *r = NULL;
	struct hlist_head *rl;
	struct hlist_node *next;
	struct dev_rcv_lists *d;
	int ret = 0;

	DBG("dev %p (%s), id %03X, mask %03X, callback %p, data %p\n",
	    dev, DNAME(dev), can_id, mask, func, data);

	spin_lock_bh(&rcv_lists_lock);

	d = find_dev_rcv_lists(dev);
	if (!d) {
		DBG("receive list not found for dev %s, id %03X, mask %03X\n",
		    DNAME(dev), can_id, mask);
		ret = -ENODEV;
		goto out;
	}

	rl = find_rcv_list(&can_id, &mask, d);

	/*
	 * Search the receiver list for the item to delete.  This should
	 * exist, since no receiver may be unregistered that hasn't
	 * been registered before.
	 */

	hlist_for_each_entry(r, next, rl, list) {
		if (r->can_id == can_id && r->mask == mask
		    && r->func == func && r->data == data)
			break;
	}

	/*
	 * Check for bug in CAN protocol implementations:
	 * If no matching list item was found, the list cursor variable next
	 * will be NULL, while r will point to the last item of the list.
	 */

	if (!next) {
		DBG("receive list entry not found for "
		    "dev %s, id %03X, mask %03X\n", DNAME(dev), can_id, mask);
		ret = -EINVAL;
		r = NULL;
		d = NULL;
		goto out;
	}

	hlist_del_rcu(&r->list);
	d->entries--;

	if (pstats.rcv_entries > 0)
		pstats.rcv_entries--;

	/* remove device structure requested by NETDEV_UNREGISTER */
	if (d->remove_on_zero_entries && !d->entries) {
		DBG("removing dev_rcv_list for %s on zero entries\n",
		    dev->name);
		hlist_del_rcu(&d->list);
	} else
		d = NULL;

 out:
	spin_unlock_bh(&rcv_lists_lock);

	/* schedule the receiver item for deletion */
	if (r)
		call_rcu(&r->rcu, can_rx_delete_receiver);

	/* schedule the device structure for deletion */
	if (d)
		call_rcu(&d->rcu, can_rx_delete_device);

	return ret;
}
EXPORT_SYMBOL(can_rx_unregister);

static inline void deliver(struct sk_buff *skb, struct receiver *r)
{
	struct sk_buff *clone = skb_clone(skb, GFP_ATOMIC);

	DBG("skbuff %p cloned to %p\n", skb, clone);
	if (clone) {
		clone->sk = skb->sk;
		r->func(clone, r->data);
		r->matches++;
	}
}

static int can_rcv_filter(struct dev_rcv_lists *d, struct sk_buff *skb)
{
	struct receiver *r;
	struct hlist_node *n;
	int matches = 0;
	struct can_frame *cf = (struct can_frame *)skb->data;
	canid_t can_id = cf->can_id;

	if (d->entries == 0)
		return 0;

	if (can_id & CAN_ERR_FLAG) {
		/* check for error frame entries only */
		hlist_for_each_entry_rcu(r, n, &d->rx[RX_ERR], list) {
			if (can_id & r->mask) {
				DBG("match on rx_err skbuff %p\n", skb);
				deliver(skb, r);
				matches++;
			}
		}
		return matches;
	}

	/* check for unfiltered entries */
	hlist_for_each_entry_rcu(r, n, &d->rx[RX_ALL], list) {
		DBG("match on rx_all skbuff %p\n", skb);
		deliver(skb, r);
		matches++;
	}

	/* check for can_id/mask entries */
	hlist_for_each_entry_rcu(r, n, &d->rx[RX_FIL], list) {
		if ((can_id & r->mask) == r->can_id) {
			DBG("match on rx_fil skbuff %p\n", skb);
			deliver(skb, r);
			matches++;
		}
	}

	/* check for inverted can_id/mask entries */
	hlist_for_each_entry_rcu(r, n, &d->rx[RX_INV], list) {
		if ((can_id & r->mask) != r->can_id) {
			DBG("match on rx_inv skbuff %p\n", skb);
			deliver(skb, r);
			matches++;
		}
	}

	/* check CAN_ID specific entries */
	if (can_id & CAN_EFF_FLAG) {
		hlist_for_each_entry_rcu(r, n, &d->rx[RX_EFF], list) {
			if (r->can_id == can_id) {
				DBG("match on rx_eff skbuff %p\n", skb);
				deliver(skb, r);
				matches++;
			}
		}
	} else {
		can_id &= CAN_SFF_MASK;
		hlist_for_each_entry_rcu(r, n, &d->rx_sff[can_id], list) {
			DBG("match on rx_sff skbuff %p\n", skb);
			deliver(skb, r);
			matches++;
		}
	}

	return matches;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
static int can_rcv(struct sk_buff *skb, struct net_device *dev,
		   struct packet_type *pt, struct net_device *orig_dev)
#else
static int can_rcv(struct sk_buff *skb, struct net_device *dev,
		   struct packet_type *pt)
#endif
{
	struct dev_rcv_lists *d;
	int matches;

	DBG("received skbuff on device %s, ptype %04x\n",
	    dev->name, ntohs(pt->type));
	DBG_SKB(skb);
	DBG_FRAME("af_can: can_rcv: received CAN frame",
		  (struct can_frame *)skb->data);

	if (dev->type != ARPHRD_CAN) {
		kfree_skb(skb);
		return 0;
	}

	/* update statistics */
	stats.rx_frames++;
	stats.rx_frames_delta++;

	rcu_read_lock();

	/* deliver the packet to sockets listening on all devices */
	matches = can_rcv_filter(&rx_alldev_list, skb);

	/* find receive list for this device */
	d = find_dev_rcv_lists(dev);
	if (d)
		matches += can_rcv_filter(d, skb);

	rcu_read_unlock();

	/* free the skbuff allocated by the netdevice driver */
	DBG("freeing skbuff %p\n", skb);
	kfree_skb(skb);

	if (matches > 0) {
		stats.matches++;
		stats.matches_delta++;
	}

	return 0;
}

/*
 * af_can protocol functions
 */

/**
 * can_proto_register - register CAN transport protocol
 * @cp: pointer to CAN protocol structure
 *
 * Return:
 *  0 on success
 *  -EINVAL invalid (out of range) protocol number
 *  -EBUSY  protocol already in use
 *  -ENOBUF if proto_register() fails
 */
int can_proto_register(struct can_proto *cp)
{
	int proto = cp->protocol;
	int err = 0;

	if (proto < 0 || proto >= CAN_NPROTO) {
		printk(KERN_ERR "can: protocol number %d out of range\n",
		       proto);
		return -EINVAL;
	}
	if (proto_tab[proto]) {
		printk(KERN_ERR "can: protocol %d already registered\n",
		       proto);
		return -EBUSY;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
	err = proto_register(cp->prot, 0);
	if (err < 0)
		return err;
#endif

	proto_tab[proto] = cp;

	/* use generic ioctl function if the module doesn't bring its own */
	if (!cp->ops->ioctl)
		cp->ops->ioctl = can_ioctl;

	return err;
}
EXPORT_SYMBOL(can_proto_register);

/**
 * can_proto_unregister - unregister CAN transport protocol
 * @cp: pointer to CAN protocol structure
 *
 * Return:
 *  0 on success
 *  -ESRCH protocol number was not registered
 */
int can_proto_unregister(struct can_proto *cp)
{
	int proto = cp->protocol;

	if (!proto_tab[proto]) {
		printk(KERN_ERR "can: protocol %d is not registered\n", proto);
		return -ESRCH;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
	proto_unregister(cp->prot);
#endif
	proto_tab[proto] = NULL;

	return 0;
}
EXPORT_SYMBOL(can_proto_unregister);

/*
 * af_can notifier to create/remove CAN netdevice specific structs
 */
static int can_notifier(struct notifier_block *nb, unsigned long msg,
			void *data)
{
	struct net_device *dev = (struct net_device *)data;
	struct dev_rcv_lists *d;

	DBG("msg %ld for dev %p (%s idx %d)\n",
	    msg, dev, dev->name, dev->ifindex);

	if (dev->type != ARPHRD_CAN)
		return NOTIFY_DONE;

	switch (msg) {

	case NETDEV_REGISTER:

		/*
		 * create new dev_rcv_lists for this device
		 *
		 * N.B. zeroing the struct is the correct initialization
		 * for the embedded hlist_head structs.
		 * Another list type, e.g. list_head, would require
		 * explicit initialization.
		 */

		DBG("creating new dev_rcv_lists for %s\n", dev->name);

		d = kzalloc(sizeof(*d),
			    in_interrupt() ? GFP_ATOMIC : GFP_KERNEL);
		if (!d) {
			printk(KERN_ERR
			       "can: allocation of receive list failed\n");
			return NOTIFY_DONE;
		}
		d->dev = dev;

		spin_lock_bh(&rcv_lists_lock);
		hlist_add_head_rcu(&d->list, &rx_dev_list);
		spin_unlock_bh(&rcv_lists_lock);

		break;

	case NETDEV_UNREGISTER:
		spin_lock_bh(&rcv_lists_lock);

		d = find_dev_rcv_lists(dev);
		if (d) {
			DBG("remove dev_rcv_list for %s (%d entries)\n",
			    dev->name, d->entries);

			if (d->entries) {
				d->remove_on_zero_entries = 1;
				d = NULL;
			} else
				hlist_del_rcu(&d->list);
		} else
			printk(KERN_ERR "can: notifier: receive list not "
			       "found for dev %s\n", dev->name);

		spin_unlock_bh(&rcv_lists_lock);

		if (d)
			call_rcu(&d->rcu, can_rx_delete_device);

		break;
	}

	return NOTIFY_DONE;
}

/*
 * af_can debugging stuff
 */

#ifdef CONFIG_CAN_DEBUG_CORE

#define DBG_BSIZE 1024

/**
 * can_debug_cframe - print CAN frame
 * @msg: pointer to message printed before the given CAN frame
 * @cf: pointer to CAN frame
 */
void can_debug_cframe(const char *msg, struct can_frame *cf, ...)
{
	va_list ap;
	int len;
	int dlc, i;
	char *buf;

	buf = kmalloc(DBG_BSIZE, GFP_ATOMIC);
	if (!buf)
		return;

	len = sprintf(buf, KERN_DEBUG);
	va_start(ap, cf);
	len += snprintf(buf + len, DBG_BSIZE - 64, msg, ap);
	buf[len++] = ':';
	buf[len++] = ' ';
	va_end(ap);

	dlc = cf->can_dlc;
	if (dlc > 8)
		dlc = 8;

	if (cf->can_id & CAN_EFF_FLAG)
		len += sprintf(buf + len, "<%08X> [%X] ",
			       cf->can_id & CAN_EFF_MASK, dlc);
	else
		len += sprintf(buf + len, "<%03X> [%X] ",
			       cf->can_id & CAN_SFF_MASK, dlc);

	for (i = 0; i < dlc; i++)
		len += sprintf(buf + len, "%02X ", cf->data[i]);

	if (cf->can_id & CAN_RTR_FLAG)
		len += sprintf(buf + len, "(RTR)");

	buf[len++] = '\n';
	buf[len]   = '\0';
	printk(buf);
	kfree(buf);
}
EXPORT_SYMBOL(can_debug_cframe);

/**
 * can_debug_skb - print socket buffer content to kernel log
 * @skb: pointer to socket buffer
 */
void can_debug_skb(struct sk_buff *skb)
{
	int len, nbytes, i;
	char *buf;

	buf = kmalloc(DBG_BSIZE, GFP_ATOMIC);
	if (!buf)
		return;

	len = sprintf(buf,
		      KERN_DEBUG "  skbuff at %p, dev: %d, proto: %04x\n"
		      KERN_DEBUG "  users: %d, dataref: %d, nr_frags: %d, "
		      "h,d,t,e,l: %p %+d %+d %+d, %d",
		      skb, skb->dev ? skb->dev->ifindex : -1,
		      ntohs(skb->protocol),
		      atomic_read(&skb->users),
		      atomic_read(&(skb_shinfo(skb)->dataref)),
		      skb_shinfo(skb)->nr_frags,
		      skb->head, skb->data - skb->head,
		      skb->tail - skb->head, skb->end - skb->head, skb->len);
	nbytes = skb->end - skb->head;
	for (i = 0; i < nbytes; i++) {
		if (i % 16 == 0)
			len += sprintf(buf + len, "\n" KERN_DEBUG "  ");
		if (len < DBG_BSIZE - 16) {
			len += sprintf(buf + len, " %02x", skb->head[i]);
		} else {
			len += sprintf(buf + len, "...");
			break;
		}
	}
	buf[len++] = '\n';
	buf[len]   = '\0';
	printk(buf);
	kfree(buf);
}
EXPORT_SYMBOL(can_debug_skb);

#endif

/*
 * af_can module init/exit functions
 */

static struct packet_type can_packet = {
	.type = __constant_htons(ETH_P_CAN),
	.dev  = NULL,
	.func = can_rcv,
};

static struct net_proto_family can_family_ops = {
	.family = PF_CAN,
	.create = can_create,
	.owner  = THIS_MODULE,
};

/* notifier block for netdevice event */
static struct notifier_block can_netdev_notifier = {
	.notifier_call = can_notifier,
};

static __init int can_init(void)
{
	printk(banner);

	rcv_cache = kmem_cache_create("can_receiver", sizeof(struct receiver),
				      0, 0, NULL, NULL);
	if (!rcv_cache)
		return -ENOMEM;

	/*
	 * Insert rx_alldev_list for reception on all devices.
	 * This struct is zero initialized which is correct for the
	 * embedded hlist heads, the dev pointer, and the entries counter.
	 */

	spin_lock_bh(&rcv_lists_lock);
	hlist_add_head_rcu(&rx_alldev_list.list, &rx_dev_list);
	spin_unlock_bh(&rcv_lists_lock);

	if (stats_timer) {
		/* the statistics are updated every second (timer triggered) */
		init_timer(&stattimer);
		stattimer.function = can_stat_update;
		stattimer.data = 0;
		/* update every second */
		stattimer.expires = jiffies + HZ;
		/* start statistics timer */
		add_timer(&stattimer);
	} else
		stattimer.function = NULL;

	/* procfs init */
	can_init_proc();

	/* protocol register */
	sock_register(&can_family_ops);
	register_netdevice_notifier(&can_netdev_notifier);
	dev_add_pack(&can_packet);

	return 0;
}

static __exit void can_exit(void)
{
	struct dev_rcv_lists *d;
	struct hlist_node *n, *next;

	if (stats_timer)
		del_timer(&stattimer);

	/* procfs remove */
	can_remove_proc();

	/* protocol unregister */
	dev_remove_pack(&can_packet);
	unregister_netdevice_notifier(&can_netdev_notifier);
	sock_unregister(PF_CAN);

	/* remove rx_dev_list */
	spin_lock_bh(&rcv_lists_lock);
	hlist_del(&rx_alldev_list.list);
	hlist_for_each_entry_safe(d, n, next, &rx_dev_list, list) {
		hlist_del(&d->list);
		kfree(d);
	}
	spin_unlock_bh(&rcv_lists_lock);

	kmem_cache_destroy(rcv_cache);
}

module_init(can_init);
module_exit(can_exit);
