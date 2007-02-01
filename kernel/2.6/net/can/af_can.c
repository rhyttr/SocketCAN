/*
 * af_can.c
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
 * Send feedback to <socketcan-users@lists.berlios.de>
 *
 */

#include <linux/autoconf.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <asm/uaccess.h>

#include <linux/can.h>
#include <linux/can/version.h>

#include "af_can.h"


RCSID("$Id$");

#define NAME "Volkswagen AG - Low Level CAN Framework (LLCF)"
#define IDENT "af_can"
static __initdata const char banner[] = BANNER(NAME);

MODULE_DESCRIPTION(NAME);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Urs Thuermann <urs.thuermann@volkswagen.de>, "
	      "Oliver Hartkopp <oliver.hartkopp@volkswagen.de>");

int stats_timer = 1; /* default: on */
module_param(stats_timer, int, S_IRUGO);

#ifdef CONFIG_CAN_DEBUG_CORE
static int debug = 0;
module_param(debug, int, S_IRUGO);
#define DBG(args...)       (debug & 1 ? \
			       (printk(KERN_DEBUG "CAN %s: ", __func__), \
				printk(args)) : 0)
#define DBG_FRAME(args...) (debug & 2 ? can_debug_cframe(args) : 0)
#define DBG_SKB(skb)       (debug & 4 ? can_debug_skb(skb) : 0)
#else
#define DBG(args...)
#define DBG_FRAME(args...)
#define DBG_SKB(skb)
#endif

static __init int  can_init(void);
static __exit void can_exit(void);

static int can_create(struct socket *sock, int protocol);
static int can_notifier(struct notifier_block *nb,
			unsigned long msg, void *data);
static int can_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
static int can_rcv(struct sk_buff *skb, struct net_device *dev,
		   struct packet_type *pt, struct net_device *orig_dev);
#else
static int can_rcv(struct sk_buff *skb, struct net_device *dev,
		   struct packet_type *pt);
#endif
static int can_rcv_filter(struct dev_rcv_lists *d, struct sk_buff *skb);
static struct dev_rcv_lists *find_dev_rcv_lists(struct net_device *dev);
static struct hlist_head *find_rcv_list(canid_t *can_id, canid_t *mask,
					struct dev_rcv_lists *d);
static void can_rcv_lists_delete(struct rcu_head *rp);
static void can_rx_delete(struct rcu_head *rp);
static void can_rx_delete_all(struct hlist_head *rl);


struct notifier {
	struct list_head list;
	struct net_device *dev;
	void (*func)(unsigned long msg, void *data);
	void *data;
};

static LIST_HEAD(notifier_list);
static rwlock_t notifier_lock = RW_LOCK_UNLOCKED;

HLIST_HEAD(rx_dev_list);
static struct dev_rcv_lists rx_alldev_list;
static spinlock_t rcv_lists_lock = SPIN_LOCK_UNLOCKED;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
static struct kmem_cache *rcv_cache __read_mostly;
#else
static kmem_cache_t *rcv_cache;
#endif

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

/* table of registered CAN protocols */
static struct can_proto *proto_tab[CAN_NPROTO];

extern struct timer_list stattimer; /* timer for statistics update */
extern struct s_stats  stats;       /* packet statistics */
extern struct s_pstats pstats;      /* receive list statistics */

module_init(can_init);
module_exit(can_exit);

/**************************************************/
/* af_can module init/exit functions              */
/**************************************************/

static __init int can_init(void)
{
	printk(banner);

	rcv_cache = kmem_cache_create("can_receiver", sizeof(struct receiver),
				      0, 0, NULL, NULL);
	if (!rcv_cache)
		return -ENOMEM;

	/* Insert struct dev_rcv_lists for reception on all devices.
	   This struct is zero initialized which is correct for the 
	   embedded hlist heads, the dev pointer, and the entries counter.
	*/

	spin_lock(&rcv_lists_lock);
	hlist_add_head_rcu(&rx_alldev_list.list, &rx_dev_list);
	spin_unlock(&rcv_lists_lock);

	if (stats_timer) {
		/* statistics init */
		init_timer(&stattimer);
	}

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

	if (stats_timer) {
		/* stop statistics timer */
		del_timer(&stattimer);
	}

	/* procfs remove */
	can_remove_proc();

	/* protocol unregister */
	dev_remove_pack(&can_packet);
	unregister_netdevice_notifier(&can_netdev_notifier);
	sock_unregister(PF_CAN);

	/* remove rx_dev_list */
	/* XXX: should we lock the receive list here? */
	hlist_del(&rx_alldev_list.list);
	hlist_for_each_entry_safe(d, n, next, &rx_dev_list, list)
		kfree(d);

	kmem_cache_destroy(rcv_cache);
}

/**************************************************/
/* af_can protocol functions                      */
/**************************************************/

void can_proto_register(struct can_proto *cp)
{
	int proto = cp->protocol;
	if (proto < 0 || proto >= CAN_NPROTO) {
		printk(KERN_ERR "CAN: protocol number %d out of range\n", proto);
		return;
	}
	if (proto_tab[proto]) {
		printk(KERN_ERR "CAN: protocol %d already registered\n", proto);
		return;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,13)
	if (proto_register(cp->prot, 0) != 0) {
		return;
	}
#endif
	proto_tab[proto] = cp;

	/* use our generic ioctl function if the module doesn't bring its own */
	if (!cp->ops->ioctl)
		cp->ops->ioctl = can_ioctl;
}

void can_proto_unregister(struct can_proto *cp)
{
	int proto = cp->protocol;
	if (!proto_tab[proto]) {
		printk(KERN_ERR "CAN: protocol %d is not registered\n", proto);
		return;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,13)
	proto_unregister(cp->prot);
#endif
	proto_tab[proto] = NULL;
}

void can_dev_register(struct net_device *dev,
		      void (*func)(unsigned long msg, void *), void *data)
{
	struct notifier *n;

	DBG("called for %s\n", dev->name);

	if (!(n = kmalloc(sizeof(*n), GFP_KERNEL)))
		return;

	n->dev  = dev;
	n->func = func;
	n->data = data;

	write_lock(&notifier_lock);
	list_add(&n->list, &notifier_list);
	write_unlock(&notifier_lock);
}

void can_dev_unregister(struct net_device *dev,
			void (*func)(unsigned long msg, void *), void *data)
{
	struct notifier *n, *next;

	DBG("called for %s\n", dev->name);

	write_lock(&notifier_lock);
	list_for_each_entry_safe(n, next, &notifier_list, list) {
		if (n->dev == dev && n->func == func && n->data == data) {
			list_del(&n->list);
			kfree(n);
			break;
		}
	}
	write_unlock(&notifier_lock);
}

/**************************************************/
/* af_can socket functions                        */
/**************************************************/

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
	int ret;

	DBG("socket %p, type %d, proto %d\n", sock, sock->type, protocol);

	sock->state = SS_UNCONNECTED;

	if (protocol < 0 || protocol >= CAN_NPROTO)
		return -EINVAL;

	DBG("looking up proto %d in proto_tab[]\n", protocol);

	/* try to load protocol module, when CONFIG_KMOD is defined */
	if (!proto_tab[protocol]) {
		char module_name[30];
		sprintf(module_name, "can-proto-%d", protocol);
		if (request_module(module_name) == -ENOSYS)
			printk(KERN_INFO "CAN: request_module(%s) not implemented.\n",
			       module_name);
	}

	/* check for success and correct type */
	if (!(cp = proto_tab[protocol]) || cp->type != sock->type)
		return -EPROTONOSUPPORT;

	if (cp->capability >= 0 && !capable(cp->capability))
		return -EPERM;

	sock->ops = cp->ops;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,13)
	sk = sk_alloc(PF_CAN, GFP_KERNEL, cp->prot, 1);
	if (!sk)
		goto oom;
#else
	sk = sk_alloc(PF_CAN, GFP_KERNEL, 1, 0);
	if (!sk)
		goto oom;
	if (cp->obj_size &&
	    !(sk->sk_protinfo = kmalloc(cp->obj_size, GFP_KERNEL))) {
		sk_free(sk);
		goto oom;
	}
	sk_set_owner(sk, proto_tab[protocol]->owner);
#endif
	sock_init_data(sock, sk);
	sk->sk_destruct = can_sock_destruct;

	DBG("created sock: %p\n", sk);

	ret = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,13)
	if (sk->sk_prot->init)
		ret = sk->sk_prot->init(sk);
#else
	if (cp->init)
		ret = cp->init(sk);
#endif
	if (ret) {
		/* we must release sk */
		sock_orphan(sk);
		sock_put(sk);
		return ret;
	}

	return 0;

 oom:
	return -ENOMEM;
}

static int can_notifier(struct notifier_block *nb,
			unsigned long msg, void *data)
{
	struct net_device *dev = (struct net_device *)data;
	struct notifier *n;

	DBG("called for %s, msg = %lu\n", dev->name, msg);

	if (dev->type != ARPHRD_CAN)
		return NOTIFY_DONE;

	switch (msg) {
		struct dev_rcv_lists *d;
		int i;

	case NETDEV_REGISTER:

		/* create new dev_rcv_lists for this device */

		DBG("creating new dev_rcv_lists for %s\n", dev->name);
		if (!(d = kmalloc(sizeof(*d),
				  in_interrupt() ? GFP_ATOMIC : GFP_KERNEL))) {
			printk(KERN_ERR "CAN: allocation of receive list failed\n");
			return NOTIFY_DONE;
		}
		/* N.B. zeroing the struct is the correct initialization
			for the embedded hlist_head structs.
			Another list type, e.g. list_head, would require
			explicit initialization. */
		memset(d, 0, sizeof(*d));
		d->dev = dev;

		spin_lock(&rcv_lists_lock);
		hlist_add_head_rcu(&d->list, &rx_dev_list);
		spin_unlock(&rcv_lists_lock);

		break;

	case NETDEV_UNREGISTER:
		spin_lock(&rcv_lists_lock);

		if (!(d = find_dev_rcv_lists(dev))) {
			printk(KERN_ERR "CAN: notifier: receive list not "
			       "found for dev %s\n", dev->name);
			goto unreg_out;
		}

		hlist_del_rcu(&d->list);

		/* remove all receivers hooked at this netdevice */
		can_rx_delete_all(&d->rx_err);
		can_rx_delete_all(&d->rx_all);
		can_rx_delete_all(&d->rx_fil);
		can_rx_delete_all(&d->rx_inv);
		can_rx_delete_all(&d->rx_eff);
		for (i = 0; i < 2048; i++)
			can_rx_delete_all(&d->rx_sff[i]);

	unreg_out:
		spin_unlock(&rcv_lists_lock);

		if (d)
			call_rcu(&d->rcu, can_rcv_lists_delete);

		break;
	}

	read_lock(&notifier_lock);
	list_for_each_entry(n, &notifier_list, list) {
		if (n->dev == dev)
			n->func(msg, n->data);
	}
	read_unlock(&notifier_lock);

	return NOTIFY_DONE;
}

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
	return 0;
}

/**************************************************/
/* af_can tx path                                 */
/**************************************************/

int can_send(struct sk_buff *skb, int loop)
{
	int err;

	if (loop) { /* local loopback (default) */
		*(struct sock **)skb->cb = skb->sk; /* tx sock reference */

		/* interface not capabable to do the loopback itself? */
		if (!(skb->dev->flags & IFF_LOOPBACK)) {
			struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
			newskb->protocol  = htons(ETH_P_CAN);
			newskb->ip_summed = CHECKSUM_UNNECESSARY;
			netif_rx(newskb); /* perform local loopback here */
		}
	} else
		*(struct sock **)skb->cb = NULL; /* no loopback required */

	if (!(skb->dev->flags & IFF_UP))
		err = -ENETDOWN;
	else if ((err = dev_queue_xmit(skb)) > 0)  /* send to netdevice */
		err = net_xmit_errno(err);

	/* update statistics */
	stats.tx_frames++;
	stats.tx_frames_delta++;

	return err;
}

/**************************************************/
/* af_can rx path                                 */
/**************************************************/

int can_rx_register(struct net_device *dev, canid_t can_id, canid_t mask,
		    void (*func)(struct sk_buff *, void *), void *data,
		    char *ident)
{
	struct receiver *r;
	struct hlist_head *rl;
	struct dev_rcv_lists *d;
	int ret = 0;

	/* insert new receiver  (dev,canid,mask) -> (func,data) */

	DBG("dev %p, id %03X, mask %03X, callback %p, data %p, ident %s\n",
	    dev, can_id, mask, func, data, ident);

	if (!(r = kmem_cache_alloc(rcv_cache, GFP_KERNEL))) {
		ret = -ENOMEM;
		goto out;
	}

	spin_lock(&rcv_lists_lock);

	if (!(d = find_dev_rcv_lists(dev))) {
		DBG("receive list not found for dev %s, id %03X, mask %03X\n",
		    DNAME(dev), can_id, mask);
		kmem_cache_free(rcv_cache, r);
		ret = -ENODEV;
		goto out_unlock;
	}

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

 out_unlock:
	spin_unlock(&rcv_lists_lock);
 out:
	return ret;
}

static void can_rcv_lists_delete(struct rcu_head *rp)
{
	struct dev_rcv_lists *d = container_of(rp, struct dev_rcv_lists, rcu);
	kfree(d);
}

static void can_rx_delete(struct rcu_head *rp)
{
	struct receiver *r = container_of(rp, struct receiver, rcu);
	kmem_cache_free(rcv_cache, r);
}

static void can_rx_delete_all(struct hlist_head *rl)
{
	struct receiver *r;
	struct hlist_node *n;

	hlist_for_each_entry_rcu(r, n, rl, list) {
		hlist_del_rcu(&r->list);
		call_rcu(&r->rcu, can_rx_delete);
	}
}

int can_rx_unregister(struct net_device *dev, canid_t can_id, canid_t mask,
		      void (*func)(struct sk_buff *, void *), void *data)
{
	struct receiver *r;
	struct hlist_head *rl;
	struct hlist_node *next;
	struct dev_rcv_lists *d;
	int ret = 0;

	DBG("dev %p, id %03X, mask %03X, callback %p, data %p\n",
	    dev, can_id, mask, func, data);

	r = NULL;

	spin_lock(&rcv_lists_lock);

	if (!(d = find_dev_rcv_lists(dev))) {
		DBG("receive list not found for dev %s, id %03X, mask %03X\n",
		    DNAME(dev), can_id, mask);
		ret = -ENODEV;
		goto out;
	}

	rl = find_rcv_list(&can_id, &mask, d);

	/*  Search the receiver list for the item to delete.  This should
	 *  exist, since no receiver may be unregistered that hasn't
	 *  been registered before.
	 */

	hlist_for_each_entry(r, next, rl, list) {
		if (r->can_id == can_id && r->mask == mask
		    && r->func == func && r->data == data)
			break;
	}

	/*  Check for bug in CAN protocol implementations:
	 *  If no matching list item was found, the list cursor variable next
	 *  will be NULL, while r will point to the last item of the list.
	 */

	if (!next) {
		DBG("receive list entry not found for "
		    "dev %s, id %03X, mask %03X\n", DNAME(dev), can_id, mask);
		ret = -EINVAL;
		r = NULL;
		goto out;
	}

	hlist_del_rcu(&r->list);
	d->entries--;

	if (pstats.rcv_entries > 0)
		pstats.rcv_entries--;

 out:
	spin_unlock(&rcv_lists_lock);

	/* schedule the receiver item for deletion */
	if (r)
		call_rcu(&r->rcu, can_rx_delete);

	return ret;
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

	/* update statistics */
	stats.rx_frames++;
	stats.rx_frames_delta++;

	rcu_read_lock();

	/* deliver the packet to sockets listening on all devices */
	matches = can_rcv_filter(&rx_alldev_list, skb);

	/* find receive list for this device */
	if ((d = find_dev_rcv_lists(dev)))
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


static inline void deliver(struct sk_buff *skb, struct receiver *r)
{
	struct sk_buff *clone = skb_clone(skb, GFP_ATOMIC);
	DBG("skbuff %p cloned to %p\n", skb, clone);
	if (clone) {
		r->func(clone, r->data);
		r->matches++;    /* update specific statistics */
	}
}

static int can_rcv_filter(struct dev_rcv_lists *d, struct sk_buff *skb)
{
	struct receiver *r;
	struct hlist_node *n;
	int matches = 0;
	struct can_frame *cf = (struct can_frame*)skb->data;
	canid_t can_id = cf->can_id;

	if (d->entries == 0)
		return 0;

	if (can_id & CAN_ERR_FLAG) {
		/* check for error frame entries only */
		hlist_for_each_entry_rcu(r, n, &d->rx_err, list) {
			if (can_id & r->mask) {
				DBG("match on rx_err skbuff %p\n", skb);
				deliver(skb, r);
				matches++;
			}
		}
		goto out;
	}

	/* check for unfiltered entries */
	hlist_for_each_entry_rcu(r, n, &d->rx_all, list) {
		DBG("match on rx_all skbuff %p\n", skb);
		deliver(skb, r);
		matches++;
	}

	/* check for can_id/mask entries */
	hlist_for_each_entry_rcu(r, n, &d->rx_fil, list) {
		if ((can_id & r->mask) == r->can_id) {
			DBG("match on rx_fil skbuff %p\n", skb);
			deliver(skb, r);
			matches++;
		}
	}

	/* check for inverted can_id/mask entries */
	hlist_for_each_entry_rcu(r, n, &d->rx_inv, list) {
		if ((can_id & r->mask) != r->can_id) {
			DBG("match on rx_inv skbuff %p\n", skb);
			deliver(skb, r);
			matches++;
		}
	}

	/* check CAN_ID specific entries */
	if (can_id & CAN_EFF_FLAG) {
		hlist_for_each_entry_rcu(r, n, &d->rx_eff, list) {
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

 out:
	return matches;
}

static struct dev_rcv_lists *find_dev_rcv_lists(struct net_device *dev)
{
	struct dev_rcv_lists *d;
	struct hlist_node *n;

	/* find receive list for this device */

	/*  The hlist_for_each_entry*() macros curse through the list
	 *  using the pointer variable n and set d to the containing
	 *  struct in each list iteration.  Therefore, after list
	 *  iteration, d is unmodified when the list is empty, and it
	 *  points to last list element, when the list is non-empty
	 *  but no match in the loop body is found.  I.e. d is *not*
	 *  NULL when no match is found.  We can, however, use the
	 *  cursor variable n to decide if a match was found.
	 */

	hlist_for_each_entry(d, n, &rx_dev_list, list)
		if (d->dev == dev)
			break;

	return n ? d : NULL;
}

static struct hlist_head *find_rcv_list(canid_t *can_id, canid_t *mask,
					struct dev_rcv_lists *d)
{
	canid_t inv = *can_id & CAN_INV_FILTER; /* save flag before masking values */
	canid_t eff = *can_id & *mask & CAN_EFF_FLAG; /* correct EFF check? */
	canid_t rtr = *can_id & *mask & CAN_RTR_FLAG; /* correct RTR check? */

	/* do not modify the error mask due to the can_id which is 0 */
	if (*mask & CAN_ERR_FLAG) { /* filter error frames */
		*mask &= CAN_ERR_MASK; /* clear CAN_ERR_FLAG in list entry */
		return &d->rx_err;
	}

	/* make some paranoic operations */
	if (*can_id & CAN_EFF_FLAG)
		*mask &= (CAN_EFF_MASK | eff | rtr);
	else
		*mask &= (CAN_SFF_MASK | rtr);

	*can_id &= *mask;

	if (inv) /* inverse can_id/can_mask filter and RTR */
		return &d->rx_inv;

	if (*can_id & CAN_RTR_FLAG) /* positive filter RTR */
		return &d->rx_fil;

	if (!(*mask)) /* mask == 0 => no filter */
		return &d->rx_all;

	if (*can_id & CAN_EFF_FLAG) {
		if (*mask == CAN_EFF_MASK) /* filter exact EFF can_id */
			return &d->rx_eff;
	} else {
		if (*mask == CAN_SFF_MASK) /* filter exact SFF can_id */
			return &d->rx_sff[*can_id];
	}

	return &d->rx_fil;  /* filter via can_id/can_mask */
}

/**************************************************/
/* af_can utility stuff                           */
/**************************************************/

unsigned long timeval2jiffies(struct timeval *tv, int round_up)
{
	unsigned long jif;
	unsigned long sec  = tv->tv_sec;
	unsigned long usec = tv->tv_usec;

	if (sec > ULONG_MAX / HZ)          /* check for overflow */
		return ULONG_MAX;

	if (round_up)                      /* any usec below one HZ? */
		usec += 1000000 / HZ - 1;  /* pump it up */

	jif = usec / (1000000 / HZ);

	if (sec * HZ > ULONG_MAX - jif)    /* check for overflow */
		return ULONG_MAX;
	else
		return jif + sec * HZ;
}


/**************************************************/
/* af_can debugging stuff                         */
/**************************************************/

#ifdef CONFIG_CAN_DEBUG_CORE

void can_debug_cframe(const char *msg, struct can_frame *cf, ...)
{
	va_list ap;
	int len;
	int dlc, i;
	char buf[1024];

	len = sprintf(buf, KERN_DEBUG);
	va_start(ap, cf);
	len += snprintf(buf + len, sizeof(buf) - 64, msg, ap);
	buf[len++] = ':';
	buf[len++] = ' ';
	va_end(ap);

	if ((dlc = cf->can_dlc) > 8)
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
}

void can_debug_skb(struct sk_buff *skb)
{
	int len, nbytes, i;
	char buf[1024];

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
		if (len < sizeof(buf) - 16) {
			len += sprintf(buf + len, " %02x", skb->head[i]);
		} else {
			len += sprintf(buf + len, "...");
			break;
		}
	}
	buf[len++] = '\n';
	buf[len]   = '\0';
	printk(buf);
}

EXPORT_SYMBOL(can_debug_cframe);
EXPORT_SYMBOL(can_debug_skb);

#endif

/**************************************************/
/* Exported symbols                               */
/**************************************************/
EXPORT_SYMBOL(can_proto_register);
EXPORT_SYMBOL(can_proto_unregister);
EXPORT_SYMBOL(can_rx_register);
EXPORT_SYMBOL(can_rx_unregister);
EXPORT_SYMBOL(can_dev_register);
EXPORT_SYMBOL(can_dev_unregister);
EXPORT_SYMBOL(can_send);
EXPORT_SYMBOL(timeval2jiffies);
