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

#define EXPORT_SYMTAB

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <asm/uaccess.h>

#include "af_can.h"
#include "version.h"


RCSID("$Id$");

#define NAME "Volkswagen AG - Low Level CAN Framework (LLCF)"
#define IDENT "af_can"
static __initdata const char banner[] = BANNER(NAME);

MODULE_DESCRIPTION(NAME);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Urs Thuermann <urs.thuermann@volkswagen.de>, "
	      "Oliver Hartkopp <oliver.hartkopp@volkswagen.de>");

int stats_timer = 1; /* default: on */
MODULE_PARM(stats_timer, "1i");

#ifdef DEBUG
static int debug = 0;
MODULE_PARM(debug, "1i");
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
static int can_rcv(struct sk_buff *skb, struct net_device *dev,
		   struct packet_type *pt);
static int can_rcv_filter(struct dev_rcv_lists *d, struct sk_buff *skb);
static struct dev_rcv_lists *find_dev_rcv_lists(struct net_device *dev);
static struct receiver **find_rcv_list(canid_t *can_id, canid_t *mask,
				       struct dev_rcv_lists *d);
static void can_rx_delete_all(struct receiver **rl);

struct notifier {
	struct list_head list;
	struct net_device *dev;
	void (*func)(unsigned long msg, void *data);
	void *data;
};

static LIST_HEAD(notifier_list);
static rwlock_t notifier_lock = RW_LOCK_UNLOCKED;

struct dev_rcv_lists *rx_dev_list;
struct dev_rcv_lists rx_alldev_list;
rwlock_t rcv_lists_lock = RW_LOCK_UNLOCKED;

static kmem_cache_t *rcv_cache;

static struct packet_type can_packet = {
	.type = __constant_htons(ETH_P_CAN),
	.dev  = NULL,
	.func = can_rcv,
};

static struct net_proto_family can_family_ops = {
	.family = PF_CAN,
	.create = can_create,
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
	struct net_device *dev;

	printk(banner);

	rcv_cache = kmem_cache_create("can_receiver", sizeof(struct receiver),
				      0, 0, NULL, NULL);
	if (!rcv_cache)
		return -ENOMEM;

	if (stats_timer) {
		/* statistics init */
		init_timer(&stattimer);
	}

	/* procfs init */
	can_init_proc();

	/* protocol register */
	sock_register(&can_family_ops);

	/* netdevice notifier register & init currently existing devices */
	read_lock_bh(&dev_base_lock);
	register_netdevice_notifier(&can_netdev_notifier);
	for (dev = dev_base; dev; dev = dev->next)
		can_netdev_notifier.notifier_call(&can_netdev_notifier,
						  NETDEV_REGISTER,
						  dev);
	read_unlock_bh(&dev_base_lock);

	dev_add_pack(&can_packet);

	return 0;
}

static __exit void can_exit(void)
{
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
	proto_tab[proto] = NULL;
}

void can_dev_register(struct net_device *dev,
		      void (*func)(unsigned long msg, void *), void *data)
{
	struct notifier *n;

	DBG("called for %s\n", DNAME(dev));

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

	DBG("called for %s\n", DNAME(dev));

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

	skb_queue_purge(&sk->receive_queue);
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
			printk(KERN_INFO "af_can: request_module(%s) not implemented.\n",
			       module_name);
	}

	/* check for success and correct type */
	if (!(cp = proto_tab[protocol]) || cp->type != sock->type)
		return -EPROTONOSUPPORT;

	if (cp->capability >= 0 && !capable(cp->capability))
		return -EPERM;

	sock->ops = cp->ops;

	if (!(sk = sk_alloc(PF_CAN, GFP_KERNEL, 1)))
		goto oom;

	sock_init_data(sock, sk);
	sk->destruct = can_sock_destruct;

	DBG("created sock: %p\n", sk);

	ret = 0;
	if (cp->init)
		ret = cp->init(sk);
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

	DBG("called for %s, msg = %lu\n", DNAME(dev), msg);

#if 0
	if (dev->type != ARPHRD_CAN)
		return NOTIFY_DONE;
#endif

	switch (msg) {
		struct dev_rcv_lists *d;
		int i;

	case NETDEV_REGISTER:

		/* create new dev_rcv_lists for this device */

		DBG("creating new dev_rcv_lists for %s\n", DNAME(dev));
		if (!(d = kmalloc(sizeof(*d), GFP_KERNEL))) {
			printk(KERN_ERR "CAN: allocation of receive list failed\n");
			return NOTIFY_DONE;
		}
		memset(d, 0, sizeof(*d));
		d->dev = dev;

		/* insert d into the list */
		write_lock_bh(&rcv_lists_lock);
		d->next        = rx_dev_list;
		d->pprev       = &rx_dev_list;
		rx_dev_list    = d;
		if (d->next)
			d->next->pprev = &d->next;
		write_unlock_bh(&rcv_lists_lock);

		break;

	case NETDEV_UNREGISTER:
		write_lock_bh(&rcv_lists_lock);

		if (!(d = find_dev_rcv_lists(dev))) {
			printk(KERN_ERR "CAN: notifier: receive list not "
			       "found for dev %s\n", DNAME(dev));
			goto unreg_out;
		}

		/* remove d from the list */
		*d->pprev = d->next;
		d->next->pprev = d->pprev;

		/* remove all receivers hooked at this netdevice */
		can_rx_delete_all(&d->rx_err);
		can_rx_delete_all(&d->rx_all);
		can_rx_delete_all(&d->rx_fil);
		can_rx_delete_all(&d->rx_inv);
		can_rx_delete_all(&d->rx_eff);
		for (i = 0; i < 2048; i++)
			can_rx_delete_all(&d->rx_sff[i]);
		kfree(d);

	unreg_out:
		write_unlock_bh(&rcv_lists_lock);

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
	int err;
	struct sock *sk = sock->sk;

	switch (cmd) {
	case SIOCGSTAMP:
		if (sk->stamp.tv_sec == 0)
			return -ENOENT;
		if (err = copy_to_user((void *)arg, &sk->stamp, sizeof(sk->stamp)))
			return err;
		break;
	default:
		return dev_ioctl(cmd, (void *)arg);
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
	struct receiver *r, **rl;
	struct dev_rcv_lists *d;
	int ret = 0;

	/* insert new receiver  (dev,canid,mask) -> (func,data) */

	DBG("dev %p, id %03X, mask %03X, callback %p, data %p, ident %s\n",
	    dev, can_id, mask, func, data, ident);

	if (!(r = kmem_cache_alloc(rcv_cache, GFP_KERNEL))) {
		ret = -ENOMEM;
		goto out;
	}

	write_lock_bh(&rcv_lists_lock);

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

	r->next = *rl;
	*rl = r;
	d->entries++;

	pstats.rcv_entries++;
	if (pstats.rcv_entries_max < pstats.rcv_entries)
		pstats.rcv_entries_max = pstats.rcv_entries;

 out_unlock:
	write_unlock_bh(&rcv_lists_lock);
 out:
	return ret;
}

static void can_rx_delete_all(struct receiver **rl)
{
	struct receiver *r, *n;

	for (r = *rl; r; r = n) {
		n = r->next;
		kfree(r);
	}
	*rl = NULL;
}

int can_rx_unregister(struct net_device *dev, canid_t can_id, canid_t mask,
		      void (*func)(struct sk_buff *, void *), void *data)
{
	struct receiver *r, **rl;
	struct dev_rcv_lists *d;
	int ret = 0;

	DBG("dev %p, id %03X, mask %03X, callback %p, data %p\n",
	    dev, can_id, mask, func, data);

	write_lock_bh(&rcv_lists_lock);

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

	for (; r = *rl; rl = &r->next) {
		if (r->can_id == can_id && r->mask == mask
		    && r->func == func && r->data == data)
			break;
	}

	/*  Check for bug in CAN protocol implementations:
	 *  If no matching list item was found, r is NULL.
	 */

	if (!r) {
		DBG("receive list entry not found for "
		    "dev %s, id %03X, mask %03X\n", DNAME(dev), can_id, mask);
		ret = -EINVAL;
		goto out;
	}

	*rl = r->next;
	kmem_cache_free(rcv_cache, r);
	d->entries--;

	if (pstats.rcv_entries > 0)
		pstats.rcv_entries--;

 out:
	write_unlock_bh(&rcv_lists_lock);

	return ret;
}

static int can_rcv(struct sk_buff *skb, struct net_device *dev,
		   struct packet_type *pt)
{
	struct dev_rcv_lists *d;
	int matches;

	DBG("received skbuff on device %s, ptype %04x\n",
	    DNAME(dev), ntohs(pt->type));
	DBG_SKB(skb);
	DBG_FRAME("af_can: can_rcv: received CAN frame",
		  (struct can_frame *)skb->data);

	/* update statistics */
	stats.rx_frames++;
	stats.rx_frames_delta++;

	read_lock(&rcv_lists_lock);

	/* deliver the packet to sockets listening on all devices */
	matches = can_rcv_filter(&rx_alldev_list, skb);

	/* find receive list for this device */
	if ((d = find_dev_rcv_lists(dev)))
		matches += can_rcv_filter(d, skb);

	read_unlock(&rcv_lists_lock);

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
	int matches = 0;
	struct can_frame *cf = (struct can_frame*)skb->data;
	canid_t can_id = cf->can_id;

	if (d->entries == 0)
		return 0;

	if (can_id & CAN_ERR_FLAG) {
		/* check for error frame entries only */
		for (r = d->rx_err; r; r = r->next) {
			if (can_id & r->mask) {
				DBG("match on rx_err skbuff %p\n", skb);
				deliver(skb, r);
				matches++;
			}
		}
		goto out;
	}

	/* check for unfiltered entries */
	for (r = d->rx_all; r; r = r->next) {
		DBG("match on rx_all skbuff %p\n", skb);
		deliver(skb, r);
		matches++;
	}

	/* check for can_id/mask entries */
	for (r = d->rx_fil; r; r = r->next) {
		if ((can_id & r->mask) == r->can_id) {
			DBG("match on rx_fil skbuff %p\n", skb);
			deliver(skb, r);
			matches++;
		}
	}

	/* check for inverted can_id/mask entries */
	for (r = d->rx_inv; r; r = r->next) {
		if ((can_id & r->mask) != r->can_id) {
			DBG("match on rx_inv skbuff %p\n", skb);
			deliver(skb, r);
			matches++;
		}
	}

	/* check CAN_ID specific entries */
	if (can_id & CAN_EFF_FLAG) {
		for (r = d->rx_eff; r; r = r->next) {
			if (r->can_id == can_id) {
				DBG("match on rx_eff skbuff %p\n", skb);
				deliver(skb, r);
				matches++;
			}
		}
	} else {
		for (r = d->rx_sff[can_id & CAN_SFF_MASK]; r; r = r->next) {
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

	/* find receive list for this device */

	if (!dev)
		return &rx_alldev_list;

	for (d = rx_dev_list; d; d = d->next)
		if (d->dev == dev)
			break;

	return d;
}

static struct receiver **find_rcv_list(canid_t *can_id, canid_t *mask,
				       struct dev_rcv_lists *d)
{
	canid_t inv = *can_id & CAN_INV_FILTER; /* save flag before masking values */
	canid_t eff = *can_id & *mask & CAN_EFF_FLAG; /* correct EFF check? */
	canid_t rtr = *can_id & *mask & CAN_RTR_FLAG; /* correct RTR check? */
	canid_t err = *mask & CAN_ERR_FLAG; /* mask for error frames only */

	/* make some paranoic operations */
	if (*can_id & CAN_EFF_FLAG)
		*mask &= (CAN_EFF_MASK | eff | rtr);
	else
		*mask &= (CAN_SFF_MASK | rtr);

	*can_id &= *mask;

	if (err) /* error frames */
		return &d->rx_err;

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

#ifdef DEBUG

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

#ifdef EXPORT_SYMTAB
EXPORT_SYMBOL(can_debug_cframe);
EXPORT_SYMBOL(can_debug_skb);
#endif

#endif

/**************************************************/
/* Exported symbols                               */
/**************************************************/
#ifdef EXPORT_SYMTAB
EXPORT_SYMBOL(can_proto_register);
EXPORT_SYMBOL(can_proto_unregister);
EXPORT_SYMBOL(can_rx_register);
EXPORT_SYMBOL(can_rx_unregister);
EXPORT_SYMBOL(can_dev_register);
EXPORT_SYMBOL(can_dev_unregister);
EXPORT_SYMBOL(can_send);
EXPORT_SYMBOL(timeval2jiffies);
#endif
