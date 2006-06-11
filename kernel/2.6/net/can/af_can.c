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
 * Send feedback to <llcf@volkswagen.de>
 *
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <asm/uaccess.h>

#include <linux/can/af_can.h>

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
module_param(stats_timer, int, S_IRUGO);

#ifdef DEBUG
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
static int can_rcv_filter(struct rcv_dev_list *q, struct sk_buff *skb);
static struct rcv_list **find_rcv_list(canid_t *can_id, canid_t *mask,
				       struct net_device *dev);

struct notifier_list {
	struct notifier_list *next;
	struct net_device *dev;
	void (*func)(unsigned long msg, void *data);
	void *data;
};

static struct notifier_list *nlist;

struct rcv_dev_list *rx_dev_list;
struct rcv_dev_list rx_alldev_list;
rwlock_t rcv_lists_lock = RW_LOCK_UNLOCKED;

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

static struct notifier_block can_netdev_notifier = {
	.notifier_call = can_notifier,
};

static struct can_proto *proto_tab[CAN_MAX];

extern struct timer_list stattimer; /* timer for statistics update */
extern struct s_stats  stats;       /* statistics */
extern struct s_pstats pstats;

module_init(can_init);
module_exit(can_exit);

/**************************************************/
/* af_can module init/exit functions              */
/**************************************************/

static __init int can_init(void)
{
	printk(banner);

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
}

/**************************************************/
/* af_can protocol functions                      */
/**************************************************/

void can_proto_register(int proto, struct can_proto *cp)
{
	if (proto < 0 || proto >= CAN_MAX) {
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

void can_proto_unregister(int proto)
{
	struct can_proto *cp;

	if (!(cp = proto_tab[proto])) {
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
	struct notifier_list *p = kmalloc(GFP_KERNEL, sizeof(*p));

	DBG("called for %s\n", dev->name);

	if (!p)
		return;
	p->next = nlist;
	p->dev  = dev;
	p->func = func;
	p->data = data;
	nlist = p;
}

void can_dev_unregister(struct net_device *dev,
			void (*func)(unsigned long msg, void *), void *data)
{
	struct notifier_list *p, **q;

	DBG("called for %s\n", dev->name);

	for (q = &nlist; p = *q; q = &p->next) {
		if (p->dev == dev && p->func == func && p->data == data) {
			*q = p->next;
			kfree(p);
			return;
		}
	}
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

	DBG("socket %p, type %d, proto %d\n", sock, sock->type, protocol);

	sock->state = SS_UNCONNECTED;

	switch (sock->type) {
	case SOCK_SEQPACKET:
		switch (protocol) {
		case CAN_TP16:
			break;
		case CAN_TP20:
			break;
		case CAN_MCNET:
			break;
		case CAN_ISOTP:
			break;
		default:
			return -EPROTONOSUPPORT;
		}
		break;
	case SOCK_DGRAM:
		switch (protocol) {
		case CAN_BCM:
			break;
		case CAN_BAP:
			break;
		default:
			return -EPROTONOSUPPORT;
		}
		break;
	case SOCK_RAW:
		switch (protocol) {
		case CAN_RAW:
			if (!capable(CAP_NET_RAW))
				return -EPERM;
			break;
		default:
			return -EPROTONOSUPPORT;
		}
		break;
	default:
		return -ESOCKTNOSUPPORT;
		break;
	}

	DBG("looking up proto %d in proto_tab[]\n", protocol);

	/* try to load protocol module, when CONFIG_KMOD is defined */
	if (!proto_tab[protocol]) {
		char module_name[30];
		sprintf(module_name, "can-proto-%d", protocol);
		if (request_module(module_name) == -ENOSYS)
			printk(KERN_INFO "af_can: request_module(%s) not implemented.\n",
			       module_name);
	}

	/* check for success */
	if (!(cp = proto_tab[protocol]))
		return -EPROTONOSUPPORT;

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

	return 0;

 oom:
	return -ENOMEM;
}

static int can_notifier(struct notifier_block *nb,
			unsigned long msg, void *data)
{
	struct net_device *dev = (struct net_device *)data;
	struct notifier_list *p;

	DBG("called for %s, msg = %lu\n", dev->name, msg);

	for (p = nlist; p; p = p->next) {
		if (p->dev == dev)
			p->func(msg, p->data);
	}
	return 0;
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

int can_send(struct sk_buff *skb)
{
	struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
	int err;

	if (!(skb->dev->flags & IFF_UP))
		err = -ENETDOWN;
	else if ((err = dev_queue_xmit(skb)) > 0)  /* send to netdevice */
		err = net_xmit_errno(err);

	/* update statistics */
	stats.tx_frames++;
	stats.tx_frames_delta++;

	newskb->protocol  = htons(ETH_P_CAN);
	newskb->ip_summed = CHECKSUM_UNNECESSARY;
	netif_rx(newskb);                          /* local loopback */

	return err;
}

/**************************************************/
/* af_can rx path                                 */
/**************************************************/

void can_rx_register(struct net_device *dev, canid_t can_id, canid_t mask,
		     void (*func)(struct sk_buff *, void *), void *data,
		     char *ident)
{
	struct rcv_list *p, **q;
	struct rcv_dev_list *d;

	DBG("dev %p, id %03X, mask %03X, callback %p, data %p, ident %s\n",
	    dev, can_id, mask, func, data, ident);

	write_lock_bh(&rcv_lists_lock);

	q = find_rcv_list(&can_id, &mask, dev);

	if (!q) {
		printk(KERN_ERR "CAN: receive list not found for "
		       "dev %s, id %03X, mask %03X, ident %s\n",
		       dev->name, can_id, mask, ident);
		goto out;
	}

	/* insert   (dev,canid,mask) -> (func,data) */
	if (!(p = kmalloc(sizeof(struct rcv_list), GFP_KERNEL)))
		return;

	p->can_id  = can_id;
	p->mask    = mask;
	p->matches = 0;
	p->func    = func;
	p->data    = data;
	p->ident   = ident;
	p->next = *q;
	*q = p;

	if (!dev)
		d = &rx_alldev_list;
	else
		for (d = rx_dev_list; d; d = d->next)
			if (d->dev == dev)
				break;
	d->entries++;

	pstats.rcv_entries++;
	if (pstats.rcv_entries_max < pstats.rcv_entries)
		pstats.rcv_entries_max = pstats.rcv_entries;

 out:
	write_unlock_bh(&rcv_lists_lock);
}

void can_rx_unregister(struct net_device *dev, canid_t can_id, canid_t mask,
		       void (*func)(struct sk_buff *, void *), void *data)
{
	struct rcv_list *p, **q;
	struct rcv_dev_list *d;

	DBG("dev %p, id %03X, mask %03X, callback %p, data %p\n",
	    dev, can_id, mask, func, data);

	write_lock_bh(&rcv_lists_lock);

	q = find_rcv_list(&can_id, &mask, dev);

	if (!q) {
		printk(KERN_ERR "CAN: receive list not found for "
		       "dev %s, id %03X, mask %03X\n", dev->name, can_id, mask);
		goto out;
	}

	for (; p = *q; q = &p->next) {
		if (p->can_id == can_id && p->mask == mask
		    && p->func == func && p->data == data)
			break;
	}

	if (!p) {
		printk(KERN_ERR "CAN: receive list entry not found for "
		       "dev %s, id %03X, mask %03X\n", dev->name, can_id, mask);
		goto out;
	}

	*q = p->next;
	kfree(p);

	if (pstats.rcv_entries > 0)
		pstats.rcv_entries--;

	if (!dev)
		d = &rx_alldev_list;
	else
		for (d = rx_dev_list; d; d = d->next)
			if (d->dev == dev)
				break;
	d->entries--;

	if(!d->entries)
		d->dev = NULL; /* mark unused */

 out:
	write_unlock_bh(&rcv_lists_lock);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
static int can_rcv(struct sk_buff *skb, struct net_device *dev,
		   struct packet_type *pt, struct net_device *orig_dev)
#else
static int can_rcv(struct sk_buff *skb, struct net_device *dev,
		   struct packet_type *pt)
#endif
{
	struct rcv_dev_list *q;
	int matches;

	DBG("received skbuff on device %s, ptype %04x\n",
	    dev->name, ntohs(pt->type));
	DBG_SKB(skb);
	DBG_FRAME("af_can: can_rcv: received CAN frame",
		  (struct can_frame *)skb->data);

	/* update statistics */
	stats.rx_frames++;
	stats.rx_frames_delta++;

	read_lock(&rcv_lists_lock);

	matches = can_rcv_filter(&rx_alldev_list, skb);

	/* find receive list for this device */
	for (q = rx_dev_list; q; q = q->next)
		if (q->dev == dev)
			break;

	if (q)
		matches += can_rcv_filter(q, skb);

	read_unlock(&rcv_lists_lock);

	DBG("freeing skbuff %p\n", skb);
	kfree_skb(skb);

	if (matches > 0) {
		stats.matches++;
		stats.matches_delta++;
	}

	return 0;
}


static inline void deliver(struct sk_buff *skb, struct rcv_list *p)
{
	struct sk_buff *clone = skb_clone(skb, GFP_ATOMIC);
	DBG("skbuff %p cloned to %p\n", skb, clone);
	if (clone) {
		p->func(clone, p->data);
		p->matches++;    /* update specific statistics */
	}
}
    
static int can_rcv_filter(struct rcv_dev_list *q, struct sk_buff *skb)
{
	struct rcv_list *p;
	int matches = 0;
	struct can_frame *cf = (struct can_frame*)skb->data;
	canid_t can_id = cf->can_id;

	if (q->entries == 0)
		return 0;

	if (can_id & CAN_ERR_FLAG) {
		/* check for error frame entries only */
		for (p = q->rx_err; p; p = p->next) {
			if (can_id & p->mask) {
				DBG("match on rx_err skbuff %p\n", skb);
				deliver(skb, p);
				matches++;
			}
		}
		goto out;
	}

	/* check for unfiltered entries */
	for (p = q->rx_all; p; p = p->next) {
		DBG("match on rx_all skbuff %p\n", skb);
		deliver(skb, p);
		matches++;
	}

	/* check for can_id/mask entries */
	for (p = q->rx_fil; p; p = p->next) {
		if ((can_id & p->mask) == p->can_id) {
			DBG("match on rx_fil skbuff %p\n", skb);
			deliver(skb, p);
			matches++;
		}
	}

	/* check for inverted can_id/mask entries */
	for (p = q->rx_inv; p; p = p->next) {
		if ((can_id & p->mask) != p->can_id) {
			DBG("match on rx_inv skbuff %p\n", skb);
			deliver(skb, p);
			matches++;
		}
	}

	/* check CAN_ID specific entries */
	if (can_id & CAN_EFF_FLAG) {
		for (p = q->rx_eff; p; p = p->next) {
			if (p->can_id == can_id) {
				DBG("match on rx_eff skbuff %p\n", skb);
				deliver(skb, p);
				matches++;
			}
		}
	} else {
		for (p = q->rx_sff[can_id & CAN_SFF_MASK]; p; p = p->next) {
			DBG("match on rx_sff skbuff %p\n", skb);
			deliver(skb, p);
			matches++;
		}
	}

 out:
	return matches;
}

static struct rcv_list **find_rcv_list(canid_t *can_id, canid_t *mask,
				       struct net_device *dev)
{
	canid_t inv = *can_id & CAN_INV_FILTER; /* save flag before masking values */
	canid_t eff = *can_id & *mask & CAN_EFF_FLAG; /* correct EFF check? */
	canid_t rtr = *can_id & *mask & CAN_RTR_FLAG; /* correct RTR check? */
	canid_t err = *mask & CAN_ERR_FLAG; /* mask for error frames only */

	struct rcv_dev_list *p;

	/* make some paranoic operations */
	if (*can_id & CAN_EFF_FLAG)
		*mask &= (CAN_EFF_MASK | eff | rtr);
	else
		*mask &= (CAN_SFF_MASK | rtr);

	*can_id &= *mask;

	/* find receive list for this device */
	if (!dev)
		p = &rx_alldev_list;
	else
		for (p = rx_dev_list; p; p = p->next)
			if (p->dev == dev)
				break;

	if (!p) {
		/* arrange new rcv_dev_list for this device */

		/* find deactivated receive list for this device */
		for (p = rx_dev_list; p; p = p->next)
			if (p->dev == NULL)
				break;

		if (p) {
			DBG("reactivating rcv_dev_list for %s\n", dev->name); 
			p->dev = dev;
		} else {
			/* create new rcv_dev_list for this device */
			DBG("creating new rcv_dev_list for %s\n", dev->name);
			if (!(p = kmalloc(sizeof(struct rcv_dev_list), GFP_KERNEL))) {
				printk(KERN_ERR "CAN: allocation of receive list failed\n");
				return NULL;
			}
			memset (p, 0, sizeof(struct rcv_dev_list));
			p->dev      = dev;
			p->next     = rx_dev_list;
			rx_dev_list = p;
		}
	}

	if (err) /* error frames */
		return &p->rx_err;

	if (inv) /* inverse can_id/can_mask filter and RTR */
		return &p->rx_inv;

	if (*can_id & CAN_RTR_FLAG) /* positive filter RTR */
		return &p->rx_fil;

	if (!(*mask)) /* mask == 0 => no filter */
		return &p->rx_all;

	if (*can_id & CAN_EFF_FLAG) {
		if (*mask == CAN_EFF_MASK) /* filter exact EFF can_id */
			return &p->rx_eff;
	} else {
		if (*mask == CAN_SFF_MASK) /* filter exact SFF can_id */
			return &p->rx_sff[*can_id];
	}

	return &p->rx_fil;  /* filter via can_id/can_mask */
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
