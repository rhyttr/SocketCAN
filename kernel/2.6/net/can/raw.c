/*
 * raw.c
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
#include <linux/init.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/uio.h>
#include <linux/poll.h>
#include <net/sock.h>

#include <linux/can.h>
#include <linux/can/error.h>
#include <linux/can/raw.h>
#include <linux/can/version.h>

#include "af_can.h"


RCSID("$Id$");

#define IDENT "raw"
static __initdata const char banner[] = KERN_INFO "CAN: raw socket protocol " VERSION "\n"; 

MODULE_DESCRIPTION("PF_CAN raw sockets");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Urs Thuermann <urs.thuermann@volkswagen.de>");

#ifdef CONFIG_CAN_DEBUG_CORE
static int debug = 0;
module_param(debug, int, S_IRUGO);
#define DBG(args...)       (debug & 1 ? \
			       (printk(KERN_DEBUG "RAW %s: ", __func__), \
				printk(args)) : 0)
#define DBG_SKB(skb)       (debug & 4 ? can_debug_skb(skb) : 0)
#else
#define DBG(args...)
#define DBG_SKB(skb)
#endif

static int raw_init(struct sock *sk);
static int raw_release(struct socket *sock);
static int raw_bind   (struct socket *sock, struct sockaddr *uaddr, int len);
static int raw_getname(struct socket *sock, struct sockaddr *uaddr,
		       int *len, int peer);
static unsigned int raw_poll(struct file *file, struct socket *sock,
			     poll_table *wait);
static int raw_setsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, int optlen);
static int raw_getsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, int __user *optlen);
static int raw_sendmsg(struct kiocb *iocb, struct socket *sock,
		       struct msghdr *msg, size_t size);
static int raw_recvmsg(struct kiocb *iocb, struct socket *sock,
		       struct msghdr *msg, size_t size, int flags);
static void raw_rcv(struct sk_buff *skb, void *data);
static void raw_notifier(unsigned long msg, void *data);

static void raw_add_filters(struct net_device *dev, struct sock *sk);
static void raw_remove_filters(struct net_device *dev, struct sock *sk);


static struct proto_ops raw_ops = {
	.family        = PF_CAN,
	.release       = raw_release,
	.bind          = raw_bind,
	.connect       = sock_no_connect,
	.socketpair    = sock_no_socketpair,
	.accept        = sock_no_accept,
	.getname       = raw_getname,
	.poll          = raw_poll,
	.ioctl         = NULL,		/* use can_ioctl() from af_can.c */
	.listen        = sock_no_listen,
	.shutdown      = sock_no_shutdown,
	.setsockopt    = raw_setsockopt,
	.getsockopt    = raw_getsockopt,
	.sendmsg       = raw_sendmsg,
	.recvmsg       = raw_recvmsg,
	.mmap          = sock_no_mmap,
	.sendpage      = sock_no_sendpage,
};


/* A raw socket has a list of can_filters attached to it, each receiving
   the CAN frames matching that filter.  If the filter list is empty,
   no CAN frames will be received by the socket.  The default after
   opening the socket, is to have one filter which receives all frames.
   The filter list is allocated dynamically with the exception of the
   list containing only one item.  This common case is optimized by
   storing the single filter in dfilter, to avoid using dynamic memory.
*/

struct raw_opt {
	int bound;
	int ifindex;
	int loopback;
	int recv_own_msgs;
	int count;                 /* number of active filters */
	struct can_filter dfilter; /* default/single filter */
	struct can_filter *filter; /* pointer to filter(s) */
	can_err_mask_t err_mask;
};

#ifdef CONFIG_CAN_RAW_USER
#define RAW_CAP (-1)
#else
#define RAW_CAP CAP_NET_RAW
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,13)

struct raw_sock {
	struct sock    sk;
	struct raw_opt opt;
};

#define canraw_sk(sk) (&((struct raw_sock *)(sk))->opt)

static struct proto raw_proto = {
	.name       = "CAN_RAW",
	.owner      = THIS_MODULE,
	.obj_size   = sizeof(struct raw_sock),
	.init       = raw_init,
};

static struct can_proto raw_can_proto = {
	.type       = SOCK_RAW,
	.protocol   = CAN_RAW,
	.capability = RAW_CAP,
	.ops        = &raw_ops,
	.prot       = &raw_proto,
};

#else

#define canraw_sk(sk) ((struct raw_opt *)(sk)->sk_protinfo)

static struct can_proto raw_can_proto = {
	.type       = SOCK_RAW,
	.protocol   = CAN_RAW,
	.capability = RAW_CAP,
	.ops        = &raw_ops,
	.owner      = THIS_MODULE,
	.obj_size   = sizeof(struct raw_opt),
	.init       = raw_init,
};

#endif

#define MASK_ALL 0

static __init int raw_module_init(void)
{
	printk(banner);

	can_proto_register(&raw_can_proto);
	return 0;
}

static __exit void raw_module_exit(void)
{
	can_proto_unregister(&raw_can_proto);
}

static int raw_init(struct sock *sk)
{
	canraw_sk(sk)->bound            = 0;

	/* set default filter to single entry dfilter */
	canraw_sk(sk)->dfilter.can_id   = 0;
	canraw_sk(sk)->dfilter.can_mask = MASK_ALL;
	canraw_sk(sk)->filter           = &canraw_sk(sk)->dfilter;
	canraw_sk(sk)->count            = 1;

	/* set default loopback behaviour */
	canraw_sk(sk)->loopback         = 1;
	canraw_sk(sk)->recv_own_msgs    = 0;

	return 0;
}

static int raw_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct net_device *dev = NULL;

	DBG("socket %p, sk %p, refcnt %d\n", sock, sk,
	    atomic_read(&sk->sk_refcnt));

	if (canraw_sk(sk)->bound && canraw_sk(sk)->ifindex)
		dev = dev_get_by_index(canraw_sk(sk)->ifindex);

	/* remove current filters & unregister */
	if (canraw_sk(sk)->bound)
		raw_remove_filters(dev, sk);
	if (canraw_sk(sk)->count > 1)
		kfree(canraw_sk(sk)->filter);

	/* remove current error mask */
	if (canraw_sk(sk)->err_mask && canraw_sk(sk)->bound)
		can_rx_unregister(dev, 0, canraw_sk(sk)->err_mask | CAN_ERR_FLAG, raw_rcv, sk);

	if (dev) {
		can_dev_unregister(dev, raw_notifier, sk);
		dev_put(dev);
	}

	sock_put(sk);

	return 0;
}

static int raw_bind(struct socket *sock, struct sockaddr *uaddr, int len)
{
	struct sockaddr_can *addr = (struct sockaddr_can *)uaddr;
	struct sock *sk = sock->sk;
	struct net_device *dev;

	DBG("socket %p to device %d\n", sock, addr->can_ifindex);

	if (len < sizeof(*addr))
		return -EINVAL;

	if (canraw_sk(sk)->bound) {
#if 1
		return -EINVAL;
#else
		/* remove current bindings / notifier */
		if (canraw_sk(sk)->ifindex) {
			dev = dev_get_by_index(canraw_sk(sk)->ifindex);
			if (!dev) {
				DBG("could not find device %d\n",
				    addr->can_ifindex);
				return -ENODEV;
			}
			if (!(dev->flags & IFF_UP)) {
				sk->sk_err = ENETDOWN;
				if (!sock_flag(sk, SOCK_DEAD))
					sk->sk_error_report(sk);
				goto out;
			}
			can_dev_unregister(dev, raw_notifier, sk);
		} else
			dev = NULL;

		/* unregister current filters for this device */
		raw_remove_filters(dev, sk);

		if (dev)
			dev_put(dev);

		canraw_sk(sk)->bound = 0;
#endif
	}

	if (addr->can_ifindex) {
		dev = dev_get_by_index(addr->can_ifindex);
		if (!dev) {
			DBG("could not find device %d\n", addr->can_ifindex);
			return -ENODEV;
		}
		if (!(dev->flags & IFF_UP)) {
			sk->sk_err = ENETDOWN;
			if (!sock_flag(sk, SOCK_DEAD))
				sk->sk_error_report(sk);
			goto out;
		}
		can_dev_register(dev, raw_notifier, sk);
	} else
		dev = NULL;

	canraw_sk(sk)->ifindex = addr->can_ifindex;

	raw_add_filters(dev, sk); /* filters set by default/setsockopt */

	if (canraw_sk(sk)->err_mask) /* error frame filter set by setsockopt */
		can_rx_register(dev, 0, canraw_sk(sk)->err_mask | CAN_ERR_FLAG, raw_rcv, sk, IDENT);

	canraw_sk(sk)->bound = 1;

 out:
	if (dev)
		dev_put(dev);

	return 0;
}

static int raw_getname(struct socket *sock, struct sockaddr *uaddr,
		       int *len, int peer)
{
	struct sockaddr_can *addr = (struct sockaddr_can *)uaddr;
	struct sock *sk = sock->sk;

	if (peer)
		return -EOPNOTSUPP;

	addr->can_family  = AF_CAN;
	addr->can_ifindex = canraw_sk(sk)->ifindex;
	*len = sizeof(*addr);

	return 0;
}

static unsigned int raw_poll(struct file *file, struct socket *sock,
			     poll_table *wait)
{
	unsigned int mask = 0;

	DBG("socket %p\n", sock);

	mask = datagram_poll(file, sock, wait);
	return mask;
}

static int raw_setsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, int optlen)
{
	struct sock *sk = sock->sk;
	struct can_filter *filter = NULL;  /* dyn. alloc'ed filters */
	struct can_filter sfilter;         /* single filter */
	struct net_device *dev = NULL;
	can_err_mask_t err_mask = 0;
	int count = 0;
	int err;

	if (level != SOL_CAN_RAW)
		return -EINVAL;

	switch (optname) {
	case CAN_RAW_FILTER:
		if (optlen % sizeof(struct can_filter) != 0)
			return -EINVAL;

		count = optlen / sizeof(struct can_filter);

		if (count > 1) { /* does not fit into dfilter */
			if (!(filter = kmalloc(optlen, GFP_KERNEL)))
				return -ENOMEM;
			if ((err = copy_from_user(filter, optval, optlen))) {
				kfree(filter);
				return err;
			}
		} else if (count == 1) {
			if ((err = copy_from_user(&sfilter, optval, optlen)))
				return err;
		}

		if (canraw_sk(sk)->bound && canraw_sk(sk)->ifindex)
			dev = dev_get_by_index(canraw_sk(sk)->ifindex);

		/* remove current filters & unregister */
		if (canraw_sk(sk)->bound)
			raw_remove_filters(dev, sk);
		if (canraw_sk(sk)->count > 1)
			kfree(canraw_sk(sk)->filter);

		if (count == 1) { /* copy data for single filter */
			canraw_sk(sk)->dfilter = sfilter;
			filter = &canraw_sk(sk)->dfilter;
		}

		/* add new filters & register */
		canraw_sk(sk)->filter = filter;
		canraw_sk(sk)->count  = count;
		if (canraw_sk(sk)->bound)
			raw_add_filters(dev, sk);

		if (dev)
			dev_put(dev);

		break;

	case CAN_RAW_ERR_FILTER:
		if (optlen != sizeof(err_mask))
			return -EINVAL;
		if ((err = copy_from_user(&err_mask, optval, optlen)))
			return err;

		err_mask &= CAN_ERR_MASK;

		if (canraw_sk(sk)->bound && canraw_sk(sk)->ifindex)
			dev = dev_get_by_index(canraw_sk(sk)->ifindex);

		/* remove current error mask */
		if (canraw_sk(sk)->err_mask && canraw_sk(sk)->bound)
			can_rx_unregister(dev, 0, canraw_sk(sk)->err_mask | CAN_ERR_FLAG, raw_rcv, sk);

		/* add new error mask */
		canraw_sk(sk)->err_mask = err_mask;
		if (canraw_sk(sk)->err_mask && canraw_sk(sk)->bound)
			can_rx_register(dev, 0, canraw_sk(sk)->err_mask | CAN_ERR_FLAG, raw_rcv, sk, IDENT);

		if (dev)
			dev_put(dev);

		break;

	case CAN_RAW_LOOPBACK:
		if (optlen != sizeof(canraw_sk(sk)->loopback))
			return -EINVAL;
		if ((err = copy_from_user(&canraw_sk(sk)->loopback, optval, optlen)))
			return err;
		break;

	case CAN_RAW_RECV_OWN_MSGS:
		if (optlen != sizeof(canraw_sk(sk)->recv_own_msgs))
			return -EINVAL;
		if ((err = copy_from_user(&canraw_sk(sk)->recv_own_msgs, optval, optlen)))
			return err;
		break;

	default:
		return -ENOPROTOOPT;
	}
	return 0;
}

static int raw_getsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	struct can_filter *filter = canraw_sk(sk)->filter;
	int count = canraw_sk(sk)->count;
	int len;

	if (level != SOL_CAN_RAW)
		return -EINVAL;

	switch (optname) {
	case CAN_RAW_FILTER:
		if (get_user(len, optlen))
			return -EFAULT;

		if (count && filter) {
			int filter_size = count * sizeof(struct can_filter);
			if (len < filter_size)
				return -EINVAL;
			if (len > filter_size)
				len = filter_size;
			if (copy_to_user(optval, filter, len))
				return -EFAULT;
		} else
			len = 0;

		if (put_user(len, optlen))
			return -EFAULT;

		break;

	case CAN_RAW_ERR_FILTER:
		if (get_user(len, optlen))
			return -EFAULT;

		if (len < sizeof(can_err_mask_t))
			return -EINVAL;

		if (len > sizeof(can_err_mask_t))
			len = sizeof(can_err_mask_t);

		if (copy_to_user(optval, &canraw_sk(sk)->err_mask, len))
			return -EFAULT;

		if (put_user(len, optlen))
			return -EFAULT;

		break;

	case CAN_RAW_LOOPBACK:
		if (get_user(len, optlen))
			return -EFAULT;

		if (len < sizeof(int))
			return -EINVAL;

		if (len > sizeof(int))
			len = sizeof(int);

		if (copy_to_user(optval, &canraw_sk(sk)->loopback, len))
			return -EFAULT;

		if (put_user(len, optlen))
			return -EFAULT;

		break;

	case CAN_RAW_RECV_OWN_MSGS:
		if (get_user(len, optlen))
			return -EFAULT;

		if (len < sizeof(int))
			return -EINVAL;

		if (len > sizeof(int))
			len = sizeof(int);

		if (copy_to_user(optval, &canraw_sk(sk)->recv_own_msgs, len))
			return -EFAULT;

		if (put_user(len, optlen))
			return -EFAULT;

		break;

	default:
		return -ENOPROTOOPT;
	}
	return 0;
}

static void raw_add_filters(struct net_device *dev, struct sock *sk)
{
	struct can_filter *filter = canraw_sk(sk)->filter;
	int i;

	for (i = 0; i < canraw_sk(sk)->count; i++) {
		can_rx_register(dev, filter[i].can_id, filter[i].can_mask,
				raw_rcv, sk, IDENT);
		DBG("filter can_id %08X, can_mask %08X%s, sk %p\n",
		    filter[i].can_id, filter[i].can_mask,
		    filter[i].can_id & CAN_INV_FILTER ? " (inv)" : "", sk);
	}
}

static void raw_remove_filters(struct net_device *dev, struct sock *sk)
{
	struct can_filter *filter = canraw_sk(sk)->filter;
	int i;

	for (i = 0; i < canraw_sk(sk)->count; i++) {
		can_rx_unregister(dev, filter[i].can_id, filter[i].can_mask,
				  raw_rcv, sk);
		DBG("filter can_id %08X, can_mask %08X%s, sk %p\n",
		    filter[i].can_id, filter[i].can_mask,
		    filter[i].can_id & CAN_INV_FILTER ? " (inv)" : "", sk);
	}
}

static int raw_sendmsg(struct kiocb *iocb, struct socket *sock,
		       struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	struct net_device *dev;
	int ifindex;
	int err;

	DBG("socket %p, sk %p\n", sock, sk);

	if (msg->msg_name) {
		struct sockaddr_can *addr = (struct sockaddr_can *)msg->msg_name;
		if (addr->can_family != AF_CAN)
			return -EINVAL;
		ifindex = addr->can_ifindex;
	} else
		ifindex = canraw_sk(sk)->ifindex;

	if (!(dev = dev_get_by_index(ifindex))) {
		DBG("device %d not found\n", ifindex);
		return -ENXIO;
	}

	if (!(skb = alloc_skb(size, GFP_KERNEL))) {
		dev_put(dev);
		return -ENOMEM;
	}

	if ((err = memcpy_fromiovec(skb_put(skb, size), msg->msg_iov, size)) < 0) {
		kfree_skb(skb);
		dev_put(dev);
		return err;
	}
	skb->dev = dev;
	skb->sk  = sk;

	DBG("sending skbuff to interface %d\n", ifindex);
	DBG_SKB(skb);

	err = can_send(skb, canraw_sk(sk)->loopback);

	dev_put(dev);

	if (err)
		return err;

	return size;
}

static int raw_recvmsg(struct kiocb *iocb, struct socket *sock,
		       struct msghdr *msg, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	int error = 0;
	int noblock;

	DBG("socket %p, sk %p\n", sock, sk);

	noblock =  flags & MSG_DONTWAIT;
	flags   &= ~MSG_DONTWAIT;

	if (!(skb = skb_recv_datagram(sk, flags, noblock, &error)))
		return error;

	DBG("delivering skbuff %p\n", skb);
	DBG_SKB(skb);

	if (size < skb->len)
		msg->msg_flags |= MSG_TRUNC;
	else
		size = skb->len;

	if ((error = memcpy_toiovec(msg->msg_iov, skb->data, size)) < 0) {
		skb_free_datagram(sk, skb);
		return error;
	}

	sock_recv_timestamp(msg, sk, skb);

	if (msg->msg_name) {
		msg->msg_namelen = sizeof(struct sockaddr_can);
		memcpy(msg->msg_name, skb->cb, msg->msg_namelen);
	}

	DBG("freeing sock %p, skbuff %p\n", sk, skb);
	skb_free_datagram(sk, skb);

	return size;
}

static void raw_rcv(struct sk_buff *skb, void *data)
{
	struct sock *sk = (struct sock*)data;
	struct sockaddr_can *addr;
	int error;

	DBG("received skbuff %p, sk %p\n", skb, sk);
	DBG_SKB(skb);

	if (!canraw_sk(sk)->recv_own_msgs) {
		if (*(struct sock **)skb->cb == sk) { /* tx sock reference */
			DBG("trashed own tx msg\n");
			kfree_skb(skb);
			return;
		}
	}

	addr = (struct sockaddr_can *)skb->cb;
	memset(addr, 0, sizeof(*addr));
	addr->can_family  = AF_CAN;
	addr->can_ifindex = skb->dev->ifindex;

	if ((error = sock_queue_rcv_skb(sk, skb)) < 0) {
		DBG("sock_queue_rcv_skb failed: %d\n", error);
		DBG("freeing skbuff %p\n", skb);
		kfree_skb(skb);
	}
}

static void raw_notifier(unsigned long msg, void *data)
{
	struct sock *sk = (struct sock *)data;

	DBG("called for sock %p\n", sk);

	switch (msg) {
	case NETDEV_UNREGISTER:
		canraw_sk(sk)->ifindex = 0;
		canraw_sk(sk)->bound   = 0;
		/* fallthrough */
	case NETDEV_DOWN:
		sk->sk_err = ENETDOWN;
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report(sk);
		break;
	}
}


module_init(raw_module_init);
module_exit(raw_module_exit);
