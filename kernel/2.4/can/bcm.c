/*
 * bcm.c
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
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/poll.h>
#include <net/sock.h>

#include "af_can.h"
#include "version.h"
#include "bcm.h"

RCSID("$Id: bcm.c,v 1.82 2006/04/10 09:37:39 ethuerm Exp $");

#ifdef DEBUG
MODULE_PARM(debug, "1i");
static int debug = 0;
#define DBG(args...)       (debug & 1 ? \
	                       (printk(KERN_DEBUG "BCM %s: ", __func__), \
			        printk(args)) : 0)
#define DBG_FRAME(args...) (debug & 2 ? can_debug_cframe(args) : 0)
#define DBG_SKB(skb)       (debug & 4 ? can_debug_skb(skb) : 0)
#else
#define DBG(args...)
#define DBG_FRAME(args...)
#define DBG_SKB(skb)
#endif

/* use of last_frames[index].can_dlc */
#define RX_RECV    0x40 /* received data for this element */
#define RX_THR     0x80 /* this element has not been sent due to throttle functionality */
#define BCM_CAN_DLC_MASK 0x0F /* clean flags by masking with BCM_CAN_DLC_MASK */

#define NAME "Broadcast Manager (BCM) for LLCF"
#define IDENT "bcm"
static __initdata const char banner[] = BANNER(NAME);

MODULE_DESCRIPTION(NAME);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Oliver Hartkopp <oliver.hartkopp@volkswagen.de>");


#define GET_U64(p) (*(unsigned long long*)(p)->data)

struct bcm_op {
    struct bcm_op *next;
    canid_t can_id;
    int flags;
    unsigned long j_ival1, j_ival2, j_lastmsg;
    unsigned long frames_abs, frames_filtered;
    struct timeval ival1, ival2, stamp;
    struct timer_list timer, thrtimer;
    int count;
    int nframes;
    int currframe;
    struct can_frame *frames;
    struct can_frame *last_frames;
    struct sock *sk;
};

struct bcm_user_data {
    struct bcm_op *rx_ops;
    struct bcm_op *tx_ops;
    struct proc_dir_entry *bcm_proc_read;
    char procname [9];
};

#define bcm_sk(sk) ((struct bcm_user_data *)(sk)->user_data)

static struct proc_dir_entry *proc_dir = NULL;
int bcm_read_proc(char *page, char **start, off_t off, int count, int *eof, void *data);

static void bcm_notifier(unsigned long msg, void *data);
static int bcm_release(struct socket *sock);
static int bcm_connect(struct socket *sock, struct sockaddr *uaddr, int len,
		       int flags);
static unsigned int bcm_poll(struct file *file, struct socket *sock,
			     poll_table *wait);
static int bcm_sendmsg(struct socket *sock, struct msghdr *msg, int size,
		       struct scm_cookie *scm);
static int bcm_recvmsg(struct socket *sock, struct msghdr *msg, int size,
		       int flags, struct scm_cookie *scm);

static void bcm_tx_timeout_handler(unsigned long data);
static void bcm_rx_handler(struct sk_buff *skb, void *op);
static void bcm_rx_timeout_handler(unsigned long data);
static void bcm_rx_thr_handler(unsigned long data);
static struct bcm_op *bcm_find_op(struct bcm_op *ops, canid_t can_id);
static void bcm_insert_op(struct bcm_op **ops, struct bcm_op *op);
static void bcm_delete_tx_op(struct bcm_op **ops, canid_t can_id);
static void bcm_delete_rx_op(struct bcm_op **ops, canid_t can_id);
static void bcm_remove_op(struct bcm_op *op);
static void bcm_can_tx(struct bcm_op *op);
static void bcm_send_to_user(struct sock *sk, struct bcm_msg_head *head,
			     struct can_frame *frames, struct timeval *tv);
static void bcm_rx_changed(struct bcm_op *op, struct can_frame *data);
static void bcm_rx_starttimer(struct bcm_op *op);
static void bcm_rx_update_and_send(struct bcm_op *op,
				   struct can_frame *lastdata,
				   struct can_frame *rxdata);
static void bcm_rx_cmp_to_index(struct bcm_op *op, int index,
				struct can_frame *rxdata);

static struct proto_ops bcm_ops = {
    .family        = PF_CAN,
    .release       = bcm_release,
    .bind          = sock_no_bind,
    .connect       = bcm_connect,
    .socketpair    = sock_no_socketpair,
    .accept        = sock_no_accept,
    .getname       = sock_no_getname,
    .poll          = bcm_poll,
    .ioctl         = 0,
    .listen        = sock_no_listen,
    .shutdown      = sock_no_shutdown,
    .setsockopt    = sock_no_setsockopt,
    .getsockopt    = sock_no_getsockopt,
    .sendmsg       = bcm_sendmsg,
    .recvmsg       = bcm_recvmsg,
    .mmap          = sock_no_mmap,
    .sendpage      = sock_no_sendpage,
};

static int __init bcm_init(void)
{
    printk(banner);

    can_proto_register(CAN_BCM, &bcm_ops);

    /* create /proc/can/bcm directory */
    proc_dir = proc_mkdir(CAN_PROC_DIR"/"IDENT, NULL);

    if (proc_dir)
	proc_dir->owner = THIS_MODULE;

    return 0;
}

static void __exit bcm_exit(void)
{
    can_proto_unregister(CAN_BCM);

    if (proc_dir)
	remove_proc_entry(CAN_PROC_DIR"/"IDENT, NULL);

}

static void bcm_notifier(unsigned long msg, void *data)
{
    struct sock *sk = (struct sock *)data;

    DBG("called for sock %p\n", sk);

    switch (msg)
    {
    case NETDEV_UNREGISTER:
	sk->bound_dev_if = 0;
    case NETDEV_DOWN:
	sk->err = ENETDOWN;
	sk->error_report(sk);
    }
}

static int bcm_release(struct socket *sock)
{
    struct sock *sk = sock->sk;
    struct bcm_user_data *ud = bcm_sk(sk);
    struct bcm_op *op,*next;

    /* many things to do here:
       free all rx_ops and tx_ops, bcm_user_data structure,
       can_rx_unregister(dev, canid, raw_rcv) and can-data in ?x_ops */

    DBG("socket %p, sk %p\n", sock, sk);

    /* remove userdata, bcm_ops, timer, etc. */

    if (ud) {
	for (op = ud->tx_ops; op ; op = next) {
	    DBG("removing tx_op (%p) for can_id <%03X>\n", op, op->can_id);
	    next = op->next;
	    bcm_remove_op(op);
	}

	for (op = ud->rx_ops; op ; op = next) {
	    DBG("removing rx_op (%p) for can_id <%03X>\n", op, op->can_id);
	    next = op->next;

	    if (sk->bound_dev_if) {
		struct net_device *dev = dev_get_by_index(sk->bound_dev_if);
		if (dev) {
		    can_rx_unregister(dev, op->can_id, 0xFFFFFFFFU, bcm_rx_handler, op);
		    dev_put(dev);
		}
	    } else
		DBG("sock %p not bound for can_rx_unregister()\n", sk);

	    bcm_remove_op(op);
	}

	if ((proc_dir) && (ud->bcm_proc_read)) {
	    remove_proc_entry(ud->procname, proc_dir);
	}

	kfree (ud);
    }

    if (sk->bound_dev_if) {
	struct net_device *dev = dev_get_by_index(sk->bound_dev_if);
	if (dev) {
	    can_dev_unregister(dev, bcm_notifier, sk);
	    dev_put(dev);
	}
    } else
	DBG("sock %p not bound for can_dev_unregister()\n", sk);

    sock_put(sk);

    return 0;
}

static int bcm_connect(struct socket *sock, struct sockaddr *uaddr, int len,
		       int flags)
{
    struct sockaddr_can *addr = (struct sockaddr_can *)uaddr;
    struct sock *sk = sock->sk;
    struct net_device *dev;
    struct bcm_user_data *ud;

    /* bind a device to this socket */

    dev = dev_get_by_index(addr->can_ifindex);
    if (!dev) {
	DBG("could not find device %d\n", addr->can_ifindex);
	return -ENODEV;
    }
    sk->bound_dev_if = dev->ifindex;
    can_dev_register(dev, bcm_notifier, sk);
    dev_put(dev);

    DBG("socket %p to device %s (idx %d)\n", sock, dev->name, dev->ifindex);

    /* create struct for BCM-specific data for this socket */

    if (!(ud = kmalloc(sizeof(struct bcm_user_data), GFP_KERNEL)))
	return -ENOMEM;

    /* intitial BCM operations */
    ud->tx_ops = NULL;
    ud->rx_ops = NULL;
    ud->bcm_proc_read = NULL;

    sk->user_data = ud;

    if (proc_dir) {
	sprintf(ud->procname, "%p", ud);
	ud->bcm_proc_read = create_proc_read_entry(ud->procname, 0644,
						   proc_dir, bcm_read_proc, ud);
    }

    return 0;
}

int bcm_read_proc(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int len = 0;
    struct bcm_user_data *ud = (struct bcm_user_data *) data;
    struct bcm_op *op;
    struct net_device *dev = NULL;

    MOD_INC_USE_COUNT;

    len += snprintf(page + len, PAGE_SIZE - len,">>> ud %p", ud);

    if (ud->rx_ops) {
	if (ud->rx_ops->sk->bound_dev_if)
	    dev = dev_get_by_index(ud->rx_ops->sk->bound_dev_if);
	len += snprintf(page + len, PAGE_SIZE - len,
			" / sk %p / socket %p", ud->rx_ops->sk, ud->rx_ops->sk->socket);
    }
    else
	if (ud->tx_ops) {
	    if (ud->tx_ops->sk->bound_dev_if)
		dev = dev_get_by_index(ud->tx_ops->sk->bound_dev_if);
	    len += snprintf(page + len, PAGE_SIZE - len,
			    " / sk %p / socket %p", ud->tx_ops->sk, ud->tx_ops->sk->socket);
    }

    if (dev) {
	len += snprintf(page + len, PAGE_SIZE - len, " / %s", dev->name);
	dev_put(dev);
    }

    len += snprintf(page + len, PAGE_SIZE - len, " <<<\n");

    for (op = ud->rx_ops; op && (len < PAGE_SIZE - 100); op = op->next) {

	unsigned long reduction;

	/* print only active entries & prevent division by zero */
	if (!op->frames_abs)
	    continue;

	len += snprintf(page + len, PAGE_SIZE - len, "rx_op: %03X [%d]%c ",
			op->can_id, op->nframes,(op->flags & RX_CHECK_DLC)?'d':' ');
	if (op->j_ival1)
	    len += snprintf(page + len, PAGE_SIZE - len, "timeo=%ld ", op->j_ival1);

	if (op->j_ival2)
	    len += snprintf(page + len, PAGE_SIZE - len, "thr=%ld ", op->j_ival2);

	len += snprintf(page + len, PAGE_SIZE - len, "# recv %ld (%ld) => reduction: ",
			op->frames_filtered, op->frames_abs);

	reduction = 100 - (op->frames_filtered * 100) / op->frames_abs;

	len += snprintf(page + len, PAGE_SIZE - len, "%s%ld%%\n",
			(reduction == 100)?"near ":"", reduction);

	if (len > PAGE_SIZE - 100) /* 100 Bytes before end of buffer */
	  len += snprintf(page + len, PAGE_SIZE - len, "(..)\n"); /* mark output cutted off */
    }

    for (op = ud->tx_ops; op && (len < PAGE_SIZE - 100); op = op->next) {

	len += snprintf(page + len, PAGE_SIZE - len, "tx_op: %03X [%d] ",
			op->can_id, op->nframes);
	if (op->j_ival1)
	    len += snprintf(page + len, PAGE_SIZE - len, "t1=%ld ", op->j_ival1);

	if (op->j_ival2)
	    len += snprintf(page + len, PAGE_SIZE - len, "t2=%ld ", op->j_ival2);

	len += snprintf(page + len, PAGE_SIZE - len, "# sent %ld\n", op->frames_abs);

	if (len > PAGE_SIZE - 100) /* 100 Bytes before end of buffer */
	  len += snprintf(page + len, PAGE_SIZE - len, "(..)\n"); /* mark output cutted off */
    }

    len += snprintf(page + len, PAGE_SIZE - len, "\n");

    MOD_DEC_USE_COUNT;

    *eof = 1;
    return len;
}

static unsigned int bcm_poll(struct file *file, struct socket *sock,
			     poll_table *wait)
{
    unsigned int mask = 0;

    DBG("socket %p\n", sock);

    mask = datagram_poll(file, sock, wait);
    return mask;
}

static int bcm_sendmsg(struct socket *sock, struct msghdr *msg, int size,
		       struct scm_cookie *scm)
{
    struct bcm_msg_head msg_head;
    int i;
    struct bcm_op *op;
    int err;
    struct sock *sk = sock->sk;
    struct bcm_user_data *ud = bcm_sk(sk);
    char c;
    int rbytes = 0; /* read bytes as return value */

    /* read message head information */

    if ((err = memcpy_fromiovec((unsigned char*)&msg_head, msg->msg_iov,
				sizeof(msg_head))) < 0)
	return err;

    DBG("opcode %d for can_id <%03X>\n", msg_head.opcode, msg_head.can_id);

    if (!sk->bound_dev_if) {
	DBG("sock %p not bound\n", sk); /* and therefore ud not initialized */
	return -ENOTCONN;
    }

    switch (msg_head.opcode) {

    case TX_SETUP:

	if (msg_head.nframes < 1) /* we need at least one can_frame */
	    return -EINVAL;

	/* check the given can_id */

	if (!(op = bcm_find_op(ud->tx_ops, msg_head.can_id))) {

	    /* insert new BCM operation for the given can_id */

	    if (!(op = kmalloc(sizeof(struct bcm_op), GFP_KERNEL)))
		return -ENOMEM;

	    memset(op, 0, sizeof(struct bcm_op)); /* init to zero, e.g. for timers */

	    DBG("TX_SETUP: creating new tx_op (%p) for can_id <%03X>\n",
		op, msg_head.can_id);

	    op->can_id    = msg_head.can_id;

	    /* create array for can_frames and copy the data */
	    if (!(op->frames = kmalloc(msg_head.nframes * sizeof(struct can_frame), GFP_KERNEL))) {
	        kfree(op);
		return -ENOMEM;
	    }

	    for (i = 0; i < msg_head.nframes; i++) {
		memcpy_fromiovec((unsigned char*)&op->frames[i], msg->msg_iov, sizeof(struct can_frame));
		if (msg_head.flags & TX_CP_CAN_ID)
		    op->frames[i].can_id = msg_head.can_id; /* copy can_id into frame */
	    }

	    op->last_frames = NULL; /* tx_ops never compare with previous received messages */

	    op->sk = sk; /* bcm_can_tx / bcm_tx_timeout_handler needs this */

	    init_timer(&op->timer); /* initialize uninitialized (kmalloc) structure */
	    init_timer(&op->thrtimer); /* currently unused in tx_ops */

	    op->timer.function = bcm_tx_timeout_handler; /* handler for tx_ops */
	    op->timer.data = (unsigned long)op; /* timer.data points to this op-structure */

	    /* add this bcm_op to the list of the tx_ops */
	    bcm_insert_op(&ud->tx_ops, op);

	}
	else {
	    /* update existing BCM operation */

	    DBG("TX_SETUP: modifying existing tx_op (%p) for can_id <%03X>\n",
		op, msg_head.can_id);

	    /* do we need more space for the can_frames? */
	    if (msg_head.nframes > op->nframes) {

		/* yes => create new array */

		struct can_frame *p;
		if (!(p = kmalloc(msg_head.nframes * sizeof(struct can_frame), GFP_KERNEL)))
		    return -ENOMEM;

		kfree (op->frames);
		op->frames = p;
	    }

	    /* update can_frames content */
	    for (i = 0; i < msg_head.nframes; i++) {
		memcpy_fromiovec((unsigned char*)&op->frames[i], msg->msg_iov, sizeof(struct can_frame));
		if (msg_head.flags & TX_CP_CAN_ID)
		    op->frames[i].can_id = msg_head.can_id; /* copy can_id into frame */
	    }

	}

	if (op->nframes != msg_head.nframes) {
	    op->nframes   = msg_head.nframes;
	    op->currframe = 0; /* start multiple frame transmission with index 0 */
	}

	/* check flags */

	op->flags = msg_head.flags;

	if (op->flags & TX_RESET_MULTI_IDX)
	    op->currframe = 0; /* start multiple frame transmission with index 0 */

	if (op->flags & SETTIMER) {

	    /* set timer values */

	    op->count   = msg_head.count;
	    op->ival1   = msg_head.ival1;
	    op->ival2   = msg_head.ival2;
	    op->j_ival1 = timeval2jiffies(&msg_head.ival1, 1);
	    op->j_ival2 = timeval2jiffies(&msg_head.ival2, 1);

	    DBG("TX_SETUP: SETTIMER count=%d j_ival1=%ld j_ival2=%ld\n",
		op->count, op->j_ival1, op->j_ival2);

	    /* disable an active timer due to zero values? */
	    if (!op->j_ival1 && !op->j_ival2) {
		del_timer(&op->timer);
		DBG("TX_SETUP: SETTIMER disabled timer.\n");
	    }

	}

	if ((op->flags & STARTTIMER) && ((op->j_ival1 && op->count) || op->j_ival2)) {

	    del_timer(&op->timer);

	    op->flags |= TX_ANNOUNCE; /* spec: send can_frame when starting timer */
	    if (op->j_ival1 && (op->count > 0)){
		op->timer.expires = jiffies + op->j_ival1;
		/* op->count-- is done in bcm_tx_timeout_handler */
		DBG("TX_SETUP: adding timer ival1. func=%p data=(%p) exp=0x%08X\n",
		    op->timer.function,
		    (char*) op->timer.data,
		    (unsigned int) op->timer.expires);
	    }
	    else{
		op->timer.expires = jiffies + op->j_ival2;
		DBG("TX_SETUP: adding timer ival2. func=%p data=(%p) exp=0x%08X\n",
		    op->timer.function,
		    (char*) op->timer.data,
		    (unsigned int) op->timer.expires);
	    }

	    add_timer(&op->timer);
	}

	if (op->flags & TX_ANNOUNCE)
	    bcm_can_tx(op);

	rbytes = msg_head.nframes * sizeof(struct can_frame) + sizeof(struct bcm_msg_head);

	break; /* TX_SETUP */

    case TX_DELETE:

	bcm_delete_tx_op(&ud->tx_ops, msg_head.can_id);

	rbytes = sizeof(struct bcm_msg_head);

	break; /* TX_DELETE */

    case TX_READ:

	/* reuse msg_head for the reply */
	msg_head.opcode  = TX_STATUS; /* reply to TX_READ */
	op = bcm_find_op(ud->tx_ops, msg_head.can_id);
	c  = 'T'; /* for nice debug output ... */

	goto TRX_READ;

    case RX_READ:

	/* reuse msg_head for the reply */
	msg_head.opcode  = RX_STATUS; /* reply to RX_READ */
	op = bcm_find_op(ud->rx_ops, msg_head.can_id);
	c  = 'R'; /* for nice debug output ... */

    TRX_READ:

	/* check the given can_id */

	if (!op) {
	    DBG("%cX_READ: did not find op for can_id <%03X>\n",
		c, msg_head.can_id);

	    msg_head.flags   |= CMD_ERROR;
	    msg_head.nframes  = 0;
	    bcm_send_to_user(sk, &msg_head, NULL, NULL);
	}
	else {
	    DBG("%cX_READ: sending status for can_id <%03X>\n",
		c, msg_head.can_id);

	    /* put current values into msg_head */
	    msg_head.flags   = op->flags;
	    msg_head.count   = op->count;
	    msg_head.ival1   = op->ival1;
	    msg_head.ival2   = op->ival2;
	    msg_head.nframes = op->nframes;

	    bcm_send_to_user(sk, &msg_head, op->frames, NULL);
	}

	rbytes = sizeof(struct bcm_msg_head);

	break; /* [T|R]X_READ */

    case TX_SEND:
	{
	    struct sk_buff *skb;
	    struct net_device *dev;
	    
	    /* just copy and send one can_frame */
	    
	    if (msg_head.nframes < 1) /* we need at least one can_frame */
		return -EINVAL;

	    skb = alloc_skb(sizeof(struct can_frame), GFP_KERNEL);

	    if (!skb)
		break;

	    memcpy_fromiovec(skb_put(skb, sizeof(struct can_frame)), msg->msg_iov, sizeof(struct can_frame));

	    DBG_FRAME("BCM: TX_SEND: sending frame", 
		      (struct can_frame *)skb->data);
	    dev = dev_get_by_index(sk->bound_dev_if);

	    if (dev) {
		skb->dev = dev;
		can_send(skb);
		dev_put(dev);
	    }

	    rbytes = sizeof(struct can_frame) + sizeof(struct bcm_msg_head);
	}
	break;

    case RX_SETUP:

	if ((msg_head.flags & RX_FILTER_ID) || (!(msg_head.nframes))) {
	    /* be robust against wrong usage ... */
	    msg_head.flags |= RX_FILTER_ID;
	    msg_head.nframes = 0; /* ignore trailing garbage */
	}

	if ((msg_head.flags & RX_RTR_FRAME) &&
	    ((msg_head.nframes != 1) || (!(msg_head.can_id & CAN_RTR_FLAG)))) {

	    DBG("RX_SETUP: bad RX_RTR_FRAME setup!\n");

	    msg_head.flags   |= CMD_ERROR; /* return msg_head back to sender */
	    msg_head.nframes  = 0;
	    bcm_send_to_user(sk, &msg_head, NULL, NULL);

	    rbytes = sizeof(struct bcm_msg_head);

	    break;
	}

	/* check the given can_id */

	if (!(op = bcm_find_op(ud->rx_ops, msg_head.can_id))) {

	    /* insert new BCM operation for the given can_id */

	    if (!(op = kmalloc(sizeof(struct bcm_op), GFP_KERNEL)))
		return -ENOMEM;

	    memset(op, 0, sizeof(struct bcm_op)); /* init to zero, e.g. for timers */

	    DBG("RX_SETUP: creating new rx_op (%p) for can_id <%03X>\n",
		op, msg_head.can_id);

	    op->can_id    = msg_head.can_id;
	    op->nframes   = msg_head.nframes;

	    if (op->nframes) {

		/* create array for can_frames and copy the data */
		if (!(op->frames = kmalloc(msg_head.nframes * sizeof(struct can_frame), GFP_KERNEL))) {
		    kfree(op);
		    return -ENOMEM;
		}

		for (i = 0; i < msg_head.nframes; i++)
		    memcpy_fromiovec((unsigned char*)&op->frames[i], msg->msg_iov, sizeof(struct can_frame));

		/* create array for received can_frames */
		if (!(op->last_frames = kmalloc(msg_head.nframes * sizeof(struct can_frame), GFP_KERNEL))) {
		    kfree(op->frames);
		    kfree(op);
		    return -ENOMEM;
		}

		/* clear received can_frames to indicate 'nothing received' */
		memset(op->last_frames, 0, msg_head.nframes * sizeof(struct can_frame));
	    }
	    else {
		op->frames = NULL;

		/* even when we have the RX_FILTER_ID case, we need to store the last frame */
		/* for the throttle functionality */

		/* create array for received can_frames */
		if (!(op->last_frames = kmalloc(sizeof(struct can_frame), GFP_KERNEL)))
		    return -ENOMEM;

		/* clear received can_frames to indicate 'nothing received' */
		memset(op->last_frames, 0, sizeof(struct can_frame));
	    }

	    op->sk = sk; /* bcm_delete_rx_op() needs this */

	    init_timer(&op->timer); /* initialize uninitialized (kmalloc) structure */
	    init_timer(&op->thrtimer); /* init throttle timer for RX_CHANGED */

	    op->timer.function = bcm_rx_timeout_handler; /* handler for rx timeouts */
	    op->timer.data = (unsigned long)op; /* timer.data points to this op-structure */

	    op->thrtimer.function = bcm_rx_thr_handler; /* handler for RX_CHANGED throttle timeouts */
	    op->thrtimer.data = (unsigned long)op; /* timer.data points to this op-structure */
 	    op->thrtimer.expires = 0; /* mark disabled timer */

	    /* add this bcm_op to the list of the tx_ops */
	    bcm_insert_op(&ud->rx_ops, op);

	    c=1; /* call can_rx_register() at end of RX_SETUP */

	}
	else {
	    /* update existing BCM operation */

	    DBG("RX_SETUP: modifying existing rx_op (%p) for can_id <%03X>\n",
		op, msg_head.can_id);

	    /* do we need more space for the can_frames? */
	    if (msg_head.nframes > op->nframes) {

		/* yes => create new arrays */

		struct can_frame *p;

		if (!(p = kmalloc(msg_head.nframes * sizeof(struct can_frame), GFP_KERNEL)))
		    return -ENOMEM;

		if (op->frames)
		    kfree (op->frames);
		op->frames = p;

		if (!(p = kmalloc(msg_head.nframes * sizeof(struct can_frame), GFP_KERNEL)))
		    return -ENOMEM;
		if (op->last_frames)
		    kfree (op->last_frames);
		op->last_frames = p;
	    }

	    if (msg_head.nframes) {
		/* update can_frames content */
		for (i = 0; i < msg_head.nframes; i++)
		    memcpy_fromiovec((unsigned char*)&op->frames[i], msg->msg_iov, sizeof(struct can_frame));

		/* clear received can_frames to indicate 'nothing received' */
		memset(op->last_frames, 0, msg_head.nframes * sizeof(struct can_frame));
	    }

	    op->nframes = msg_head.nframes;
	    c=0; /* do not call can_rx_register() at end of RX_SETUP */

	} /* if (!bcm_find_op(ud->tx_ops, msg_head.can_id)) */


	/* check flags */

	op->flags = msg_head.flags;

	if (op->flags & RX_RTR_FRAME) {

	    /* no timers in RTR-mode */
	    del_timer(&op->thrtimer);
	    del_timer(&op->timer);

	    /* funny feature in RX(!)_SETUP only for RTR-mode: */
	    /* copy can_id into frame BUT without RTR-flag to  */
	    /* prevent a full-load-loopback-test ... ;-]       */
	    if ((op->flags & TX_CP_CAN_ID) ||
		(op->frames[0].can_id == op->can_id))
		op->frames[0].can_id = op->can_id & ~CAN_RTR_FLAG;

	}
	else {
	    if (op->flags & SETTIMER) {

		/* set timer value */

		op->ival1   = msg_head.ival1;
		op->j_ival1 = timeval2jiffies(&msg_head.ival1, 1);
		op->ival2   = msg_head.ival2;
		op->j_ival2 = timeval2jiffies(&msg_head.ival2, 1);

		DBG("RX_SETUP: SETTIMER j_ival1=%ld j_ival2=%ld\n",
		    op->j_ival1, op->j_ival2);

		/* disable an active timer due to zero value? */
		if (!op->j_ival1) {
		    del_timer(&op->timer);
		    DBG("RX_SETUP: disabled timer for rx timeouts.\n");
		}

		/* free currently blocked msgs ? */
		if (op->thrtimer.expires) { /* running throttle timer? */
		    DBG("RX_SETUP: unblocking throttled msgs.\n");
		    del_timer(&op->thrtimer);
		    op->thrtimer.expires = jiffies + 2; /* send blocked msgs hereafter */
		    add_timer(&op->thrtimer);
		}
		/* if (op->j_ival2) is zero, no (new) throttling will happen */
		/* see bcm_rx_update_and_send() and bcm_rx_thr_handler()     */
	    }

	    if ((op->flags & STARTTIMER) && op->j_ival1) {

		del_timer(&op->timer);

		op->timer.expires = jiffies + op->j_ival1;

		DBG("RX_SETUP: adding timer ival1. func=%p data=(%p) exp=0x%08X\n",
		    (char *) op->timer.function,
		    (char *) op->timer.data,
		    (unsigned int) op->timer.expires);

		add_timer(&op->timer);
	    }
	}

	/* now we can register for can_ids, if we added a new bcm_op */
	if (c) {
	    struct net_device *dev = dev_get_by_index(sk->bound_dev_if);

	    DBG("RX_SETUP: can_rx_register() for can_id <%03X>. rx_op is (%p)\n", op->can_id, op);

	    if (dev) {
		can_rx_register(dev, op->can_id, 0xFFFFFFFFU, bcm_rx_handler, op, IDENT);
		dev_put(dev);
	    }
	}

	rbytes = msg_head.nframes * sizeof(struct can_frame) + sizeof(struct bcm_msg_head);

	break; /* RX_SETUP */

    case RX_DELETE:

	bcm_delete_rx_op(&ud->rx_ops, msg_head.can_id);

	rbytes = sizeof(struct bcm_msg_head);

	break; /* RX_DELETE */

    default:

	DBG("Unknown opcode %d\n", msg_head.opcode);

	msg_head.flags   |= CMD_ERROR; /* return msg_head back to sender */
	msg_head.nframes  = 0;
	bcm_send_to_user(sk, &msg_head, NULL, NULL);

	rbytes = sizeof(struct bcm_msg_head);

	break;
    }

    return rbytes;
}

static int bcm_recvmsg(struct socket *sock, struct msghdr *msg, int size,
		       int flags, struct scm_cookie *scm)
{
    struct sock *sk = sock->sk;
    struct sk_buff *skb;
    int error = 0;
    int noblock;
    int err;

    DBG("socket %p, sk %p\n", sock, sk);

    noblock =  flags & MSG_DONTWAIT;
    flags   &= ~MSG_DONTWAIT;
    if (!(skb = skb_recv_datagram(sk, flags, noblock, &error))) {
	return error;
    }

    DBG("delivering skbuff %p\n", skb);
    DBG_SKB(skb);

    if (skb->len < size)
	size = skb->len;
    if ((err = memcpy_toiovec(msg->msg_iov, skb->data, size)) < 0) {
	skb_free_datagram(sk, skb);
	return err;
    }

    sock_recv_timestamp(msg, sk, skb);

    DBG("freeing sock %p, skbuff %p\n", sk, skb);
    skb_free_datagram(sk, skb);

    return size;
}

static void bcm_tx_timeout_handler(unsigned long data)
{
    struct bcm_op *op = (struct bcm_op*)data;

    DBG("Called with bcm_op (%p)\n", op);

    if (op->j_ival1 && (op->count > 0)) {

	op->count--;

	if (!op->count && (op->flags & TX_COUNTEVT)) { /* create notification to user? */

	    struct bcm_msg_head msg_head;

	    DBG("sending TX_EXPIRED for can_id <%03X>\n", op->can_id);

	    msg_head.opcode  = TX_EXPIRED;
	    msg_head.flags   = op->flags;
	    msg_head.count   = op->count;
	    msg_head.ival1   = op->ival1;
	    msg_head.ival2   = op->ival2;
	    msg_head.can_id  = op->can_id;
	    msg_head.nframes = 0;

	    bcm_send_to_user(op->sk, &msg_head, NULL, NULL);
	}
    }

    DBG("count=%d j_ival1=%ld j_ival2=%ld\n",
	op->count, op->j_ival1, op->j_ival2);

    if (op->j_ival1 && (op->count > 0)) {

	op->timer.expires = jiffies + op->j_ival1;
	add_timer(&op->timer);

	DBG("adding timer ival1. func=%p data=(%p) exp=0x%08X\n",
	    op->timer.function,
	    (char*) op->timer.data,
	    (unsigned int) op->timer.expires);

	bcm_can_tx(op); /* send (next) frame */
    }
    else {
	if (op->j_ival2) {
	    op->timer.expires = jiffies + op->j_ival2;
	    add_timer(&op->timer);

	DBG("adding timer ival2. func=%p data=(%p) exp=0x%08X\n",
	    op->timer.function,
	    (char*) op->timer.data,
	    (unsigned int) op->timer.expires);

	    bcm_can_tx(op); /* send (next) frame */
	}
	else
	    DBG("no timer restart\n");
    }

    return;

}

static void bcm_rx_handler(struct sk_buff *skb, void *data)
{
    struct bcm_op *op = (struct bcm_op*)data;
    struct can_frame rxframe;
    int i;

    del_timer(&op->timer); /* disable timeout */

    DBG("Called with bcm_op (%p)\n", op);

    if (skb->len == sizeof(rxframe)) {
	memcpy(&rxframe, skb->data, sizeof(rxframe));
	op->stamp = skb->stamp; /* save rx timestamp */
	op->frames_abs++; /* statistics */
	kfree_skb(skb);
	DBG("got can_frame with can_id <%03X>\n", rxframe.can_id);
    }
    else {
	DBG("Wrong skb->len = %d\n", skb->len);
	kfree_skb(skb);
	return;
    }

    DBG_FRAME("BCM: bcm_rx_handler: CAN frame", &rxframe);

    if (op->can_id != rxframe.can_id) {
	DBG("ERROR! Got wrong can_id <%03X>! Expected <%03X>.\n",
	    rxframe.can_id, op->can_id);
	return;
    }

    if (op->flags & RX_RTR_FRAME) { /* send reply for RTR-request */
	DBG("RTR-request\n");
	bcm_can_tx(op); /* send op->frames[0] to CAN device */
	return;
    }

    if (op->flags & RX_FILTER_ID) { /* the easiest case */
	DBG("Easy does it with RX_FILTER_ID\n");
	bcm_rx_update_and_send(op, &op->last_frames[0], &rxframe);
	bcm_rx_starttimer(op);
	return;
    }

    if (op->nframes == 1) { /* simple compare with index 0 */
	DBG("Simple compare\n");
	bcm_rx_cmp_to_index(op, 0, &rxframe);
	bcm_rx_starttimer(op);
	return;
    }

    if (op->nframes > 1) { /* multiplex compare */

	DBG("Multiplex compare\n");
	/* find the first multiplex mask that fits */
	/* MUX-mask is in index 0 */

	for (i=1; i < op->nframes; i++) {

	    if ((GET_U64(&op->frames[0]) & GET_U64(&rxframe)) ==
		(GET_U64(&op->frames[0]) & GET_U64(&op->frames[i]))) {
		DBG("found MUX index %d\n", i);
		bcm_rx_cmp_to_index(op, i, &rxframe);
		break;
	    }
	}
	bcm_rx_starttimer(op);
    }
}

static void bcm_rx_cmp_to_index(struct bcm_op *op, int index,
				struct can_frame *rxdata)
{
    /* no one uses the MSBs of can_dlc for comparation, */
    /* so we use it here to detect the first time of reception */

    if (!(op->last_frames[index].can_dlc & RX_RECV)) { /* first time? */
	DBG("first time :)\n");
	bcm_rx_update_and_send(op, &op->last_frames[index], rxdata);
	return;
    }

    /* do a real check in can_data */

    DBG("op->frames[index].data = 0x%016llx\n", GET_U64(&op->frames[index]));
    DBG("op->last_frames[index].data = 0x%016llx\n",
	GET_U64(&op->last_frames[index]));
    DBG("rxdata->data = 0x%016llx\n", GET_U64(rxdata));

    if ((GET_U64(&op->frames[index]) & GET_U64(rxdata)) !=
	(GET_U64(&op->frames[index]) & GET_U64(&op->last_frames[index]))) {
	DBG("relevant data change :)\n");
	bcm_rx_update_and_send(op, &op->last_frames[index], rxdata);
	return;
    }


    if (op->flags & RX_CHECK_DLC) {

	/* do a real check in dlc */

	if (rxdata->can_dlc != (op->last_frames[index].can_dlc & BCM_CAN_DLC_MASK)) {
	    DBG("dlc change :)\n");
	    bcm_rx_update_and_send(op, &op->last_frames[index], rxdata);
	    return;
	}
    }
    DBG("no relevant change :(\n");
}

static void bcm_rx_update_and_send(struct bcm_op *op,
				   struct can_frame *lastdata,
				   struct can_frame *rxdata)
{
    unsigned long nexttx = op->j_lastmsg + op->j_ival2;

    memcpy(lastdata, rxdata, sizeof(struct can_frame));
    lastdata->can_dlc |= RX_RECV; /* mark as used */

    /* throttle bcm_rx_changed ? */
    if ((op->thrtimer.expires) || /* somebody else is already waiting OR */
	((op->j_ival2) && (nexttx > jiffies))) {      /* we have to wait */

	lastdata->can_dlc |= RX_THR; /* mark as 'throttled' */

	if (!(op->thrtimer.expires)) { /* start only the first time */
	    op->thrtimer.expires = nexttx;
	    add_timer(&op->thrtimer);

	    DBG("adding thrtimer. func=%p data=(%p) exp=0x%08X\n",
		op->thrtimer.function,
		(char*) op->thrtimer.data,
		(unsigned int) op->thrtimer.expires);
	}
    }
    else
	bcm_rx_changed(op, rxdata); /* send RX_CHANGED to the user */
}

static void bcm_rx_starttimer(struct bcm_op *op)
{
    if (op->flags & RX_NO_AUTOTIMER)
	return;

    if (op->j_ival1) {

	op->timer.expires = jiffies + op->j_ival1;

	DBG("adding rx timeout timer ival1. func=%p data=(%p) exp=0x%08X\n",
	    op->timer.function,
	    (char*) op->timer.data,
	    (unsigned int) op->timer.expires);

	add_timer(&op->timer);
    }
}


static void bcm_rx_changed(struct bcm_op *op, struct can_frame *data)
{
    struct bcm_msg_head head;

    op->j_lastmsg = jiffies;
    op->frames_filtered++; /* statistics */

    if (op->frames_filtered > ULONG_MAX/100)
	op->frames_filtered = op->frames_abs = 0; /* restart - spinlock ? */

    DBG("setting j_lastmsg to 0x%08X for rx_op(%p)\n",
	(unsigned int) op->j_lastmsg, op);
    DBG("sending notification\n");

    head.opcode  = RX_CHANGED;
    head.flags   = op->flags;
    head.count   = op->count;
    head.ival1   = op->ival1;
    head.ival2   = op->ival2;
    head.can_id  = op->can_id;
    head.nframes = 1;

    bcm_send_to_user(op->sk, &head, data, &op->stamp);
}


static void bcm_rx_timeout_handler(unsigned long data)
{
    struct bcm_op *op = (struct bcm_op*)data;
    struct bcm_msg_head msg_head;

    DBG("sending RX_TIMEOUT for can_id <%03X>. op is (%p)\n", op->can_id, op);

    msg_head.opcode  = RX_TIMEOUT;
    msg_head.flags   = op->flags;
    msg_head.count   = op->count;
    msg_head.ival1   = op->ival1;
    msg_head.ival2   = op->ival2;
    msg_head.can_id  = op->can_id;
    msg_head.nframes = 0;

    bcm_send_to_user(op->sk, &msg_head, NULL, NULL);

    /* no restart of the timer is done here! */

    /* if the user wants to be informed, when cyclic CAN-Messages come back ... */
    if ((op->flags & RX_ANNOUNCE_RESUME) && op->last_frames) {
	/* clear received can_frames to indicate 'nothing received' */
	memset(op->last_frames, 0, op->nframes * sizeof(struct can_frame));
	DBG("RX_ANNOUNCE_RESTART\n");
    }

}

static void bcm_rx_thr_handler(unsigned long data)
{
    struct bcm_op *op = (struct bcm_op*)data;
    int i = 0;

    op->thrtimer.expires = 0; /* mark disabled / consumed timer */

    if (op->nframes > 1){

	DBG("sending MUX RX_CHANGED for can_id <%03X>. op is (%p)\n",
	    op->can_id, op);
	/* for MUX filter we start at index 1 */
	for (i=1; i<op->nframes; i++){
	    if ((op->last_frames) && (op->last_frames[i].can_dlc & RX_THR)){
		op->last_frames[i].can_dlc &= ~RX_THR;
		bcm_rx_changed(op, &op->last_frames[i]);
	    }
	}
    }
    else{

	DBG("sending simple RX_CHANGED for can_id <%03X>. op is (%p)\n",
	    op->can_id, op);
	/* for RX_FILTER_ID and simple filter */
	if (op->last_frames && (op->last_frames[0].can_dlc & RX_THR)){
	    op->last_frames[0].can_dlc &= ~RX_THR;
	    bcm_rx_changed(op, &op->last_frames[0]);
	}
    }
}

static void bcm_can_tx(struct bcm_op *op)
{
    struct sk_buff *skb;
    struct net_device *dev;
    struct can_frame *cf = &op->frames[op->currframe];

    DBG_FRAME("BCM: bcm_can_tx: sending frame", cf);

    skb = alloc_skb(sizeof(struct can_frame), in_interrupt() ? GFP_ATOMIC : GFP_KERNEL);

    if (!skb)
	return;

    memcpy(skb_put(skb, sizeof(struct can_frame)), cf, sizeof(struct can_frame));

    if (op->sk->bound_dev_if) {
	dev = dev_get_by_index(op->sk->bound_dev_if);

	if (dev) {
	    skb->dev = dev;
	    can_send(skb);
	    dev_put(dev);
	}
    }

    op->currframe++;
    op->frames_abs++; /* statistics */

    /* reached last frame? */
    if (op->currframe >= op->nframes)
	op->currframe = 0;

}

static void bcm_send_to_user(struct sock *sk, struct bcm_msg_head *head,
			     struct can_frame *frames, struct timeval *tv)
{
    struct sk_buff *skb;
    struct can_frame *firstframe;
    int datalen = head->nframes * sizeof(struct can_frame);
    int err;

    if (!sk) {
	DBG("no sk available\n");
	return;
    }

    skb = alloc_skb(sizeof(*head) + datalen, in_interrupt() ? GFP_ATOMIC : GFP_KERNEL);
    memcpy(skb_put(skb, sizeof(*head)), head, sizeof(*head));
    firstframe = (struct can_frame *) skb->tail; /* can_frames starting here */

    if (tv)
	skb->stamp = *tv;

    if (head->nframes){
	memcpy(skb_put(skb, datalen), frames, datalen);

	/* the BCM uses the can_dlc-element of the can_frame structure */
	/* for internal purposes. This is only relevant for updates that */
	/* are generated by the BCM, where nframes is 1                  */
	if (head->nframes == 1)
       	    firstframe->can_dlc &= BCM_CAN_DLC_MASK;
    }
    if ((err = sock_queue_rcv_skb(sk, skb)) < 0) {
	DBG("sock_queue_rcv_skb failed: %d\n", err);
	kfree_skb(skb);
    }
}

static struct bcm_op *bcm_find_op(struct bcm_op *ops, canid_t can_id)
{
    struct bcm_op *p;

    for (p = ops; p; p = p->next)
	if (p->can_id == can_id)
	    return p;

    return NULL;
}

static void bcm_delete_rx_op(struct bcm_op **ops, canid_t can_id)
{
    struct bcm_op *p, **q;

    for (q = ops; p = *q; q = &p->next)
	if (p->can_id == can_id) {
	    *q = p->next;
	    DBG("removing rx_op (%p) for can_id <%03X>\n", p, p->can_id);

	    if (p->sk->bound_dev_if) {
		struct net_device *dev = dev_get_by_index(p->sk->bound_dev_if);
		if (dev) {
		    can_rx_unregister(dev, p->can_id, 0xFFFFFFFFU, bcm_rx_handler, p);
		    dev_put(dev);
		}
	    } else
		DBG("sock %p not bound for can_rx_unregister()\n", p->sk);

	    bcm_remove_op(p);
	    return;
	}
}

static void bcm_delete_tx_op(struct bcm_op **ops, canid_t can_id)
{
    struct bcm_op *p, **q;

    for (q = ops; p = *q; q = &p->next)
	if (p->can_id == can_id) {
	    *q = p->next;
	    DBG("removing rx_op (%p) for can_id <%03X>\n", p, p->can_id);
	    bcm_remove_op(p);
	    return;
	}
}

static void bcm_remove_op(struct bcm_op *op)
{
    del_timer(&op->timer);
    del_timer(&op->thrtimer);
    if (op->frames)
	kfree(op->frames);
    if (op->last_frames)
	kfree(op->last_frames);
    kfree(op);

    return;
}

static void bcm_insert_op(struct bcm_op **ops, struct bcm_op *op)
{
    op->next = *ops;
    *ops = op;
}

module_init(bcm_init);
module_exit(bcm_exit);
