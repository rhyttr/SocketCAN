/*
 * isotp.c - ISO 15765-2 CAN transport protocol for protocol family CAN
 *
 * WARNING: This is ALPHA code for discussions and first tests that should
 *          not be used in production environments.
 *
 * In the discussion the Socket-API to the userspace or the ISO-TP socket
 * options or the return values we may change! Current behaviour:
 *
 * - no ISO-TP specific return values are provided to the userspace
 * - when a transfer (tx) is on the run the next write() blocks until it's done
 * - no support for sending wait frames to the data source in the rx path
 *
 * Copyright (c) 2008 Volkswagen Group Electronic Research
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
#include <linux/version.h>
#include <linux/init.h>
#include <linux/wait.h>
#include <linux/uio.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <socketcan/can.h>
#include <socketcan/can/core.h>
#include <socketcan/can/isotp.h>
#include <net/sock.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#include <net/net_namespace.h>
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#include "compat.h"
#endif

#include <socketcan/can/version.h> /* for RCSID. Removed by mkpatch script */
RCSID("$Id$");

#define CAN_ISOTP_VERSION CAN_VERSION
static __initdata const char banner[] =
	KERN_INFO "can: isotp protocol (rev " CAN_ISOTP_VERSION " alpha)\n";

MODULE_DESCRIPTION("PF_CAN isotp 15765-2 protocol");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Oliver Hartkopp <oliver.hartkopp@volkswagen.de>");
MODULE_ALIAS("can-proto-6");

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
#error This modules needs hrtimers (available since Kernel 2.6.22)
#endif

#define DBG(fmt, args...) (printk( KERN_DEBUG "can-isotp: %s: " fmt, \
				   __func__, ##args))
#undef DBG
#define DBG(fmt, args...) 

#define SINGLE_MASK(id) ((id & CAN_EFF_FLAG) ? \
			 (CAN_EFF_MASK | CAN_EFF_FLAG | CAN_RTR_FLAG) : \
			 (CAN_SFF_MASK | CAN_EFF_FLAG | CAN_RTR_FLAG))

/* N_PCI type values in bits 7-4 of N_PCI bytes */
#define N_PCI_SF 0x00	/* single frame */
#define N_PCI_FF 0x10	/* first frame */
#define N_PCI_CF 0x20	/* consecutive frame */
#define N_PCI_FC 0x30	/* flow control */

/* Flow Status given in FC frame */
#define ISOTP_FC_CTS	0	/* clear to send */
#define ISOTP_FC_WT	1	/* wait */
#define ISOTP_FC_OVFLW	2	/* overflow */

enum {
	ISOTP_IDLE = 0,
	ISOTP_WAIT_FIRST_FC,
	ISOTP_WAIT_FC,
	ISOTP_WAIT_DATA,
	ISOTP_SENDING
};

struct tpcon {
	int idx;
	int len;
	u8  state;
	u8  bs;
	u8  sn;
	u8  buf[4096];
};
 
struct isotp_sock {
	struct sock sk;
	int bound;
	int ifindex;
	canid_t txid;
	canid_t rxid;
	ktime_t tx_gap;
	ktime_t lastrxcf_tstamp;
	struct hrtimer rxtimer, txtimer;
	struct tasklet_struct txtsklet;
	struct can_isotp_options opt;
	struct can_isotp_fc_options rxfc, txfc;
	__u32 force_tx_stmin;
	__u32 force_rx_stmin;
	struct tpcon rx, tx;
	struct notifier_block notifier;
	wait_queue_head_t wait;
};

static inline struct isotp_sock *isotp_sk(const struct sock *sk)
{
	return (struct isotp_sock *)sk;
}

static enum hrtimer_restart isotp_rx_timer_handler(struct hrtimer *hrtimer)
{
	struct isotp_sock *so = container_of(hrtimer, struct isotp_sock,
					     rxtimer);
	if (so->rx.state == ISOTP_WAIT_DATA) {
#if 0
		struct sock *sk = &so->sk;

		/* report 'timeout' */
		sk->sk_err = E?????;
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report(sk);
#endif
		DBG("we did not get new data frames in time.\n");

		/* reset tx state */
		so->rx.state = ISOTP_IDLE;
	}

	return HRTIMER_NORESTART;
}

static int isotp_send_fc(struct sock *sk, int ae)
{
	struct net_device *dev;
	struct sk_buff *nskb;
	struct can_frame *ncf;
	struct isotp_sock *so = isotp_sk(sk);

	nskb = alloc_skb(sizeof(struct can_frame), gfp_any());
	if (!nskb)
		return 1;

	dev = dev_get_by_index(&init_net, so->ifindex);
	if (!dev) {
		kfree_skb(nskb);
		return 1;
	}
	nskb->dev = dev;
	nskb->sk = sk;
	ncf = (struct can_frame *) nskb->data;
	skb_put(nskb, sizeof(struct can_frame));

	/* create & send flow control reply */
	ncf->can_id = so->txid;

	if (so->opt.flags & CAN_ISOTP_RX_PADDING) {
		memset(ncf->data, so->opt.rxpad_content, 8);
		ncf->can_dlc = 8;
	} else
		ncf->can_dlc = ae+3;

	ncf->data[ae] = N_PCI_FC | ISOTP_FC_CTS;
	ncf->data[ae+1] = so->rxfc.bs;
	ncf->data[ae+2] = so->rxfc.stmin;

	if (ae)
		ncf->data[0] = so->opt.ext_address;

	can_send(nskb, 1);
	dev_put(dev);

	/* reset blocksize counter */
	so->rx.bs = 0;

	/* reset last CF frame rx timestamp for rx stmin enforcement */
	so->lastrxcf_tstamp = ktime_set(0,0);

	/* start rx timeout watchdog */
	hrtimer_start(&so->rxtimer, ktime_set(1,0), HRTIMER_MODE_REL);
	return 0;
}

static void isotp_rcv_skb(struct sk_buff *skb, struct sock *sk)
{
	struct sockaddr_can *addr = (struct sockaddr_can *)skb->cb;

	BUILD_BUG_ON(sizeof(skb->cb) < sizeof(struct sockaddr_can));

	skb->sk = sk;

	memset(addr, 0, sizeof(*addr));
	addr->can_family  = AF_CAN;
	addr->can_ifindex = skb->dev->ifindex;

	if (sock_queue_rcv_skb(sk, skb) < 0)
		kfree_skb(skb);
}

static int check_pad(struct isotp_sock *so, struct can_frame *cf,
		     int start_index, __u8 content)
{
	int i;

	/* check datalength code */
	if ((so->opt.flags & CAN_ISOTP_CHK_PAD_LEN) && cf->can_dlc != 8)
			return 1;

	/* check padding content */
	if (so->opt.flags & CAN_ISOTP_CHK_PAD_DATA) {
		for (i = start_index; i < 8; i++)
			if (cf->data[i] != content)
				return 1;
	}
	return 0;
}

static int isotp_rcv_fc(struct isotp_sock *so, struct can_frame *cf, int ae)
{
	if (so->tx.state != ISOTP_WAIT_FC &&
	    so->tx.state != ISOTP_WAIT_FIRST_FC)
		return 0;

	hrtimer_cancel(&so->txtimer);

	if ((so->opt.flags & CAN_ISOTP_TX_PADDING) &&
	    check_pad(so, cf, ae+3, so->opt.txpad_content)) {
		so->tx.state = ISOTP_IDLE;
		wake_up_interruptible(&so->wait);
		return 1;
	}

	/* get communication parameters only from the first FC frame */
	if (so->tx.state == ISOTP_WAIT_FIRST_FC) {

		so->txfc.bs = cf->data[ae+1];
		so->txfc.stmin = cf->data[ae+2];

		/* fix wrong STmin values according spec */
		if ((so->txfc.stmin > 0x7F) && 
		    ((so->txfc.stmin < 0xF1) || (so->txfc.stmin > 0xF9)))
			so->txfc.stmin = 0x7F;

		so->tx_gap = ktime_set(0,0);
		/* add transmission time for CAN frame N_As */
		so->tx_gap = ktime_add_ns(so->tx_gap, so->opt.frame_txtime);
		/* add waiting time for consecutive frames N_Cs */
		if (so->opt.flags & CAN_ISOTP_FORCE_TXSTMIN) 
			so->tx_gap = ktime_add_ns(so->tx_gap,
						  so->force_tx_stmin);
		else if (so->txfc.stmin < 0x80)
			so->tx_gap = ktime_add_ns(so->tx_gap,
						  so->txfc.stmin * 1000000);
		else
			so->tx_gap = ktime_add_ns(so->tx_gap,
						  (so->txfc.stmin - 0xF0)
						  * 100000);
		so->tx.state = ISOTP_WAIT_FC;
	}

	DBG("FC frame: FS %d, BS %d, STmin 0x%02X, tx_gap %lld\n",
	    cf->data[ae] & 0x0F & 0x0F, so->txfc.bs, so->txfc.stmin,
	    (long long)so->tx_gap.tv64);

	switch (cf->data[ae] & 0x0F) {

	case ISOTP_FC_CTS:
		so->tx.bs = 0;
		so->tx.state = ISOTP_SENDING;
		DBG("starting txtimer for sending\n");
		/* start cyclic timer for sending CF frame */
		hrtimer_start(&so->txtimer, so->tx_gap,
			      HRTIMER_MODE_REL);
		break;

	case ISOTP_FC_WT:
		DBG("starting waiting for next FC\n");
		/* start timer to wait for next FC frame */
		hrtimer_start(&so->txtimer, ktime_set(1,0),
			      HRTIMER_MODE_REL);
		break;

	case ISOTP_FC_OVFLW:
		DBG("overflow in receiver side\n");

	default:
		/* stop this tx job. TODO: error reporting? */
		so->tx.state = ISOTP_IDLE;
		wake_up_interruptible(&so->wait);
	}
	return 0;
}

static int isotp_rcv_sf(struct sock *sk, struct can_frame *cf, int ae,
			struct sk_buff *skb)
{
	struct isotp_sock *so = isotp_sk(sk);
	int len = cf->data[ae] & 0x0F;
	struct sk_buff *nskb;

	hrtimer_cancel(&so->rxtimer);
	so->rx.state = ISOTP_IDLE;

	if (!len || len > 7 || (ae && len > 6))
		return 1;

	if ((so->opt.flags & CAN_ISOTP_RX_PADDING) &&
	    check_pad(so, cf, 1+ae+len, so->opt.rxpad_content))
		return 1;

	nskb = alloc_skb(len, gfp_any());
	if (!nskb)
		return 1;

	memcpy(skb_put(nskb, len), &cf->data[1+ae], len);

	nskb->tstamp = skb->tstamp;
	nskb->dev = skb->dev;
	isotp_rcv_skb(nskb, sk);
	return 0;
}

static int isotp_rcv_ff(struct sock *sk, struct can_frame *cf, int ae)
{
	struct isotp_sock *so = isotp_sk(sk);
	int i;

	hrtimer_cancel(&so->rxtimer);
	so->rx.state = ISOTP_IDLE;

	if (cf->can_dlc != 8)
		return 1;

	so->rx.len = (cf->data[ae] & 0x0F) << 8;
	so->rx.len += cf->data[ae+1];

	if (so->rx.len + ae < 8)
		return 1;

	/* copy the first received data bytes */
	so->rx.idx = 0;
	for (i = ae+2; i < 8; i++)
		so->rx.buf[so->rx.idx++] = cf->data[i];

	/* initial setup for this pdu receiption */
	so->rx.sn = 1;
	so->rx.state = ISOTP_WAIT_DATA;

	/* no creation of flow control frames */
	if (so->opt.flags & CAN_ISOTP_LISTEN_MODE)
		return 0;

	/* send our first FC frame */
	isotp_send_fc(sk, ae);
	return 0;
}

static int isotp_rcv_cf(struct sock *sk, struct can_frame *cf, int ae,
			struct sk_buff *skb)
{
	struct isotp_sock *so = isotp_sk(sk);
	struct sk_buff *nskb;
	int i;

	if (so->rx.state != ISOTP_WAIT_DATA)
		return 0;

	/* drop if timestamp gap is less than force_rx_stmin nano secs */
	if (so->opt.flags & CAN_ISOTP_FORCE_RXSTMIN) {

		if (ktime_to_ns(ktime_sub(skb->tstamp, so->lastrxcf_tstamp)) <
		    so->force_rx_stmin)
			return 0;

		so->lastrxcf_tstamp = skb->tstamp; 
	}

	hrtimer_cancel(&so->rxtimer);

	if ((cf->data[ae] & 0x0F) != so->rx.sn) {
		DBG("wrong sn %d. expected %d.\n",
		    cf->data[ae] & 0x0F, so->rx.sn);
		/* some error reporting? */
		so->rx.state = ISOTP_IDLE;
		return 1;
	}
	so->rx.sn++;
	so->rx.sn %= 16;

	for (i = ae+1; i < 8; i++) {
		so->rx.buf[so->rx.idx++] = cf->data[i];
		if (so->rx.idx >= so->rx.len)
			break;
	}

	if (so->rx.idx >= so->rx.len) {

		/* we are done */
		so->rx.state = ISOTP_IDLE;

		if ((so->opt.flags & CAN_ISOTP_RX_PADDING) &&
		    check_pad(so, cf, i+1, so->opt.rxpad_content))
			return 1;

		nskb = alloc_skb(so->rx.len, gfp_any());
		if (!nskb)
			return 1;

		memcpy(skb_put(nskb, so->rx.len), so->rx.buf,
		       so->rx.len);

		nskb->tstamp = skb->tstamp;
		nskb->dev = skb->dev;
		isotp_rcv_skb(nskb, sk);
		return 0;
	}

	/* no creation of flow control frames */
	if (so->opt.flags & CAN_ISOTP_LISTEN_MODE)
		return 0;

	/* perform blocksize handling, if enabled */
	if (!so->rxfc.bs || ++so->rx.bs < so->rxfc.bs) {

		/* start rx timeout watchdog */
		hrtimer_start(&so->rxtimer, ktime_set(1,0),
			      HRTIMER_MODE_REL);
		return 0;
	}

	/* we reached the specified blocksize so->rxfc.bs */
	isotp_send_fc(sk, ae);
	return 0;
}

static void isotp_rcv(struct sk_buff *skb, void *data)
{
	struct sock *sk = (struct sock *)data;
	struct isotp_sock *so = isotp_sk(sk);
	struct can_frame *cf;
	int ae = (so->opt.flags & CAN_ISOTP_EXTEND_ADDR)? 1:0;
	u8 n_pci_type;

	/* read CAN frame and free skbuff */
	BUG_ON(skb->len != sizeof(struct can_frame));
	cf = (struct can_frame *) skb->data;

	/* if enabled: check receiption of my configured extended address */
	if (ae && cf->data[0] != so->opt.ext_address)
		return;

	n_pci_type = cf->data[ae] & 0xF0;

	if (so->opt.flags & CAN_ISOTP_HALF_DUPLEX) {
		/* check rx/tx path half duplex expectations */
		if ((so->tx.state != ISOTP_IDLE && n_pci_type != N_PCI_FC) ||
		    (so->rx.state != ISOTP_IDLE && n_pci_type == N_PCI_FC))
			return;
	}

	switch (n_pci_type) {
	case N_PCI_FC:
		/* tx path: flow control frame containing the FC parameters */
		isotp_rcv_fc(so, cf, ae);
		break;

	case N_PCI_SF:
		/* rx path: single frame */
		isotp_rcv_sf(sk, cf, ae, skb);
		break;

	case N_PCI_FF:
		/* rx path: first frame */
		isotp_rcv_ff(sk, cf, ae);
		break;

	case N_PCI_CF:
		/* rx path: consecutive frame */
		isotp_rcv_cf(sk, cf, ae, skb);
		break;
	}
}

static void isotp_fill_dataframe(struct can_frame *cf, struct isotp_sock *so,
				 int ae)
{
	unsigned char space = 7 - ae;
	int num = min_t(int, so->tx.len - so->tx.idx, space);
	int i;

	cf->can_id = so->txid;

	if (so->opt.flags & CAN_ISOTP_TX_PADDING) {
		if (num < space)
			memset(cf->data, so->opt.txpad_content, 8);

		cf->can_dlc = 8;
	} else
		cf->can_dlc = num + 1 + ae;


	for (i = 0; i < num; i++)
		cf->data[i+ae+1] = so->tx.buf[so->tx.idx++];

	if (ae)
		cf->data[0] = so->opt.ext_address;
}

static void isotp_create_fframe(struct can_frame *cf, struct isotp_sock *so,
				int ae)
{
	int i;

	cf->can_id = so->txid;
	cf->can_dlc = 8;
	if (ae)
		cf->data[0] = so->opt.ext_address;

	/* N_PCI bytes with FF_DL data length */
	cf->data[ae] = (u8) (so->tx.len>>8) | N_PCI_FF;
	cf->data[ae+1] = (u8) so->tx.len & 0xFFU;

	/* add first 5 or 6 data bytes depending on ae */
	for (i = ae+2; i < 8; i++)
		cf->data[i] = so->tx.buf[so->tx.idx++];

	so->tx.sn = 1;
	so->tx.state = ISOTP_WAIT_FIRST_FC;
}

static void isotp_tx_timer_tsklet(unsigned long data)
{
	struct isotp_sock *so = (struct isotp_sock *)data;
	struct sock *sk = &so->sk;
	struct sk_buff *skb;
	struct net_device *dev;
	struct can_frame *cf;
	int ae = (so->opt.flags & CAN_ISOTP_EXTEND_ADDR)? 1:0;

	switch (so->tx.state) {

	case ISOTP_WAIT_FC:
	case ISOTP_WAIT_FIRST_FC:

		/* we did not get any flow control frame in time */

		DBG("we did not get FC frame in time.\n");

#if 0
		/* report 'communication error on send' */
		sk->sk_err = ECOMM;
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report(sk);
#endif
		/* reset tx state */
		so->tx.state = ISOTP_IDLE;
		wake_up_interruptible(&so->wait);
		break;

	case ISOTP_SENDING:

		/* push out the next segmented pdu */

		DBG("next pdu to send.\n");

		dev = dev_get_by_index(&init_net, so->ifindex);
		if (!dev)
			break;

isotp_tx_burst:
		skb = alloc_skb(sizeof(*cf), gfp_any());
		if (!skb) {
			dev_put(dev);
			break;
		}

		cf = (struct can_frame *)skb->data;
		skb_put(skb, sizeof(*cf));

		/* create consecutive frame */
		isotp_fill_dataframe(cf, so, ae);

		/* place consecutive frame N_PCI in appropriate index */
		cf->data[ae] = N_PCI_CF | so->tx.sn++;
		so->tx.sn %= 16;
		so->tx.bs++;

		skb->dev = dev;
		skb->sk  = sk;
		can_send(skb, 1);

		if (so->tx.idx >= so->tx.len) {
			/* we are done */
			DBG("we are done\n");
			so->tx.state = ISOTP_IDLE;
			dev_put(dev);
			wake_up_interruptible(&so->wait);
			break;
		}

		if (so->txfc.bs && so->tx.bs >= so->txfc.bs) {
			/* stop and wait for FC */
			DBG("BS stop and wait for FC\n");
			so->tx.state = ISOTP_WAIT_FC;
			dev_put(dev);
			hrtimer_start(&so->txtimer,
				      ktime_add(ktime_get(), ktime_set(1,0)),
				      HRTIMER_MODE_ABS);
			break;
		} 

		/* no gap between data frames needed => use burst mode */
		if (!so->tx_gap.tv64)
			goto isotp_tx_burst;

		/* start timer to send next data frame with correct delay */
		dev_put(dev);
		hrtimer_start(&so->txtimer,
			      ktime_add(ktime_get(), so->tx_gap),
			      HRTIMER_MODE_ABS);
		break;

	default:
		BUG_ON(1);
	}
}

static enum hrtimer_restart isotp_tx_timer_handler(struct hrtimer *hrtimer)
{
	struct isotp_sock *so = container_of(hrtimer, struct isotp_sock,
					     txtimer);
	tasklet_schedule(&so->txtsklet);

	return HRTIMER_NORESTART;
}

static int isotp_sendmsg(struct kiocb *iocb, struct socket *sock,
		       struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;
	struct isotp_sock *so = isotp_sk(sk);
	struct sk_buff *skb;
	struct net_device *dev;
	struct can_frame *cf;
	int ae = (so->opt.flags & CAN_ISOTP_EXTEND_ADDR)? 1:0;
	int err;

	if (!so->bound)
		return -EADDRNOTAVAIL;

	/* we do not support multiple buffers - for now */
	if (so->tx.state != ISOTP_IDLE) {
		if (msg->msg_flags & MSG_DONTWAIT)
			return -EAGAIN;

		/* wait for complete transmission of current pdu */
		wait_event_interruptible(so->wait, so->tx.state == ISOTP_IDLE);
	}

	if (!size || size > 4095)
		return -EINVAL;

	err = memcpy_fromiovec(so->tx.buf, msg->msg_iov, size);
	if (err < 0)
		return err;

	dev = dev_get_by_index(&init_net, so->ifindex);
	if (!dev)
		return -ENXIO;

	skb = sock_alloc_send_skb(sk, sizeof(*cf),
				  msg->msg_flags & MSG_DONTWAIT, &err);
	if (!skb) {
		dev_put(dev);
		return err;
	}

	so->tx.state = ISOTP_SENDING;
	so->tx.len = size;
	so->tx.idx = 0;

	cf = (struct can_frame *)skb->data;
	skb_put(skb, sizeof(*cf));

	/* check for single frame transmission */
	if (size <= 7 - ae) {

		isotp_fill_dataframe(cf, so, ae);

		/* place single frame N_PCI in appropriate index */
		cf->data[ae] = size | N_PCI_SF;

		so->tx.state = ISOTP_IDLE;
		wake_up_interruptible(&so->wait);
	} else {
		/* send first frame and wait for FC */

		isotp_create_fframe(cf, so, ae);

		DBG("starting txtimer for fc\n");
		/* start timeout for FC */
		hrtimer_start(&so->txtimer, ktime_set(1,0), HRTIMER_MODE_REL);
	}

	/* send the first or only CAN frame */
	skb->dev = dev;
	skb->sk  = sk;
	err = can_send(skb, 1);
	dev_put(dev);
	if (err)
		return err;

	return size;
}

static int isotp_recvmsg(struct kiocb *iocb, struct socket *sock,
			 struct msghdr *msg, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	int err = 0;
	int noblock;

	noblock =  flags & MSG_DONTWAIT;
	flags   &= ~MSG_DONTWAIT;

	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (!skb)
		return err;

	if (size < skb->len)
		msg->msg_flags |= MSG_TRUNC;
	else
		size = skb->len;

	err = memcpy_toiovec(msg->msg_iov, skb->data, size);
	if (err < 0) {
		skb_free_datagram(sk, skb);
		return err;
	}

	sock_recv_timestamp(msg, sk, skb);

	if (msg->msg_name) {
		msg->msg_namelen = sizeof(struct sockaddr_can);
		memcpy(msg->msg_name, skb->cb, msg->msg_namelen);
	}

	skb_free_datagram(sk, skb);

	return size;
}

static int isotp_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct isotp_sock *so = isotp_sk(sk);

	/* wait for complete transmission of current pdu */
	wait_event_interruptible(so->wait, so->tx.state == ISOTP_IDLE);

	unregister_netdevice_notifier(&so->notifier);

	lock_sock(sk);

	hrtimer_cancel(&so->txtimer);
	hrtimer_cancel(&so->rxtimer);
	tasklet_kill(&so->txtsklet);

	/* remove current filters & unregister */
	if (so->bound) {
		if (so->ifindex) {
			struct net_device *dev;

			dev = dev_get_by_index(&init_net, so->ifindex);
			if (dev) {
				can_rx_unregister(dev, so->rxid,
						  SINGLE_MASK(so->rxid),
						  isotp_rcv, sk);
				dev_put(dev);
			}
		}
	}

	so->ifindex = 0;
	so->bound   = 0;

	sock_orphan(sk);
	sock->sk = NULL;

	release_sock(sk);
	sock_put(sk);

	return 0;
}

static int isotp_bind(struct socket *sock, struct sockaddr *uaddr, int len)
{
	struct sockaddr_can *addr = (struct sockaddr_can *)uaddr;
	struct sock *sk = sock->sk;
	struct isotp_sock *so = isotp_sk(sk);
	int ifindex;
	struct net_device *dev;
	int err = 0;
	int notify_enetdown = 0;

	if (len < sizeof(*addr))
		return -EINVAL;

	if (addr->can_addr.tp.rx_id == addr->can_addr.tp.tx_id)
		return -EADDRNOTAVAIL;

	if ((addr->can_addr.tp.rx_id | addr->can_addr.tp.tx_id) &
	    (CAN_ERR_FLAG | CAN_RTR_FLAG))
		return -EADDRNOTAVAIL;

	if (!addr->can_ifindex)
		return -ENODEV;

	lock_sock(sk);

	if (so->bound && addr->can_ifindex == so->ifindex &&
	    addr->can_addr.tp.rx_id == so->rxid &&
	    addr->can_addr.tp.tx_id == so->txid)
		goto out;

	dev = dev_get_by_index(&init_net, addr->can_ifindex);
	if (!dev) {
		err = -ENODEV;
		goto out;
	}
	if (dev->type != ARPHRD_CAN) {
		dev_put(dev);
		err = -ENODEV;
		goto out;
	}
	if (!(dev->flags & IFF_UP))
		notify_enetdown = 1;

	ifindex = dev->ifindex;

	can_rx_register(dev, addr->can_addr.tp.rx_id,
			SINGLE_MASK(addr->can_addr.tp.rx_id),
			isotp_rcv, sk, "isotp");
	dev_put(dev);

	if (so->bound) {
		/* unregister old filter */
		if (so->ifindex) {
			dev = dev_get_by_index(&init_net, so->ifindex);
			if (dev) {
				can_rx_unregister(dev, so->rxid,
						  SINGLE_MASK(so->rxid),
						  isotp_rcv, sk);
				dev_put(dev);
			}
		}
	}

	/* switch to new settings */
	so->ifindex = ifindex;
	so->rxid = addr->can_addr.tp.rx_id;
	so->txid = addr->can_addr.tp.tx_id;
	so->bound = 1;

 out:
	release_sock(sk);

	if (notify_enetdown) {
		sk->sk_err = ENETDOWN;
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report(sk);
	}

	return err;
}

static int isotp_getname(struct socket *sock, struct sockaddr *uaddr,
		       int *len, int peer)
{
	struct sockaddr_can *addr = (struct sockaddr_can *)uaddr;
	struct sock *sk = sock->sk;
	struct isotp_sock *so = isotp_sk(sk);

	if (peer)
		return -EOPNOTSUPP;

	addr->can_family  = AF_CAN;
	addr->can_ifindex = so->ifindex;

	*len = sizeof(*addr);

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
static int isotp_setsockopt(struct socket *sock, int level, int optname,
			    char __user *optval, unsigned int optlen)
#else
static int isotp_setsockopt(struct socket *sock, int level, int optname,
			    char __user *optval, int optlen)
#endif
{
	struct sock *sk = sock->sk;
	struct isotp_sock *so = isotp_sk(sk);
	int ret = 0;

	if (level != SOL_CAN_ISOTP)
		return -EINVAL;
	if (optlen < 0)
		return -EINVAL;

	switch (optname) {

	case CAN_ISOTP_OPTS:
		if (optlen != sizeof(struct can_isotp_options))
			return -EINVAL;

		if (copy_from_user(&so->opt, optval, optlen))
			return -EFAULT;
		break;

	case CAN_ISOTP_RECV_FC:
		if (optlen != sizeof(struct can_isotp_fc_options))
			return -EINVAL;

		if (copy_from_user(&so->rxfc, optval, optlen))
			return -EFAULT;
		break;

	case CAN_ISOTP_TX_STMIN:
		if (optlen != sizeof(__u32))
			return -EINVAL;

		if (copy_from_user(&so->force_tx_stmin, optval, optlen))
			return -EFAULT;
		break;

	case CAN_ISOTP_RX_STMIN:
		if (optlen != sizeof(__u32))
			return -EINVAL;

		if (copy_from_user(&so->force_rx_stmin, optval, optlen))
			return -EFAULT;
		break;

	default:
		ret = -ENOPROTOOPT;
	}

	return ret;
}

static int isotp_getsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	struct isotp_sock *so = isotp_sk(sk);
	int len;
	void *val;

	if (level != SOL_CAN_ISOTP)
		return -EINVAL;
	if (get_user(len, optlen))
		return -EFAULT;
	if (len < 0)
		return -EINVAL;

	switch (optname) {

	case CAN_ISOTP_OPTS:
		len = min_t(int, len, sizeof(struct can_isotp_options));
		val = &so->opt;
		break;

	case CAN_ISOTP_RECV_FC:
		len = min_t(int, len, sizeof(struct can_isotp_fc_options));
		val = &so->rxfc;
		break;

	case CAN_ISOTP_TX_STMIN:
		len = min_t(int, len, sizeof(__u32));
		val = &so->force_tx_stmin;
		break;

	case CAN_ISOTP_RX_STMIN:
		len = min_t(int, len, sizeof(__u32));
		val = &so->force_rx_stmin;
		break;

	default:
		return -ENOPROTOOPT;
	}

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, val, len))
		return -EFAULT;
	return 0;
}


static int isotp_notifier(struct notifier_block *nb,
			unsigned long msg, void *data)
{
	struct net_device *dev = (struct net_device *)data;
	struct isotp_sock *so = container_of(nb, struct isotp_sock, notifier);
	struct sock *sk = &so->sk;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
	if (dev_net(dev) != &init_net)
		return NOTIFY_DONE;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	if (dev->nd_net != &init_net)
		return NOTIFY_DONE;
#endif

	if (dev->type != ARPHRD_CAN)
		return NOTIFY_DONE;

	if (so->ifindex != dev->ifindex)
		return NOTIFY_DONE;

	switch (msg) {

	case NETDEV_UNREGISTER:
		lock_sock(sk);
		/* remove current filters & unregister */
		if (so->bound)
			can_rx_unregister(dev, so->rxid, SINGLE_MASK(so->rxid),
					  isotp_rcv, sk);

		so->ifindex = 0;
		so->bound   = 0;
		release_sock(sk);

		sk->sk_err = ENODEV;
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report(sk);
		break;

	case NETDEV_DOWN:
		sk->sk_err = ENETDOWN;
		if (!sock_flag(sk, SOCK_DEAD))
			sk->sk_error_report(sk);
		break;
	}

	return NOTIFY_DONE;
}


static int isotp_init(struct sock *sk)
{
	struct isotp_sock *so = isotp_sk(sk);

	so->ifindex = 0;
	so->bound   = 0;

	so->opt.flags		= CAN_ISOTP_DEFAULT_FLAGS;
	so->opt.ext_address	= CAN_ISOTP_DEFAULT_EXT_ADDRESS;
	so->opt.rxpad_content	= CAN_ISOTP_DEFAULT_RXPAD_CONTENT;
	so->opt.txpad_content	= CAN_ISOTP_DEFAULT_TXPAD_CONTENT;
	so->opt.frame_txtime	= CAN_ISOTP_DEFAULT_FRAME_TXTIME;
	so->rxfc.bs		= CAN_ISOTP_DEFAULT_RECV_BS;
	so->rxfc.stmin		= CAN_ISOTP_DEFAULT_RECV_STMIN;
	so->rxfc.wftmax		= CAN_ISOTP_DEFAULT_RECV_WFTMAX;

	so->rx.state = ISOTP_IDLE;
	so->tx.state = ISOTP_IDLE;

	hrtimer_init(&so->rxtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	so->rxtimer.function = isotp_rx_timer_handler;
	hrtimer_init(&so->txtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	so->txtimer.function = isotp_tx_timer_handler;

	tasklet_init(&so->txtsklet, isotp_tx_timer_tsklet, (unsigned long)so);

	init_waitqueue_head(&so->wait);

	so->notifier.notifier_call = isotp_notifier;
	register_netdevice_notifier(&so->notifier);

	return 0;
}


static const struct proto_ops isotp_ops = {
	.family        = PF_CAN,
	.release       = isotp_release,
	.bind          = isotp_bind,
	.connect       = sock_no_connect,
	.socketpair    = sock_no_socketpair,
	.accept        = sock_no_accept,
	.getname       = isotp_getname,
	.poll          = datagram_poll,
	.ioctl         = can_ioctl,	/* use can_ioctl() from af_can.c */
	.listen        = sock_no_listen,
	.shutdown      = sock_no_shutdown,
	.setsockopt    = isotp_setsockopt,
	.getsockopt    = isotp_getsockopt,
	.sendmsg       = isotp_sendmsg,
	.recvmsg       = isotp_recvmsg,
	.mmap          = sock_no_mmap,
	.sendpage      = sock_no_sendpage,
};

static struct proto isotp_proto __read_mostly = {
	.name       = "CAN_ISOTP",
	.owner      = THIS_MODULE,
	.obj_size   = sizeof(struct isotp_sock),
	.init       = isotp_init,
};

static struct can_proto isotp_can_proto __read_mostly = {
	.type       = SOCK_DGRAM,
	.protocol   = CAN_ISOTP,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	.capability = -1,
#endif
	.ops        = &isotp_ops,
	.prot       = &isotp_proto,
};

static __init int isotp_module_init(void)
{
	int err;

	printk(banner);

	err = can_proto_register(&isotp_can_proto);
	if (err < 0)
		printk(KERN_ERR "can: registration of isotp protocol failed\n");

	return err;
}

static __exit void isotp_module_exit(void)
{
	can_proto_unregister(&isotp_can_proto);
}

module_init(isotp_module_init);
module_exit(isotp_module_exit);
