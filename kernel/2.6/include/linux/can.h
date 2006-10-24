/*
 * $Id$
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

#ifndef CAN_H
#define CAN_H

#include <linux/version.h>
#include <linux/types.h>

#include <linux/can/error.h>
#include <linux/can/ioctl.h>

/* controller area network (CAN) kernel definitions */

/* CAN socket protocol family definition */
#define PF_CAN		29	/* to be moved to include/linux/socket.h */
#define AF_CAN		PF_CAN

/* ethernet protocol identifier */
#define ETH_P_CAN	0x000C	/* to be moved to include/linux/if_ether.h */

/* ARP protocol identifier (dummy type for non ARP hardware) */
#define ARPHRD_CAN	804	/* to be moved to include/linux/if_arp.h */




/* special address description flags for the CAN_ID */
#define CAN_EFF_FLAG 0x80000000U /* EFF/SFF is set in the MSB */
#define CAN_RTR_FLAG 0x40000000U /* remote transmission request */
#define CAN_ERR_FLAG 0x20000000U /* error frame */

/* valid bits in CAN ID for frame formats */
#define CAN_SFF_MASK 0x000007FFU /* standard frame format (SFF) */
#define CAN_EFF_MASK 0x1FFFFFFFU /* extended frame format (EFF) */

typedef __u32 canid_t;

struct can_frame {
	canid_t can_id;  /* 32 bit CAN_ID + EFF/RTR/ERR flags */
	__u8    can_dlc; /* data length code: 0 .. 8 */
	__u8    data[8] __attribute__ ((aligned(8)));
};



/* particular protocols of the protocol family PF_CAN */
#define CAN_RAW		1 /* RAW sockets */
#define CAN_BCM		2 /* Broadcast Manager */
#define CAN_TP16	3 /* VAG Transport Protocol v1.6 */
#define CAN_TP20	4 /* VAG Transport Protocol v2.0 */
#define CAN_MCNET	5 /* Bosch MCNet */
#define CAN_ISOTP	6 /* ISO 15765-2 Transport Protocol */
#define CAN_BAP		7 /* VAG Bedien- und Anzeigeprotokoll */
#define CAN_NPROTO	8

#define SOL_CAN_BASE 100

struct sockaddr_can {
	sa_family_t   can_family;
	int           can_ifindex;
	union {
		struct { canid_t rx_id, tx_id; } tp16;
		struct { canid_t rx_id, tx_id; } tp20;
		struct { canid_t rx_id, tx_id; } mcnet;
	} can_addr;
};

typedef canid_t can_err_mask_t;

struct can_filter {
	canid_t can_id;
	canid_t can_mask;
};

#define CAN_INV_FILTER 0x20000000U /* to be set in can_filter.can_id */



#ifdef __KERNEL__

#define CAN_PROC_DIR "net/can" /* /proc/... */

struct can_proto {
	int              type;
	int              protocol;
	int              capability;
	struct proto_ops *ops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,13)
	struct proto     *prot;
#else
	struct module    *owner;
	int              (*init)(struct sock *sk);
	size_t           obj_size;
#endif
};

void can_proto_register(struct can_proto *cp);
void can_proto_unregister(struct can_proto *cp);
void can_rx_register(struct net_device *dev, canid_t can_id, canid_t mask,
		     void (*func)(struct sk_buff *, void *), void *data,
		     char *ident);
void can_rx_unregister(struct net_device *dev, canid_t can_id, canid_t mask,
		       void (*func)(struct sk_buff *, void *), void *data);
void can_dev_register(struct net_device *dev,
		      void (*func)(unsigned long msg, void *), void *data);
void can_dev_unregister(struct net_device *dev,
			void (*func)(unsigned long msg, void *), void *data);
int  can_send(struct sk_buff *skb, int loop);

unsigned long timeval2jiffies(struct timeval *tv, int round_up);

#endif


#endif /* CAN_H */
