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
 * Send feedback to <llcf@volkswagen.de>
 *
 */

#ifndef AF_CAN_H
#define AF_CAN_H

#ifdef __KERNEL__
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/if.h>
#else
#include <net/if.h>
#endif

#include <linux/can/can.h>

/* CAN socket protocol family definition */
/* to be moved to include/linux/socket.h */
#define PF_CAN		29	/* Controller Area Network      */
#define AF_CAN		PF_CAN

/* particular protocols of the protocol family PF_CAN */
#define CAN_RAW		1 /* RAW sockets */
#define CAN_BCM		2 /* Broadcast Manager */
#define CAN_TP16	3 /* VAG Transport Protocol v1.6 */
#define CAN_TP20	4 /* VAG Transport Protocol v2.0 */
#define CAN_MCNET	5 /* Bosch MCNet */
#define CAN_ISOTP	6 /* ISO 15765-2 Transport Protocol */
#define CAN_BAP		7 /* VAG Bedien- und Anzeigeprotokoll */
#define CAN_MAX		8

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

#define CAN_PROC_DIR "sys/net/can" /* /proc/... */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,13)
struct can_proto {
    struct proto_ops *ops;
    struct proto     *prot;
};
#else
struct can_proto {
    struct proto_ops *ops;
    struct module    *owner;
    size_t           obj_size;
};
#endif

void can_proto_register(int proto, struct can_proto *cp);
void can_proto_unregister(int proto);
void can_rx_register(struct net_device *dev, canid_t can_id, canid_t mask,
	void (*func)(struct sk_buff *, void *), void *data, char *ident);
void can_rx_unregister(struct net_device *dev, canid_t can_id, canid_t mask,
	void (*func)(struct sk_buff *, void *), void *data);
void can_dev_register(struct net_device *dev,
	void (*func)(unsigned long msg, void *), void *data);
void can_dev_unregister(struct net_device *dev,
	void (*func)(unsigned long msg, void *), void *data);
int  can_send(struct sk_buff *skb);

unsigned long timeval2jiffies(struct timeval *tv, int round_up);

void can_debug_skb(struct sk_buff *skb);
void can_debug_cframe(const char *msg, struct can_frame *cframe, ...);

/* af_can rx dispatcher structures */

struct rcv_list {
    struct rcv_list *next;
    canid_t can_id;
    canid_t mask;
    unsigned long matches;
    void (*func)(struct sk_buff *, void *);
    void *data;
    char *ident;
};

struct rcv_dev_list {
    struct rcv_dev_list *next;
    struct net_device *dev;
    struct rcv_list *rx_err;
    struct rcv_list *rx_all;
    struct rcv_list *rx_fil;
    struct rcv_list *rx_inv;
    struct rcv_list *rx_sff[0x800];
    struct rcv_list *rx_eff;
    int entries;
};

/* statistic structures */

struct s_stats {
    unsigned long jiffies_init;

    unsigned long rx_frames;
    unsigned long tx_frames;
    unsigned long matches;

    unsigned long total_rx_rate;
    unsigned long total_tx_rate;
    unsigned long total_rx_match_ratio;

    unsigned long current_rx_rate;
    unsigned long current_tx_rate;
    unsigned long current_rx_match_ratio;

    unsigned long max_rx_rate;
    unsigned long max_tx_rate;
    unsigned long max_rx_match_ratio;

    unsigned long rx_frames_delta;
    unsigned long tx_frames_delta;
    unsigned long matches_delta;
}; /* can be reset e.g. by can_init_stats() */

struct s_pstats {
    unsigned long stats_reset;
    unsigned long rcv_entries;
    unsigned long rcv_entries_max;
}; /* persistent statistics */

void can_init_proc(void);
void can_remove_proc(void);

#endif

#endif /* AF_CAN_H */
