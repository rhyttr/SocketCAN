/*
 * can_core.h
 *
 * Protoypes and definitions for CAN protocol modules using the PF_CAN core
 *
 * Copyright (c) 2002-2007 Volkswagen Group Electronic Research
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

#ifndef CAN_CORE_H
#define CAN_CORE_H

#include "version.h"
RCSID("$Id$");

#include <linux/skbuff.h>
#include <linux/netdevice.h>

#include "can.h"

#define DNAME(dev) ((dev) ? (dev)->name : "any")

#define CAN_PROC_DIR "net/can" /* /proc/... */

struct can_proto {
	int              type;
	int              protocol;
	int              capability;
	struct proto_ops *ops;
	int              (*init)(struct sock *sk);
	size_t           obj_size;
};

/* function prototypes for the CAN networklayer core (af_can.c) */

void can_proto_register(struct can_proto *cp);
void can_proto_unregister(struct can_proto *cp);
int  can_rx_register(struct net_device *dev, canid_t can_id, canid_t mask,
		     void (*func)(struct sk_buff *, void *), void *data,
		     char *ident);
int  can_rx_unregister(struct net_device *dev, canid_t can_id, canid_t mask,
		       void (*func)(struct sk_buff *, void *), void *data);
void can_dev_register(struct net_device *dev,
		      void (*func)(unsigned long msg, void *), void *data);
void can_dev_unregister(struct net_device *dev,
			void (*func)(unsigned long msg, void *), void *data);
int  can_send(struct sk_buff *skb, int loop);

unsigned long timeval2jiffies(struct timeval *tv, int round_up);

#endif /* CAN_CORE_H */
