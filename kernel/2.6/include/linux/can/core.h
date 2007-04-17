/*
 * linux/can/core.h
 *
 * Protoypes and definitions for CAN protocol modules using the PF_CAN core
 *
 * $Id$
 *
 * Authors: Oliver Hartkopp <oliver.hartkopp@volkswagen.de>
 *          Urs Thuermann   <urs.thuermann@volkswagen.de>
 * Copyright (c) 2002-2007 Volkswagen Group Electronic Research
 * All rights reserved.
 *
 * Send feedback to <socketcan-users@lists.berlios.de>
 *
 */

#ifndef CAN_CORE_H
#define CAN_CORE_H

#include <linux/can.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

#define DNAME(dev) ((dev) ? (dev)->name : "any")

#define CAN_PROC_DIR "net/can" /* /proc/... */

/**
 * struct can_proto - CAN protocol structure
 * @type:       type argument in socket() syscall, e.g. SOCK_DGRAM.
 * @protocol:   protocol number in socket() syscall.
 * @capability: capability needed to open the socket, or -1 for no restriction.
 * @ops:        pointer to struct proto_ops for sock->ops.
 * @prot:       pointer to struct proto structure.
 */

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

/* function prototypes for the CAN networklayer core (af_can.c) */

void can_debug_skb(struct sk_buff *skb);
void can_debug_cframe(const char *msg, struct can_frame *cframe, ...);

int can_proto_register(struct can_proto *cp);
int can_proto_unregister(struct can_proto *cp);

int can_rx_register(struct net_device *dev, canid_t can_id, canid_t mask,
		    void (*func)(struct sk_buff *, void *), void *data,
		    char *ident);
int can_rx_unregister(struct net_device *dev, canid_t can_id, canid_t mask,
		      void (*func)(struct sk_buff *, void *), void *data);

int can_dev_register(struct net_device *dev,
		     void (*func)(unsigned long msg, void *), void *data);
int can_dev_unregister(struct net_device *dev,
		       void (*func)(unsigned long msg, void *), void *data);

int can_send(struct sk_buff *skb, int loop);

unsigned long timeval2jiffies(struct timeval *tv, int round_up);

#endif /* CAN_CORE_H */
