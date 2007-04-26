/*
 * linux/can.h
 *
 * Definitions for CAN networklayer (socket addr / CAN frame / CAN filter)
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

#ifndef CAN_H
#define CAN_H

#include <linux/version.h>
#include <linux/types.h>
#include <linux/socket.h>

/* controller area network (CAN) kernel definitions */

/* special address description flags for the CAN_ID */
#define CAN_EFF_FLAG 0x80000000U /* EFF/SFF is set in the MSB */
#define CAN_RTR_FLAG 0x40000000U /* remote transmission request */
#define CAN_ERR_FLAG 0x20000000U /* error frame */

/* valid bits in CAN ID for frame formats */
#define CAN_SFF_MASK 0x000007FFU /* standard frame format (SFF) */
#define CAN_EFF_MASK 0x1FFFFFFFU /* extended frame format (EFF) */
#define CAN_ERR_MASK 0x1FFFFFFFU /* omit EFF, RTR, ERR flags */

typedef __u32 canid_t;

/**
 * struct can_frame - basic CAN frame structure
 * @can_id:  the CAN ID of the frame and CAN_*_FLAG flags, see above.
 * @can_dlc: the data length field of the CAN frame
 * @data:    the CAN frame payload.
 */
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

/**
 * struct sockaddr_can - the sockaddr structure for CAN sockets
 * @can_family:  address family number AF_CAN.
 * @can_ifindex: CAN network interface index.
 * @can_addr:    transport protocol specific address, mostly CAN IDs.
 */
struct sockaddr_can {
	sa_family_t can_family;
	int         can_ifindex;
	union {
		struct { canid_t rx_id, tx_id; } tp16;
		struct { canid_t rx_id, tx_id; } tp20;
		struct { canid_t rx_id, tx_id; } mcnet;
		struct { canid_t rx_id, tx_id; } isotp;
		struct { int     lcu,   type;  } bap;
	} can_addr;
};

typedef canid_t can_err_mask_t;

/**
 * struct can_filter - CAN ID based filter in can_register().
 * @can_id:   relevant bits of CAN ID which are not masked out.
 * @can_mask: CAN mask (see description)
 *
 * Description:
 * A filter matches, when
 *
 *          <received_can_id> & mask == can_id & mask
 *
 * The filter can be inverted (CAN_INV_FILTER bit set in can_id) or it can
 * filter for error frames (CAN_ERR_FLAG bit set in mask).
 */
struct can_filter {
	canid_t can_id;
	canid_t can_mask;
};

#define CAN_INV_FILTER 0x20000000U /* to be set in can_filter.can_id */

#endif /* CAN_H */
