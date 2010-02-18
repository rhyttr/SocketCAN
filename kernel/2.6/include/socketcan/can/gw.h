/*
 * socketcan/can/gw.h
 *
 * Definitions for CAN frame Gateway/Router/Bridge 
 *
 * $Id$
 *
 * Author: Oliver Hartkopp <oliver.hartkopp@volkswagen.de>
 * Copyright (c) 2002-2010 Volkswagen Group Electronic Research
 * All rights reserved.
 *
 * Send feedback to <socketcan-users@lists.berlios.de>
 *
 */

#ifndef CAN_GW_H
#define CAN_GW_H

#include <socketcan/can.h>

struct rtcanmsg {
	__u8  can_family;
	__u8  can_txflags;
	__u16 pad;
	__u32 src_ifindex;
	__u32 dst_ifindex;
};

#define CAN_GW_TXFLAGS_LOOPBACK 0x01

/* CAN rtnetlink attribute definitions */
enum {
	CGW_UNSPEC,
	CGW_FILTER,	/* specify struct can_filter on source CAN device */
	CGW_MOD_AND,	/* CAN frame modification binary AND */
	CGW_MOD_OR,	/* CAN frame modification binary OR */
	CGW_MOD_XOR,	/* CAN frame modification binary XOR */
	CGW_MOD_SET,	/* CAN frame modification set alternate values */
	__CGW_MAX
};

#define CGW_MAX (__CGW_MAX - 1)

#define CGW_MOD_FUNCS 4 /* AND OR XOR SET */

/* CAN frame elements that are affected by curr. 3 CAN frame modifications */
#define CGW_MOD_ID	0x01
#define CGW_MOD_DLC	0x02
#define CGW_MOD_DATA	0x04

#define CGW_FRAME_MODS 3 /* ID DLC DATA */

#define MAX_MODFUNCTIONS (CGW_MOD_FUNCS * CGW_FRAME_MODS)

#define CGW_MODATTR_LEN (sizeof(struct can_frame) + 1)

/*
 * CAN rtnetlink attribute contents in detail
 *
 * CGW_FILTER (length 32 bytes):
 * Sets a CAN receive filter for the gateway job specified by the
 * struct can_filter described in include/linux/can.h
 *
 * CGW_MOD_XXX (length 17 bytes):
 * Specifies a modification that's done to a received CAN frame before it is
 * send out to the destination interface.
 *
 * <u8> affected CAN frame elements
 * <struct can_frame> data used as operator
 *
 * Remark: The attribute data is a linear buffer. Beware of sending structs!
 */

#endif
