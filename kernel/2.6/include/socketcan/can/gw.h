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
	__u8  gwtype;
	__u16 flags;
};

/* CAN gateway types */
enum {
	CGW_TYPE_UNSPEC,
	CGW_TYPE_CAN_CAN,	/* CAN->CAN routing */
	__CGW_TYPE_MAX
};

#define CGW_TYPE_MAX (__CGW_TYPE_MAX - 1)

/* CAN rtnetlink attribute definitions */
enum {
	CGW_UNSPEC,
	CGW_MOD_AND,	/* CAN frame modification binary AND */
	CGW_MOD_OR,	/* CAN frame modification binary OR */
	CGW_MOD_XOR,	/* CAN frame modification binary XOR */
	CGW_MOD_SET,	/* CAN frame modification set alternate values */
	CGW_CS_XOR,	/* set data[] XOR checksum into data[index] */
	CGW_CS_CRC8,	/* set data[] CRC8 checksum into data[index] */
	CGW_HANDLED,	/* number of handled CAN frames */
	CGW_DROPPED,	/* number of dropped CAN frames */
	CGW_SRC_IF,	/* ifindex of source network interface */
	CGW_DST_IF,	/* ifindex of destination network interface */
	CGW_FILTER,	/* specify struct can_filter on source CAN device */
	__CGW_MAX
};

#define CGW_MAX (__CGW_MAX - 1)

#define CGW_FLAGS_CAN_ECHO 0x01
#define CGW_FLAGS_CAN_SRC_TSTAMP 0x02

#define CGW_MOD_FUNCS 4 /* AND OR XOR SET */

/* CAN frame elements that are affected by curr. 3 CAN frame modifications */
#define CGW_MOD_ID	0x01
#define CGW_MOD_DLC	0x02
#define CGW_MOD_DATA	0x04

#define CGW_FRAME_MODS 3 /* ID DLC DATA */

#define MAX_MODFUNCTIONS (CGW_MOD_FUNCS * CGW_FRAME_MODS)

struct cgw_frame_mod {
	struct can_frame cf;
	__u8 modtype;
} __attribute__((packed));

#define CGW_MODATTR_LEN sizeof(struct cgw_frame_mod)

struct cgw_csum_xor {
	__s8 from_idx;
	__s8 to_idx;
	__s8 result_idx;
	__u8 prefix_value;
} __attribute__ ((packed));

struct cgw_csum_crc8 {
	__s8 from_idx;
	__s8 to_idx;
	__s8 result_idx;
	__u8 crctab[256];
} __attribute__ ((packed));

/* length of checksum operation parameters. idx = index in CAN frame data[] */
#define CGW_CS_XOR_LEN  sizeof(struct cgw_csum_xor)
#define CGW_CS_CRC8_LEN  sizeof(struct cgw_csum_crc8)

/*
 * CAN rtnetlink attribute contents in detail
 *
 * CGW_XXX_IF (length 4 bytes):
 * Sets an interface index for source/destination network interfaces.
 * For the CAN->CAN gwtype the indices of _two_ CAN interfaces are mandatory.
 *
 * CGW_FILTER (length 8 bytes):
 * Sets a CAN receive filter for the gateway job specified by the
 * struct can_filter described in include/linux/can.h
 *
 * CGW_MOD_XXX (length 17 bytes):
 * Specifies a modification that's done to a received CAN frame before it is
 * send out to the destination interface.
 *
 * <struct can_frame> data used as operator
 * <u8> affected CAN frame elements
 *
 * CGW_CS_XOR (length 4 bytes):
 * Set a simple XOR checksum starting with the initial prefix-value into
 * data[result-idx] using data[start-idx] .. data[end-idx]
 *
 * CGW_CS_CRC8 (length 259 bytes):
 * Set a CRC8 value into data[result-idx] using a given 256 byte CRC8 table and
 * a defined input data[start-idx] .. data[end-idx]
 *
 * Remark: The attribute data is a linear buffer. Beware of sending structs!
 */

#endif
