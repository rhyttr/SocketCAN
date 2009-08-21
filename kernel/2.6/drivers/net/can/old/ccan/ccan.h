/*
 * drivers/can/c_can.h
 *
 * Copyright (C) 2007
 *
 * - Sascha Hauer, Marc Kleine-Budde, Pengutronix
 * - Simon Kallweit, intefo AG
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the version 2 of the GNU General Public License
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __CCAN_H__
#define __CCAN_H__

#include <socketcan/can.h>
#include <linux/platform_device.h>

#undef CCAN_DEBUG

enum c_regs {
	CAN_CONTROL = 0x00,
	CAN_STATUS  = 0x02,
	CAN_ERROR   = 0x04,
	CAN_BTR     = 0x06,
	CAN_IR      = 0x08,
	CAN_TEST    = 0x0a,
	CAN_BRP_EXT = 0x0c,
	CAN_IF1     = 0x10,
	CAN_IF2     = 0x40,
	CAN_TXRQST  = 0x80, /* 32bit */
	CAN_NEWDAT  = 0x90, /* 32bit */
	CAN_INTPND  = 0xa0, /* 32bit */
	CAN_MSGVAL  = 0xb0, /* 32bit */
};

#define CAN_IF_COMR(x)   (CAN_IF1 + (x) * 0x30 + 0x00)
#define CAN_IF_COMM(x)   (CAN_IF1 + (x) * 0x30 + 0x02)
#define CAN_IF_MASK(x)   (CAN_IF1 + (x) * 0x30 + 0x04)  /* 32bit */
#define CAN_IF_ARB(x)    (CAN_IF1 + (x) * 0x30 + 0x08)  /* 32bit */
#define CAN_IF_MCONT(x)  (CAN_IF1 + (x) * 0x30 + 0x0c)
#define CAN_IF_DATAA(x)  (CAN_IF1 + (x) * 0x30 + 0x0e)  /* 32bit */
#define CAN_IF_DATAB(x)  (CAN_IF1 + (x) * 0x30 + 0x12)  /* 32bit */

#define CONTROL_TEST (1<<7)
#define CONTROL_CCE  (1<<6)
#define CONTROL_DAR  (1<<5)
#define CONTROL_EIE  (1<<3)
#define CONTROL_SIE  (1<<2)
#define CONTROL_IE   (1<<1)
#define CONTROL_INIT (1<<0)

#define TEST_RX     (1<<7)
#define TEST_TX1    (1<<6)
#define TEST_TX2    (1<<5)
#define TEST_LBACK  (1<<4)
#define TEST_SILENT (1<<3)
#define TEST_BASIC  (1<<2)

#define STATUS_BOFF     (1<<7)
#define STATUS_EWARN    (1<<6)
#define STATUS_EPASS    (1<<5)
#define STATUS_RXOK     (1<<4)
#define STATUS_TXOK     (1<<3)
#define STATUS_LEC_MASK (1<<2)
#define LEC_STUFF_ERROR 1
#define LEC_FORM_ERROR  2
#define LEC_ACK_ERROR   3
#define LEC_BIT1_ERROR  4

#define BTR_BRP_MASK	0x3f
#define BTR_BRP_SHIFT	0
#define BTR_SJW_SHIFT	6
#define BTR_SJW_MASK	(0x3 << BTR_SJW_SHIFT)
#define BTR_TSEG1_SHIFT	8
#define BTR_TSEG1_MASK	(0xf << BTR_TSEG1_SHIFT)
#define BTR_TSEG2_SHIFT	12
#define BTR_TSEG2_MASK	(0x7 << BTR_TSEG2_SHIFT)

#define IF_COMR_BUSY (1<<15)

#define IF_COMM_WR          (1<<7)
#define IF_COMM_MASK        (1<<6)
#define IF_COMM_ARB         (1<<5)
#define IF_COMM_CONTROL     (1<<4)
#define IF_COMM_CLR_INT_PND (1<<3)
#define IF_COMM_TXRQST      (1<<2)
#define IF_COMM_DATAA       (1<<1)
#define IF_COMM_DATAB       (1<<0)

#define IF_COMM_ALL (IF_COMM_MASK | IF_COMM_ARB | IF_COMM_CONTROL | \
		     IF_COMM_TXRQST | IF_COMM_DATAA | IF_COMM_DATAB)

#define IF_ARB_MSGVAL   (1<<31)
#define IF_ARB_MSGXTD   (1<<30)
#define IF_ARB_TRANSMIT (1<<29)

#define IF_MCONT_NEWDAT (1<<15)
#define IF_MCONT_MSGLST (1<<14)
#define IF_MCONT_INTPND (1<<13)
#define IF_MCONT_UMASK  (1<<12)
#define IF_MCONT_TXIE   (1<<11)
#define IF_MCONT_RXIE   (1<<10)
#define IF_MCONT_RMTEN  (1<<9)
#define IF_MCONT_TXRQST (1<<8)
#define IF_MCONT_EOB    (1<<7)

#define MAX_OBJECT 31
#define MAX_TRANSMIT_OBJECT 15
#define RECEIVE_OBJECT_BITS 0xffff0000

struct ccan_priv {
	struct can_priv can;
	struct net_device *dev;
	int tx_object;
	int last_status;
	struct delayed_work work;
	u16 (*read_reg)(struct net_device *dev, enum c_regs reg);
	void (*write_reg)(struct net_device *dev, enum c_regs reg, u16 val);
#ifdef CCAN_DEBUG
	unsigned int bufstat[MAX_OBJECT + 1];
#endif
};

extern struct net_device *alloc_ccandev(int sizeof_priv);
extern void free_ccandev(struct net_device *dev);
extern int register_ccandev(struct net_device *dev);
extern void unregister_ccandev(struct net_device *dev);

#endif /* __CCAN_H__ */
