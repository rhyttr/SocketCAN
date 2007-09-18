/*
 * $Id$
 *
 * i82527.h -  Intel I82527 network device driver
 *
 * Copyright (c) 2002-2007 Volkswagen Group Electronic Research
 * All rights reserved.
 *
 * Original version Written by Arnaud Westenberg email:arnaud@wanadoo.nl
 * This software is released under the GPL-License.
 *
 * Major Refactoring and Integration into can4linux version 3.1 by
 * Henrik W Maier of FOCUS Software Engineering Pty Ltd <www.focus-sw.com>
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

#ifndef I82527_H
#define I82527_H

#define I82527_IO_SIZE 0x100

#define CHIP_NAME	"i82527"

#define DRV_NAME_LEN	30 /* for "<chip_name>-<hal_name>" */

#define PROCBASE          "driver" /* /proc/ ... */

#define DEFAULT_HW_CLK	16000000
#define DEFAULT_SPEED	500 /* kBit/s */
#define DEFAULT_FORCE_DMC 0 /* for critical register access, e.g. ser1274 */

#define IRQ_MODE_SHARED 1 /* enable shared interrupts */
#define IRQ_MODE_DISABLE_LOCAL_IRQS 2 /* when processing the irq handler */
#define DEFAULT_IRQ_MODE IRQ_MODE_SHARED

/* The message object 15 has a shadow register for reliable data receiption  */
/* under heavy bus load. Therefore it makes sense to use this message object */
/* (mo15) for the needed use case. The frame type (EFF/SFF) for the mo15 can */
/* be defined on the module command line. The default is 11 bit SFF format.  */

#define MO15_NONE 0
#define MO15_SFF  1
#define MO15_EFF  2

#define MO15_DEFLT MO15_SFF /* the default */

#define CAN_NETDEV_NAME	"can%d"

#define TX_TIMEOUT      (50*HZ/1000) /* 50ms */ 
#define RESTART_MS      100  /* restart chip on persistent errors in 100ms */
#define MAX_BUS_ERRORS  200  /* prevent from flooding bus error interrupts */

/* bus timing */
#define MAX_TSEG1	15
#define MAX_TSEG2	 7
#define SAMPLE_POINT	62
#define JUMPWIDTH     0x40

typedef struct canmessage {
	uint8_t	msgCtrl0Reg;	
	uint8_t	msgCtrl1Reg;	
	uint8_t	idReg[4];
	uint8_t	messageConfigReg;
	uint8_t	dataReg[8];	
} canmessage_t; // __attribute__ ((packed));

typedef struct canregs {
  union
  {
    struct
    {
      canmessage_t messageReg;
      uint8_t someOtherReg; // padding
    } msgArr[16];
    struct
    {
      uint8_t      controlReg;               // Control Register
      uint8_t      statusReg;                // Status Register
      uint8_t      cpuInterfaceReg;          // CPU Interface Register
      uint8_t      reserved1Reg;
      uint8_t      highSpeedReadReg[2];      // High Speed Read
      uint8_t      globalMaskStandardReg[2]; // Standard Global Mask byte 0
      uint8_t      globalMaskExtendedReg[4]; // Extended Global Mask bytes
      uint8_t      message15MaskReg[4];      // Message 15 Mask bytes
      canmessage_t message1Reg;
      uint8_t      clkOutReg;                // Clock Out Register
      canmessage_t message2Reg;
      uint8_t      busConfigReg;             // Bus Configuration Register
      canmessage_t message3Reg;
      uint8_t      bitTiming0Reg;            // Bit Timing Register byte 0
      canmessage_t message4Reg;
      uint8_t      bitTiming1Reg;            // Bit Timing Register byte 1
      canmessage_t message5Reg;
      uint8_t      interruptReg;             // Interrupt Register
      canmessage_t message6Reg;
      uint8_t      reserved2Reg;
      canmessage_t message7Reg;
      uint8_t      reserved3Reg;
      canmessage_t message8Reg;
      uint8_t      reserved4Reg;
      canmessage_t message9Reg;
      uint8_t      p1ConfReg;
      canmessage_t message10Reg;
      uint8_t      p2ConfReg;
      canmessage_t message11Reg;
      uint8_t      p1InReg;
      canmessage_t message12Reg;
      uint8_t      p2InReg;
      canmessage_t message13Reg;
      uint8_t      p1OutReg;
      canmessage_t message14Reg;
      uint8_t      p2OutReg;
      canmessage_t message15Reg;
      uint8_t      serialResetAddressReg;
    };
  };
} canregs_t; // __attribute__ ((packed));

/* Control Register (0x00) */
enum i82527_iCTL {
	iCTL_INI = 1,		// Initialization
	iCTL_IE  = 1<<1,	// Interrupt Enable
	iCTL_SIE = 1<<2,	// Status Interrupt Enable
	iCTL_EIE = 1<<3,	// Error Interrupt Enable
	iCTL_CCE = 1<<6		// Change Configuration Enable
};

/* Status Register (0x01) */
enum i82527_iSTAT {
	iSTAT_TXOK = 1<<3,	// Transmit Message Successfully
	iSTAT_RXOK = 1<<4,	// Receive Message Successfully
	iSTAT_WAKE = 1<<5,	// Wake Up Status
	iSTAT_WARN = 1<<6,	// Warning Status
	iSTAT_BOFF = 1<<7	// Bus Off Status
};

/* CPU Interface Register (0x02) */
enum i82527_iCPU {
	iCPU_CEN = 1,		// Clock Out Enable
	iCPU_MUX = 1<<2,	// Multiplex
	iCPU_SLP = 1<<3,	// Sleep
	iCPU_PWD = 1<<4,	// Power Down Mode
	iCPU_DMC = 1<<5,	// Divide Memory Clock
	iCPU_DSC = 1<<6,	// Divide System Clock
	iCPU_RST = 1<<7,	// Hardware Reset Status
};

/* Clock Out Register (0x1f) */
enum i82527_iCLK {
	iCLK_CD0 = 1,		// Clock Divider bit 0
	iCLK_CD1 = 1<<1,
	iCLK_CD2 = 1<<2,
	iCLK_CD3 = 1<<3,
	iCLK_SL0 = 1<<4,	// Slew Rate bit 0
	iCLK_SL1 = 1<<5
};

/* Bus Configuration Register (0x2f) */
enum i82527_iBUS {
	iBUS_DR0 = 1,		// Disconnect RX0 Input
	iBUS_DR1 = 1<<1,	// Disconnect RX1 Input
	iBUS_DT1 = 1<<3,	// Disconnect TX1 Output
	iBUS_POL = 1<<5,	// Polarity
	iBUS_CBY = 1<<6		// Comparator Bypass
};

#define RESET 1			// Bit Pair Reset Status
#define SET 2			// Bit Pair Set Status
#define UNCHANGED 3		// Bit Pair Unchanged

/* Message Control Register 0 (Base Address + 0x0) */
enum i82527_iMSGCTL0 {
	INTPD_SET = SET,		// Interrupt pending
	INTPD_RES = RESET,		// No Interrupt pending
	INTPD_UNC = UNCHANGED,
	RXIE_SET  = SET<<2,		// Receive Interrupt Enable
	RXIE_RES  = RESET<<2,		// Receive Interrupt Disable
	RXIE_UNC  = UNCHANGED<<2,
	TXIE_SET  = SET<<4,		// Transmit Interrupt Enable
	TXIE_RES  = RESET<<4,		// Transmit Interrupt Disable
	TXIE_UNC  = UNCHANGED<<4,
	MVAL_SET  = SET<<6,		// Message Valid
	MVAL_RES  = RESET<<6,		// Message Invalid
	MVAL_UNC  = UNCHANGED<<6
};

/* Message Control Register 1 (Base Address + 0x01) */
enum i82527_iMSGCTL1 {
	NEWD_SET = SET,			// New Data
	NEWD_RES = RESET,		// No New Data
	NEWD_UNC = UNCHANGED,
	MLST_SET = SET<<2,		// Message Lost
	MLST_RES = RESET<<2,		// No Message Lost
	MLST_UNC = UNCHANGED<<2,
	CPUU_SET = SET<<2,		// CPU Updating
	CPUU_RES = RESET<<2,		// No CPU Updating
	CPUU_UNC = UNCHANGED<<2,
	TXRQ_SET = SET<<4,		// Transmission Request
	TXRQ_RES = RESET<<4,		// No Transmission Request
	TXRQ_UNC = UNCHANGED<<4,
	RMPD_SET = SET<<6,		// Remote Request Pending
	RMPD_RES = RESET<<6,		// No Remote Request Pending
	RMPD_UNC = UNCHANGED<<6
};

/* Message Configuration Register (Base Address + 0x06) */
enum i82527_iMSGCFG {
	MCFG_XTD = 1<<2,		// Extended Identifier
	MCFG_DIR = 1<<3			// Direction is Transmit
};

#undef IOPRINT
#undef IODEBUG

#ifdef IOPRINT
#define CANout(base,adr,v) \
	printk("CANout: (%lx+%x)=%x\n", base,\
					(int)(long)&((canregs_t *)0)->adr,v)

#define CANin(base,adr) \
	printk("CANin: (%lx+%x)\n", base, (int)(long)&((canregs_t *)0)->adr)

#else /* IOPRINT */

#ifdef IODEBUG
#define CANout(base,adr,v)      \
	(printk("CANout: (%lx+%x)=%x\n", base,\
		(int)(long)&((canregs_t *)0)->adr,v),\
		hw_writereg(base, (int)(long)&((canregs_t *)0)->adr, v))
#else
#define CANout(base,adr,v) hw_writereg(base,\
					(int)(long)&((canregs_t *)0)->adr, v)
#endif

#define CANin(base,adr)	hw_readreg(base, (int)(long)&((canregs_t *)0)->adr)

#endif /* IOPRINT */

/* CAN private data structure */

struct can_priv {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	struct net_device_stats	stats;
#endif
	struct can_device_stats	can_stats;
	long			open_time;
	int			clock;
	int			hw_regs;
	int			restart_ms;
	int			debug;
	int			speed;
	int			btr;
	int			rx_probe;
	int			mo15;
	struct timer_list       timer;
	int			state;
};

#define STATE_UNINITIALIZED	0
#define STATE_PROBE		1
#define STATE_ACTIVE		2
#define STATE_ERROR_ACTIVE	3
#define STATE_ERROR_PASSIVE	4
#define STATE_BUS_OFF		5
#define STATE_RESET_MODE	6

void can_proc_create(const char *drv_name);
void can_proc_remove(const char *drv_name);

#endif /* I82527_H */
