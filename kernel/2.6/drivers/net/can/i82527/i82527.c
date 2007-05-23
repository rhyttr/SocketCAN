/*
 * i82527.c -  Intel I82527 network device driver
 *
 * Copyright (c) 2002-2007 Volkswagen Group Electronic Research
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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/skbuff.h>

#include <linux/can.h>
#include <linux/can/ioctl.h> /* for struct can_device_stats */
#include "hal.h"
#include "i82527.h"

#include <linux/can/version.h> /* for RCSID. Removed by mkpatch script */
RCSID("$Id$");

MODULE_AUTHOR("Oliver Hartkopp <oliver.hartkopp@volkswagen.de>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("LLCF/socketcan '" CHIP_NAME "' network device driver");

#ifdef CONFIG_CAN_DEBUG_DEVICES
#define DBG(args...)   ((priv->debug > 0) ? printk(args) : 0)
/* logging in interrupt context! */
#define iDBG(args...)  ((priv->debug > 1) ? printk(args) : 0)
#define iiDBG(args...) ((priv->debug > 2) ? printk(args) : 0)
#else
#define DBG(args...)
#define iDBG(args...)
#define iiDBG(args...)
#endif

char drv_name[DRV_NAME_LEN] = "undefined";

/* driver and version information */
static const char *drv_version	= "0.0.3";
static const char *drv_reldate	= "2007-04-11";

static const canid_t rxobjflags[] = {0, CAN_EFF_FLAG,
				     CAN_RTR_FLAG, CAN_RTR_FLAG | CAN_EFF_FLAG,
				     0, CAN_EFF_FLAG}; 
#define RXOBJBASE 10

/* array of all can chips */
struct net_device *can_dev[MAXDEV];

/* module parameters */
unsigned long base[MAXDEV]	= { 0 }; /* hardware address */
unsigned long rbase[MAXDEV]	= { 0 }; /* (remapped) device address */
unsigned int  irq[MAXDEV]	= { 0 };

unsigned int speed[MAXDEV]	= { DEFAULT_SPEED, DEFAULT_SPEED };
unsigned int btr[MAXDEV]	= { 0 };
unsigned int bcr[MAXDEV]	= { 0 }; /* bus configuration register */
unsigned int cdv[MAXDEV]	= { 0 }; /* CLKOUT clock divider */
unsigned int mo15[MAXDEV]	= { MO15_DEFLT, MO15_DEFLT }; /* msg obj 15 */

static int rx_probe[MAXDEV]	= { 0 };
static int clk			= DEFAULT_HW_CLK;
static int force_dmc		= DEFAULT_FORCE_DMC;
static int debug		= 0;
static int restart_ms		= 100;

static int base_n;
static int irq_n;
static int speed_n;
static int btr_n;
static int bcr_n;
static int cdv_n;
static int mo15_n;
static int rx_probe_n;

static u8 dsc = 0; /* devide system clock */
static u8 dmc = 0; /* devide memory clock */

module_param_array(base, int, &base_n, 0);
module_param_array(irq, int, &irq_n, 0);
module_param_array(speed, int, &speed_n, 0);
module_param_array(btr, int, &btr_n, 0);
module_param_array(bcr, int, &bcr_n, 0);
module_param_array(cdv, int, &cdv_n, 0);
module_param_array(mo15, int, &mo15_n, 0);
module_param_array(rx_probe, int, &rx_probe_n, 0);

module_param(clk, int, 0);
module_param(force_dmc, int, 0);
module_param(debug, int, 0);
module_param(restart_ms, int, 0);

MODULE_PARM_DESC(base, "CAN controller base address");
MODULE_PARM_DESC(irq, "CAN controller interrupt");
MODULE_PARM_DESC(speed, "CAN bus bitrate");
MODULE_PARM_DESC(btr, "Bit Timing Register value 0x<btr0><btr1>, e.g. 0x4014");
MODULE_PARM_DESC(bcr, "i82527 bus configuration register value (default: 0)");
MODULE_PARM_DESC(cdv, "clockout devider value (0-14) (default: 0)");
MODULE_PARM_DESC(mo15, "rx message object 15 usage. 0:none 1:sff(default) 2:eff");
MODULE_PARM_DESC(rx_probe, "switch to trx mode after correct msg receiption. (default off)");

MODULE_PARM_DESC(clk, "CAN controller chip clock (default: 16MHz)");
MODULE_PARM_DESC(force_dmc, "set i82527 DMC bit (default: calculate from clk)"); 
MODULE_PARM_DESC(debug, "set debug mask (default: 0)");
MODULE_PARM_DESC(restart_ms, "restart chip on heavy bus errors / bus off after x ms (default 100ms)");

/* function declarations */

static void chipset_init(struct net_device *dev, int wake);
static void chipset_init_rx(struct net_device *dev);
static void chipset_init_trx(struct net_device *dev);
static void can_netdev_setup(struct net_device *dev);
static struct net_device* can_create_netdev(int dev_num, int hw_regs);
static int  can_set_drv_name(void);
int set_reset_mode(struct net_device *dev);

static int i82527_probe_chip(unsigned long base)
{
	// Check if hardware reset is still inactive OR
	// maybe there is no chip in this address space
	if (CANin(base, cpuInterfaceReg) & iCPU_RST) {
		printk(KERN_INFO "%s: probing @ 0x%lX failed (reset)\n",
		       drv_name, base);
		return 0;
	}

	// Write test pattern
	CANout(base, message1Reg.dataReg[1], 0x25);
	CANout(base, message2Reg.dataReg[3], 0x52);
	CANout(base, message10Reg.dataReg[6], 0xc3);

	// Read back test pattern
	if ((CANin(base, message1Reg.dataReg[1]) != 0x25 ) ||
	    (CANin(base, message2Reg.dataReg[3]) != 0x52 ) ||
	    (CANin(base, message10Reg.dataReg[6]) != 0xc3 )) {
		printk(KERN_INFO "%s: probing @ 0x%lX failed (pattern)\n",
		       drv_name, base);
		return 0;
	}

	return 1;
}

/*
 * set baud rate divisor values
 */
static void set_btr(struct net_device *dev, int btr0, int btr1)
{
	struct can_priv *priv = netdev_priv(dev);
	unsigned long base = dev->base_addr;

	/* no bla bla when restarting the device */
	if (priv->state == STATE_UNINITIALIZED)
		printk(KERN_INFO "%s: setting BTR0=%02X BTR1=%02X\n",
		       dev->name, btr0, btr1);

	CANout(base, bitTiming0Reg, btr0);
	CANout(base, bitTiming1Reg, btr1);
}

/*
 * calculate baud rate divisor values
 */
static void set_baud(struct net_device *dev, int baud, int clock)
{
	struct can_priv *priv = netdev_priv(dev);

	int error;
	int brp;
	int tseg;
	int tseg1 = 0;
	int tseg2 = 0;

	int best_error = 1000000000;
	int best_tseg = 0;
	int best_brp = 0;
	int best_baud = 0;

	int SAM = (baud > 100000 ? 0 : 1);

	if (dsc) /* devide system clock */
		clock >>= 1; /* calculate BTR with this value */

	for (tseg = (0 + 0 + 2) * 2;
	     tseg <= (MAX_TSEG2 + MAX_TSEG1 + 2) * 2 + 1;
	     tseg++) {
		brp = clock / ((1 + tseg / 2) * baud) + tseg % 2;
		if ((brp > 0) && (brp <= 64)) {
			error = baud - clock / (brp * (1 + tseg / 2));
			if (error < 0) {
				error = -error;
			}
			if (error <= best_error) {
				best_error = error;
				best_tseg = tseg / 2;
				best_brp = brp - 1;
				best_baud = clock / (brp * (1 + tseg / 2));
			}
		}
	}
	if (best_error && (baud / best_error < 10)) {
		printk("%s: unable to set baud rate %d (ext clock %dHz)\n",
		       dev->name, baud, clock * 2);
		return;
//		return -EINVAL;
	}
	tseg2 = best_tseg - (SAMPLE_POINT * (best_tseg + 1)) / 100;
	if (tseg2 < 0) {
		tseg2 = 0;
	} else if (tseg2 > MAX_TSEG2) {
		tseg2 = MAX_TSEG2;
	}
	tseg1 = best_tseg - tseg2 - 2;
	if (tseg1 > MAX_TSEG1) {
		tseg1 = MAX_TSEG1;
		tseg2 = best_tseg - tseg1 - 2;
	}

	priv->btr = ((best_brp | JUMPWIDTH)<<8) + 
		((SAM << 7) | (tseg2 << 4) | tseg1);

	printk(KERN_INFO "%s: calculated best baudrate: %d / btr is 0x%04X\n",
	       dev->name, best_baud, priv->btr);

	set_btr(dev, (priv->btr>>8) & 0xFF, priv->btr & 0xFF);
//	set_btr(dev, best_brp | JUMPWIDTH, (SAM << 7) | (tseg2 << 4) | tseg1);
}

static inline int obj2rxo(int obj)
{
	/* obj4 = obj15 SFF, obj5 = obj15 EFF */ 
	if (obj < 4)
		return RXOBJBASE + obj;
	else
		return 15;
}

void enable_rx_obj(unsigned long base, int obj)
{
	u8 mcfg = 0;
	int rxo = obj2rxo(obj);

	// Configure message object for receiption
	if (rxobjflags[obj] & CAN_EFF_FLAG)
		mcfg = MCFG_XTD;

	if (rxobjflags[obj] & CAN_RTR_FLAG) {
		CANout(base, msgArr[rxo].messageReg.messageConfigReg,
		       mcfg | MCFG_DIR);
		CANout(base, msgArr[rxo].messageReg.msgCtrl0Reg,
		       MVAL_SET | TXIE_RES | RXIE_SET | INTPD_RES);
		CANout(base, msgArr[rxo].messageReg.msgCtrl1Reg,
		       NEWD_RES | CPUU_SET | TXRQ_RES | RMPD_RES);
	} else {
		CANout(base, msgArr[rxo].messageReg.messageConfigReg, mcfg);
		CANout(base, msgArr[rxo].messageReg.msgCtrl0Reg,
		       MVAL_SET | TXIE_RES | RXIE_SET | INTPD_RES);
		CANout(base, msgArr[rxo].messageReg.msgCtrl1Reg,
		       NEWD_RES | MLST_RES | TXRQ_RES | RMPD_RES);
	}
}

void disable_rx_obj(unsigned long base, int obj)
{
	int rxo = obj2rxo(obj);

	CANout(base, msgArr[rxo].messageReg.msgCtrl1Reg,
	       NEWD_RES | MLST_RES | TXRQ_RES | RMPD_RES);
	CANout(base, msgArr[rxo].messageReg.msgCtrl0Reg,
	       MVAL_RES | TXIE_RES | RXIE_RES | INTPD_RES);
}

int set_reset_mode(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);
	unsigned long base = dev->base_addr;

	// Configure cpu interface
	CANout(base, cpuInterfaceReg,(dsc | dmc | iCPU_CEN));

	// Enable configuration and puts chip in bus-off, disable interrupts
	CANout(base, controlReg, iCTL_CCE | iCTL_INI);

	// Clear interrupts
	CANin(base, interruptReg);

	// Clear status register
	CANout(base, statusReg, 0);

	// Clear message objects for receiption
	if (priv->mo15 == MO15_SFF)
		disable_rx_obj(base, 4); /* rx via obj15 SFF */
	else
		disable_rx_obj(base, 0); /* rx via obj10 SFF */

	if (priv->mo15 == MO15_EFF)
		disable_rx_obj(base, 5); /* rx via obj15 EFF */
	else
		disable_rx_obj(base, 1); /* rx via obj11 EFF */

	disable_rx_obj(base, 2);
	disable_rx_obj(base, 3);

	// Clear message object for send
	CANout(base, message1Reg.msgCtrl1Reg,
	       RMPD_RES | TXRQ_RES | CPUU_RES | NEWD_RES);
	CANout(base, message1Reg.msgCtrl0Reg,
	       MVAL_RES | TXIE_RES | RXIE_RES | INTPD_RES);

	DBG(KERN_INFO "%s: %s: CtrlReg 0x%x CPUifReg 0x%x\n",
	    dev->name, __FUNCTION__,
	    CANin(base, controlReg), CANin(base, cpuInterfaceReg));

	return 0;
}

static int set_normal_mode(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);
	unsigned long base = dev->base_addr;

	// Clear interrupts
	CANin(base, interruptReg);

	// Clear status register
	CANout(base, statusReg, 0);

	// Configure message objects for receiption
	if (priv->mo15 == MO15_SFF) {
		enable_rx_obj(base, 4); /* rx via obj15 SFF */
		printk(KERN_INFO "%s: %s: using msg object 15 for "
		       "SFF receiption.\n",
		       dev->name, CHIP_NAME);
	} else
		enable_rx_obj(base, 0); /* rx via obj10 SFF */

	if (priv->mo15 == MO15_EFF) {
		enable_rx_obj(base, 5); /* rx via obj15 EFF */
		printk(KERN_INFO "%s: %s: using msg object 15 for "
		       "EFF receiption.\n",
		       dev->name, CHIP_NAME);
	} else
		enable_rx_obj(base, 1); /* rx via obj11 EFF */

	enable_rx_obj(base, 2);
	enable_rx_obj(base, 3);

	// Clear message object for send
	CANout(base, message1Reg.msgCtrl1Reg,
	       RMPD_RES | TXRQ_RES | CPUU_RES | NEWD_RES);
	CANout(base, message1Reg.msgCtrl0Reg,
	       MVAL_RES | TXIE_RES | RXIE_RES | INTPD_RES);

	return 0;
}

static int set_listen_mode(struct net_device *dev)
{
	return set_normal_mode(dev); /* for now */
}

/*
 * Clear and invalidate message objects
 */
int i82527_clear_msg_objects(unsigned long base)
{
    int i;
    int id;
    int data;

    for (i = 1; i <= 15; i++) {
	    CANout(base, msgArr[i].messageReg.msgCtrl0Reg,
		   INTPD_UNC | RXIE_RES | TXIE_RES | MVAL_RES);
	    CANout(base, msgArr[i].messageReg.msgCtrl0Reg,
		   INTPD_RES | RXIE_RES | TXIE_RES | MVAL_RES);
	    CANout(base, msgArr[i].messageReg.msgCtrl1Reg,
		   NEWD_RES | MLST_RES | TXRQ_RES | RMPD_RES);
	    for (data = 0; data < 8; data++)
		    CANout(base, msgArr[i].messageReg.dataReg[data], 0);
	    for (id = 0; id < 4; id++)
		    CANout(base, msgArr[i].messageReg.idReg[id], 0);
	    CANout(base, msgArr[i].messageReg.messageConfigReg, 0);
    }

    return 0;
}

/*
 * initialize I82527 chip:
 *   - reset chip
 *   - set output mode
 *   - set baudrate
 *   - enable interrupts
 *   - start operating mode
 */
static void chipset_init_regs(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);
	unsigned long base = dev->base_addr;

	// Enable configuration and puts chip in bus-off, disable interrupts
	CANout(base, controlReg, (iCTL_CCE | iCTL_INI));

	// Set CLKOUT devider and slew rates is was done in i82527_init_module

	// Bus configuration was done in i82527_init_module

	// Clear interrupts
	CANin(base, interruptReg);

	// Clear status register
	CANout(base, statusReg, 0);

	i82527_clear_msg_objects(base);

	// Set all global ID masks to "don't care"
	CANout(base, globalMaskStandardReg[0], 0);	
	CANout(base, globalMaskStandardReg[1], 0);
	CANout(base, globalMaskExtendedReg[0], 0);
	CANout(base, globalMaskExtendedReg[1], 0);
	CANout(base, globalMaskExtendedReg[2], 0);
	CANout(base, globalMaskExtendedReg[3], 0);

	DBG(KERN_INFO "%s: %s: CtrlReg 0x%x CPUifReg 0x%x\n",
	    dev->name, __FUNCTION__,
	    CANin(base, controlReg), CANin(base, cpuInterfaceReg));

	// Note: At this stage the CAN ship is still in bus-off condition
	// and must be started using StartChip()

	/* set baudrate */
	if (priv->btr) { /* no calculation when btr is provided */
		set_btr(dev, (priv->btr>>8) & 0xFF, priv->btr & 0xFF);
	} else {
		if (priv->speed == 0) {
			priv->speed = DEFAULT_SPEED;
		}
		set_baud(dev, priv->speed * 1000, priv->clock);
	}

}

static void chipset_init(struct net_device *dev, int wake)
{
	struct can_priv *priv = netdev_priv(dev);

	if (priv->rx_probe)
		chipset_init_rx(dev); /* wait for valid reception first */
	else
		chipset_init_trx(dev);

	if ((wake) && netif_queue_stopped(dev))
		netif_wake_queue(dev);
}

static void chipset_init_rx(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);
	unsigned long base    = dev->base_addr;

	iDBG(KERN_INFO "%s: %s()\n", dev->name, __FUNCTION__);

	/* set chip into reset mode */
	set_reset_mode(dev);

	/* set registers */
	chipset_init_regs(dev);

	/* automatic bit rate detection */
	set_listen_mode(dev);

	priv->state = STATE_PROBE;

	// Clear bus-off, Interrupts only for errors, not for status change
	CANout(base, controlReg, iCTL_IE | iCTL_EIE);

	DBG(KERN_INFO "%s: %s: CtrlReg 0x%x CPUifReg 0x%x\n",
	    dev->name, __FUNCTION__,
	    CANin(base, controlReg), CANin(base, cpuInterfaceReg));
}

static void chipset_init_trx(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);
	unsigned long base    = dev->base_addr;

	iDBG(KERN_INFO "%s: %s()\n", dev->name, __FUNCTION__);

	/* set chip into reset mode */
	set_reset_mode(dev);

	/* set registers */
	chipset_init_regs(dev);

	/* leave reset mode */
	set_normal_mode(dev);

	priv->state = STATE_ACTIVE;

	// Clear bus-off, Interrupts only for errors, not for status change
	CANout(base, controlReg, iCTL_IE | iCTL_EIE);

	DBG(KERN_INFO "%s: %s: CtrlReg 0x%x CPUifReg 0x%x\n",
	    dev->name, __FUNCTION__,
	    CANin(base, controlReg), CANin(base, cpuInterfaceReg));
}

/*
 * transmit a CAN message
 * message layout in the sk_buff should be like this:
 * xx xx xx xx  ll   00 11 22 33 44 55 66 77
 * [  can-id ] [len] [can data (up to 8 bytes]
 */
static int can_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct can_priv  *priv	= netdev_priv(dev);
	struct can_frame *cf	= (struct can_frame*)skb->data;
	unsigned long base	= dev->base_addr;
	uint8_t	dlc;
	uint8_t	rtr;
	canid_t	id;
	int	i;

	if ((CANin(base, message1Reg.msgCtrl1Reg) & TXRQ_UNC) == TXRQ_SET) {
		printk(KERN_ERR "%s: %s: TX register is occupied!\n",
		       dev->name, drv_name);
		return 0;
	}

	netif_stop_queue(dev);

	dlc = cf->can_dlc;
	id  = cf->can_id;

	if ( cf->can_id & CAN_RTR_FLAG )
		rtr = 0;
	else
		rtr = MCFG_DIR;

	CANout(base, message1Reg.msgCtrl1Reg,
	       RMPD_RES | TXRQ_RES | CPUU_SET | NEWD_RES);
	CANout(base, message1Reg.msgCtrl0Reg,
	       MVAL_SET | TXIE_SET | RXIE_RES | INTPD_RES);

	if (id & CAN_EFF_FLAG) {
		id &= CAN_EFF_MASK;
		CANout(base, message1Reg.messageConfigReg,
		       (dlc << 4) + rtr + MCFG_XTD);
		CANout(base, message1Reg.idReg[3], (id << 3) & 0xFFU);
		CANout(base, message1Reg.idReg[2], (id >> 5) & 0xFFU);
		CANout(base, message1Reg.idReg[1], (id >> 13) & 0xFFU);
		CANout(base, message1Reg.idReg[0], (id >> 21) & 0xFFU);
	}
	else {
		id &= CAN_SFF_MASK;
		CANout(base, message1Reg.messageConfigReg,
		       ( dlc << 4 ) + rtr);
		CANout(base, message1Reg.idReg[0], (id >> 3) & 0xFFU);
		CANout(base, message1Reg.idReg[1], (id << 5) & 0xFFU);
	}

	dlc &= 0x0f; //restore length only
	for ( i=0; i < dlc; i++ ) {
		CANout(base, message1Reg.dataReg[i],
		       cf->data[i]);
	}

	CANout(base, message1Reg.msgCtrl1Reg,
	       (RMPD_RES | TXRQ_SET | CPUU_RES | NEWD_UNC));

	// HM: We had some cases of repeated IRQs
	// so make sure the INT is acknowledged
	// I know it's already further up, but doing again fixed the issue
	CANout(base, message1Reg.msgCtrl0Reg,
	       (MVAL_UNC | TXIE_UNC | RXIE_UNC | INTPD_RES));

	priv->stats.tx_bytes += dlc;

	dev->trans_start = jiffies;

	kfree_skb(skb);

	return 0;
}

static void can_tx_timeout(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);

	priv->stats.tx_errors++;

	/* do not conflict with e.g. bus error handling */
	if (!(priv->timer.expires)){ /* no restart on the run */
		chipset_init_trx(dev); /* no tx queue wakeup */
		netif_wake_queue(dev); /* wakeup here */
	}
	else
		DBG(KERN_INFO "%s: %s: can_restart_dev already active.\n",
		    dev->name, __FUNCTION__ );

}

# if 0
static void can_restart_on(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);

	if (!(priv->timer.expires)){ /* no restart on the run */

		set_reset_mode(dev);

		priv->timer.function = can_restart_dev;
		priv->timer.data = (unsigned long) dev;

		/* restart chip on persistent error in <xxx> ms */
		priv->timer.expires = jiffies + (priv->restart_ms * HZ) / 1000;
		add_timer(&priv->timer);

		iDBG(KERN_INFO "%s: %s start (%ld)\n",
		     dev->name, __FUNCTION__ , jiffies);
	} else
		iDBG(KERN_INFO "%s: %s already (%ld)\n",
		     dev->name, __FUNCTION__ , jiffies);
}

static void can_restart_dev(unsigned long data)
{
	struct net_device *dev = (struct net_device*) data;
	struct can_priv *priv = netdev_priv(dev);

	DBG(KERN_INFO "%s: can_restart_dev (%ld)\n",
	    dev->name, jiffies);

	/* mark inactive timer */
	priv->timer.expires = 0;

	if (priv->state != STATE_UNINITIALIZED) {

		/* count number of restarts */
		priv->can_stats.restarts++;

		chipset_init(dev, 1);
	}
}
#endif

#if 0
/* the timerless version */

static void can_restart_now(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);

	if (priv->state != STATE_UNINITIALIZED) {

		/* count number of restarts */
		priv->can_stats.restarts++;

		chipset_init(dev, 1);
	}
}
#endif

/*
 * Subroutine of ISR for RX interrupts.
 *
 */
static void can_rx(struct net_device *dev, int obj)
{
	struct can_priv *priv	= netdev_priv(dev);
	unsigned long base	= dev->base_addr;
	struct can_frame *cf;
	struct sk_buff	*skb;
	uint8_t msgctlreg;
	uint8_t ctl1reg;
	canid_t	id;
	uint8_t	dlc;
	int	i;
	int	rxo = obj2rxo(obj);

	skb = dev_alloc_skb(sizeof(struct can_frame));
	if (skb == NULL) {
		return;
	}
	skb->dev = dev;
	skb->protocol = htons(ETH_P_CAN);

	ctl1reg = CANin(base, msgArr[rxo].messageReg.msgCtrl1Reg);
	msgctlreg = CANin(base, msgArr[rxo].messageReg.messageConfigReg);

	if( msgctlreg & MCFG_XTD ) {
		id = CANin(base, msgArr[rxo].messageReg.idReg[3])
			| (CANin(base, msgArr[rxo].messageReg.idReg[2]) << 8)
			| (CANin(base, msgArr[rxo].messageReg.idReg[1]) << 16)
			| (CANin(base, msgArr[rxo].messageReg.idReg[0]) << 24);
		id >>= 3;
		id |= CAN_EFF_FLAG;
	} else {
		id = CANin(base, msgArr[rxo].messageReg.idReg[1])
			|(CANin(base, msgArr[rxo].messageReg.idReg[0]) << 8);
		id >>= 5;
	}

	if (ctl1reg & RMPD_SET) {
		id |= CAN_RTR_FLAG;
	}

	msgctlreg  &= 0xf0;/* strip length code */
	dlc  = msgctlreg >> 4;
	dlc %= 9;	/* limit count to 8 bytes */

	cf = (struct can_frame*)skb_put(skb, sizeof(struct can_frame));
	memset(cf, 0, sizeof(struct can_frame));
	cf->can_id    = id;
	cf->can_dlc   = dlc;
	for (i = 0; i < dlc; i++) {
		cf->data[i] = CANin(base, msgArr[rxo].messageReg.dataReg[i]);
	}

	// Make the chip ready to receive the next message
	enable_rx_obj(base, obj);

	netif_rx(skb);

	dev->last_rx = jiffies;
	priv->stats.rx_packets++;
	priv->stats.rx_bytes += dlc;
}

static struct net_device_stats *can_get_stats(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);

	/* TODO: read statistics from chip */
	return &priv->stats;
}

static int can_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	if (!netif_running(dev))
		return -EINVAL;

	switch (cmd) {
	case SIOCSCANBAUDRATE:
		;
		return 0;
	case SIOCGCANBAUDRATE:
		;
		return 0;
	}
	return 0;
}

/*
 * I82527 interrupt handler
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
static irqreturn_t can_interrupt(int irq, void *dev_id, struct pt_regs *regs)
#else
static irqreturn_t can_interrupt(int irq, void *dev_id)
#endif
{
	struct net_device *dev	= (struct net_device*)dev_id;
	struct can_priv *priv	= netdev_priv(dev);
	unsigned long base	= dev->base_addr;
	uint8_t irqreg;
	uint8_t lastIrqreg;
	int n = 0;

	hw_preirq(dev);

	iiDBG(KERN_INFO "%s: interrupt\n", dev->name);

	if (priv->state == STATE_UNINITIALIZED) {
		printk(KERN_ERR "%s: %s: uninitialized controller!\n",
		       dev->name, __FUNCTION__);
		//chipset_init(dev, 1); /* should be possible at this stage */
		return IRQ_NONE;
	}

	if (priv->state == STATE_RESET_MODE) {
		iiDBG(KERN_ERR "%s: %s: controller is in reset mode!\n",
		      dev->name, __FUNCTION__);
		return IRQ_NONE;
	}

     
	// Read the highest pending interrupt request
	irqreg = CANin(base, interruptReg);
	lastIrqreg = irqreg;
    
	while ( irqreg ) {
		n++;
		switch (irqreg)	{

		case 1: // Status register
		{
			uint8_t status;

			// Read the STATUS reg
			status = CANin(base, statusReg);
			CANout (base, statusReg, 0);

			if ( status & iSTAT_RXOK ) {
				// Intel: Software must clear this bit in ISR
				CANout (base, statusReg, status & ~iSTAT_RXOK);
			}
			if ( status & iSTAT_TXOK ) {
				// Intel: Software must clear this bit in ISR
				CANout (base, statusReg, status & ~iSTAT_TXOK);
			}
			if ( status & iSTAT_WARN ) {
				// Note: status bit is read-only, don't clear
				/* error warning interrupt */
				iDBG(KERN_INFO "%s: error warning\n",
				     dev->name);
				priv->can_stats.error_warning++;
			}
			if ( status & iSTAT_BOFF ) {
				uint8_t flags;

				// Note: status bit is read-only, don't clear

				priv->can_stats.bus_error++;

				// Clear init flag and reenable interrupts
				flags = CANin(base, controlReg) |
					( iCTL_IE | iCTL_EIE );

				flags &= ~iCTL_INI; // Reset init flag
				CANout(base, controlReg, flags);
			}
		}
		break;

		case 0x2: // Receiption, message object 15
		{
			uint8_t ctl1reg;

			ctl1reg = CANin(base, message15Reg.msgCtrl1Reg);
			while (ctl1reg & NEWD_SET) {
				if (ctl1reg & MLST_SET)
					priv->can_stats.data_overrun++;

				if (priv->mo15 == MO15_SFF)
					can_rx(dev, 4); /* rx via obj15 SFF */
				else
					can_rx(dev, 5); /* rx via obj15 EFF */

				ctl1reg = CANin(base, message15Reg.msgCtrl1Reg);
			}

			if (priv->state == STATE_PROBE) {
				/* valid RX -> switch to trx-mode */
				chipset_init_trx(dev); /* no tx queue wakeup */
				break; /* check again after init controller */
			}
		}
		break;

		case 0xC: // Receiption, message object 10
		case 0xD: // Receiption, message object 11
		{
			int obj = irqreg - 0xC;
			int rxo = obj2rxo(obj);
			uint8_t ctl1reg;
			ctl1reg = CANin(base, msgArr[rxo].messageReg.msgCtrl1Reg);
			while (ctl1reg & NEWD_SET) {
				if (ctl1reg & MLST_SET)
					priv->can_stats.data_overrun++;
				CANout(base, msgArr[rxo].messageReg.msgCtrl1Reg,
				       NEWD_RES | MLST_RES | TXRQ_UNC | RMPD_UNC);
				can_rx(dev, obj);
				ctl1reg = CANin(base,
						msgArr[rxo].messageReg.msgCtrl1Reg);
			}

			if (priv->state == STATE_PROBE) {
				/* valid RX -> switch to trx-mode */
				chipset_init_trx(dev); /* no tx queue wakeup */
				break; /* check again after init controller */
			}
		}
		break;

		case 0xE: // Receiption, message object 12 (RTR)
		case 0xF: // Receiption, message object 13 (RTR)
		{
			int obj = irqreg - 0xC;
			int rxo = obj2rxo(obj);
			uint8_t ctl0reg;
			ctl0reg = CANin(base, msgArr[rxo].messageReg.msgCtrl0Reg);
			while (ctl0reg & INTPD_SET) {
				can_rx(dev, obj);
				ctl0reg = CANin(base, msgArr[rxo].messageReg.msgCtrl0Reg);
			}

			if (priv->state == STATE_PROBE) {
				/* valid RX -> switch to trx-mode */
				chipset_init_trx(dev); /* no tx queue wakeup */
				break; /* check again after init controller */
			}
		}
		break;

		case 3: // Message object 1 (our write object)
			/* transmission complete interrupt */

			// Nothing more to send, switch off interrupts
			CANout(base, message1Reg.msgCtrl0Reg,
			       (MVAL_RES | TXIE_RES | RXIE_RES | INTPD_RES));
			// We had some cases of repeated IRQ
			// so make sure the INT is acknowledged
			CANout(base, message1Reg.msgCtrl0Reg,
			       (MVAL_UNC | TXIE_UNC | RXIE_UNC | INTPD_RES));

			priv->stats.tx_packets++;
			netif_wake_queue(dev);
			break;

		default: // Unexpected
			iDBG(KERN_INFO "%s: Unexpected i82527 interrupt: "
			     "irqreq=0x%X\n", dev->name, irqreg);
			break;
		}

		// Get irq status again for next loop iteration
		irqreg = CANin(base, interruptReg);
		if (irqreg == lastIrqreg)
			iDBG(KERN_INFO "%s: i82527 interrupt repeated: "
			     "irqreq=0x%X\n", dev->name, irqreg);

		lastIrqreg = irqreg;
	} /* end while (irqreq) */

	if (n > 1) {
		iDBG(KERN_INFO "%s: handled %d IRQs\n", dev->name, n);
	}

	hw_postirq(dev);

	return n == 0 ? IRQ_NONE : IRQ_HANDLED;
}

/*
 * initialize CAN bus driver
 */
static int can_open(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);

	/* set chip into reset mode */
	set_reset_mode(dev);

	priv->state = STATE_UNINITIALIZED;

	/* register interrupt handler */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
	if (request_irq(dev->irq, &can_interrupt, SA_SHIRQ,
			dev->name, (void*)dev)) {
#else
	if (request_irq(dev->irq, &can_interrupt, IRQF_SHARED,
			dev->name, (void*)dev)) {
#endif
		return -EAGAIN;
	}

	/* clear statistics */
	memset(&priv->stats, 0, sizeof(priv->stats));

	/* init chip */
	chipset_init(dev, 0);
	priv->open_time = jiffies;

	netif_start_queue(dev);

	return 0;
}

/*
 * stop CAN bus activity
 */
static int can_close(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);

	/* set chip into reset mode */
	set_reset_mode(dev);

	priv->open_time = 0;

	if (priv->timer.expires) {
		del_timer(&priv->timer);
		priv->timer.expires = 0;
	}

	free_irq(dev->irq, (void*)dev);
	priv->state = STATE_UNINITIALIZED;

	netif_stop_queue(dev);

	return 0;
}

void can_netdev_setup(struct net_device *dev)
{
	/* Fill in the the fields of the device structure
	   with CAN netdev generic values */

	dev->change_mtu			= NULL;
	dev->hard_header		= NULL;
	dev->rebuild_header		= NULL;
	dev->set_mac_address		= NULL;
	dev->hard_header_cache		= NULL;
	dev->header_cache_update	= NULL;
	dev->hard_header_parse		= NULL;

	dev->type			= ARPHRD_CAN;
	dev->hard_header_len		= 0;
	dev->mtu			= sizeof(struct can_frame);
	dev->addr_len			= 0;
	dev->tx_queue_len		= 10;

	dev->flags			= IFF_NOARP;
	dev->features			= NETIF_F_NO_CSUM;

	dev->open			= can_open;
	dev->stop			= can_close;
	dev->hard_start_xmit		= can_start_xmit;
	dev->get_stats			= can_get_stats;
	dev->do_ioctl           	= can_ioctl;

	dev->tx_timeout			= can_tx_timeout;
	dev->watchdog_timeo		= TX_TIMEOUT;

	SET_MODULE_OWNER(dev);
}

static struct net_device* can_create_netdev(int dev_num, int hw_regs)
{
	struct net_device	*dev;
	struct can_priv		*priv;

	const char mo15mode [3][6] = {"none", "sff", "eff"};

	if (!(dev = alloc_netdev(sizeof(struct can_priv), CAN_NETDEV_NAME,
				 can_netdev_setup))) {
		printk(KERN_ERR "%s: out of memory\n", CHIP_NAME);
		return NULL;
	}

	printk(KERN_INFO "%s: base 0x%lX / irq %d / speed %d / "
	       "btr 0x%X / rx_probe %d / mo15 %s\n",
	       drv_name, rbase[dev_num], irq[dev_num],
	       speed[dev_num], btr[dev_num], rx_probe[dev_num],
	       mo15mode[mo15[dev_num]]);

	/* fill net_device structure */

	priv             = netdev_priv(dev);

	dev->irq         = irq[dev_num];
	dev->base_addr   = rbase[dev_num];

	priv->speed      = speed[dev_num];
	priv->btr        = btr[dev_num];
	priv->rx_probe   = rx_probe[dev_num];
	priv->mo15       = mo15[dev_num];
	priv->clock      = clk;
	priv->hw_regs    = hw_regs;
	priv->restart_ms = restart_ms;
	priv->debug      = debug;

	init_timer(&priv->timer);
	priv->timer.expires = 0;

	if (register_netdev(dev)) {
		printk(KERN_INFO "%s: register netdev failed\n", CHIP_NAME);
		free_netdev(dev);
		return NULL;
	}

	return dev;
}

int can_set_drv_name(void)
{
	char *hname = hal_name();

	if (strlen(CHIP_NAME) + strlen(hname) >= DRV_NAME_LEN-1) {
		printk(KERN_ERR "%s: driver name too long!\n", CHIP_NAME);
		return -EINVAL;
	}
	sprintf(drv_name, "%s-%s", CHIP_NAME, hname);
	return 0;
}

static __exit void i82527_exit_module(void)
{
	int i, ret;

	for (i = 0; i < MAXDEV; i++) {
		if (can_dev[i] != NULL) {
			struct can_priv *priv = netdev_priv(can_dev[i]);
			unregister_netdev(can_dev[i]);
			del_timer(&priv->timer);
			hw_detach(i);
			hal_release_region(i, I82527_IO_SIZE);
			free_netdev(can_dev[i]);
		}
	}
	can_proc_remove(drv_name);

	if ((ret = hal_exit()))
		printk(KERN_INFO "%s: hal_exit error %d.\n", drv_name, ret);
}

static __init int i82527_init_module(void)
{
	int i, ret;
	struct net_device *dev;

	if ((sizeof(canmessage_t) != 15) || (sizeof(canregs_t) != 256)) {
		printk(KERN_WARNING "%s sizes: canmessage_t %d canregs_t %d\n",
		       CHIP_NAME, sizeof(canmessage_t), sizeof(canregs_t));
		return -EBUSY;
	}

	if ((ret = hal_init()))
		return ret;

	if ((ret = can_set_drv_name()))
		return ret;

	if (clk < 1000 ) /* MHz command line value */
		clk *= 1000000;

	if (clk < 1000000 ) /* kHz command line value */
		clk *= 1000;

	printk(KERN_INFO "%s driver v%s (%s)\n",
	       drv_name, drv_version, drv_reldate);
	printk(KERN_INFO "%s - options [clk %d.%06d MHz] [restart_ms %dms]"
	       " [debug %d]\n",
	       drv_name, clk/1000000, clk%1000000, restart_ms, debug);

	if (!base[0]) {
		printk(KERN_INFO "%s: loading defaults.\n", drv_name);
		hal_use_defaults();
	}
		
	/* to ensure the proper access to the i82527 registers */
	/* the timing dependend settings have to be done first */
	if (clk > 10000000)
		dsc = iCPU_DSC; /* devide system clock => MCLK is 8MHz save */
	else if (clk > 8000000) /* 8MHz < clk <= 10MHz */
		dmc = iCPU_DMC; /* devide memory clock */

	/* devide memory clock even if it's not needed (regarding the spec) */
	if (force_dmc)
		dmc = iCPU_DMC;

	for (i = 0; base[i]; i++) {
		int clkout;
		u8 clockdiv;

		printk(KERN_DEBUG "%s: checking for %s on address 0x%lX ...\n",
		       drv_name, CHIP_NAME, base[i]);

		if (!hal_request_region(i, I82527_IO_SIZE, drv_name)) {
			printk(KERN_ERR "%s: memory already in use\n",
			       drv_name);
			i82527_exit_module();
			return -EBUSY;
		}

		hw_attach(i);
		hw_reset_dev(i);

		// Enable configuration, put chip in bus-off, disable ints
		CANout(rbase[i], controlReg, iCTL_CCE | iCTL_INI);

		// Configure cpu interface / CLKOUT disable
		CANout(rbase[i], cpuInterfaceReg,(dsc | dmc));

		if (!i82527_probe_chip(rbase[i])) {
			printk(KERN_ERR "%s: probably missing controller"
			       " hardware\n", drv_name);
			hw_detach(i);
			hal_release_region(i, I82527_IO_SIZE);
			i82527_exit_module();
			return -ENODEV;
		}

		/* CLKOUT devider and slew rate calculation */
		if ((cdv[i] < 0) || (cdv[i] > 14)) {
			printk(KERN_WARNING "%s: adjusted cdv[%d]=%d to 0.\n",
			       drv_name, i, cdv[i]);
			cdv[i] = 0;
		}

		clkout = clk / (cdv[i] + 1); /* CLKOUT frequency */
		clockdiv = (u8)cdv[i]; /* devider value (see i82527 spec) */

		if (clkout <= 16000000) {
			clockdiv |= iCLK_SL1;
			if (clkout <= 8000000)
				clockdiv |= iCLK_SL0;
		} else if (clkout <= 24000000)
				clockdiv |= iCLK_SL0;

		// Set CLKOUT devider and slew rates
		CANout(rbase[i], clkOutReg, clockdiv);

		// Configure cpu interface / CLKOUT enable
		CANout(rbase[i], cpuInterfaceReg,(dsc | dmc | iCPU_CEN));

		CANout(rbase[i], busConfigReg, bcr[i]);

		dev = can_create_netdev(i, I82527_IO_SIZE);

		if (dev != NULL) {
			can_dev[i] = dev;
			set_reset_mode(dev);
			can_proc_create(drv_name);
		} else {
			can_dev[i] = NULL;
			hw_detach(i);
			hal_release_region(i, I82527_IO_SIZE);
		}
	}
	return 0;
}

module_init(i82527_init_module);
module_exit(i82527_exit_module);

