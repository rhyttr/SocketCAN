/*
 * sja1000.c -  Philips SJA1000 network device driver
 *
 * Copyright (c) 2003 Matthias Brukner, Trajet Gmbh, Rebenring 33,
 * 38106 Braunschweig, GERMANY
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
#include "sja1000.h"
#include "hal.h"

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
static const char *drv_version	= "0.1.1";
static const char *drv_reldate	= "2007-04-13";

#ifdef CONFIG_CAN_DEBUG_DEVICES
static const char *ecc_errors[] = {
	NULL,
	NULL,
	"ID.28 to ID.28",
	"start of frame",
	"bit SRTR",
	"bit IDE",
	"ID.20 to ID.18",
	"ID.17 to ID.13",
	"CRC sequence",
	"reserved bit 0",
	"data field",
	"data length code",
	"bit RTR",
	"reserved bit 1",
	"ID.4 to ID.0",
	"ID.12 to ID.5",
	NULL,
	"active error flag",
	"intermission",
	"tolerate dominant bits",
	NULL,
	NULL,
	"passive error flag",
	"error delimiter",
	"CRC delimiter",
	"acknowledge slot",
	"end of frame",
	"acknowledge delimiter",
	"overload flag",
	NULL,
	NULL,
	NULL
};

static const char *ecc_types[] = {
	"bit error",
	"form error",
	"stuff error",
	"other type of error"
};
#endif

/* array of all can chips */
struct net_device *can_dev[MAXDEV];

/* module parameters */
unsigned long base[MAXDEV]	= { 0 }; /* hardware address */
unsigned long rbase[MAXDEV]	= { 0 }; /* (remapped) device address */
unsigned int  irq[MAXDEV]	= { 0 };

unsigned int speed[MAXDEV]	= { DEFAULT_SPEED, DEFAULT_SPEED };
unsigned int btr[MAXDEV]	= { 0 };

static int rx_probe[MAXDEV]	= { 0 };
static int clk			= DEFAULT_HW_CLK;
static int debug		= 0;
static int restart_ms		= 100;
static int echo			= 1;

static int base_n;
static int irq_n;
static int speed_n;
static int btr_n;
static int rx_probe_n;

module_param_array(base, int, &base_n, 0);
module_param_array(irq, int, &irq_n, 0);
module_param_array(speed, int, &speed_n, 0);
module_param_array(btr, int, &btr_n, 0);
module_param_array(rx_probe, int, &rx_probe_n, 0);

module_param(clk, int, 0);
module_param(debug, int, 0);
module_param(restart_ms, int, 0);
module_param(echo, int, S_IRUGO);

MODULE_PARM_DESC(base, "CAN controller base address");
MODULE_PARM_DESC(irq, "CAN controller interrupt");
MODULE_PARM_DESC(speed, "CAN bus bitrate");
MODULE_PARM_DESC(btr, "Bit Timing Register value 0x<btr0><btr1>, e.g. 0x4014");
MODULE_PARM_DESC(rx_probe, "switch to trx mode after correct msg receiption. (default off)");

MODULE_PARM_DESC(clk, "CAN controller chip clock (default: 16MHz)");
MODULE_PARM_DESC(debug, "set debug mask (default: 0)");
MODULE_PARM_DESC(restart_ms, "restart chip on heavy bus errors / bus off after x ms (default 100ms)");
MODULE_PARM_DESC(echo, "Echo sent frames. default: 1 (On)");

/*
 * CAN network devices *should* support a local echo functionality
 * (see Documentation/networking/can.txt). To test the handling of CAN
 * interfaces that do not support the local echo both driver types are
 * implemented inside this sja1000 driver. In the case that the driver does
 * not support the echo the IFF_ECHO remains clear in dev->flags.
 * This causes the PF_CAN core to perform the echo as a fallback solution.
 */

/* function declarations */

static void can_restart_dev(unsigned long data);
static void chipset_init(struct net_device *dev, int wake);
static void chipset_init_rx(struct net_device *dev);
static void chipset_init_trx(struct net_device *dev);
static void can_netdev_setup(struct net_device *dev);
static struct net_device* can_create_netdev(int dev_num, int hw_regs);
static int  can_set_drv_name(void);
int set_reset_mode(struct net_device *dev);

static int sja1000_probe_chip(unsigned long base)
{
	if (base && (hw_readreg(base, 0) == 0xFF)) {
		printk(KERN_INFO "%s: probing @0x%lX failed\n",
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

	/* no bla bla when restarting the device */
	if (priv->state == STATE_UNINITIALIZED)
		printk(KERN_INFO "%s: setting BTR0=%02X BTR1=%02X\n",
		       dev->name, btr0, btr1);

	hw_writereg(dev->base_addr, REG_BTR0, btr0);
	hw_writereg(dev->base_addr, REG_BTR1, btr1);
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

	clock >>= 1;

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

int set_reset_mode(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);
	unsigned char status = hw_readreg(dev->base_addr, REG_MOD);
	int i;

	priv->can_stats.bus_error_at_init = priv->can_stats.bus_error;

	/* disable interrupts */
	hw_writereg(dev->base_addr, REG_IER, IRQ_OFF);

	for (i = 0; i < 10; i++) {
		/* check reset bit */
		if (status & MOD_RM) {
			if (i > 1) {
				iDBG(KERN_INFO "%s: %s looped %d times\n",
				     dev->name, __FUNCTION__, i);
			}
			priv->state = STATE_RESET_MODE;
			return 0;
		}

		hw_writereg(dev->base_addr, REG_MOD, MOD_RM); /* reset chip */
		status = hw_readreg(dev->base_addr, REG_MOD);

	}

	printk(KERN_ERR "%s: setting sja1000 into reset mode failed!\n",
	       dev->name);
	return 1;

}

static int set_normal_mode(struct net_device *dev)
{
	unsigned char status = hw_readreg(dev->base_addr, REG_MOD);
	int i;

	for (i = 0; i < 10; i++) {
		/* check reset bit */
		if ((status & MOD_RM) == 0) {
#ifdef CONFIG_CAN_DEBUG_DEVICES
			if (i > 1) {
				struct can_priv *priv = netdev_priv(dev);
				iDBG(KERN_INFO "%s: %s looped %d times\n",
				     dev->name, __FUNCTION__, i);
			}
#endif
			return 0;
		}

		/* set chip to normal mode */
		hw_writereg(dev->base_addr, REG_MOD, 0x00);
		status = hw_readreg(dev->base_addr, REG_MOD);
	}

	printk(KERN_ERR "%s: setting sja1000 into normal mode failed!\n",
	       dev->name);
	return 1;

}

static int set_listen_mode(struct net_device *dev)
{
	unsigned char status = hw_readreg(dev->base_addr, REG_MOD);
	int i;

	for (i = 0; i < 10; i++) {
		/* check reset mode bit */
		if ((status & MOD_RM) == 0) {
#ifdef CONFIG_CAN_DEBUG_DEVICES
			if (i > 1) {
				struct can_priv *priv = netdev_priv(dev);
				iDBG(KERN_INFO "%s: %s looped %d times\n",
				     dev->name, __FUNCTION__, i);
			}
#endif
			return 0;
		}

		/* set listen only mode, clear reset */
		hw_writereg(dev->base_addr, REG_MOD, MOD_LOM);
		status = hw_readreg(dev->base_addr, REG_MOD);
	}

	printk(KERN_ERR "%s: setting sja1000 into listen mode failed!\n",
	       dev->name);
	return 1;

}

/*
 * initialize SJA1000 chip:
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

	/* go into Pelican mode, disable clkout, disable comparator */
	hw_writereg(base, REG_CDR, 0xCF);

	/* output control */
	/* connected to external transceiver */
	hw_writereg(base, REG_OCR, 0x1A);

	/* set acceptance filter (accept all) */
	hw_writereg(base, REG_ACCC0, 0x00);
	hw_writereg(base, REG_ACCC1, 0x00);
	hw_writereg(base, REG_ACCC2, 0x00);
	hw_writereg(base, REG_ACCC3, 0x00);

	hw_writereg(base, REG_ACCM0, 0xFF);
	hw_writereg(base, REG_ACCM1, 0xFF);
	hw_writereg(base, REG_ACCM2, 0xFF);
	hw_writereg(base, REG_ACCM3, 0xFF);

	/* set baudrate */
	if (priv->btr) { /* no calculation when btr is provided */
		set_btr(dev, (priv->btr>>8) & 0xFF, priv->btr & 0xFF);
	} else {
		if (priv->speed == 0) {
			priv->speed = DEFAULT_SPEED;
		}
		set_baud(dev, priv->speed * 1000, priv->clock);
	}

	/* output control */
	/* connected to external transceiver */
	hw_writereg(base, REG_OCR, 0x1A);
}

static void chipset_init(struct net_device *dev, int wake)
{
	struct can_priv *priv = netdev_priv(dev);

	if (priv->rx_probe)
		chipset_init_rx(dev); /* wait for valid reception first */
	else
		chipset_init_trx(dev);

	if ((wake) && netif_queue_stopped(dev)) {
		if (priv->echo_skb) { /* pending echo? */
			kfree_skb(priv->echo_skb);
			priv->echo_skb = NULL;
		}
		netif_wake_queue(dev);
	}
}

static void chipset_init_rx(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);

	iDBG(KERN_INFO "%s: %s()\n", dev->name, __FUNCTION__);

	/* set chip into reset mode */
	set_reset_mode(dev);

	/* set registers */
	chipset_init_regs(dev);

	/* automatic bit rate detection */
	set_listen_mode(dev);

	priv->state = STATE_PROBE;

	/* enable receive and error interrupts */
	hw_writereg(dev->base_addr, REG_IER, IRQ_RI | IRQ_EI);
}

static void chipset_init_trx(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);

	iDBG(KERN_INFO "%s: %s()\n", dev->name, __FUNCTION__);

	/* set chip into reset mode */
	set_reset_mode(dev);

	/* set registers */
	chipset_init_regs(dev);

	/* leave reset mode */
	set_normal_mode(dev);

	priv->state = STATE_ACTIVE;

	/* enable all interrupts */
	hw_writereg(dev->base_addr, REG_IER, IRQ_ALL);
}

/*
 * transmit a CAN message
 * message layout in the sk_buff should be like this:
 * xx xx xx xx	 ff	 ll   00 11 22 33 44 55 66 77
 * [  can-id ] [flags] [len] [can data (up to 8 bytes]
 */
static int can_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct can_priv  *priv	= netdev_priv(dev);
	struct net_device_stats *stats = dev->get_stats(dev);
	struct can_frame *cf	= (struct can_frame*)skb->data;
	unsigned long base	= dev->base_addr;
	uint8_t	fi;
	uint8_t	dlc;
	canid_t	id;
	uint8_t	dreg;
	int	loop;
	int	i;

	netif_stop_queue(dev);

	fi = dlc = cf->can_dlc;
	id = cf->can_id;

	if (id & CAN_RTR_FLAG)
		fi |= FI_RTR;

	if (id & CAN_EFF_FLAG) {
		fi |= FI_FF;
		dreg = EFF_BUF;
		hw_writereg(base, REG_FI, fi);
		hw_writereg(base, REG_ID1, (id & 0x1fe00000) >> (5 + 16));
		hw_writereg(base, REG_ID2, (id & 0x001fe000) >> (5 + 8));
		hw_writereg(base, REG_ID3, (id & 0x00001fe0) >> 5);
		hw_writereg(base, REG_ID4, (id & 0x0000001f) << 3);
	} else {
		dreg = SFF_BUF;
		hw_writereg(base, REG_FI, fi);
		hw_writereg(base, REG_ID1, (id & 0x000007f8) >> 3);
		hw_writereg(base, REG_ID2, (id & 0x00000007) << 5);
	}

	for (i = 0; i < dlc; i++) {
		hw_writereg(base, dreg++, cf->data[i]);
	}

	hw_writereg(base, REG_CMR, CMD_TR);

	stats->tx_bytes += dlc;

	dev->trans_start = jiffies;

	/* set flag whether this packet has to be looped back */
	loop = skb->pkt_type == PACKET_LOOPBACK;

	if (!echo || !loop) {
		kfree_skb(skb);
		return 0;
	}

	if (!priv->echo_skb) {
		struct sock *srcsk = skb->sk;

		if (atomic_read(&skb->users) != 1) {
			struct sk_buff *old_skb = skb;

			skb = skb_clone(old_skb, GFP_ATOMIC);
			DBG(KERN_INFO "%s: %s: freeing old skbuff %p, "
			    "using new skbuff %p\n",
			    dev->name, __FUNCTION__, old_skb, skb);
			kfree_skb(old_skb);
			if (!skb) {
				return 0;
			}
		} else
			skb_orphan(skb);

		skb->sk = srcsk;

		/* make settings for echo to reduce code in irq context */
		skb->protocol	= htons(ETH_P_CAN);
		skb->pkt_type	= PACKET_BROADCAST;
		skb->ip_summed	= CHECKSUM_UNNECESSARY;
		skb->dev	= dev;

		/* save this skb for tx interrupt echo handling */
		priv->echo_skb = skb;

	} else {
		/* locking problem with netif_stop_queue() ?? */
		printk(KERN_ERR "%s: %s: occupied echo_skb!\n",
		       dev->name, __FUNCTION__ );
		kfree_skb(skb);
	}

	return 0;
}

static void can_tx_timeout(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);
	struct net_device_stats *stats = dev->get_stats(dev);

	stats->tx_errors++;

	/* do not conflict with e.g. bus error handling */
	if (!(priv->timer.expires)){ /* no restart on the run */
		chipset_init_trx(dev); /* no tx queue wakeup */
		if (priv->echo_skb) { /* pending echo? */
			kfree_skb(priv->echo_skb);
			priv->echo_skb = NULL;
		}
		netif_wake_queue(dev); /* wakeup here */
	}
	else
		DBG(KERN_INFO "%s: %s: can_restart_dev already active.\n",
		    dev->name, __FUNCTION__ );

}

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

static void can_rx(struct net_device *dev)
{
	struct net_device_stats *stats = dev->get_stats(dev);
	unsigned long base = dev->base_addr;
	struct can_frame *cf;
	struct sk_buff	*skb;
	uint8_t	fi;
	uint8_t	dreg;
	canid_t	id;
	uint8_t	dlc;
	int	i;

	skb = dev_alloc_skb(sizeof(struct can_frame));
	if (skb == NULL) {
		return;
	}
	skb->dev = dev;
	skb->protocol = htons(ETH_P_CAN);

	fi = hw_readreg(base, REG_FI);
	dlc = fi & 0x0F;

	if (fi & FI_FF) {
		/* extended frame format (EFF) */
		dreg = EFF_BUF;
		id = (hw_readreg(base, REG_ID1) << (5+16))
			| (hw_readreg(base, REG_ID2) << (5+8))
			| (hw_readreg(base, REG_ID3) << 5)
			| (hw_readreg(base, REG_ID4) >> 3);
		id |= CAN_EFF_FLAG;
	} else {
		/* standard frame format (SFF) */
		dreg = SFF_BUF;
		id = (hw_readreg(base, REG_ID1) << 3)
			| (hw_readreg(base, REG_ID2) >> 5);
	}

	if (fi & FI_RTR)
		id |= CAN_RTR_FLAG;

	cf = (struct can_frame*)skb_put(skb, sizeof(struct can_frame));
	memset(cf, 0, sizeof(struct can_frame));
	cf->can_id    = id;
	cf->can_dlc   = dlc;
	for (i = 0; i < dlc; i++) {
		cf->data[i] = hw_readreg(base, dreg++);
	}
	while (i < 8)
		cf->data[i++] = 0;

	/* release receive buffer */
	hw_writereg(base, REG_CMR, CMD_RRB);

	netif_rx(skb);

	dev->last_rx = jiffies;
	stats->rx_packets++;
	stats->rx_bytes += dlc;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
static struct net_device_stats *can_get_stats(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);

	/* TODO: read statistics from chip */
	return &priv->stats;
}
#endif

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
 * SJA1000 interrupt handler
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
static irqreturn_t can_interrupt(int irq, void *dev_id, struct pt_regs *regs)
#else
static irqreturn_t can_interrupt(int irq, void *dev_id)
#endif
{
	struct net_device *dev	= (struct net_device*)dev_id;
	struct can_priv *priv	= netdev_priv(dev);
	struct net_device_stats *stats = dev->get_stats(dev);
	unsigned long base	= dev->base_addr;
	uint8_t isrc, status, ecc, alc;
	int n = 0;

	hw_preirq(dev);

	iiDBG(KERN_INFO "%s: interrupt\n", dev->name);

	if (priv->state == STATE_UNINITIALIZED) {
		printk(KERN_ERR "%s: %s: uninitialized controller!\n",
		       dev->name, __FUNCTION__);
		chipset_init(dev, 1); /* should be possible at this stage */
		return IRQ_NONE;
	}

	if (priv->state == STATE_RESET_MODE) {
		iiDBG(KERN_ERR "%s: %s: controller is in reset mode! "
		      "MOD=0x%02X IER=0x%02X IR=0x%02X SR=0x%02X!\n",
		      dev->name, __FUNCTION__, hw_readreg(base, REG_MOD),
		      hw_readreg(base, REG_IER), hw_readreg(base, REG_IR),
		      hw_readreg(base, REG_SR));
		return IRQ_NONE;
	}

	while ((isrc = hw_readreg(base, REG_IR)) && (n < 20)) {
		n++;
		status = hw_readreg(base, REG_SR);

		if (isrc & IRQ_WUI) {
			/* wake-up interrupt */
			priv->can_stats.wakeup++;
		}
		if (isrc & IRQ_TI) {
			/* transmission complete interrupt */
			stats->tx_packets++;

			if (echo && priv->echo_skb) {
				netif_rx(priv->echo_skb);
				priv->echo_skb = NULL;
			}

			netif_wake_queue(dev);
		}
		if (isrc & IRQ_RI) {
			/* receive interrupt */

			while (status & SR_RBS) {
				can_rx(dev);
				status = hw_readreg(base, REG_SR);
			}
			if (priv->state == STATE_PROBE) {
				/* valid RX -> switch to trx-mode */
				iDBG(KERN_INFO "%s: RI #%d#\n", dev->name, n);
				chipset_init_trx(dev); /* no tx queue wakeup */
				break; /* check again after init controller */
			}
		}
		if (isrc & IRQ_DOI) {
			/* data overrun interrupt */
			iiDBG(KERN_INFO "%s: data overrun isrc=0x%02X "
			      "status=0x%02X\n",
			      dev->name, isrc, status);
			iDBG(KERN_INFO "%s: DOI #%d#\n", dev->name, n);
			priv->can_stats.data_overrun++;
			hw_writereg(base, REG_CMR, CMD_CDO); /* clear bit */
		}
		if (isrc & IRQ_EI) {
			/* error warning interrupt */
			iiDBG(KERN_INFO "%s: error warning isrc=0x%02X "
			      "status=0x%02X\n",
			      dev->name, isrc, status);
			iDBG(KERN_INFO "%s: EI #%d#\n", dev->name, n);
			priv->can_stats.error_warning++;
			if (status & SR_BS) {
				printk(KERN_INFO "%s: BUS OFF, "
				       "restarting device\n", dev->name);
				can_restart_on(dev);
				/* controller has been restarted: leave here */
				goto out;
			} else if (status & SR_ES) {
				iDBG(KERN_INFO "%s: error\n", dev->name);
			}
		}
		if (isrc & IRQ_BEI) {
			/* bus error interrupt */
			iiDBG(KERN_INFO "%s: bus error isrc=0x%02X "
			      "status=0x%02X\n",
			      dev->name, isrc, status);
			iDBG(KERN_INFO "%s: BEI #%d# [%d]\n", dev->name, n,
			     priv->can_stats.bus_error - 
			     priv->can_stats.bus_error_at_init);
			priv->can_stats.bus_error++;
			ecc = hw_readreg(base, REG_ECC);
			iDBG(KERN_INFO "%s: ECC = 0x%02X (%s, %s, %s)\n",
			     dev->name, ecc,
			     (ecc & ECC_DIR) ? "RX" : "TX",
			     ecc_types[ecc >> ECC_ERR],
			     ecc_errors[ecc & ECC_SEG]);

			/* when the bus errors flood the system, */
			/* restart the controller                */
			if (priv->can_stats.bus_error_at_init +
			    MAX_BUS_ERRORS < priv->can_stats.bus_error) {
				iDBG(KERN_INFO "%s: heavy bus errors,"
				     " restarting device\n", dev->name);
				can_restart_on(dev);
				/* controller has been restarted: leave here */
				goto out;
			}
#if 1
			/* don't know, if this is a good idea, */
			/* but it works fine ...               */
			if (hw_readreg(base, REG_RXERR) > 128) {
				iDBG(KERN_INFO "%s: RX_ERR > 128,"
				     " restarting device\n", dev->name);
				can_restart_on(dev);
				/* controller has been restarted: leave here */
				goto out;
			}
#endif
		}
		if (isrc & IRQ_EPI) {
			/* error passive interrupt */
			iiDBG(KERN_INFO "%s: error passive isrc=0x%02X"
			      " status=0x%02X\n",
			      dev->name, isrc, status);
			iDBG(KERN_INFO "%s: EPI #%d#\n", dev->name, n);
			priv->can_stats.error_passive++;
			if (status & SR_ES) {
				iDBG(KERN_INFO "%s: -> ERROR PASSIVE, "
				     "restarting device\n", dev->name);
				can_restart_on(dev);
				/* controller has been restarted: leave here */
				goto out;
			} else {
				iDBG(KERN_INFO "%s: -> ERROR ACTIVE\n",
				     dev->name);
			}
		}
		if (isrc & IRQ_ALI) {
			/* arbitration lost interrupt */
			iiDBG(KERN_INFO "%s: error arbitration lost "
			      "isrc=0x%02X status=0x%02X\n",
			      dev->name, isrc, status);
			iDBG(KERN_INFO "%s: ALI #%d#\n", dev->name, n);
			priv->can_stats.arbitration_lost++;
			alc = hw_readreg(base, REG_ALC);
			iDBG(KERN_INFO "%s: ALC = 0x%02X\n", dev->name, alc);
		}
	}
	if (n > 1) {
		iDBG(KERN_INFO "%s: handled %d IRQs\n", dev->name, n);
	}
out:
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
	if (request_irq(dev->irq, &can_interrupt, SA_SHIRQ,
			dev->name, (void*)dev)) {
#else
	if (request_irq(dev->irq, &can_interrupt, IRQF_SHARED,
			dev->name, (void*)dev)) {
#endif
		return -EAGAIN;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	/* clear statistics */
	memset(&priv->stats, 0, sizeof(priv->stats));
#endif

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

#if 0
static void test_if(struct net_device *dev)
{
	int i;
	int j;
	int x;

	hw_writereg(base, REG_CDR, 0xCF);
	for (i = 0; i < 10000; i++) {
		for (j = 0; j < 256; j++) {
			hw_writereg(base, REG_EWL, j);
			x = hw_readreg(base, REG_EWL);
			if (x != j) {
				printk(KERN_INFO "%s: is: %02X expected: "
				       "%02X (%d)\n", dev->name, x, j, i);
			}
		}
	}
}
#endif

void can_netdev_setup(struct net_device *dev)
{
	/* Fill in the the fields of the device structure
	   with CAN netdev generic values */

	dev->change_mtu			= NULL;
	dev->set_mac_address		= NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	dev->hard_header		= NULL;
	dev->rebuild_header		= NULL;
	dev->hard_header_cache		= NULL;
	dev->header_cache_update	= NULL;
	dev->hard_header_parse		= NULL;
#else
	dev->header_ops			= NULL;
#endif

	dev->type			= ARPHRD_CAN;
	dev->hard_header_len		= 0;
	dev->mtu			= sizeof(struct can_frame);
	dev->addr_len			= 0;
	dev->tx_queue_len		= 10;

	dev->flags			= IFF_NOARP;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#define IFF_ECHO IFF_LOOPBACK
#endif
	/* set flags according to driver capabilities */
	if (echo)
		dev->flags |= IFF_ECHO;

	dev->features			= NETIF_F_NO_CSUM;

	dev->open			= can_open;
	dev->stop			= can_close;
	dev->hard_start_xmit		= can_start_xmit;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	dev->get_stats			= can_get_stats;
#endif
	dev->do_ioctl           	= can_ioctl;

	dev->tx_timeout			= can_tx_timeout;
	dev->watchdog_timeo		= TX_TIMEOUT;
}

static struct net_device* can_create_netdev(int dev_num, int hw_regs)
{
	struct net_device	*dev;
	struct can_priv		*priv;

	if (!(dev = alloc_netdev(sizeof(struct can_priv), CAN_NETDEV_NAME,
				 can_netdev_setup))) {
		printk(KERN_ERR "%s: out of memory\n", CHIP_NAME);
		return NULL;
	}

	printk(KERN_INFO "%s: base 0x%lX / irq %d / speed %d / "
	       "btr 0x%X / rx_probe %d\n",
	       drv_name, rbase[dev_num], irq[dev_num],
	       speed[dev_num], btr[dev_num], rx_probe[dev_num]);

	/* fill net_device structure */

	priv             = netdev_priv(dev);

	dev->irq         = irq[dev_num];
	dev->base_addr   = rbase[dev_num];

	priv->speed      = speed[dev_num];
	priv->btr        = btr[dev_num];
	priv->rx_probe   = rx_probe[dev_num];
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

static __exit void sja1000_exit_module(void)
{
	int i, ret;

	for (i = 0; i < MAXDEV; i++) {
		if (can_dev[i] != NULL) {
			struct can_priv *priv = netdev_priv(can_dev[i]);
			unregister_netdev(can_dev[i]);
			del_timer(&priv->timer);
			hw_detach(i);
			hal_release_region(i, SJA1000_IO_SIZE_BASIC);
			free_netdev(can_dev[i]);
		}
	}
	can_proc_remove(drv_name);

	if ((ret = hal_exit()))
		printk(KERN_INFO "%s: hal_exit error %d.\n", drv_name, ret);
}

static __init int sja1000_init_module(void)
{
	int i, ret;
	struct net_device *dev;

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
		
	for (i = 0; base[i]; i++) {
		printk(KERN_DEBUG "%s: checking for %s on address 0x%lX ...\n",
		       drv_name, CHIP_NAME, base[i]);

		if (!hal_request_region(i, SJA1000_IO_SIZE_BASIC, drv_name)) {
			printk(KERN_ERR "%s: memory already in use\n",
			       drv_name);
			sja1000_exit_module();
			return -EBUSY;
		}

		hw_attach(i);
		hw_reset_dev(i);

		if (!sja1000_probe_chip(rbase[i])) {
			printk(KERN_ERR "%s: probably missing controller"
			       " hardware\n", drv_name);
			hw_detach(i);
			hal_release_region(i, SJA1000_IO_SIZE_BASIC);
			sja1000_exit_module();
			return -ENODEV;
		}

		dev = can_create_netdev(i, SJA1000_IO_SIZE_BASIC);

		if (dev != NULL) {
			can_dev[i] = dev;
			set_reset_mode(dev);
			can_proc_create(drv_name);
		} else {
			can_dev[i] = NULL;
			hw_detach(i);
			hal_release_region(i, SJA1000_IO_SIZE_BASIC);
		}
	}
	return 0;
}

module_init(sja1000_init_module);
module_exit(sja1000_exit_module);

