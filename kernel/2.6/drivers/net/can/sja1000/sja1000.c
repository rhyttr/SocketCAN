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
#include <linux/kernel.h>
#include <linux/version.h>
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
#include <linux/delay.h>

#include <linux/can.h>
#include <linux/can/dev.h>
#include <linux/can/error.h>
#include <linux/can/dev.h>

#include "sja1000.h"

#include <linux/can/version.h>	/* for RCSID. Removed by mkpatch script */
RCSID("$Id: sja1000.c 531 2007-10-19 07:38:29Z hartkopp $");

#define DRV_NAME "sja1000"

MODULE_AUTHOR("Oliver Hartkopp <oliver.hartkopp@volkswagen.de>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION(DRV_NAME " CAN netdevice driver");

#ifdef CONFIG_CAN_DEBUG_DEVICES
#define DBG(args...)   ((debug > 0) ? printk(args) : 0)
/* logging in interrupt context! */
#define iDBG(args...)  ((debug > 1) ? printk(args) : 0)
#define iiDBG(args...) ((debug > 2) ? printk(args) : 0)
#else
#define DBG(args...)
#define iDBG(args...)
#define iiDBG(args...)
#endif

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

static struct can_bittiming_const sja1000_bittiming_const = {
	.tseg1_min = 1,
	.tseg1_max = 16,
	.tseg2_min = 1,
	.tseg2_max = 8,
	.sjw_max = 4,
	.brp_min = 1,
	.brp_max = 64,
	.brp_inc = 1,
};

static int debug;

module_param(debug, int, S_IRUGO | S_IWUSR);

MODULE_PARM_DESC(debug, "Set debug mask (default: 0)");

static int sja1000_probe_chip(struct net_device *dev)
{
	struct sja1000_priv *priv = netdev_priv(dev);

	if (dev->base_addr && (priv->read_reg(dev, 0) == 0xFF)) {
		printk(KERN_INFO "%s: probing @0x%lX failed\n",
		       DRV_NAME, dev->base_addr);
		return 0;
	}
	return 1;
}

int set_reset_mode(struct net_device *dev)
{
	struct sja1000_priv *priv = netdev_priv(dev);
	unsigned char status = priv->read_reg(dev, REG_MOD);
	int i;

	/* disable interrupts */
	priv->write_reg(dev, REG_IER, IRQ_OFF);

	for (i = 0; i < 100; i++) {
		/* check reset bit */
		if (status & MOD_RM) {
			if (i > 1) {
				iDBG(KERN_INFO "%s: %s looped %d times\n",
				     dev->name, __func__, i);
			}
			priv->can.state = CAN_STATE_STOPPED;
			return 0;
		}

		priv->write_reg(dev, REG_MOD, MOD_RM);	/* reset chip */
		status = priv->read_reg(dev, REG_MOD);
		udelay(10);
	}

	dev_err(ND2D(dev), "setting SJA1000 into reset mode failed!\n");
	return 1;

}

static int set_normal_mode(struct net_device *dev)
{
	struct sja1000_priv *priv = netdev_priv(dev);
	unsigned char status = priv->read_reg(dev, REG_MOD);
	int i;

	for (i = 0; i < 100; i++) {
		/* check reset bit */
		if ((status & MOD_RM) == 0) {
#ifdef CONFIG_CAN_DEBUG_DEVICES
			if (i > 1) {
				iDBG(KERN_INFO "%s: %s looped %d times\n",
				     dev->name, __func__, i);
			}
#endif
			priv->can.state = CAN_STATE_ACTIVE;
			/* enable all interrupts */
			priv->write_reg(dev, REG_IER, IRQ_ALL);

			return 0;
		}

		/* set chip to normal mode */
		priv->write_reg(dev, REG_MOD, 0x00);
		status = priv->read_reg(dev, REG_MOD);
		udelay(10);
	}

	dev_err(ND2D(dev), "setting SJA1000 into normal mode failed!\n");
	return 1;

}

static void sja1000_start(struct net_device *dev)
{
	struct sja1000_priv *priv = netdev_priv(dev);

	iDBG(KERN_INFO "%s: %s()\n", dev->name, __func__);

	/* leave reset mode */
	if (priv->can.state != CAN_STATE_STOPPED)
		set_reset_mode(dev);

	/* Clear error counters and error code capture */
	priv->write_reg(dev, REG_TXERR, 0x0);
	priv->write_reg(dev, REG_RXERR, 0x0);
	priv->read_reg(dev, REG_ECC);

	/* leave reset mode */
	set_normal_mode(dev);
}

static int sja1000_set_mode(struct net_device *dev, enum can_mode mode)
{
	struct sja1000_priv *priv = netdev_priv(dev);

	switch (mode) {
	case CAN_MODE_START:
		DBG("%s: CAN_MODE_START requested\n", __func__);
		if (!priv->open_time)
			return -EINVAL;

		sja1000_start(dev);
		if (netif_queue_stopped(dev))
			netif_wake_queue(dev);
		break;

	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static int sja1000_get_state(struct net_device *dev, enum can_state *state)
{
	struct sja1000_priv *priv = netdev_priv(dev);
	u8 status;

	/* FIXME: inspecting the status register to get the current state
	 * is not really necessary, because state changes are handled by
	 * in the ISR and the variable priv->can.state gets updated. The
	 * CAN devicde interface needs fixing!
	 */

	spin_lock_irq(&priv->can.irq_lock);

	if (priv->can.state == CAN_STATE_STOPPED) {
		*state =  CAN_STATE_STOPPED;
	} else {
		status = priv->read_reg(dev, REG_SR);
		if (status & SR_BS)
			*state = CAN_STATE_BUS_OFF;
		else if (status & SR_ES) {
			if (priv->read_reg(dev, REG_TXERR) > 127 ||
			    priv->read_reg(dev, REG_RXERR) > 127)
				*state = CAN_STATE_BUS_PASSIVE;
			else
				*state = CAN_STATE_BUS_WARNING;
		} else
			*state = CAN_STATE_ACTIVE;
	}
#ifdef CONFIG_CAN_DEBUG_DEVICES
	/* Check state */
	if (*state != priv->can.state)
		dev_err(ND2D(dev),
			"Oops, state mismatch: hard %d != soft %d\n",
			*state, priv->can.state);
#endif
	spin_unlock_irq(&priv->can.irq_lock);
	return 0;
}

static int sja1000_set_bittiming(struct net_device *dev)
{
	struct sja1000_priv *priv = netdev_priv(dev);
	struct can_bittiming *bt = &priv->can.bittiming;
	u8 btr0, btr1;

	btr0 = ((bt->brp - 1) & 0x3f) | (((bt->sjw - 1) & 0x3) << 6);
	btr1 = ((bt->prop_seg + bt->phase_seg1 - 1) & 0xf) |
		(((bt->phase_seg2 - 1) & 0x7) << 4) |
	  ((priv->can.ctrlmode & CAN_CTRLMODE_3_SAMPLES) << 7);

	dev_info(ND2D(dev), "BTR0=0x%02x BTR1=0x%02x\n", btr0, btr1);

	priv->write_reg(dev, REG_BTR0, btr0);
	priv->write_reg(dev, REG_BTR1, btr1);

	return 0;
}

/*
 * initialize SJA1000 chip:
 *   - reset chip
 *   - set output mode
 *   - set baudrate
 *   - enable interrupts
 *   - start operating mode
 */
static void chipset_init(struct net_device *dev)
{
	struct sja1000_priv *priv = netdev_priv(dev);

	/* set clock divider and output control register */
	priv->write_reg(dev, REG_CDR, priv->cdr | CDR_PELICAN);

	/* set acceptance filter (accept all) */
	priv->write_reg(dev, REG_ACCC0, 0x00);
	priv->write_reg(dev, REG_ACCC1, 0x00);
	priv->write_reg(dev, REG_ACCC2, 0x00);
	priv->write_reg(dev, REG_ACCC3, 0x00);

	priv->write_reg(dev, REG_ACCM0, 0xFF);
	priv->write_reg(dev, REG_ACCM1, 0xFF);
	priv->write_reg(dev, REG_ACCM2, 0xFF);
	priv->write_reg(dev, REG_ACCM3, 0xFF);

	priv->write_reg(dev, REG_OCR, priv->ocr | OCR_MODE_NORMAL);
}

/*
 * transmit a CAN message
 * message layout in the sk_buff should be like this:
 * xx xx xx xx	 ff	 ll   00 11 22 33 44 55 66 77
 * [  can-id ] [flags] [len] [can data (up to 8 bytes]
 */
static int sja1000_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct sja1000_priv *priv = netdev_priv(dev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	struct net_device_stats *stats = can_get_stats(dev);
#else
	struct net_device_stats *stats = &dev->stats;
#endif
	struct can_frame *cf = (struct can_frame *)skb->data;
	uint8_t fi;
	uint8_t dlc;
	canid_t id;
	uint8_t dreg;
	int i;

	netif_stop_queue(dev);

	fi = dlc = cf->can_dlc;
	id = cf->can_id;

	if (id & CAN_RTR_FLAG)
		fi |= FI_RTR;

	if (id & CAN_EFF_FLAG) {
		fi |= FI_FF;
		dreg = EFF_BUF;
		priv->write_reg(dev, REG_FI, fi);
		priv->write_reg(dev, REG_ID1, (id & 0x1fe00000) >> (5 + 16));
		priv->write_reg(dev, REG_ID2, (id & 0x001fe000) >> (5 + 8));
		priv->write_reg(dev, REG_ID3, (id & 0x00001fe0) >> 5);
		priv->write_reg(dev, REG_ID4, (id & 0x0000001f) << 3);
	} else {
		dreg = SFF_BUF;
		priv->write_reg(dev, REG_FI, fi);
		priv->write_reg(dev, REG_ID1, (id & 0x000007f8) >> 3);
		priv->write_reg(dev, REG_ID2, (id & 0x00000007) << 5);
	}

	for (i = 0; i < dlc; i++)
		priv->write_reg(dev, dreg++, cf->data[i]);

	stats->tx_bytes += dlc;
	dev->trans_start = jiffies;

	can_put_echo_skb(skb, dev, 0);

	priv->write_reg(dev, REG_CMR, CMD_TR);

	return 0;
}

static void sja1000_rx(struct net_device *dev)
{
	struct sja1000_priv *priv = netdev_priv(dev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	struct net_device_stats *stats = can_get_stats(dev);
#else
	struct net_device_stats *stats = &dev->stats;
#endif
	struct can_frame *cf;
	struct sk_buff *skb;
	uint8_t fi;
	uint8_t dreg;
	canid_t id;
	uint8_t dlc;
	int i;

	skb = dev_alloc_skb(sizeof(struct can_frame));
	if (skb == NULL)
		return;
	skb->dev = dev;
	skb->protocol = htons(ETH_P_CAN);

	fi = priv->read_reg(dev, REG_FI);
	dlc = fi & 0x0F;

	if (fi & FI_FF) {
		/* extended frame format (EFF) */
		dreg = EFF_BUF;
		id = (priv->read_reg(dev, REG_ID1) << (5 + 16))
		    | (priv->read_reg(dev, REG_ID2) << (5 + 8))
		    | (priv->read_reg(dev, REG_ID3) << 5)
		    | (priv->read_reg(dev, REG_ID4) >> 3);
		id |= CAN_EFF_FLAG;
	} else {
		/* standard frame format (SFF) */
		dreg = SFF_BUF;
		id = (priv->read_reg(dev, REG_ID1) << 3)
		    | (priv->read_reg(dev, REG_ID2) >> 5);
	}

	if (fi & FI_RTR)
		id |= CAN_RTR_FLAG;

	cf = (struct can_frame *)skb_put(skb, sizeof(struct can_frame));
	memset(cf, 0, sizeof(struct can_frame));
	cf->can_id = id;
	cf->can_dlc = dlc;
	for (i = 0; i < dlc; i++)
		cf->data[i] = priv->read_reg(dev, dreg++);

	while (i < 8)
		cf->data[i++] = 0;

	/* release receive buffer */
	priv->write_reg(dev, REG_CMR, CMD_RRB);

	netif_rx(skb);

	dev->last_rx = jiffies;
	stats->rx_packets++;
	stats->rx_bytes += dlc;
}

static int sja1000_err(struct net_device *dev,
		       uint8_t isrc, uint8_t status, int n)
{
	struct sja1000_priv *priv = netdev_priv(dev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	struct net_device_stats *stats = can_get_stats(dev);
#else
	struct net_device_stats *stats = &dev->stats;
#endif
	struct can_frame *cf;
	struct sk_buff *skb;
	enum can_state state = priv->can.state;
	uint8_t ecc, alc;

	skb = dev_alloc_skb(sizeof(struct can_frame));
	if (skb == NULL)
		return -ENOMEM;
	skb->dev = dev;
	skb->protocol = htons(ETH_P_CAN);
	cf = (struct can_frame *)skb_put(skb, sizeof(struct can_frame));
	memset(cf, 0, sizeof(struct can_frame));
	cf->can_id = CAN_ERR_FLAG;
	cf->can_dlc = CAN_ERR_DLC;

	if (isrc & IRQ_DOI) {
		/* data overrun interrupt */
		iiDBG(KERN_INFO "%s: data overrun isrc=0x%02X "
		      "status=0x%02X\n", dev->name, isrc, status);
		iDBG(KERN_INFO "%s: DOI #%d#\n", dev->name, n);
		cf->can_id |= CAN_ERR_CRTL;
		cf->data[1] = CAN_ERR_CRTL_RX_OVERFLOW;
		priv->can.can_stats.data_overrun++;
		priv->write_reg(dev, REG_CMR, CMD_CDO);	/* clear bit */
	}

	if (isrc & IRQ_EI) {
		/* error warning interrupt */
		iiDBG(KERN_INFO "%s: error warning isrc=0x%02X "
		      "status=0x%02X\n", dev->name, isrc, status);
		iDBG(KERN_INFO "%s: EI #%d#\n", dev->name, n);
		priv->can.can_stats.error_warning++;

		if (status & SR_BS) {
			state = CAN_STATE_BUS_OFF;
			cf->can_id |= CAN_ERR_BUSOFF;
			can_bus_off(dev);
			iDBG(KERN_INFO "%s: BUS OFF\n", dev->name);
		} else if (status & SR_ES) {
			state = CAN_STATE_BUS_WARNING;
			iDBG(KERN_INFO "%s: error\n", dev->name);
		} else
			state = CAN_STATE_ACTIVE;
	}
	if (isrc & IRQ_BEI) {
		/* bus error interrupt */
		iiDBG(KERN_INFO "%s: bus error isrc=0x%02X "
		      "status=0x%02X\n", dev->name, isrc, status);
		iDBG(KERN_INFO "%s: BEI #%d# [%d]\n", dev->name, n,
		     priv->can.can_stats.bus_error);
		priv->can.can_stats.bus_error++;
		ecc = priv->read_reg(dev, REG_ECC);
		iDBG(KERN_INFO "%s: ECC = 0x%02X (%s, %s, %s)\n",
		     dev->name, ecc,
		     (ecc & ECC_DIR) ? "RX" : "TX",
		     ecc_types[ecc >> ECC_ERR],
		     ecc_errors[ecc & ECC_SEG]);

		cf->can_id |= CAN_ERR_PROT | CAN_ERR_BUSERROR;

		switch (ecc & ECC_MASK) {
		case ECC_BIT:
			cf->data[2] |= CAN_ERR_PROT_BIT;
			break;
		case ECC_FORM:
			cf->data[2] |= CAN_ERR_PROT_FORM;
			break;
		case ECC_STUFF:
			cf->data[2] |= CAN_ERR_PROT_STUFF;
			break;
		default:
			cf->data[2] |= CAN_ERR_PROT_UNSPEC;
			cf->data[3] = ecc & ECC_SEG;
			break;
		}
		/* Error occured during transmission? */
		if ((ecc & ECC_DIR) == 0)
			cf->data[2] |= CAN_ERR_PROT_TX;
	}
	if (isrc & IRQ_EPI) {
		/* error passive interrupt */
		iiDBG(KERN_INFO "%s: error passive isrc=0x%02X"
		      " status=0x%02X\n", dev->name, isrc, status);
		iDBG(KERN_INFO "%s: EPI #%d#\n", dev->name, n);
		priv->can.can_stats.error_passive++;
		if (status & SR_ES) {
			iDBG(KERN_INFO "%s: ERROR PASSIVE\n", dev->name);
			state = CAN_STATE_BUS_PASSIVE;
		} else {
			iDBG(KERN_INFO "%s: ERROR ACTIVE\n", dev->name);
			state = CAN_STATE_ACTIVE;
		}
	}
	if (isrc & IRQ_ALI) {
		/* arbitration lost interrupt */
		iiDBG(KERN_INFO "%s: error arbitration lost "
		      "isrc=0x%02X status=0x%02X\n",
		      dev->name, isrc, status);
		iDBG(KERN_INFO "%s: ALI #%d#\n", dev->name, n);
		alc = priv->read_reg(dev, REG_ALC);
		iDBG(KERN_INFO "%s: ALC = 0x%02X\n", dev->name, alc);
		priv->can.can_stats.arbitration_lost++;
		cf->can_id |= CAN_ERR_LOSTARB;
		cf->data[0] = alc & 0x1f;
	}

	if (state != priv->can.state && (state == CAN_STATE_BUS_WARNING ||
					 state == CAN_STATE_BUS_PASSIVE)) {
		uint8_t rxerr = priv->read_reg(dev, REG_RXERR);
		uint8_t txerr = priv->read_reg(dev, REG_TXERR);
		cf->can_id |= CAN_ERR_CRTL;
		if (state == CAN_STATE_BUS_WARNING)
			cf->data[1] = (txerr > rxerr) ?
				CAN_ERR_CRTL_TX_WARNING :
				CAN_ERR_CRTL_RX_WARNING;
		else
			cf->data[1] = (txerr > rxerr) ?
				CAN_ERR_CRTL_TX_PASSIVE :
				CAN_ERR_CRTL_RX_PASSIVE;
	}

	priv->can.state = state;

	netif_rx(skb);

	dev->last_rx = jiffies;
	stats->rx_packets++;
	stats->rx_bytes += cf->can_dlc;

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
irqreturn_t sja1000_interrupt(int irq, void *dev_id, struct pt_regs *regs)
#else
irqreturn_t sja1000_interrupt(int irq, void *dev_id)
#endif
{
	struct net_device *dev = (struct net_device *)dev_id;
	struct sja1000_priv *priv = netdev_priv(dev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	struct net_device_stats *stats = can_get_stats(dev);
#else
	struct net_device_stats *stats = &dev->stats;
#endif
	uint8_t isrc, status;
	int n = 0;

	if (priv->pre_irq)
		priv->pre_irq(dev);

	iiDBG(KERN_INFO "%s: interrupt\n", dev->name);

	if (priv->can.state == CAN_STATE_STOPPED) {
		iiDBG(KERN_ERR "%s: %s: controller is in reset mode! "
		      "MOD=0x%02X IER=0x%02X IR=0x%02X SR=0x%02X!\n",
		      dev->name, __func__, priv->read_reg(dev, REG_MOD),
		      priv->read_reg(dev, REG_IER), priv->read_reg(dev, REG_IR),
		      priv->read_reg(dev, REG_SR));
		goto out;
	}

	while ((isrc = priv->read_reg(dev, REG_IR)) && (n < 20)) {
		n++;
		status = priv->read_reg(dev, REG_SR);

		if (isrc & IRQ_WUI) {
			/* wake-up interrupt */
			priv->can.can_stats.wakeup++;
		}
		if (isrc & IRQ_TI) {
			/* transmission complete interrupt */
			stats->tx_packets++;
			can_get_echo_skb(dev, 0);
			netif_wake_queue(dev);
		}
		if (isrc & IRQ_RI) {
			/* receive interrupt */
			while (status & SR_RBS) {
				sja1000_rx(dev);
				status = priv->read_reg(dev, REG_SR);
			}
		}
		if (isrc & (IRQ_DOI | IRQ_EI | IRQ_BEI | IRQ_EPI | IRQ_ALI)) {
			/* error interrupt */
			if (sja1000_err(dev, isrc, status, n))
				break;
		}
	}
	if (n > 1)
		iDBG(KERN_INFO "%s: handled %d IRQs\n", dev->name, n);

out:
	if (priv->post_irq)
		priv->post_irq(dev);

	return (n) ? IRQ_HANDLED : IRQ_NONE;
}
EXPORT_SYMBOL_GPL(sja1000_interrupt);

static int sja1000_open(struct net_device *dev)
{
	struct sja1000_priv *priv = netdev_priv(dev);
	int err;

	/* set chip into reset mode */
	set_reset_mode(dev);

	/* determine and set bittime */
	err = can_set_bittiming(dev);
	if (err)
		return err;

	/* register interrupt handler, if not done by the device driver */
	if (!(priv->flags & SJA1000_CUSTOM_IRQ_HANDLER)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
		err = request_irq(dev->irq, &sja1000_interrupt, SA_SHIRQ,
				  dev->name, (void *)dev);
#else
		err = request_irq(dev->irq, &sja1000_interrupt, IRQF_SHARED,
				  dev->name, (void *)dev);
#endif
		if (err)
			return -EAGAIN;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	/* clear statistics */
	memset(&priv->can.net_stats, 0, sizeof(priv->can.net_stats));
#endif

	/* init and start chi */
	sja1000_start(dev);
	priv->open_time = jiffies;

	netif_start_queue(dev);

	return 0;
}

static int sja1000_close(struct net_device *dev)
{
	struct sja1000_priv *priv = netdev_priv(dev);

	set_reset_mode(dev);
	netif_stop_queue(dev);
	priv->open_time = 0;
	can_close_cleanup(dev);

	if (!(priv->flags & SJA1000_CUSTOM_IRQ_HANDLER))
		free_irq(dev->irq, (void *)dev);

	return 0;
}

struct net_device *alloc_sja1000dev(int sizeof_priv)
{
	struct net_device *dev;
	struct sja1000_priv *priv;

	dev = alloc_candev(sizeof(struct sja1000_priv) + sizeof_priv);
	if (!dev)
		return NULL;

	priv = netdev_priv(dev);
	priv->dev = dev;

	if (sizeof_priv)
		priv->priv = (void *)priv + sizeof(struct sja1000_priv);

	return dev;
}
EXPORT_SYMBOL_GPL(alloc_sja1000dev);

void free_sja1000dev(struct net_device *dev)
{
	free_candev(dev);
}
EXPORT_SYMBOL(free_sja1000dev);

int register_sja1000dev(struct net_device *dev)
{
	struct sja1000_priv *priv = netdev_priv(dev);
	int err;

	if (!sja1000_probe_chip(dev))
		return -ENODEV;

	dev->flags |= IFF_ECHO;	/* we support local echo */

	dev->open = sja1000_open;
	dev->stop = sja1000_close;

	dev->hard_start_xmit = sja1000_start_xmit;

	priv->can.bittiming_const = &sja1000_bittiming_const;
	priv->can.do_set_bittiming = sja1000_set_bittiming;
	priv->can.do_get_state = sja1000_get_state;
	priv->can.do_set_mode = sja1000_set_mode;
	priv->dev = dev;

	err = register_netdev(dev);
	if (err) {
		printk(KERN_INFO
		       "%s: registering netdev failed\n", DRV_NAME);
		free_netdev(dev);
		return err;
	}

	set_reset_mode(dev);
	chipset_init(dev);
	return 0;
}
EXPORT_SYMBOL(register_sja1000dev);

void unregister_sja1000dev(struct net_device *dev)
{
	set_reset_mode(dev);
	unregister_netdev(dev);
}
EXPORT_SYMBOL(unregister_sja1000dev);

static __init int sja1000_init(void)
{
	printk(KERN_INFO "%s CAN netdevice driver\n", DRV_NAME);

	if (debug)
		printk(KERN_INFO "%s: debug level set to %d.\n",
		       DRV_NAME, debug);

	return 0;
}

module_init(sja1000_init);

static __exit void sja1000_exit(void)
{
	printk(KERN_INFO "%s: driver removed\n", DRV_NAME);
}

module_exit(sja1000_exit);
