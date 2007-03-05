/*
 * $Id$
 *
 * sja1000.c -  Philips SJA1000 network device driver
 *
 * Copyright (c) 2003 Matthias Brukner, Trajet Gmbh, Rebenring 33,
 * 38106 Braunschweig, GERMANY
 *
 * Copyright (c) 2002-2005 Volkswagen Group Electronic Research
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

#include <linux/autoconf.h>
#include <linux/module.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <asm/io.h>

#include <linux/can.h>
#include <linux/can/ioctl.h>
#include "sja1000.h"

#ifdef CONFIG_CAN_DEBUG_DEVICES
#define DBG(args...)   ((priv->debug > 0) ? printk(args) : 0)
#define iDBG(args...)  ((priv->debug > 1) ? printk(args) : 0)  /* logging in interrupt context */
#define iiDBG(args...) ((priv->debug > 2) ? printk(args) : 0)  /* logging in interrupt context */
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

/* declarations */

static void can_restart_dev(unsigned long data);
static void chipset_init(struct net_device *dev, int wake);
static void chipset_init_rx(struct net_device *dev);
static void chipset_init_trx(struct net_device *dev);


/*
 * set baud rate divisor values
 */
static void set_btr(struct net_device *dev, int btr0, int btr1)
{
	struct can_priv *priv = netdev_priv(dev);

	if (priv->state == STATE_UNINITIALIZED) /* no bla bla when restarting the device */
		printk(KERN_INFO "%s: setting BTR0=%02X BTR1=%02X\n",
		       dev->name, btr0, btr1);

	REG_WRITE(REG_BTR0, btr0);
	REG_WRITE(REG_BTR1, btr1);
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

	for (tseg = (0 + 0 + 2) * 2; tseg <= (MAX_TSEG2 + MAX_TSEG1 + 2) * 2 + 1; tseg++) {
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

	priv->btr = ((best_brp | JUMPWIDTH)<<8) + ((SAM << 7) | (tseg2 << 4) | tseg1);

	printk(KERN_INFO "%s: calculated best baudrate: %d / btr is 0x%04X\n",
	       dev->name, best_baud, priv->btr);

	set_btr(dev, (priv->btr>>8) & 0xFF, priv->btr & 0xFF);
//	set_btr(dev, best_brp | JUMPWIDTH, (SAM << 7) | (tseg2 << 4) | tseg1);
}

int set_reset_mode(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);
	unsigned char status = REG_READ(REG_MOD);
	int i;

	priv->can_stats.bus_error_at_init = priv->can_stats.bus_error;

	/* disable interrupts */
	REG_WRITE(REG_IER, IRQ_OFF);

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

		REG_WRITE(REG_MOD, MOD_RM); /* reset chip */
		status = REG_READ(REG_MOD);

	}

	printk(KERN_ERR "%s: setting sja1000 into reset mode failed!\n", dev->name);
	return 1;

}

static int set_normal_mode(struct net_device *dev)
{
	unsigned char status = REG_READ(REG_MOD);
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

		REG_WRITE(REG_MOD, 0x00); /* set chip to normal mode */
		status = REG_READ(REG_MOD);
	}

	printk(KERN_ERR "%s: setting sja1000 into normal mode failed!\n", dev->name);
	return 1;

}

static int set_listen_mode(struct net_device *dev)
{
	unsigned char status = REG_READ(REG_MOD);
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
		REG_WRITE(REG_MOD, MOD_LOM);
		status = REG_READ(REG_MOD);
	}

	printk(KERN_ERR "%s: setting sja1000 into listen mode failed!\n", dev->name);
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

	/* go into Pelican mode, disable clkout, disable comparator */
	REG_WRITE(REG_CDR, 0xCF);

	/* set acceptance filter (accept all) */
	REG_WRITE(REG_ACCC0, 0x00);
	REG_WRITE(REG_ACCC1, 0x00);
	REG_WRITE(REG_ACCC2, 0x00);
	REG_WRITE(REG_ACCC3, 0x00);

	REG_WRITE(REG_ACCM0, 0xFF);
	REG_WRITE(REG_ACCM1, 0xFF);
	REG_WRITE(REG_ACCM2, 0xFF);
	REG_WRITE(REG_ACCM3, 0xFF);

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
	REG_WRITE(REG_OCR, 0x1A);	/* connected to external transceiver */

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

	iDBG(KERN_INFO "%s: %s()\n", dev->name, __FUNCTION__);

	/* set chip into reset mode */
	set_reset_mode(dev);

	/* set registers */
	chipset_init_regs(dev);

	/* automatic bit rate detection */
	set_listen_mode(dev);

	priv->state = STATE_PROBE;

	/* enable receive and error interrupts */
	REG_WRITE(REG_IER, IRQ_RI | IRQ_EI);
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
	REG_WRITE(REG_IER, IRQ_ALL);
}

/*
 * transmit a CAN message
 * message layout in the sk_buff should be like this:
 * xx xx xx xx	 ff	 ll   00 11 22 33 44 55 66 77
 * [  can-id ] [flags] [len] [can data (up to 8 bytes]
 */
static int can_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct can_priv  *priv = netdev_priv(dev);
	struct can_frame *cf   = (struct can_frame*)skb->data;
	uint8_t	fi;
	uint8_t	dlc;
	canid_t	id;
	uint8_t	dreg;
	int	i;

	netif_stop_queue(dev);

	fi = dlc = cf->can_dlc;
	id = cf->can_id;

	if (id & CAN_RTR_FLAG)
		fi |= FI_RTR;

	if (id & CAN_EFF_FLAG) {
		fi |= FI_FF;
		dreg = EFF_BUF;
		REG_WRITE(REG_FI, fi);
		REG_WRITE(REG_ID1, (id & 0x1fe00000) >> (5 + 16));
		REG_WRITE(REG_ID2, (id & 0x001fe000) >> (5 + 8));
		REG_WRITE(REG_ID3, (id & 0x00001fe0) >> 5);
		REG_WRITE(REG_ID4, (id & 0x0000001f) << 3);
	} else {
		dreg = SFF_BUF;
		REG_WRITE(REG_FI, fi);
		REG_WRITE(REG_ID1, (id & 0x000007f8) >> 3);
		REG_WRITE(REG_ID2, (id & 0x00000007) << 5);
	}

	for (i = 0; i < dlc; i++) {
		REG_WRITE(dreg++, cf->data[i]);
	}

	REG_WRITE(REG_CMR, CMD_TR);

	priv->stats.tx_bytes += dlc;

	dev->trans_start = jiffies;

	dev_kfree_skb(skb);

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
	struct can_priv *priv = netdev_priv(dev);
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

	fi = REG_READ(REG_FI);
	dlc = fi & 0x0F;

	if (fi & FI_FF) {
		/* extended frame format (EFF) */
		dreg = EFF_BUF;
		id = (REG_READ(REG_ID1) << (5+16))
			| (REG_READ(REG_ID2) << (5+8))
			| (REG_READ(REG_ID3) << 5)
			| (REG_READ(REG_ID4) >> 3);
		id |= CAN_EFF_FLAG;
	} else {
		/* standard frame format (SFF) */
		dreg = SFF_BUF;
		id = (REG_READ(REG_ID1) << 3) | (REG_READ(REG_ID2) >> 5);
	}

	if (fi & FI_RTR)
		id |= CAN_RTR_FLAG;

	cf = (struct can_frame*)skb_put(skb, sizeof(struct can_frame));
	memset(cf, 0, sizeof(struct can_frame));
	cf->can_id    = id;
	cf->can_dlc   = dlc;
	for (i = 0; i < dlc; i++) {
		cf->data[i] = REG_READ(dreg++);
	}
	while (i < 8)
		cf->data[i++] = 0;

	/* release receive buffer */
	REG_WRITE(REG_CMR, CMD_RRB);

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
 * SJA1000 interrupt handler
 */
static irqreturn_t can_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	struct net_device *dev = (struct net_device*)dev_id;
	struct can_priv *priv = netdev_priv(dev);
	uint8_t isrc, status, ecc, alc;
	int n = 0;

	if (priv->state == STATE_UNINITIALIZED) {
		printk(KERN_ERR "%s: %s: uninitialized controller!\n", dev->name, __FUNCTION__);
		chipset_init(dev, 1); /* this should be possible at this stage */
		return IRQ_NONE;
	}

	if (priv->state == STATE_RESET_MODE) {
		iiDBG(KERN_ERR "%s: %s: controller is in reset mode! MOD=0x%02X IER=0x%02X IR=0x%02X SR=0x%02X!\n",
		      dev->name, __FUNCTION__, REG_READ(REG_MOD), REG_READ(REG_IER), REG_READ(REG_IR), REG_READ(REG_SR));
		return IRQ_NONE;
	}

	while ((isrc = REG_READ(REG_IR)) && (n < 20)) {
		n++;
		status = REG_READ(REG_SR);

		if (isrc & IRQ_WUI) {
			/* wake-up interrupt */
			priv->can_stats.wakeup++;
		}
		if (isrc & IRQ_TI) {
			/* transmission complete interrupt */
			priv->stats.tx_packets++;
			netif_wake_queue(dev);
		}
		if (isrc & IRQ_RI) {
			/* receive interrupt */

			while (status & SR_RBS) {
				can_rx(dev);
				status = REG_READ(REG_SR);
			}
			if (priv->state == STATE_PROBE) { /* valid RX -> switch to trx-mode */
				iDBG(KERN_INFO "%s: RI #%d#\n", dev->name, n);
				chipset_init_trx(dev); /* no tx queue wakeup */
				break; /* check again after initializing the controller */
			}
		}
		if (isrc & IRQ_DOI) {
			/* data overrun interrupt */
			iiDBG(KERN_INFO "%s: data overrun isrc=0x%02X status=0x%02X\n",
			      dev->name, isrc, status);
			iDBG(KERN_INFO "%s: DOI #%d#\n", dev->name, n);
			priv->can_stats.data_overrun++;
			REG_WRITE(REG_CMR, CMD_CDO); /* clear bit */
		}
		if (isrc & IRQ_EI) {
			/* error warning interrupt */
			iiDBG(KERN_INFO "%s: error warning isrc=0x%02X status=0x%02X\n",
			      dev->name, isrc, status);
			iDBG(KERN_INFO "%s: EI #%d#\n", dev->name, n);
			priv->can_stats.error_warning++;
			if (status & SR_BS) {
				printk(KERN_INFO "%s: BUS OFF, restarting device\n", dev->name);
				can_restart_on(dev);
				return IRQ_HANDLED; /* controller has been restarted, so we leave here */
			} else if (status & SR_ES) {
				iDBG(KERN_INFO "%s: error\n", dev->name);
			}
		}
		if (isrc & IRQ_BEI) {
			/* bus error interrupt */
			iiDBG(KERN_INFO "%s: bus error isrc=0x%02X status=0x%02X\n",
			      dev->name, isrc, status);
			iDBG(KERN_INFO "%s: BEI #%d# [%d]\n", dev->name, n,
			     priv->can_stats.bus_error - priv->can_stats.bus_error_at_init);
			priv->can_stats.bus_error++;
			ecc = REG_READ(REG_ECC);
			iDBG(KERN_INFO "%s: ECC = 0x%02X (%s, %s, %s)\n",
			     dev->name, ecc,
			     (ecc & ECC_DIR) ? "RX" : "TX",
			     ecc_types[ecc >> ECC_ERR],
			     ecc_errors[ecc & ECC_SEG]);

			/* when the bus errors flood the system, restart the controller */
			if (priv->can_stats.bus_error_at_init + MAX_BUS_ERRORS < priv->can_stats.bus_error) {
				iDBG(KERN_INFO "%s: heavy bus errors, restarting device\n", dev->name);
				can_restart_on(dev);
				return IRQ_HANDLED; /* controller has been restarted, so we leave here */
			}
#if 1
			/* don't know, if this is a good idea, but it works fine ... */
			if (REG_READ(REG_RXERR) > 128) {
				iDBG(KERN_INFO "%s: RX_ERR > 128, restarting device\n", dev->name);
				can_restart_on(dev);
				return IRQ_HANDLED; /* controller has been restarted, so we leave here */
			}
#endif
		}
		if (isrc & IRQ_EPI) {
			/* error passive interrupt */
			iiDBG(KERN_INFO "%s: error passive isrc=0x%02X status=0x%02X\n",
			      dev->name, isrc, status);
			iDBG(KERN_INFO "%s: EPI #%d#\n", dev->name, n);
			priv->can_stats.error_passive++;
			if (status & SR_ES) {
				iDBG(KERN_INFO "%s: -> ERROR PASSIVE, restarting device\n", dev->name);
				can_restart_on(dev);
				return IRQ_HANDLED; /* controller has been restarted, so we leave here */
			} else {
				iDBG(KERN_INFO "%s: -> ERROR ACTIVE\n", dev->name);
			}
		}
		if (isrc & IRQ_ALI) {
			/* arbitration lost interrupt */
			iiDBG(KERN_INFO "%s: error arbitration lost isrc=0x%02X status=0x%02X\n",
			      dev->name, isrc, status);
			iDBG(KERN_INFO "%s: ALI #%d#\n", dev->name, n);
			priv->can_stats.arbitration_lost++;
			alc = REG_READ(REG_ALC);
			iDBG(KERN_INFO "%s: ALC = 0x%02X\n", dev->name, alc);
		}
	}
	if (n > 1) {
		iDBG(KERN_INFO "%s: handled %d IRQs\n", dev->name, n);
	}

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
	if (request_irq(dev->irq, &can_interrupt, SA_SHIRQ,
			dev->name, (void*)dev)) {
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

#if 0
static uint8_t reg_read(struct net_device *dev, int reg)
{
	return readb(dev->base_addr + reg);
}

static void reg_write(struct net_device *dev, int reg, uint8_t val)
{
	writeb(val, dev->base_addr + reg);
}

static void test_if(struct net_device *dev)
{
	int i;
	int j;
	int x;

	REG_WRITE(REG_CDR, 0xCF);
	for (i = 0; i < 10000; i++) {
		for (j = 0; j < 256; j++) {
			REG_WRITE(REG_EWL, j);
			x = REG_READ(REG_EWL);
			if (x != j) {
				printk(KERN_INFO "%s: is: %02X expected: %02X (%d)\n", dev->name, x, j, i);
			}
		}
	}
}
#endif

void sja1000_setup(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);

	/* Fill in the the fields of the device structure
	   with CAN/LLCF generic values */

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

	dev->open		= can_open;
	dev->stop		= can_close;
	dev->hard_start_xmit	= can_start_xmit;
	dev->get_stats		= can_get_stats;
	dev->do_ioctl           = can_ioctl;

	dev->tx_timeout		= can_tx_timeout;
	dev->watchdog_timeo	= TX_TIMEOUT;

	init_timer(&priv->timer);
	priv->timer.expires = 0;

	//	SET_MODULE_OWNER(dev);
}
