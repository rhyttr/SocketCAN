/*
 * $Id: mscan_hw.c,v 1.1 2006/03/09 13:17:16 hartko Exp $
 *
 * mscan_hw.c - Motorola MPC52xx MSCAN network device driver
 *
 * Copyright (c) 2002-2006 Volkswagen Group Electronic Research
 * All rights reserved.
 *
 * Copyright (c) 2003 Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 *
 * Copyright (c) 2005 Felix Daners, Plugit AG, felix.daners@plugit.ch
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
 * Send feedback to <llcf@volkswagen.de>
 *
 */

#include <linux/module.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <asm/io.h>

#include <linux/netdevice.h>
#include <linux/skbuff.h>

#include "can.h"
#include "can_ioctl.h"
#include <asm/mpc5xxx.h>
#include <asm/ppcboot.h>
#include "mscan.h"

#define BUFFER_STD_RTR  0x10
#define BUFFER_EXT_RTR  0x01
#define BUFFER_EXTENDED 0x08

/* These constants are used for calculating timing parameters for a given bitrate */
#define MAX_TSEG1 15
#define MAX_TSEG2 7
#define BTR1_SAM  (1 << 1)

#ifdef DEBUG
#define DBG(args...)   ((priv->debug > 0) ? printk(args) : 0)
#define iDBG(args...)  ((priv->debug > 1) ? printk(args) : 0)  /* logging in interrupt context */
#define iiDBG(args...) ((priv->debug > 2) ? printk(args) : 0)  /* logging in interrupt context */
#else
#define DBG(args...)
#define iDBG(args...)
#define iiDBG(args...)
#endif

/*
 * set baud rate divisor values
 */
static void set_btr(struct net_device *dev, u8 btr0, u8 btr1)
{
    struct can_priv *priv = (struct can_priv*)dev->priv;
    struct mpc5xxx_mscan *regs = priv->regs;
	
    if (priv->state == STATE_UNINITIALIZED) /* no bla bla when restarting the device */
	printk(KERN_INFO "%s: setting BTR0=%02X BTR1=%02X\n",
	       dev->name, btr0, btr1);

    /* Set bus timings */
    regs->canbtr0 = btr0;
    regs->canbtr1 = btr1;
}

/*
 * calculate baud rate divisor values
 */
static void set_baud(struct net_device *dev, int rate, int clock)
{
    struct can_priv *priv = (struct can_priv*)dev->priv;

    int best_error = 1000000000;
    int error;
    int best_tseg=0, best_brp=0, best_rate=0, brp=0;
    int tseg=0, tseg1=0, tseg2=0;
    int sjw = 0;
    int sampl_pt = 90;
    int flags = 0;

    /* some heuristic specials */
    if (rate > ((1000000 + 500000) / 2))
	sampl_pt = 75;

    if (rate < ((12500 + 10000) / 2))
	sampl_pt = 75;

    if (rate < ((100000 + 125000) / 2))
	sjw = 1;

    /* tseg even = round down, odd = round up */
    for (tseg = (0 + 0 + 2) * 2; tseg <= (MAX_TSEG2 + MAX_TSEG1 + 2) * 2 + 1; tseg++) {
	brp = clock / ((1 + tseg / 2) * rate) + tseg % 2;
	if ((brp == 0) || (brp > 64))
	    continue;

	error = rate - clock / (brp * (1 + tseg / 2));
	if (error < 0)
	    error = -error;

	if (error <= best_error) {
	    best_error = error;
	    best_tseg = tseg/2;
	    best_brp = brp-1;
	    best_rate = clock/(brp*(1+tseg/2));
	}
    }

    if (best_error && (rate / best_error < 10)) {
	DBG(KERN_ERR
		"%s: bitrate %d is not possible with %d Hz clock\n",
		DRV_NAME, rate, clock);
	return;
    }

    tseg2 = best_tseg - (sampl_pt * (best_tseg + 1)) / 100;

    if (tseg2 < 0)
	tseg2 = 0;

    if (tseg2 > MAX_TSEG2)
	tseg2 = MAX_TSEG2;

    tseg1 = best_tseg - tseg2 - 2;

    if (tseg1 > MAX_TSEG1) {
	tseg1 = MAX_TSEG1;
	tseg2 = best_tseg - tseg1 - 2;
    }

    /* MSCAN has the sjw bits encoded not in the lexicographical
     * order, unlike the sja1000. We have to asjust for that here.
     */
    if (sjw && sjw < 3) {
	/* 01 ==> 10
	 * 10 ==> 01
	 */
	sjw ^= 3;
    }

    priv->btr = ((sjw << 6 | best_brp) << 8) | (((flags & BTR1_SAM) != 0) << 7 | tseg2 << 4 | tseg1);

    printk(KERN_INFO "%s: calculated best baudrate: %d / btr is 0x%04X\n",
	   dev->name, best_rate, priv->btr);

    set_btr(dev, (priv->btr>>8) & 0xFF, priv->btr & 0xFF);
}

static int set_init_mode(struct net_device *dev)
{
    struct can_priv *priv = (struct can_priv*)dev->priv;
    struct mpc5xxx_mscan *regs = priv->regs;

    DBG(KERN_DEBUG "%s: set_init_mode()\n", DRV_NAME);

    /* Switch to sleep mode */
    regs->canctl0 |= MPC5xxx_MSCAN_SLPRQ;
    while (!(regs->canctl1 & MPC5xxx_MSCAN_SLPAK));

    /* Switch to initialization mode */
    regs->canctl0 |= MPC5xxx_MSCAN_INITRQ;
    while (!(regs->canctl1 & MPC5xxx_MSCAN_INITAK));

    return 0;
}
	
static int set_normal_mode(struct net_device *dev)
{
    struct can_priv *priv = (struct can_priv*)dev->priv;
    struct mpc5xxx_mscan *regs = priv->regs;

    DBG(KERN_DEBUG "%s: set_init_mode()\n", DRV_NAME);

    /* Switch back to normal mode */
    regs->canctl0 &= ~MPC5xxx_MSCAN_INITRQ;
    regs->canctl0 &= ~MPC5xxx_MSCAN_SLPRQ;
    while((regs->canctl1 & MPC5xxx_MSCAN_INITAK) ||
	  (regs->canctl1 & MPC5xxx_MSCAN_SLPAK));

    return 0;
}

static void chipset_init(struct net_device *dev)
{
    struct can_priv *priv = (struct can_priv*)dev->priv;
    struct mpc5xxx_mscan *regs = priv->regs;

    DBG(KERN_DEBUG "%s: chipset_init()\n", DRV_NAME);

    set_init_mode(dev);

#if 0
    /* Set listen-only mode if needed */
    if (dev->ucListenOnly)
	regs->canctl1 |= MPC5xxx_MSCAN_LISTEN;
    else
	regs->canctl1 &= ~MPC5xxx_MSCAN_LISTEN;
#else
    regs->canctl1 &= ~MPC5xxx_MSCAN_LISTEN;
#endif

    /* set baudrate */
    if (priv->btr) { /* no calculation when btr is provided */
	set_btr(dev, (priv->btr>>8) & 0xFF, priv->btr & 0xFF);
    } else {
	if (priv->speed == 0) {
	    priv->speed = DEFAULT_KBIT_PER_SEC;
	}
	set_baud(dev, priv->speed * 1000, priv->clk);
    }

    /* Choose IP bus as clock source */
    regs->canctl1 |= MPC5xxx_MSCAN_CLKSRC;

    /* Configure MSCAN to accept all incoming messages */
    regs->canidar0 = regs->canidar1 = 0x00;
    regs->canidar2 = regs->canidar3 = 0x00;
    regs->canidmr0 = regs->canidmr1 = 0xFF;
    regs->canidmr2 = regs->canidmr3 = 0xFF;
    regs->canidar4 = regs->canidar5 = 0x00;
    regs->canidar6 = regs->canidar7 = 0x00;
    regs->canidmr4 = regs->canidmr5 = 0xFF;
    regs->canidmr6 = regs->canidmr7 = 0xFF;
    regs->canidac &= ~(MPC5xxx_MSCAN_IDAM0 | MPC5xxx_MSCAN_IDAM1);

    set_normal_mode(dev);
}

/*
 * transmit a CAN message
 */
static int mscan_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct can_priv	 *priv = (struct can_priv*)dev->priv;
    struct mpc5xxx_mscan *regs = priv->regs;
    struct can_frame *cf = (struct can_frame*)skb->data;
    uint8_t dlc;
    canid_t id;
    int	i, buf;

    netif_stop_queue(dev);

    dlc = cf->can_dlc;
    id  = cf->can_id;

    /* Find an empty buffer */
    for (buf = 0; buf < 3; buf++) {
	if (regs->cantflg & (1 << buf))
	    break; /* Buffer # buf is free */
    }

    if (buf == 3) {
	/* No buffer is available */
	printk(KERN_ERR "%s: %s: no buffer is available\n", DRV_NAME, __FUNCTION__);
	return 0;
    }

    /* Select the buffer we've found */
    regs->cantbsel = 1 << buf;

    if (id & CAN_EFF_FLAG) {

	regs->cantxfg.idr[0]  = (id & 0x1fe00000) >> 21;
	regs->cantxfg.idr[1]  = (id & 0x001c0000) >> 13;
	regs->cantxfg.idr[1] |= (id & 0x00038000) >> 15;
	regs->cantxfg.idr[1] |= 0x18; /* set SRR and IDE bits */

	regs->cantxfg.idr[4]  = (id & 0x00007f80) >> 7 ;
	regs->cantxfg.idr[5]  = (id & 0x0000007f) << 1 ;

	if (id & CAN_RTR_FLAG)
	    regs->canrxfg.idr[5] |= BUFFER_EXT_RTR;

    } else {

	regs->cantxfg.idr[0] = (id & 0x000007f8) >> 3;
	regs->cantxfg.idr[1] = (id & 0x00000007) << 5;

	if (id & CAN_RTR_FLAG)
	    regs->canrxfg.idr[1] |= BUFFER_STD_RTR;
    }

    for (i = 0; i < dlc; i++)
	regs->cantxfg.dsr[i + (i / 2) * 2] = cf->data[i];

    regs->cantxfg.dlr = dlc;

    /* all messages have the same prio */
    regs->cantxfg.tbpr = 0;

    /* Trigger transmission */
    regs->cantflg = (1 << buf);

    /* Enable interrupt */
    regs->cantier |= (1 << buf);

    priv->stats.tx_bytes += dlc;

    dev->trans_start = jiffies;

    dev_kfree_skb(skb);

    return 0;
}

static void mscan_tx_timeout(struct net_device *dev)
{
    struct can_priv *priv = (struct can_priv*)dev->priv;

    priv->stats.tx_errors++;
    netif_wake_queue(dev);
}

static void mscan_rx(struct net_device *dev)
{
    struct can_priv *priv = (struct can_priv*)dev->priv;
    struct mpc5xxx_mscan *regs = priv->regs;
    struct can_frame *cf;
    struct sk_buff *skb;

    canid_t id;
    uint8_t dlc;
    int	i;

    skb = dev_alloc_skb(sizeof(struct can_frame));
    if (skb == NULL) {
	return;
    }
    skb->dev = dev;
    skb->protocol = htons(ETH_P_CAN);
    
    if (regs->canrxfg.idr[1] & BUFFER_EXTENDED) {
	/* extended frame format (EFF) */

	id = (regs->canrxfg.idr[0] << 21)
	    |((regs->canrxfg.idr[1] & 0xE0) << 13) /* urgs! */
	    |((regs->canrxfg.idr[1] & 0x07) << 15)
	    |(regs->canrxfg.idr[4] << 7)
	    |(regs->canrxfg.idr[5] >> 1);
	
	id |= CAN_EFF_FLAG;

	if (regs->canrxfg.idr[5] & BUFFER_EXT_RTR)
	    id |= CAN_RTR_FLAG;

    } else {
	/* standard frame format (SFF) */

	id = (regs->canrxfg.idr[0] << 3)
	    |(regs->canrxfg.idr[1] >> 5);

	if (regs->canrxfg.idr[1] & BUFFER_STD_RTR)
	    id |= CAN_RTR_FLAG;
    }

    /* Get data length */
    dlc = regs->canrxfg.dlr & 0x0F;

    cf = (struct can_frame*)skb_put(skb, sizeof(struct can_frame));
    cf->can_id    = id;
    cf->can_dlc   = dlc;

    for (i = 0; i < dlc; i++)
	cf->data[i] = regs->canrxfg.dsr[i + (i / 2) * 2]; /* kill them! */

    while (i < 8)
	cf->data[i++] = 0;

    netif_rx(skb);

    dev->last_rx = jiffies;
    priv->stats.rx_packets++;
    priv->stats.rx_bytes += dlc;
}

static struct net_device_stats *mscan_get_stats(struct net_device *dev)
{
    struct can_priv *priv = (struct can_priv*)dev->priv;

    /* TODO: read statistics from chip */
    return &priv->stats;
}

static int mscan_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
    if (!netif_running(dev))
	return -EINVAL;
    
    switch (cmd) {
    case SIOCSRATE:
	;
	return 0;
    case SIOCGRATE:
	;
	return 0;
    }
    return 0;
}

/*
 * MSCAN interrupt handler
 */
static void mscan_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
    struct net_device *dev = (struct net_device*)dev_id;
    struct can_priv *priv = (struct can_priv*)dev->priv;
    struct mpc5xxx_mscan *mscan_regs  = priv->regs;
    u8 t_status = mscan_regs->cantflg;
    u8 r_status = mscan_regs->canrflg;

    DBG(KERN_DEBUG "%s: mscan_interrupt() on %s: r = 0x%x t = 0x%x\n",
	    DRV_NAME, dev->name, r_status, t_status);

    if (t_status & MPC5xxx_MSCAN_TXE) {
	/* transmission complete interrupt */

	/* Disable transmit interrupt here or it will constantly be pending */
	mscan_regs->cantier &= ~MPC5xxx_MSCAN_TXIE;

	priv->stats.tx_packets++;
	netif_wake_queue(dev);
    }

    if (r_status & MPC5xxx_MSCAN_OVRIF) {
	/* Handle data overrun */
	priv->can_stats.data_overrun++;
    }

    if (r_status & MPC5xxx_MSCAN_RXF) {
	/* Handle receiption */
	mscan_rx(dev);
    }

    /* Acknowledge the handled interrupt within the controller */
    mscan_regs->canrflg = r_status;

    return;
}

/*
 * initialize MSCAN controller
 */
static int mscan_open(struct net_device *dev)
{
    struct can_priv *priv = (struct can_priv*)dev->priv;
    struct mpc5xxx_mscan *regs = priv->regs;

    DBG(KERN_DEBUG "%s: mscan_open()\n", DRV_NAME);

    /* Enable MSCAN module */
    regs->canctl1 |= MPC5xxx_MSCAN_CANE;
    udelay(100);

    chipset_init(dev);

    /* register interrupt handler */
    if (request_irq(dev->irq, &mscan_interrupt, SA_SHIRQ,
		    dev->name, (void*)dev)) {
	return -EAGAIN;
    }

    /* Enable receive interrupts */
    regs->canrier |= MPC5xxx_MSCAN_OVRIE | MPC5xxx_MSCAN_RXFIE;

    /* Enable transmit interrupts */
    regs->cantier |= MPC5xxx_MSCAN_TXIE;

    priv->state = STATE_ACTIVE;

    /* clear statistics */
    memset(&priv->stats, 0, sizeof(priv->stats));

    netif_start_queue(dev);

    return 0;
}

/*
 * stop CAN bus activity
 */
static int mscan_close(struct net_device *dev)
{
    struct can_priv *priv = (struct can_priv*)dev->priv;
    struct mpc5xxx_mscan *regs = priv->regs;
    u8 temp;
    unsigned long flags;

    DBG(KERN_DEBUG "%s: mscan_close()\n", DRV_NAME);

    /* Abort scheduled messages if any */

    save_flags(flags);
    cli();

    temp = regs->cantflg & MPC5xxx_MSCAN_TXE;

    if (temp != MPC5xxx_MSCAN_TXE) {
	regs->cantarq = ~temp;
	while (temp != MPC5xxx_MSCAN_TXE) {
	    udelay(100);
	    temp = regs->cantflg & MPC5xxx_MSCAN_TXE;
	}
    }

    restore_flags(flags);

    /* Reset and disable module */
    regs->canctl0 |= MPC5xxx_MSCAN_SLPRQ;
    regs->canctl0 |= MPC5xxx_MSCAN_INITRQ;
    while (!(regs->canctl1 & MPC5xxx_MSCAN_INITAK));
    regs->canctl1 &= ~MPC5xxx_MSCAN_CANE;

    free_irq(dev->irq, (void*)dev);
    priv->state = STATE_UNINITIALIZED;

    netif_stop_queue(dev);

    return 0;
}

struct net_device* mscan_register(struct mpc5xxx_mscan *regs, int irq, int speed, int btr, int clk, int debug)
{
    struct net_device *dev;
    struct can_priv   *priv;
    int	ret;

    dev = (struct net_device*)kmalloc(sizeof(struct net_device), GFP_KERNEL);
    if (dev == NULL) {
	printk(KERN_ERR "%s: out of memory\n", DRV_NAME);
	return NULL;
    }
    memset(dev, 0, sizeof(struct net_device));

    priv = (struct can_priv*)kmalloc(sizeof(struct can_priv), GFP_KERNEL);
    if (priv == NULL) {
	printk(KERN_ERR "%s: out of memory\n", DRV_NAME);
	kfree(dev);
	return NULL;
    }
    memset(priv, 0, sizeof(struct can_priv));

    dev->priv = priv;

    /* fill net_device structure */
    SET_MODULE_OWNER(dev);
    strcpy(dev->name, CAN_DEV_NAME);
    dev->irq  = irq;

    priv->regs  = regs;
    priv->speed = speed;
    priv->btr   = btr;
    priv->clk   = clk;
    priv->debug = debug;

    /* Fill in the the fields of the device structure with CAN/LLCF generic values */

    dev->change_mtu		= NULL;
    dev->hard_header		= NULL;
    dev->rebuild_header		= NULL;
    dev->set_mac_address	= NULL;
    dev->hard_header_cache	= NULL;
    dev->header_cache_update	= NULL;
    dev->hard_header_parse	= NULL;

    //	dev->type		= ARPHRD_CAN;
    dev->hard_header_len	= 4;
    dev->mtu			= 8;
    dev->addr_len		= 2;
    dev->tx_queue_len		= 10;

    dev->flags			= IFF_NOARP;

    dev->open			= mscan_open;
    dev->stop			= mscan_close;
    dev->hard_start_xmit	= mscan_start_xmit;
    dev->get_stats		= mscan_get_stats;
    dev->do_ioctl		= mscan_ioctl;

    dev->tx_timeout		= mscan_tx_timeout;
    dev->watchdog_timeo		= TX_TIMEOUT;

    SET_MODULE_OWNER(dev);

    ret = register_netdev(dev);
    if (ret != 0) {
	kfree(dev);
	return NULL;
    }
    return dev;
}

