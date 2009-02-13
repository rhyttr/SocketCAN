/*
 *
 * CAN bus driver for Microchip 251x CAN Controller with SPI Interface
 *
 * MCP2510 support and bug fixes by Christian Pellegrin
 * <chripell@evolware.org>
 *
 * Copyright 2007 Raymarine UK, Ltd. All Rights Reserved.
 * Written under contract by:
 *   Chris Elston, Katalix Systems, Ltd.
 *
 * Based on Microchip MCP251x CAN controller driver written by
 * David Vrabel, Copyright 2006 Arcom Control Systems Ltd.
 *
 * Based on CAN bus driver for the CCAN controller written by
 * - Sascha Hauer, Marc Kleine-Budde, Pengutronix
 * - Simon Kallweit, intefo AG
 * Copyright 2007
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
 *
 *
 *
 * Your platform definition file should specify something like:
 *
 * static struct mcp251x_platform_data mcp251x_info = {
 *         .oscillator_frequency = 8000000,
 *         .board_specific_setup = &mcp251x_setup,
 *         .model = CAN_MCP251X_MCP2510,
 *         .power_enable = mcp251x_power_enable,
 *         .transceiver_enable = NULL,
 * };
 *
 * static struct spi_board_info spi_board_info[] = {
 *         {
 *                 .modalias      = "mcp251x",
 *                 .platform_data = &mcp251x_info,
 *                 .irq           = IRQ_EINT13,
 *                 .max_speed_hz  = 2*1000*1000,
 *                 .chip_select   = 2,
 *         },
 * };
 *
 * Please see mcp251x.h for a description of the fields in
 * struct mcp251x_platform_data.
 *
 */

#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/netdevice.h>
#include <linux/can.h>
#include <linux/spi/spi.h>
#include <linux/can/dev.h>
#include <linux/can/core.h>
#include <linux/if_arp.h>
#include <linux/dma-mapping.h>
#include <linux/delay.h>
#include <linux/completion.h>
#include <linux/freezer.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/can/platform/mcp251x.h>

/* SPI interface instruction set */
#define INSTRUCTION_WRITE		0x02
#define INSTRUCTION_READ		0x03
#define INSTRUCTION_BIT_MODIFY	0x05
#define INSTRUCTION_LOAD_TXB(n)	(0x40 + 2 * (n))
#define INSTRUCTION_READ_RXB(n)	(((n) == 0) ? 0x90 : 0x94)
#define INSTRUCTION_RESET		0xC0

/* MPC251x registers */
#define CANSTAT	      0x0e
#define CANCTRL	      0x0f
#  define CANCTRL_REQOP_MASK	    0xe0
#  define CANCTRL_REQOP_CONF	    0x80
#  define CANCTRL_REQOP_LISTEN_ONLY 0x60
#  define CANCTRL_REQOP_LOOPBACK    0x40
#  define CANCTRL_REQOP_SLEEP	    0x20
#  define CANCTRL_REQOP_NORMAL	    0x00
#  define CANCTRL_OSM		    0x08
#  define CANCTRL_ABAT		    0x10
#define TEC	      0x1c
#define REC	      0x1d
#define CNF1	      0x2a
#define CNF2	      0x29
#  define CNF2_BTLMODE	0x80
#define CNF3	      0x28
#  define CNF3_SOF	0x08
#  define CNF3_WAKFIL	0x04
#  define CNF3_PHSEG2_MASK 0x07
#define CANINTE	      0x2b
#  define CANINTE_MERRE 0x80
#  define CANINTE_WAKIE 0x40
#  define CANINTE_ERRIE 0x20
#  define CANINTE_TX2IE 0x10
#  define CANINTE_TX1IE 0x08
#  define CANINTE_TX0IE 0x04
#  define CANINTE_RX1IE 0x02
#  define CANINTE_RX0IE 0x01
#define CANINTF	      0x2c
#  define CANINTF_MERRF 0x80
#  define CANINTF_WAKIF 0x40
#  define CANINTF_ERRIF 0x20
#  define CANINTF_TX2IF 0x10
#  define CANINTF_TX1IF 0x08
#  define CANINTF_TX0IF 0x04
#  define CANINTF_RX1IF 0x02
#  define CANINTF_RX0IF 0x01
#define EFLG	      0x2d
#  define EFLG_EWARN	0x01
#  define EFLG_RXWAR	0x02
#  define EFLG_TXWAR	0x04
#  define EFLG_RXEP	0x08
#  define EFLG_TXEP	0x10
#  define EFLG_TXBO	0x20
#  define EFLG_RX0OVR	0x40
#  define EFLG_RX1OVR	0x80
#define TXBCTRL(n)  ((n * 0x10) + 0x30)
#  define TXBCTRL_ABTF	0x40
#  define TXBCTRL_MLOA	0x20
#  define TXBCTRL_TXERR 0x10
#  define TXBCTRL_TXREQ 0x08
#define RXBCTRL(n)  ((n * 0x10) + 0x60)
#  define RXBCTRL_BUKT	 0x04
#  define RXBCTRL_RXM0	 0x20
#  define RXBCTRL_RXM1	 0x40

/* Buffer size required for the largest SPI transfer (i.e., reading a
 * frame). */
#define CAN_FRAME_MAX_DATA_LEN	8
#define SPI_TRANSFER_BUF_LEN	(2*(6 + CAN_FRAME_MAX_DATA_LEN))
#define CAN_FRAME_MAX_BITS	128

#define DEVICE_NAME "mcp251x"

static int mcp251x_enable_dma; /* Enable SPI DMA. Default: 0 (Off) */
module_param(mcp251x_enable_dma, int, S_IRUGO);
MODULE_PARM_DESC(mcp251x_enable_dma, "Enable SPI DMA. Default: 0 (Off)");

static struct can_bittiming_const mcp251x_bittiming_const = {
	.tseg1_min = 3,
	.tseg1_max = 16,
	.tseg2_min = 2,
	.tseg2_max = 8,
	.sjw_max = 4,
	.brp_min = 1,
	.brp_max = 64,
	.brp_inc = 1,
};

struct mcp251x_priv {
	struct can_priv	   can;
	struct net_device *net;
	struct spi_device *spi;

	struct mutex spi_lock; /* SPI buffer lock */
	u8 *spi_tx_buf;
	u8 *spi_rx_buf;
	dma_addr_t spi_tx_dma;
	dma_addr_t spi_rx_dma;

	struct sk_buff *tx_skb;
	struct workqueue_struct *wq;
	struct work_struct tx_work;
	struct work_struct irq_work;
	struct completion awake;
	int wake;
	int force_quit;
	int after_suspend;
#define AFTER_SUSPEND_UP 1
#define AFTER_SUSPEND_DOWN 2
#define AFTER_SUSPEND_POWER 4
	int restart_tx;
};

static u8 mcp251x_read_reg(struct spi_device *spi, uint8_t reg)
{
	struct mcp251x_priv *priv = dev_get_drvdata(&spi->dev);
	struct spi_transfer t = {
		.tx_buf = priv->spi_tx_buf,
		.rx_buf = priv->spi_rx_buf,
		.len = 3,
		.cs_change = 0,
	};
	struct spi_message m;
	u8 val = 0;
	int ret;

	mutex_lock(&priv->spi_lock);

	priv->spi_tx_buf[0] = INSTRUCTION_READ;
	priv->spi_tx_buf[1] = reg;

	spi_message_init(&m);

	if (mcp251x_enable_dma) {
		t.tx_dma = priv->spi_tx_dma;
		t.rx_dma = priv->spi_rx_dma;
		m.is_dma_mapped = 1;
	}

	spi_message_add_tail(&t, &m);

	ret = spi_sync(spi, &m);
	if (ret < 0)
		dev_dbg(&spi->dev, "%s: failed: ret = %d\n", __func__, ret);
	else
		val = priv->spi_rx_buf[2];

	mutex_unlock(&priv->spi_lock);

	dev_dbg(&spi->dev, "%s: read %02x = %02x\n", __func__, reg, val);
	return val;
}

static void mcp251x_write_reg(struct spi_device *spi, u8 reg, uint8_t val)
{
	struct mcp251x_priv *priv = dev_get_drvdata(&spi->dev);
	struct spi_transfer t = {
		.tx_buf = priv->spi_tx_buf,
		.rx_buf = priv->spi_rx_buf,
		.len = 3,
		.cs_change = 0,
	};
	struct spi_message m;
	int ret;

	mutex_lock(&priv->spi_lock);

	priv->spi_tx_buf[0] = INSTRUCTION_WRITE;
	priv->spi_tx_buf[1] = reg;
	priv->spi_tx_buf[2] = val;

	spi_message_init(&m);

	if (mcp251x_enable_dma) {
		t.tx_dma = priv->spi_tx_dma;
		t.rx_dma = priv->spi_rx_dma;
		m.is_dma_mapped = 1;
	}

	spi_message_add_tail(&t, &m);

	ret = spi_sync(spi, &m);

	mutex_unlock(&priv->spi_lock);

	if (ret < 0)
		dev_dbg(&spi->dev, "%s: failed\n", __func__);
}

static void mcp251x_write_bits(struct spi_device *spi, u8 reg,
			       u8 mask, uint8_t val)
{
	struct mcp251x_priv *priv = dev_get_drvdata(&spi->dev);
	struct spi_transfer t = {
		.tx_buf = priv->spi_tx_buf,
		.rx_buf = priv->spi_rx_buf,
		.len = 4,
		.cs_change = 0,
	};
	struct spi_message m;
	int ret;

	mutex_lock(&priv->spi_lock);

	priv->spi_tx_buf[0] = INSTRUCTION_BIT_MODIFY;
	priv->spi_tx_buf[1] = reg;
	priv->spi_tx_buf[2] = mask;
	priv->spi_tx_buf[3] = val;

	spi_message_init(&m);

	if (mcp251x_enable_dma) {
		t.tx_dma = priv->spi_tx_dma;
		t.rx_dma = priv->spi_rx_dma;
		m.is_dma_mapped = 1;
	}

	spi_message_add_tail(&t, &m);

	ret = spi_sync(spi, &m);

	mutex_unlock(&priv->spi_lock);

	if (ret < 0)
		dev_dbg(&spi->dev, "%s: failed\n", __func__);
}

static int mcp251x_hw_tx(struct spi_device *spi, struct can_frame *frame,
			  int tx_buf_idx)
{
	struct mcp251x_platform_data *pdata = spi->dev.platform_data;
	struct mcp251x_priv *priv = dev_get_drvdata(&spi->dev);
	u32 sid, eid, exide, rtr;

	dev_dbg(&spi->dev, "%s\n", __func__);

	exide = (frame->can_id & CAN_EFF_FLAG) ? 1 : 0; /* Extended ID Enable */
	if (exide)
		sid = (frame->can_id & CAN_EFF_MASK) >> 18;
	else
		sid = frame->can_id & CAN_SFF_MASK; /* Standard ID */
	eid = frame->can_id & CAN_EFF_MASK; /* Extended ID */
	rtr = (frame->can_id & CAN_RTR_FLAG) ? 1 : 0; /* Remote transmission */

	if (pdata->model == CAN_MCP251X_MCP2510) {
		int i;

		mcp251x_write_reg(spi, TXBCTRL(tx_buf_idx) + 1, sid >> 3);
		mcp251x_write_reg(spi, TXBCTRL(tx_buf_idx) + 2,
				  ((sid & 7) << 5) | (exide << 3) |
				  ((eid >> 16) & 3));
		mcp251x_write_reg(spi, TXBCTRL(tx_buf_idx) + 3,
				  (eid >> 8) & 0xff);
		mcp251x_write_reg(spi, TXBCTRL(tx_buf_idx) + 4, eid & 0xff);
		mcp251x_write_reg(spi, TXBCTRL(tx_buf_idx) + 5,
				  (rtr << 6) | frame->can_dlc);

		for (i = 0; i < frame->can_dlc ; i++) {
			mcp251x_write_reg(spi, TXBCTRL(tx_buf_idx) + 6 + i,
					  frame->data[i]);
		}
	} else {
		struct spi_transfer t = {
			.tx_buf = priv->spi_tx_buf,
			.rx_buf = priv->spi_rx_buf,
			.cs_change = 0,
			.len = 6 + CAN_FRAME_MAX_DATA_LEN,
		};
		struct spi_message m;
		int ret;
		u8 *tx_buf = priv->spi_tx_buf;

		mutex_lock(&priv->spi_lock);

		tx_buf[0] = INSTRUCTION_LOAD_TXB(tx_buf_idx);
		tx_buf[1] = sid >> 3;
		tx_buf[2] = ((sid & 7) << 5) | (exide << 3) |
		  ((eid >> 16) & 3);
		tx_buf[3] = (eid >> 8) & 0xff;
		tx_buf[4] = eid & 0xff;
		tx_buf[5] = (rtr << 6) | frame->can_dlc;

		memcpy(tx_buf + 6, frame->data, frame->can_dlc);

		spi_message_init(&m);

		if (mcp251x_enable_dma) {
			t.tx_dma = priv->spi_tx_dma;
			t.rx_dma = priv->spi_rx_dma;
			m.is_dma_mapped = 1;
		}

		spi_message_add_tail(&t, &m);

		ret = spi_sync(spi, &m);

		mutex_unlock(&priv->spi_lock);

		if (ret < 0) {
			dev_dbg(&spi->dev, "%s: failed: ret = %d\n", __func__,
				ret);
			return -1;
		}
	}
	mcp251x_write_reg(spi, TXBCTRL(tx_buf_idx), TXBCTRL_TXREQ);
	return 0;
}

static void mcp251x_hw_rx(struct spi_device *spi, int buf_idx)
{
	struct mcp251x_priv *priv = dev_get_drvdata(&spi->dev);
	struct mcp251x_platform_data *pdata = spi->dev.platform_data;
	struct sk_buff *skb;
	struct can_frame *frame;

	dev_dbg(&spi->dev, "%s\n", __func__);

	skb = dev_alloc_skb(sizeof(struct can_frame));
	if (!skb) {
		dev_dbg(&spi->dev, "%s: out of memory for Rx'd frame\n",
			__func__);
		priv->net->stats.rx_dropped++;
		return;
	}
	skb->dev = priv->net;
	frame = (struct can_frame *)skb_put(skb, sizeof(struct can_frame));

	if (pdata->model == CAN_MCP251X_MCP2510) {
		int i;
		u8 rx_buf[6];

		rx_buf[1] = mcp251x_read_reg(spi, RXBCTRL(buf_idx) + 1);
		rx_buf[2] = mcp251x_read_reg(spi, RXBCTRL(buf_idx) + 2);
		rx_buf[3] = mcp251x_read_reg(spi, RXBCTRL(buf_idx) + 3);
		rx_buf[4] = mcp251x_read_reg(spi, RXBCTRL(buf_idx) + 4);
		rx_buf[5] = mcp251x_read_reg(spi, RXBCTRL(buf_idx) + 5);

		if ((rx_buf[2] >> 3) & 0x1) {
			/* Extended ID format */
			frame->can_id = CAN_EFF_FLAG;
			frame->can_id |= ((rx_buf[2] & 3) << 16) |
			  (rx_buf[3] << 8) | rx_buf[4] |
			  (((rx_buf[1] << 3) | (rx_buf[2] >> 5)) << 18);
		} else {
			/* Standard ID format */
			frame->can_id = (rx_buf[1] << 3) | (rx_buf[2] >> 5);
		}

		if ((rx_buf[5] >> 6) & 0x1) {
			/* Remote transmission request */
			frame->can_id |= CAN_RTR_FLAG;
		}

		/* Data length */
		frame->can_dlc = rx_buf[5] & 0x0f;
		if (frame->can_dlc > 8) {
			dev_warn(&spi->dev, "invalid frame recevied\n");
			priv->net->stats.rx_errors++;
			dev_kfree_skb(skb);
			return;
		}

		for (i = 0; i < frame->can_dlc; i++) {
			frame->data[i] = mcp251x_read_reg(spi,
							  RXBCTRL(buf_idx) +
							  6 + i);
		}
	} else {
		struct spi_transfer t = {
			.tx_buf = priv->spi_tx_buf,
			.rx_buf = priv->spi_rx_buf,
			.cs_change = 0,
			.len = 14, /* RX buffer: RXBnCTRL to RXBnD7 */
		};
		struct spi_message m;
		int ret;
		u8 *tx_buf = priv->spi_tx_buf;
		u8 *rx_buf = priv->spi_rx_buf;

		mutex_lock(&priv->spi_lock);

		tx_buf[0] = INSTRUCTION_READ_RXB(buf_idx);

		spi_message_init(&m);

		if (mcp251x_enable_dma) {
			t.tx_dma = priv->spi_tx_dma;
			t.rx_dma = priv->spi_rx_dma;
			m.is_dma_mapped = 1;
		}

		spi_message_add_tail(&t, &m);

		ret = spi_sync(spi, &m);

		if (ret < 0) {
			dev_dbg(&spi->dev, "%s: failed: ret = %d\n",
				__func__, ret);
			priv->net->stats.rx_errors++;
			mutex_unlock(&priv->spi_lock);
			return;
		}

		if ((rx_buf[2] >> 3) & 0x1) {
			/* Extended ID format */
			frame->can_id = CAN_EFF_FLAG;
			frame->can_id |= ((rx_buf[2] & 3) << 16) |
			  (rx_buf[3] << 8) | rx_buf[4] |
			  (((rx_buf[1] << 3) | (rx_buf[2] >> 5)) << 18);
		} else {
			/* Standard ID format */
			frame->can_id = (rx_buf[1] << 3) | (rx_buf[2] >> 5);
		}

		if ((rx_buf[5] >> 6) & 0x1) {
			/* Remote transmission request */
			frame->can_id |= CAN_RTR_FLAG;
		}

		/* Data length */
		frame->can_dlc = rx_buf[5] & 0x0f;
		if (frame->can_dlc > 8) {
			dev_warn(&spi->dev, "invalid frame recevied\n");
			priv->net->stats.rx_errors++;
			dev_kfree_skb(skb);
			mutex_unlock(&priv->spi_lock);
			return;
		}

		memcpy(frame->data, rx_buf + 6, CAN_FRAME_MAX_DATA_LEN);

		mutex_unlock(&priv->spi_lock);
	}

	priv->net->stats.rx_packets++;
	priv->net->stats.rx_bytes += frame->can_dlc;

	skb->protocol = __constant_htons(ETH_P_CAN);
	skb->pkt_type = PACKET_BROADCAST;
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	netif_rx(skb);
}

static void mcp251x_hw_sleep(struct spi_device *spi)
{
	mcp251x_write_reg(spi, CANCTRL, CANCTRL_REQOP_SLEEP);
}

static void mcp251x_hw_wakeup(struct spi_device *spi)
{
	struct mcp251x_priv *priv = dev_get_drvdata(&spi->dev);

	priv->wake = 1;

	/* Can only wake up by generating a wake-up interrupt. */
	mcp251x_write_bits(spi, CANINTE, CANINTE_WAKIE, CANINTE_WAKIE);
	mcp251x_write_bits(spi, CANINTF, CANINTF_WAKIF, CANINTF_WAKIF);

	/* Wait until the device is awake */
	if (!wait_for_completion_timeout(&priv->awake, HZ))
		dev_err(&spi->dev, "MCP251x didn't wake-up\n");
}

static int mcp251x_hard_start_xmit(struct sk_buff *skb, struct net_device *net)
{
	struct mcp251x_priv *priv = netdev_priv(net);
	struct spi_device *spi = priv->spi;

	dev_dbg(&spi->dev, "%s\n", __func__);

	if (priv->tx_skb) {
		dev_warn(&spi->dev, "hard_xmit called with not null tx_skb\n");
		return NETDEV_TX_BUSY;
	}

	if (skb->len != sizeof(struct can_frame)) {
		dev_dbg(&spi->dev, "dropping packet - bad length\n");
		dev_kfree_skb(skb);
		net->stats.tx_dropped++;
		return 0;
	}

	netif_stop_queue(net);
	priv->tx_skb = skb;
	net->trans_start = jiffies;
	queue_work(priv->wq, &priv->tx_work);

	return NETDEV_TX_OK;
}

static int mcp251x_do_set_mode(struct net_device *net, enum can_mode mode)
{
	struct mcp251x_priv *priv = netdev_priv(net);
	struct spi_device *spi = priv->spi;

	dev_dbg(&spi->dev, "%s (unimplemented)\n", __func__);

	switch (mode) {
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static void mcp251x_set_normal_mode(struct spi_device *spi)
{
	struct mcp251x_priv *priv = dev_get_drvdata(&spi->dev);
	unsigned long timeout;

	/* Enable interrupts */
	mcp251x_write_reg(spi, CANINTE,
		CANINTE_ERRIE | CANINTE_TX2IE | CANINTE_TX1IE |
		CANINTE_TX0IE | CANINTE_RX1IE | CANINTE_RX0IE);

	if (priv->can.ctrlmode & CAN_CTRLMODE_LOOPBACK) {
		/* Put device into loopback mode */
		mcp251x_write_reg(spi, CANCTRL, CANCTRL_REQOP_LOOPBACK);
	} else {
		/* Put device into normal mode */
		mcp251x_write_reg(spi, CANCTRL, CANCTRL_REQOP_NORMAL);

		/* Wait for the device to enter normal mode */
		timeout = jiffies + HZ;
		while (mcp251x_read_reg(spi, CANSTAT) & 0xE0) {
			udelay(10);
			if (time_after(jiffies, timeout)) {
				dev_err(&spi->dev, "MCP251x didn't"
					" enter in normal mode\n");
				break;
			}
		}
	}
}

static int mcp251x_do_set_bittiming(struct net_device *net)
{
	struct mcp251x_priv *priv = netdev_priv(net);
	struct can_bittiming *bt = &priv->can.bittiming;
	struct spi_device *spi = priv->spi;
	u8 state;

	dev_dbg(&spi->dev, "%s: BRP = %d, PropSeg = %d, PS1 = %d,"
		" PS2 = %d, SJW = %d\n", __func__, bt->brp,
		bt->prop_seg, bt->phase_seg1, bt->phase_seg2,
		bt->sjw);

	/* Store original mode and set mode to config */
	state = mcp251x_read_reg(spi, CANCTRL);
	state = mcp251x_read_reg(spi, CANSTAT) & CANCTRL_REQOP_MASK;
	mcp251x_write_bits(spi, CANCTRL, CANCTRL_REQOP_MASK,
			   CANCTRL_REQOP_CONF);

	mcp251x_write_reg(spi, CNF1, ((bt->sjw - 1) << 6) | (bt->brp - 1));
	mcp251x_write_reg(spi, CNF2, CNF2_BTLMODE |
			  ((bt->phase_seg1 - 1) << 3) |
			  (bt->prop_seg - 1));
	mcp251x_write_bits(spi, CNF3, CNF3_PHSEG2_MASK,
			   (bt->phase_seg2 - 1));

	/* Restore original state */
	mcp251x_write_bits(spi, CANCTRL, CANCTRL_REQOP_MASK, state);

	return 0;
}

static void mcp251x_setup(struct net_device *net, struct mcp251x_priv *priv,
			  struct spi_device *spi)
{
	int ret;

	/* Set initial baudrate. Make sure that registers are updated
	   always by explicitly calling mcp251x_do_set_bittiming */
	ret = can_set_bittiming(net);
	if (ret)
		dev_err(&spi->dev, "unable to set initial baudrate!\n");
	else
		mcp251x_do_set_bittiming(net);

	/* Enable RX0->RX1 buffer roll over and disable filters */
	mcp251x_write_bits(spi, RXBCTRL(0),
			   RXBCTRL_BUKT | RXBCTRL_RXM0 | RXBCTRL_RXM1,
			   RXBCTRL_BUKT | RXBCTRL_RXM0 | RXBCTRL_RXM1);
	mcp251x_write_bits(spi, RXBCTRL(1),
			   RXBCTRL_RXM0 | RXBCTRL_RXM1,
			   RXBCTRL_RXM0 | RXBCTRL_RXM1);

	dev_dbg(&spi->dev, "%s RXBCTL 0 and 1: %02x %02x\n", __func__,
		mcp251x_read_reg(spi, RXBCTRL(0)),
		mcp251x_read_reg(spi, RXBCTRL(1)));
}

static void mcp251x_hw_reset(struct spi_device *spi)
{
	struct mcp251x_priv *priv = dev_get_drvdata(&spi->dev);
	int ret;

	mutex_lock(&priv->spi_lock);

	priv->spi_tx_buf[0] = INSTRUCTION_RESET;

	ret = spi_write(spi, priv->spi_tx_buf, 1);

	mutex_unlock(&priv->spi_lock);

	if (ret < 0)
		dev_dbg(&spi->dev, "%s: failed: ret = %d\n", __func__, ret);
	/* wait for reset to finish */
	mdelay(10);
}

static int mcp251x_hw_probe(struct spi_device *spi)
{
	int st1, st2;

	mcp251x_hw_reset(spi);

	st1 = mcp251x_read_reg(spi, CANSTAT) & 0xEE;
	st2 = mcp251x_read_reg(spi, CANCTRL) & 0x17;

	dev_dbg(&spi->dev, "%s: 0x%02x - 0x%02x\n", __func__,
		st1, st2);

	/* check for power up default values */
	return (st1 == 0x80 && st2 == 0x07) ? 1 : 0;
}

static int mcp251x_open(struct net_device *net)
{
	struct mcp251x_priv *priv = netdev_priv(net);
	struct spi_device *spi = priv->spi;
	struct mcp251x_platform_data *pdata = spi->dev.platform_data;

	dev_dbg(&spi->dev, "%s\n", __func__);

	if (pdata->transceiver_enable)
		pdata->transceiver_enable(1);

	priv->force_quit = 0;
	priv->tx_skb = NULL;
	enable_irq(spi->irq);
	mcp251x_hw_wakeup(spi);
	mcp251x_hw_reset(spi);
	mcp251x_setup(net, priv, spi);
	mcp251x_set_normal_mode(spi);
	netif_wake_queue(net);

	return 0;
}

static int mcp251x_stop(struct net_device *net)
{
	struct mcp251x_priv *priv = netdev_priv(net);
	struct spi_device *spi = priv->spi;
	struct mcp251x_platform_data *pdata = spi->dev.platform_data;

	dev_dbg(&spi->dev, "%s\n", __func__);

	/* Disable and clear pending interrupts */
	mcp251x_write_reg(spi, CANINTE, 0x00);
	mcp251x_write_reg(spi, CANINTF, 0x00);

	priv->force_quit = 1;
	disable_irq(spi->irq);
	flush_workqueue(priv->wq);

	mcp251x_write_reg(spi, TXBCTRL(0), 0);
	if (priv->tx_skb) {
		net->stats.tx_errors++;
		dev_kfree_skb(priv->tx_skb);
		priv->tx_skb = NULL;
	}

	mcp251x_hw_sleep(spi);

	if (pdata->transceiver_enable)
		pdata->transceiver_enable(0);

	return 0;
}

static int mcp251x_do_get_state(struct net_device *net, enum can_state	*state)
{
	struct mcp251x_priv *priv = netdev_priv(net);
	struct spi_device *spi = priv->spi;
	u8 eflag;

	eflag = mcp251x_read_reg(spi, EFLG);

	if (eflag & EFLG_TXBO)
		*state = CAN_STATE_BUS_OFF;
	else if (eflag & (EFLG_RXEP | EFLG_TXEP))
		*state = CAN_STATE_BUS_PASSIVE;
	else if (eflag & EFLG_EWARN)
		*state = CAN_STATE_BUS_WARNING;
	else
		*state = CAN_STATE_ACTIVE;

	return 0;
}

static void mcp251x_tx_work_handler(struct work_struct *ws)
{
	struct mcp251x_priv *priv = container_of(ws, struct mcp251x_priv,
						 tx_work);
	struct spi_device *spi = priv->spi;
	struct can_frame *frame;

	dev_dbg(&spi->dev, "%s\n", __func__);

	if (priv->tx_skb) {
		frame = (struct can_frame *)priv->tx_skb->data;
		if (frame->can_dlc > CAN_FRAME_MAX_DATA_LEN)
			frame->can_dlc = CAN_FRAME_MAX_DATA_LEN;
		mcp251x_hw_tx(spi, frame, 0);
	}
}

static void mcp251x_irq_work_handler(struct work_struct *ws)
{
	struct mcp251x_priv *priv = container_of(ws, struct mcp251x_priv,
						 irq_work);
	struct spi_device *spi = priv->spi;
	struct net_device *net = priv->net;
	u8 intf;
	u8 txbnctrl;

	if (priv->after_suspend) {
		/* Wait whilst the device wakes up */
		mdelay(10);
		mcp251x_hw_reset(spi);
		mcp251x_setup(net, priv, spi);
		if (priv->after_suspend & AFTER_SUSPEND_UP) {
			netif_device_attach(net);
			/* clear since we lost tx buffer */
			if (priv->tx_skb) {
				net->stats.tx_errors++;
				dev_kfree_skb(priv->tx_skb);
				priv->tx_skb = NULL;
				netif_wake_queue(net);
			}
			mcp251x_set_normal_mode(spi);
		} else
			mcp251x_hw_sleep(spi);
		priv->after_suspend = 0;
		return;
	}

	while (!priv->force_quit && !freezing(current)) {
		if (priv->restart_tx) {
			priv->restart_tx = 0;
			dev_warn(&spi->dev,
				 "timeout in txing a packet, restarting\n");
			mcp251x_write_reg(spi, TXBCTRL(0), 0);
			if (priv->tx_skb) {
				net->stats.tx_errors++;
				dev_kfree_skb(priv->tx_skb);
				priv->tx_skb = NULL;
			}
			netif_wake_queue(net);
		}

		if (priv->wake) {
			/* Wait whilst the device wakes up */
			mdelay(10);
			priv->wake = 0;
		}

		intf = mcp251x_read_reg(spi, CANINTF);
		if (intf == 0x00)
			break;
		mcp251x_write_bits(spi, CANINTF, intf, 0x00);

		dev_dbg(&spi->dev, "interrupt:%s%s%s%s%s%s%s%s\n",
			(intf & CANINTF_MERRF) ? " MERR" : "",
			(intf & CANINTF_WAKIF) ? " WAK" : "",
			(intf & CANINTF_ERRIF) ? " ERR" : "",
			(intf & CANINTF_TX2IF) ? " TX2" : "",
			(intf & CANINTF_TX1IF) ? " TX1" : "",
			(intf & CANINTF_TX0IF) ? " TX0" : "",
			(intf & CANINTF_RX1IF) ? " RX1" : "",
			(intf & CANINTF_RX0IF) ? " RX0" : "");

		if (intf & CANINTF_WAKIF)
			complete(&priv->awake);

		if (intf & CANINTF_MERRF) {
			/* if there are no pending Tx buffers, restart queue */
			txbnctrl = mcp251x_read_reg(spi, TXBCTRL(0));
			if (!(txbnctrl & TXBCTRL_TXREQ)) {
				if (priv->tx_skb) {
					net->stats.tx_errors++;
					dev_kfree_skb(priv->tx_skb);
					priv->tx_skb = NULL;
				}
				netif_wake_queue(net);
			}
		}

		if (intf & CANINTF_ERRIF) {
			struct sk_buff *skb;
			struct can_frame *frame = NULL;
			u8 eflag = mcp251x_read_reg(spi, EFLG);

			dev_dbg(&spi->dev, "EFLG = 0x%02x\n", eflag);

			/* Create error frame */
			skb = dev_alloc_skb(sizeof(struct can_frame));
			if (skb) {
				frame = (struct can_frame *)
					skb_put(skb, sizeof(struct can_frame));
				*(unsigned long long *)&frame->data = 0ULL;
				frame->can_id = CAN_ERR_FLAG;
				frame->can_dlc = CAN_ERR_DLC;

				skb->dev = net;
				skb->protocol = __constant_htons(ETH_P_CAN);
				skb->pkt_type = PACKET_BROADCAST;
				skb->ip_summed = CHECKSUM_UNNECESSARY;

				/* Set error frame flags based on bus state */
				if (eflag & EFLG_TXBO) {
					frame->can_id |= CAN_ERR_BUSOFF;
				} else if (eflag & EFLG_TXEP) {
					frame->can_id |= CAN_ERR_CRTL;
					frame->data[1] |=
					  CAN_ERR_CRTL_TX_PASSIVE;
				} else if (eflag & EFLG_RXEP) {
					frame->can_id |= CAN_ERR_CRTL;
					frame->data[1] |=
					  CAN_ERR_CRTL_RX_PASSIVE;
				} else if (eflag & EFLG_TXWAR) {
					frame->can_id |= CAN_ERR_CRTL;
					frame->data[1] |=
					  CAN_ERR_CRTL_TX_WARNING;
				} else if (eflag & EFLG_RXWAR) {
					frame->can_id |= CAN_ERR_CRTL;
					frame->data[1] |=
					  CAN_ERR_CRTL_RX_WARNING;
				}
			}

			if (eflag & (EFLG_RX0OVR | EFLG_RX1OVR)) {
				if (eflag & EFLG_RX0OVR)
					net->stats.rx_over_errors++;
				if (eflag & EFLG_RX1OVR)
					net->stats.rx_over_errors++;
				if (frame) {
					frame->can_id |= CAN_ERR_CRTL;
					frame->data[1] =
					  CAN_ERR_CRTL_RX_OVERFLOW;
				}
			}
			mcp251x_write_reg(spi, EFLG, 0x00);

			if (skb)
				netif_rx(skb);
		}

		if (intf & (CANINTF_TX2IF | CANINTF_TX1IF | CANINTF_TX0IF)) {
			if (priv->tx_skb) {
				net->stats.tx_packets++;
				net->stats.tx_bytes +=
					((struct can_frame *)
					 (priv->tx_skb->data))->can_dlc;
				dev_kfree_skb(priv->tx_skb);
				priv->tx_skb = NULL;
			}
			netif_wake_queue(net);
		}

		if (intf & CANINTF_RX0IF)
			mcp251x_hw_rx(spi, 0);

		if (intf & CANINTF_RX1IF)
			mcp251x_hw_rx(spi, 1);

	}

	mcp251x_read_reg(spi, CANSTAT);

	dev_dbg(&spi->dev, "interrupt ended\n");
}

static irqreturn_t mcp251x_can_isr(int irq, void *dev_id)
{
	struct net_device *net = (struct net_device *)dev_id;
	struct mcp251x_priv *priv = netdev_priv(net);

	dev_dbg(&priv->spi->dev, "%s: irq\n", __func__);
	/* Schedule bottom half */
	if (!work_pending(&priv->irq_work))
		queue_work(priv->wq, &priv->irq_work);

	return IRQ_HANDLED;
}

static void mcp251x_tx_timeout(struct net_device *net)
{
	struct mcp251x_priv *priv = netdev_priv(net);

	priv->restart_tx = 1;
	queue_work(priv->wq, &priv->irq_work);
}

static struct net_device *alloc_mcp251x_netdev(int sizeof_priv)
{
	struct net_device *net;
	struct mcp251x_priv *priv;

	net = alloc_candev(sizeof_priv);
	if (!net)
		return NULL;

	priv = netdev_priv(net);

	net->open		= mcp251x_open;
	net->stop		= mcp251x_stop;
	net->hard_start_xmit	= mcp251x_hard_start_xmit;
	net->tx_timeout		= mcp251x_tx_timeout;
	net->watchdog_timeo	= HZ;

	priv->can.bittiming_const = &mcp251x_bittiming_const;
	priv->can.do_get_state	  = mcp251x_do_get_state;
	priv->can.do_set_mode	  = mcp251x_do_set_mode;

	priv->net = net;

	return net;
}

static int __devinit mcp251x_can_probe(struct spi_device *spi)
{
	struct net_device *net;
	struct mcp251x_priv *priv;
	struct mcp251x_platform_data *pdata = spi->dev.platform_data;
	int ret = -ENODEV;

	if (!pdata) {
		/* Platform data is required for osc freq */
		goto error_out;
	}

	/* Allocate can/net device */
	net = alloc_mcp251x_netdev(sizeof(struct mcp251x_priv));
	if (!net) {
		ret = -ENOMEM;
		goto error_alloc;
	}

	priv = netdev_priv(net);
	dev_set_drvdata(&spi->dev, priv);

	priv->spi = spi;
	mutex_init(&priv->spi_lock);

	priv->can.bittiming.clock = pdata->oscillator_frequency / 2;

	/* If requested, allocate DMA buffers */
	if (mcp251x_enable_dma) {
		spi->dev.coherent_dma_mask = DMA_32BIT_MASK;

		/* Minimum coherent DMA allocation is PAGE_SIZE, so allocate
		   that much and share it between Tx and Rx DMA buffers. */
		priv->spi_tx_buf = dma_alloc_coherent(&spi->dev,
			PAGE_SIZE, &priv->spi_tx_dma, GFP_DMA);

		if (priv->spi_tx_buf) {
			priv->spi_rx_buf = (u8 *)(priv->spi_tx_buf +
				(PAGE_SIZE / 2));
			priv->spi_rx_dma = (dma_addr_t)(priv->spi_tx_dma +
				(PAGE_SIZE / 2));
		} else {
			/* Fall back to non-DMA */
			mcp251x_enable_dma = 0;
		}
	}

	/* Allocate non-DMA buffers */
	if (!mcp251x_enable_dma) {
		priv->spi_tx_buf = kmalloc(SPI_TRANSFER_BUF_LEN, GFP_KERNEL);
		if (!priv->spi_tx_buf) {
			ret = -ENOMEM;
			goto error_tx_buf;
		}
		priv->spi_rx_buf = kmalloc(SPI_TRANSFER_BUF_LEN, GFP_KERNEL);
		if (!priv->spi_tx_buf) {
			ret = -ENOMEM;
			goto error_rx_buf;
		}
	}

	if (pdata->power_enable)
		pdata->power_enable(1);

	/* Call out to platform specific setup */
	if (pdata->board_specific_setup)
		pdata->board_specific_setup(spi);

	SET_NETDEV_DEV(net, &spi->dev);

	priv->wq = create_freezeable_workqueue("mcp251x_wq");

	INIT_WORK(&priv->tx_work, mcp251x_tx_work_handler);
	INIT_WORK(&priv->irq_work, mcp251x_irq_work_handler);

	init_completion(&priv->awake);

	/* Configure the SPI bus */
	spi->mode = SPI_MODE_0;
	spi->bits_per_word = 8;
	spi_setup(spi);

	/* Register IRQ */
	if (request_irq(spi->irq, mcp251x_can_isr,
			IRQF_TRIGGER_FALLING, DEVICE_NAME, net) < 0) {
		dev_err(&spi->dev, "failed to acquire irq %d\n", spi->irq);
		goto error_irq;
	}
	disable_irq(spi->irq);

	if (!mcp251x_hw_probe(spi)) {
		dev_info(&spi->dev, "Probe failed\n");
		goto error_probe;
	}
	mcp251x_hw_sleep(spi);

	if (pdata->transceiver_enable)
		pdata->transceiver_enable(0);

	ret = register_candev(net);
	if (ret >= 0) {
		dev_info(&spi->dev, "probed\n");
		return ret;
	}
error_probe:
	free_irq(spi->irq, net);
error_irq:
	if (!mcp251x_enable_dma)
		kfree(priv->spi_rx_buf);
error_rx_buf:
	if (!mcp251x_enable_dma)
		kfree(priv->spi_tx_buf);
error_tx_buf:
	free_candev(net);
	if (mcp251x_enable_dma) {
		dma_free_coherent(&spi->dev, PAGE_SIZE,
			priv->spi_tx_buf, priv->spi_tx_dma);
	}
error_alloc:
	dev_err(&spi->dev, "probe failed\n");
error_out:
	return ret;
}

static int __devexit mcp251x_can_remove(struct spi_device *spi)
{
	struct mcp251x_platform_data *pdata = spi->dev.platform_data;
	struct mcp251x_priv *priv = dev_get_drvdata(&spi->dev);
	struct net_device *net = priv->net;

	unregister_candev(net);
	free_candev(net);

	free_irq(spi->irq, net);
	priv->force_quit = 1;
	flush_workqueue(priv->wq);
	destroy_workqueue(priv->wq);

	if (mcp251x_enable_dma) {
		dma_free_coherent(&spi->dev, PAGE_SIZE,
			priv->spi_tx_buf, priv->spi_tx_dma);
	} else {
		kfree(priv->spi_tx_buf);
		kfree(priv->spi_rx_buf);
	}

	if (pdata->power_enable)
		pdata->power_enable(0);

	return 0;
}

#ifdef CONFIG_PM
static int mcp251x_can_suspend(struct spi_device *spi, pm_message_t state)
{
	struct mcp251x_platform_data *pdata = spi->dev.platform_data;
	struct mcp251x_priv *priv = dev_get_drvdata(&spi->dev);
	struct net_device *net = priv->net;

	if (netif_running(net)) {
		netif_device_detach(net);

		mcp251x_hw_sleep(spi);
		if (pdata->transceiver_enable)
			pdata->transceiver_enable(0);
		priv->after_suspend = AFTER_SUSPEND_UP;
	} else
		priv->after_suspend = AFTER_SUSPEND_DOWN;

	if (pdata->power_enable) {
		pdata->power_enable(0);
		priv->after_suspend |= AFTER_SUSPEND_POWER;
	}

	return 0;
}

static int mcp251x_can_resume(struct spi_device *spi)
{
	struct mcp251x_platform_data *pdata = spi->dev.platform_data;
	struct mcp251x_priv *priv = dev_get_drvdata(&spi->dev);

	if (priv->after_suspend & AFTER_SUSPEND_POWER) {
		pdata->power_enable(1);
		queue_work(priv->wq, &priv->irq_work);
	} else {
		if (priv->after_suspend & AFTER_SUSPEND_UP) {
			if (pdata->transceiver_enable)
				pdata->transceiver_enable(1);
			queue_work(priv->wq, &priv->irq_work);
		} else
			priv->after_suspend = 0;
	}
	return 0;
}
#else
#define mcp251x_can_suspend NULL
#define mcp251x_can_resume NULL
#endif

static struct spi_driver mcp251x_can_driver = {
	.driver = {
		.name		= DEVICE_NAME,
		.bus		= &spi_bus_type,
		.owner		= THIS_MODULE,
	},

	.probe		= mcp251x_can_probe,
	.remove		= __devexit_p(mcp251x_can_remove),
	.suspend	= mcp251x_can_suspend,
	.resume		= mcp251x_can_resume,
};

static int __init mcp251x_can_init(void)
{
	return spi_register_driver(&mcp251x_can_driver);
}

static void __exit mcp251x_can_exit(void)
{
	spi_unregister_driver(&mcp251x_can_driver);
}

module_init(mcp251x_can_init);
module_exit(mcp251x_can_exit);

MODULE_AUTHOR("Chris Elston <celston@katalix.com>, "
	      "Christian Pellegrin <chripell@evolware.org>");
MODULE_DESCRIPTION("Microchip 251x CAN driver");
MODULE_LICENSE("GPL v2");
