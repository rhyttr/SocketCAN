/*
 * Copyright (C) 2009 Thomas Koerper <thomas.koerper@esd.eu>, esd gmbh
 * derived from kernel/2.6/drivers/net/can/sja1000/esd_pci.c,
 * * Copyright (C) 2007 Wolfgang Grandegger <wg@grandegger.com>
 * * Copyright (C) 2008 Sascha Hauer <s.hauer@pengutronix.de>, Pengutronix
 * * Copyright (C) 2009 Matthias Fuchs <matthias.fuchs@esd.eu>, esd gmbh
 * and kernel/2.6/drivers/net/can/at91_can.c,
 * * Copyright (C) 2007 by Hans J. Koch <hjk@linutronix.de>
 * * Copyright (C) 2008 by Marc Kleine-Budde <kernel@pengutronix.de
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
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/byteorder/generic.h>
#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <socketcan/can.h>
#include <socketcan/can/error.h>
#include <socketcan/can/dev.h>

#define DRV_NAME "esd_pci331"

MODULE_AUTHOR("Thomas Koerper <thomas.koerper@esd.eu>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Socket-CAN driver for the esd 331 CAN cards");
MODULE_DEVICE_TABLE(pci, esd331_pci_tbl);
MODULE_SUPPORTED_DEVICE("esd CAN-PCI/331, CAN-CPCI/331, CAN-PMC/331");

#ifndef PCI_DEVICE_ID_PLX_9030
# define PCI_DEVICE_ID_PLX_9030	0x9030
#endif
#ifndef PCI_DEVICE_ID_PLX_9050
# define PCI_DEVICE_ID_PLX_9050	0x9050
#endif
#ifndef PCI_VENDOR_ID_ESDGMBH
#define PCI_VENDOR_ID_ESDGMBH   0x12fe
#endif

#define ESD_PCI_SUB_SYS_ID_PCI331 0x0001
#define ESD_PCI_SUB_SYS_ID_PMC331 0x000C

/* Maximum number of interfaces supported per card */
#define ESD331_MAX_CAN			2
/* 331's fifo size. Don't change! */
#define ESD331_DPRSIZE			1024
/* Max. messages to handle per interrupt */
#define ESD331_MAX_INTERRUPT_WORK	8
#define ESD331_MAX_BOARD_MESSAGES	5
#define ESD331_RTR_FLAG			0x10
#define ESD331_ERR_OK			0x00
#define ESD331_ERR_WARN			0x40
#define ESD331_ERR_BUSOFF1		0x80
#define ESD331_ERR_BUSOFF2		0xc0
#define ESD331_CONF_OFFS_ICS		0x4c
#define ESD331_CONF_OFFS_MISC_CTRL	0x50
#define ESD331_OFFS_LINK_BASE		0x846
#define ESD331_OFFS_IRQ_ACK		0xc0100
#define ESD331_NETS_MASK		0x07
#define ESD331_EVENT_MASK		0x7f
#define ESD331_DLC_MASK			0x0f
#define ESD331_EFF_SUPP_FLAG		0x80
#define ESD331_IRQ_FLAG			0x00000004
#define ESD331_ENABLE_IRQ_FLAG		0x00000041
#define ESD331_STOP_OS			0x40000010
#define ESD331_RESTART_OS		0x40000028

#define ESD331_I20_BCAN			0
#define ESD331_I20_ENABLE		1
#define ESD331_I20_BAUD			4
#define ESD331_I20_TXDONE		5
#define ESD331_I20_TXTOUT		12
#define ESD331_I20_ERROR		13
#define ESD331_I20_BOARD		14
#define ESD331_I20_EX_BCAN		15
#define ESD331_I20_EX_TXDONE		16
#define ESD331_I20_EX_TXTOUT		17
#define ESD331_I20_BOARD2		20
#define ESD331_I20_FAST			21

#define ESD331_ECHO_SKB_MAX		1

static struct pci_device_id esd331_pci_tbl[] = {
	{PCI_VENDOR_ID_PLX, PCI_DEVICE_ID_PLX_9050,
	PCI_VENDOR_ID_ESDGMBH, ESD_PCI_SUB_SYS_ID_PCI331},
	{PCI_VENDOR_ID_PLX, PCI_DEVICE_ID_PLX_9030,
	PCI_VENDOR_ID_ESDGMBH, ESD_PCI_SUB_SYS_ID_PMC331},
	{0, }
};

struct esd331_can_msg {
	u8 cmmd;
	u8 net;
	s16 id;
	s16 len;
	u8 data[8];
	u16 x1;
	u16 x2;
	u16 x3;
} __attribute__((packed));
#define ESD331_CM_SSIZE (sizeof(struct esd331_can_msg) / sizeof(u16))

struct esd331_idp {
	u8 dummy[16];
	u8 buffer[4];
} __attribute__((packed));

struct esd331_dpr {
	char magic[16];
	u16 rx_in;
	u16 dummy1;
	u16 rx_ou;
	u16 dummy2;
	struct esd331_can_msg rx_buff[ESD331_DPRSIZE];
	u16 tx_in;
	u16 dummy3;
	u16 tx_ou;
	u16 dummy4;
	struct esd331_can_msg tx_buff[ESD331_DPRSIZE];
} __attribute__((packed));

struct esd331_pci {
	struct pci_dev *pci_dev;
	struct net_device *dev[ESD331_MAX_CAN];
	void __iomem *conf_addr;
	void __iomem *base_addr1;
	void __iomem *base_addr2;
	spinlock_t irq_lock; /* locks access to card's fifo */
	struct esd331_dpr *dpr;
	int eff_supp;
	int net_count;
};

struct esd331_priv {
	struct can_priv can; /* must be the first member! */
	struct esd331_pci *board;
	u8 boards_net;
};

struct esd331_baud_entry {
	u32 rate;
	u16 index;
};

static struct esd331_baud_entry esd331_baud_table[] = {
	{1600000, 15},
	{1000000, 0},
	{800000, 14},
	{666666, 1},
	{500000, 2},
	{333333, 3},
	{250000, 4},
	{166666, 5},
	{125000, 6},
	{100000, 7},
	{83333, 16},
	{66666, 8},
	{50000, 9},
	{33333, 10},
	{20000, 11},
	{12500, 12},
	{10000, 13}
};

static void esd331_reset(void *pci331_confspace, int wait_for_restart)
{
	unsigned long data;
	void __iomem *addr = pci331_confspace + ESD331_CONF_OFFS_MISC_CTRL;

	data = readl(addr);
	data |= ESD331_STOP_OS;
	writel(data, addr);
	msleep(10);

	data = readl(addr);
	data &= ~ESD331_RESTART_OS;
	writel(data, addr);

	if (wait_for_restart)
		msleep_interruptible(3500);
}

static struct esd331_dpr *esd331_init_pointer(void __iomem *pci331_space2)
{
	unsigned long data;
	struct esd331_idp *idp;
	void __iomem *ptr = pci331_space2 + ESD331_OFFS_LINK_BASE;

	data = readb(ptr++);
	data = (data << 8) + readb(ptr++);
	data = (data << 8) + readb(ptr++);
	data = (data << 8) + readb(ptr++);

	idp = (struct esd331_idp *)(pci331_space2 + data);
	data = idp->buffer[0];
	data = (data << 8) + idp->buffer[1];
	data = (data << 8) + idp->buffer[2];
	data = (data << 8) + idp->buffer[3];

	return (struct esd331_dpr *)(pci331_space2 + data);
}

static void esd331_enable_irq(void *pci331_confspace)
{
	void __iomem *addr = pci331_confspace + ESD331_CONF_OFFS_ICS;
	u32 data;

	data = readl(addr);
	data |= ESD331_ENABLE_IRQ_FLAG;
	writel(data, addr);
}

static void esd331_disable_irq(void *pci331_confspace)
{
	void __iomem *addr = pci331_confspace + ESD331_CONF_OFFS_ICS;
	u32 data;

	data = readl(addr);
	data &= ~ESD331_ENABLE_IRQ_FLAG;
	writel(data, addr);
}

static int esd331_write(struct esd331_can_msg *mesg, struct esd331_pci *board)
{
	u16 in;
	u16 in_new;
	u16 out;
	unsigned long irq_flags;
	int err = -EAGAIN; /* = card's fifo full */
	int i;

	spin_lock_irqsave(&board->irq_lock, irq_flags);

	out = be16_to_cpu(readw(&board->dpr->rx_ou));
	in = be16_to_cpu(readw(&board->dpr->rx_in));

	in_new = (in + 1) % ESD331_DPRSIZE;

	if (in_new != out) {
		u16 *ptr1;
		u16 *ptr2;

		ptr1 = (u16 *)mesg;
		ptr2 = (u16 *)&board->dpr->rx_buff[in];
		for (i = 0; i < ESD331_CM_SSIZE; i++)
			writew(*ptr1++, ptr2++);

		in_new = cpu_to_be16(in_new);
		wmb();
		writew(in_new, &board->dpr->rx_in);

		err = 0;
	}

	spin_unlock_irqrestore(&board->irq_lock, irq_flags);
	return err;
}

static int esd331_read(struct esd331_can_msg *mesg, struct esd331_pci *board)
{
	u16 in;
	u16 out;
	unsigned long irq_flags;
	int err = -ENODATA;

	spin_lock_irqsave(&board->irq_lock, irq_flags);

	out = be16_to_cpu(readw(&board->dpr->tx_ou));
	in = be16_to_cpu(readw(&board->dpr->tx_in));

	if (in != out) {
		u16 *ptr1;
		u16 *ptr2;
		int ll;

		ptr1 = (u16 *)mesg;
		ptr2 = (u16 *)&board->dpr->tx_buff[out];
		for (ll = 0; ll < ESD331_CM_SSIZE; ll++)
			*ptr1++ = readw(ptr2++);

		out++;
		out %= ESD331_DPRSIZE;

		wmb();
		writew(cpu_to_be16(out), &board->dpr->tx_ou);

		mesg->id = be16_to_cpu(mesg->id);
		mesg->len = be16_to_cpu(mesg->len);
		mesg->x1 = be16_to_cpu(mesg->x1);
		mesg->x2 = be16_to_cpu(mesg->x2);
		mesg->x3 = be16_to_cpu(mesg->x3);

		err = 0;
	}

	spin_unlock_irqrestore(&board->irq_lock, irq_flags);
	return err;
}

static int esd331_write_allid(u8 net, struct esd331_pci *board)
{
	struct esd331_can_msg mesg;
	u16 id;

	memset(&mesg, 0, sizeof(mesg));

	mesg.cmmd = ESD331_I20_ENABLE;
	mesg.net = net;

	for (id = 0; id < 2048; id++) {
		int retryCount = 5;

		mesg.id = cpu_to_be16(id);

		while (esd331_write(&mesg, board) && (retryCount--))
			msleep(1);

		if (retryCount == 0)
			return -EIO;
	}

	return 0;
}

static int esd331_write_fast(struct esd331_pci *board)
{
	struct esd331_can_msg mesg;

	memset(&mesg, 0, sizeof(mesg));
	mesg.cmmd = ESD331_I20_FAST;

	return esd331_write(&mesg, board);
}

static int esd331_write_baud(u8 pci331net, int index, struct esd331_pci *board)
{
	struct esd331_can_msg mesg;

	memset(&mesg, 0, sizeof(mesg));
	mesg.cmmd = ESD331_I20_BAUD;
	mesg.net = pci331net;
	mesg.data[0] = (u8)(index >> 8);
	mesg.data[1] = (u8)index;

	return esd331_write(&mesg, board);
}

static int esd331_read_features(struct esd331_pci *board)
{
	struct esd331_can_msg msg;
	int max_msg = ESD331_MAX_BOARD_MESSAGES;

	board->net_count = 0;
	board->eff_supp = 0;

	while ((esd331_read(&msg, board) == 0) && (max_msg--)) {
		if (msg.cmmd == ESD331_I20_BOARD) {
			u8 magic = (msg.x1 >> 8);

			if (magic == 0) {
				u8 features = (u8)msg.x1;
				u8 nets = (features & ESD331_NETS_MASK);

				if (nets <= ESD331_MAX_CAN)
					board->net_count = nets;

				if (features & ESD331_EFF_SUPP_FLAG)
					board->eff_supp = 1;
			}
		} else if (msg.cmmd == ESD331_I20_BOARD2) {
			u8 features = msg.net;

			if (features & ESD331_EFF_SUPP_FLAG)
				board->eff_supp = 1;

			if (board->net_count == 0) {
				u8 nets = (features & ESD331_NETS_MASK);

				if (nets <= ESD331_MAX_CAN)
					board->net_count = nets;
			}
		}
	}

	return (board->net_count < 1) ? -EIO : 0;
}

static int esd331_create_err_frame(struct net_device *dev, canid_t idflags,
					u8 d1)
{
	struct net_device_stats *stats;
	struct can_frame *cf;
	struct sk_buff *skb;

	skb = alloc_can_err_skb(dev, &cf);
	if (unlikely(skb == NULL))
		return -ENOMEM;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	stats = can_get_stats(dev);
#else
	stats = &dev->stats;
#endif

	cf->can_id |= idflags;
	cf->data[1] = d1;

	netif_rx(skb);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
	dev->last_rx = jiffies;
#endif
	stats->rx_packets++;
	stats->rx_bytes += cf->can_dlc;

	return 0;
}

static void esd331_irq_rx(struct net_device *dev, struct esd331_can_msg *msg,
				int eff)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	struct net_device_stats *stats = can_get_stats(dev);
#else
	struct net_device_stats *stats = &dev->stats;
#endif
	struct can_frame *cfrm;
	struct sk_buff *skb;
	int i;

	skb = alloc_can_skb(dev, &cfrm);
	if (unlikely(skb == NULL)) {
		stats->rx_dropped++;
		return;
	}

	if (eff) {
		cfrm->can_id = (msg->id << 16);
		cfrm->can_id |= (msg->x2);
	} else {
		cfrm->can_id = msg->id;
	}
	if (msg->len & ESD331_RTR_FLAG)
		cfrm->can_id |= CAN_RTR_FLAG;

	if (eff)
		cfrm->can_id |= CAN_EFF_FLAG;

	cfrm->can_dlc = get_can_dlc(msg->len & ESD331_DLC_MASK);

	for (i = 0; i < cfrm->can_dlc; ++i)
		cfrm->data[i] = msg->data[i];

	netif_rx(skb);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
	dev->last_rx = jiffies;
#endif
	stats->rx_packets++;
	stats->rx_bytes += cfrm->can_dlc;
}

static void esd331_handle_errmsg(struct net_device *dev,
					struct esd331_can_msg *msg)
{
	struct esd331_priv *priv = netdev_priv(dev);

	if (msg->id & ESD331_EVENT_MASK)
		return;

	switch (msg->data[1]) {
	case ESD331_ERR_OK:
		if (priv->can.state != CAN_STATE_STOPPED)
			priv->can.state = CAN_STATE_ERROR_ACTIVE;
		break;

	case ESD331_ERR_WARN:
		if ((priv->can.state != CAN_STATE_ERROR_WARNING)
				&& (priv->can.state != CAN_STATE_STOPPED)) {
			priv->can.can_stats.error_warning++;
			priv->can.state = CAN_STATE_ERROR_WARNING;

			/* might be RX warning, too... */
			esd331_create_err_frame(dev, CAN_ERR_CRTL,
						CAN_ERR_CRTL_TX_WARNING);
		}
		break;

	case ESD331_ERR_BUSOFF1:
	case ESD331_ERR_BUSOFF2:
		if ((priv->can.state != CAN_STATE_BUS_OFF)
				&& (priv->can.state != CAN_STATE_STOPPED)) {
			priv->can.state = CAN_STATE_BUS_OFF;
			esd331_create_err_frame(dev, CAN_ERR_BUSOFF, 0);
			can_bus_off(dev);
		}
		break;

	default:
		break;
	}

}

static void esd331_handle_messages(struct esd331_pci *board)
{
	struct net_device *dev;
	struct esd331_priv *priv;
	struct net_device_stats *stats;
	struct esd331_can_msg msg;
	int msg_count = ESD331_MAX_INTERRUPT_WORK;

	while ((esd331_read(&msg, board) == 0) && (msg_count--)) {
		if (unlikely((msg.net >= ESD331_MAX_CAN)
				|| (board->dev[msg.net] == NULL)))
			continue;

		dev = board->dev[msg.net];
		priv = netdev_priv(dev);
		if (priv->can.state == CAN_STATE_STOPPED)
			continue;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
		stats = can_get_stats(dev);
#else
		stats = &dev->stats;
#endif
		switch (msg.cmmd) {

		case ESD331_I20_BCAN:
		case ESD331_I20_EX_BCAN:
			esd331_irq_rx(dev, &msg,
					(msg.cmmd == ESD331_I20_EX_BCAN));
			break;

		case ESD331_I20_TXDONE:
		case ESD331_I20_EX_TXDONE:
			stats->tx_packets++;
			stats->tx_bytes += msg.x1;
			can_get_echo_skb(dev, 0);
			netif_wake_queue(dev);
			break;

		case ESD331_I20_TXTOUT:
		case ESD331_I20_EX_TXTOUT:
			stats->tx_errors++;
			stats->tx_dropped++;
			can_free_echo_skb(dev, 0);
			netif_wake_queue(dev);
			break;

		case ESD331_I20_ERROR:
			esd331_handle_errmsg(dev, &msg);
			break;

		default:
			break;
		}
	}
}

static int esd331_all_nets_stopped(struct esd331_pci *board)
{
	int i;

	for (i = 0; i < ESD331_MAX_CAN; i++) {
		if (board->dev[i] == NULL) {
			break;
		} else {
			struct esd331_priv *priv = netdev_priv(board->dev[i]);

			if (priv->can.state != CAN_STATE_STOPPED)
				return 0;
		}
	}

	return 1;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
irqreturn_t esd331_interrupt(int irq, void *dev_id, struct pt_regs *regs)
#else
irqreturn_t esd331_interrupt(int irq, void *dev_id)
#endif
{
	struct esd331_pci *board = (struct esd331_pci *)dev_id;
	void __iomem *ics = board->conf_addr + ESD331_CONF_OFFS_ICS;

	if (!(readl(ics) & ESD331_IRQ_FLAG))
		return IRQ_NONE;

	writew(0xffff, board->base_addr2 + ESD331_OFFS_IRQ_ACK);
	esd331_handle_messages(board);

	return IRQ_HANDLED;
}

/* also enables interrupt when no other net on card is openened yet */
static int esd331_open(struct net_device *dev)
{
	struct esd331_priv *priv = netdev_priv(dev);
	int err;

	err = open_candev(dev);
	if (err)
		return err;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	memset(&priv->can.net_stats, 0, sizeof(priv->can.net_stats));
#endif

	if (esd331_all_nets_stopped(priv->board))
		esd331_enable_irq(priv->board->conf_addr);

	priv->can.state = CAN_STATE_ERROR_ACTIVE;
	netif_start_queue(dev);

	return 0;
}

/* also disables interrupt when all other nets on card are closed already*/
static int esd331_close(struct net_device *dev)
{
	struct esd331_priv *priv = netdev_priv(dev);

	priv->can.state = CAN_STATE_STOPPED;
	netif_stop_queue(dev);
	close_candev(dev);

	if (esd331_all_nets_stopped(priv->board))
		esd331_disable_irq(priv->board->conf_addr);

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
static int esd331_start_xmit(struct sk_buff *skb, struct net_device *dev)
#else
static netdev_tx_t esd331_start_xmit(struct sk_buff *skb,
					struct net_device *dev)
#endif
{
	struct esd331_priv *priv = netdev_priv(dev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	struct net_device_stats *stats = can_get_stats(dev);
#else
	struct net_device_stats *stats = &dev->stats;
#endif
	struct can_frame *cf = (struct can_frame *)skb->data;
	struct esd331_can_msg msg;
	int i;

	if (can_dropped_invalid_skb(dev, skb))
		return NETDEV_TX_OK;

	if ((cf->can_id & CAN_EFF_FLAG) && (priv->board->eff_supp == 0)) {
		stats->tx_dropped++;
		kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	memset(&msg, 0, sizeof(msg));
	if (cf->can_id & CAN_EFF_FLAG) {
		msg.cmmd = ESD331_I20_EX_BCAN;
		msg.id = cpu_to_be16((cf->can_id & CAN_EFF_MASK) >> 16);
		msg.x2 = cpu_to_be16(cf->can_id & CAN_EFF_MASK);
	} else {
		msg.cmmd = ESD331_I20_BCAN;
		msg.id = cpu_to_be16(cf->can_id & CAN_EFF_MASK);
	}
	msg.x1 = cpu_to_be16(cf->can_dlc);
	msg.net = priv->boards_net;
	msg.len = cpu_to_be16((cf->can_id & CAN_RTR_FLAG) ?
				cf->can_dlc | ESD331_RTR_FLAG : cf->can_dlc);

	for (i = 0; i < cf->can_dlc; i++)
		msg.data[i] = cf->data[i];

	can_put_echo_skb(skb, dev, 0);
	if (unlikely(esd331_write(&msg, priv->board))) {
		can_free_echo_skb(dev, 0);
		dev_err(ND2D(dev), "Couldn't write frame to card's FIFO!\n");
		stats->tx_dropped++;
		return NETDEV_TX_OK;
	}

	netif_stop_queue(dev);
	dev->trans_start = jiffies;

	return NETDEV_TX_OK;
}

static int esd331_set_bittiming(struct net_device *dev)
{
	struct esd331_priv *priv = netdev_priv(dev);
	int i;

	for (i = 0; i < ARRAY_SIZE(esd331_baud_table); i++) {
		if (priv->can.bittiming.bitrate == esd331_baud_table[i].rate) {
			return esd331_write_baud(priv->boards_net,
				esd331_baud_table[i].index, priv->board);
		}
	}

	return -EINVAL;
}

static int esd331_set_mode(struct net_device *dev, enum can_mode mode)
{
	struct esd331_priv *priv = netdev_priv(dev);

	switch (mode) {
	case CAN_MODE_START:
		priv->can.state = CAN_STATE_ERROR_ACTIVE;
		if (netif_queue_stopped(dev))
			netif_wake_queue(dev);

		break;

	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,28)
static const struct net_device_ops esd331_netdev_ops = {
	.ndo_open = esd331_open,
	.ndo_stop = esd331_close,
	.ndo_start_xmit = esd331_start_xmit,
};
#endif

static struct net_device *__devinit esd331_pci_add_chan(struct pci_dev *pdev,
		struct esd331_pci *board, u8 boards_net)
{
	struct net_device *dev;
	struct esd331_priv *priv;
	int err;

	dev = alloc_candev(sizeof(*priv), ESD331_ECHO_SKB_MAX);
	if (dev == NULL)
		return ERR_PTR(-ENOMEM);

	priv = netdev_priv(dev);
	priv->boards_net = boards_net;
	priv->board = board;

	SET_NETDEV_DEV(dev, &pdev->dev);

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,28)
	dev->netdev_ops = &esd331_netdev_ops;
#else
	dev->open = esd331_open;
	dev->stop = esd331_close;
	dev->hard_start_xmit = esd331_start_xmit;
#endif

	dev->irq = pdev->irq;
	/* Set and enable PCI interrupts */
	dev->flags |= IFF_ECHO;

	priv->can.do_set_bittiming = esd331_set_bittiming;
	priv->can.do_set_mode = esd331_set_mode;
	priv->can.ctrlmode_supported = CAN_CTRLMODE_3_SAMPLES;

	err = register_candev(dev);
	if (err) {
		dev_err(&pdev->dev, "registering candev failed\n");
		free_netdev(dev);
		return ERR_PTR(err);
	}

	dev_info(&pdev->dev, "device %s registered\n", dev->name);

	return dev;
}

static int __devinit esd331_pci_init_one(struct pci_dev *pdev,
		const struct pci_device_id *ent)
{
	struct esd331_pci *board;
	int err;
	int i;
	int read_features = 0;

	dev_info(&pdev->dev,
			"Initializing device %04x:%04x %04x:%04x\n",
			pdev->vendor, pdev->device,
			pdev->subsystem_vendor, pdev->subsystem_device);

	board = kzalloc(sizeof(*board), GFP_KERNEL);
	if (board == NULL)
		return -ENOMEM;

	err = pci_enable_device(pdev);
	if (err)
		goto failure;

	err = pci_request_regions(pdev, DRV_NAME);
	if (err)
		goto failure;

	board->conf_addr = pci_iomap(pdev, 0, 0);
	if (board->conf_addr == NULL) {
		err = -ENODEV;
		goto failure_release_pci;
	}
	board->base_addr1 = pci_iomap(pdev, 2, 0);
	if (board->base_addr1 == NULL) {
		err = -ENODEV;
		goto failure_iounmap_conf;
	}
	board->base_addr2 = pci_iomap(pdev, 3, 0);
	if (board->base_addr2 == NULL) {
		err = -ENODEV;
		goto failure_iounmap_base1;
	}

	spin_lock_init(&board->irq_lock);

retry_features:
	board->dpr = esd331_init_pointer(board->base_addr1);
	err = esd331_read_features(board);
	if (err) {
		/* esd331_read_features() works only after board reset */
		/* So if failed: reset board and retry: */
		if (!read_features) {
			read_features++;
			esd331_reset(board->conf_addr, 1);
			goto retry_features;
		}

		goto failure_iounmap_base2;
	}

	for (i = 0; i < board->net_count; ++i) {
		board->dev[i] = esd331_pci_add_chan(pdev, board, i);
		if (IS_ERR(board->dev[i])) {
			err = PTR_ERR(board->dev[i]);
			goto failure_iounmap_base2;
		}
		if (esd331_write_allid(i, board)) {
			dev_err(&pdev->dev, "device %s failed to enable all "
						"IDs\n", board->dev[i]->name);
		}
	}

	if (esd331_write_fast(board))
		dev_err(&pdev->dev, "failed to enable fast mode\n");

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
	err = request_irq(pdev->irq, &esd331_interrupt, SA_SHIRQ, "pci331",
			(void *)board);
#else
	err = request_irq(pdev->irq, &esd331_interrupt, IRQF_SHARED, "pci331",
			(void *)board);
#endif
	if (err) {
		err = -EAGAIN;
		goto failure_iounmap_base2;
	}
	pci_set_drvdata(pdev, board);
	return 0;

failure_iounmap_base2:
	pci_iounmap(pdev, board->base_addr2);

failure_iounmap_base1:
	pci_iounmap(pdev, board->base_addr1);

failure_iounmap_conf:
	pci_iounmap(pdev, board->conf_addr);

failure_release_pci:
	pci_release_regions(pdev);

failure:
	kfree(board);

	return err;
}

static void __devexit esd331_pci_remove_one(struct pci_dev *pdev)
{
	struct esd331_pci *board = pci_get_drvdata(pdev);
	int i;

	esd331_disable_irq(board->conf_addr);
	free_irq(pdev->irq, (void *)board);

	for (i = 0; i < ESD331_MAX_CAN; i++) {
		if (board->dev[i] == NULL)
			break;

		unregister_candev(board->dev[i]);
		free_netdev(board->dev[i]);
	}

	esd331_reset(board->conf_addr, 0); /* 0 = No wait for restart here */
	/* If module is reloaded too early, it will try a reset with waiting */

	pci_iounmap(pdev, board->base_addr2);
	pci_iounmap(pdev, board->base_addr1);
	pci_iounmap(pdev, board->conf_addr);
	pci_release_regions(pdev);

	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);

	kfree(board);
}

static struct pci_driver esd331_pci_driver = {
	.name = DRV_NAME,
	.id_table = esd331_pci_tbl,
	.probe = esd331_pci_init_one,
	.remove = __devexit_p(esd331_pci_remove_one), };

static int __init esd331_pci_init(void)
{
	printk(KERN_INFO "%s CAN netdevice driver\n", DRV_NAME);
	return pci_register_driver(&esd331_pci_driver);
}

static void __exit esd331_pci_exit(void)
{
	pci_unregister_driver(&esd331_pci_driver);
	printk(KERN_INFO "%s driver removed\n", DRV_NAME);
}

module_init(esd331_pci_init);
module_exit(esd331_pci_exit);
