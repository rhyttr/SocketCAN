/*
 * drivers/can/c_can.c
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

#ifdef CONFIG_CAN_DEBUG_DEVICES
#define DBG(args...) printk(args)
#else
#define DBG(args...)
#endif

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <socketcan/can.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
#include <linux/io.h>
#else
#include <asm/io.h>
#endif

#include <socketcan/can/dev.h>
#include <socketcan/can/error.h>
#include "ccan.h"

static u32 ccan_read_reg32(struct net_device *dev, enum c_regs reg)
{
	struct ccan_priv *priv = netdev_priv(dev);

	u32 val = priv->read_reg(dev, reg);
	val |= ((u32) priv->read_reg(dev, reg + 2)) << 16;

	return val;
}

static void ccan_write_reg32(struct net_device *dev, enum c_regs reg, u32 val)
{
	struct ccan_priv *priv = netdev_priv(dev);

	priv->write_reg(dev, reg, val & 0xffff);
	priv->write_reg(dev, reg + 2, val >> 16);
}

static inline void ccan_object_get(struct net_device *dev,
				   int iface, int objno, int mask)
{
	struct ccan_priv *priv = netdev_priv(dev);

	priv->write_reg(dev, CAN_IF_COMM(iface), mask);
	priv->write_reg(dev, CAN_IF_COMR(iface), objno + 1);
	while (priv->read_reg(dev, CAN_IF_COMR(iface)) & IF_COMR_BUSY)
		DBG("busy\n");
}

static inline void ccan_object_put(struct net_device *dev,
				   int iface, int objno, int mask)
{
	struct ccan_priv *priv = netdev_priv(dev);

	priv->write_reg(dev, CAN_IF_COMM(iface), IF_COMM_WR | mask);
	priv->write_reg(dev, CAN_IF_COMR(iface), objno + 1);
	while (priv->read_reg(dev, CAN_IF_COMR(iface)) & IF_COMR_BUSY)
		DBG("busy\n");
}

static int ccan_write_object(struct net_device *dev,
			     int iface, struct can_frame *frame, int objno)
{
	struct ccan_priv *priv = netdev_priv(dev);
	unsigned int val;

	if (frame->can_id & CAN_EFF_FLAG)
		val = IF_ARB_MSGXTD | (frame->can_id & CAN_EFF_MASK);
	else
		val = ((frame->can_id & CAN_SFF_MASK) << 18);

	if (!(frame->can_id & CAN_RTR_FLAG))
		val |=  IF_ARB_TRANSMIT;

	val |=  IF_ARB_MSGVAL;
	ccan_write_reg32(dev, CAN_IF_ARB(iface), val);

	memcpy(&val, &frame->data[0], 4);
	ccan_write_reg32(dev, CAN_IF_DATAA(iface), val);
	memcpy(&val, &frame->data[4], 4);
	ccan_write_reg32(dev, CAN_IF_DATAB(iface), val);
	priv->write_reg(dev, CAN_IF_MCONT(iface),
			IF_MCONT_TXIE |	IF_MCONT_TXRQST | IF_MCONT_EOB |
			(frame->can_dlc & 0xf));

	ccan_object_put(dev, 0, objno, IF_COMM_ALL);

	return 0;
}

static int ccan_read_object(struct net_device *dev, int iface, int objno)
{
	struct ccan_priv *priv = netdev_priv(dev);
	unsigned int val, ctrl, data;
	struct sk_buff *skb;
	struct can_frame *frame;

	skb = dev_alloc_skb(sizeof(struct can_frame));
	skb->dev = dev;

	ccan_object_get(dev, 0, objno, IF_COMM_ALL & ~IF_COMM_TXRQST);
#ifdef CCAN_DEBUG
	priv->bufstat[objno]++;
#endif
	frame = (struct can_frame *)skb_put(skb, sizeof(struct can_frame));

	ctrl = priv->read_reg(dev, CAN_IF_MCONT(iface));

	if (ctrl & IF_MCONT_MSGLST) {
		priv->can.net_stats.rx_errors++;
		DBG("%s: msg lost in buffer %d\n", __func__, objno);
	}

	frame->can_dlc = ctrl & 0xf;

	val = ccan_read_reg32(dev, CAN_IF_ARB(iface));

	data = ccan_read_reg32(dev, CAN_IF_DATAA(iface));
	memcpy(&frame->data[0], &data, 4);
	data = ccan_read_reg32(dev, CAN_IF_DATAB(iface));
	memcpy(&frame->data[4], &data, 4);

	if (val & IF_ARB_MSGXTD)
		frame->can_id = (val & CAN_EFF_MASK) | CAN_EFF_FLAG;
	else
		frame->can_id = (val >> 18) & CAN_SFF_MASK;

	if (val & IF_ARB_TRANSMIT)
		frame->can_id |= CAN_RTR_FLAG;

	priv->write_reg(dev, CAN_IF_MCONT(iface), ctrl &
			~(IF_MCONT_MSGLST | IF_MCONT_INTPND | IF_MCONT_NEWDAT));

	ccan_object_put(dev, 0, objno, IF_COMM_CONTROL);

	skb->protocol = __constant_htons(ETH_P_CAN);
	netif_rx(skb);

	priv->can.net_stats.rx_packets++;
	priv->can.net_stats.rx_bytes += frame->can_dlc;

	return 0;
}

static int ccan_setup_receive_object(struct net_device *dev, int iface,
				     int objno, unsigned int mask,
				     unsigned int id, unsigned int mcont)
{
	struct ccan_priv *priv = netdev_priv(dev);

	ccan_write_reg32(dev, CAN_IF_MASK(iface), mask);
	ccan_write_reg32(dev, CAN_IF_ARB(iface), IF_ARB_MSGVAL | id);

	priv->write_reg(dev, CAN_IF_MCONT(iface), mcont);

	ccan_object_put(dev, 0, objno, IF_COMM_ALL & ~IF_COMM_TXRQST);

	DBG("%s: obj no %d msgval: 0x%08x\n", __func__,
		objno, ccan_read_reg32(dev, CAN_MSGVAL));

	return 0;
}

static int ccan_inval_object(struct net_device *dev, int iface, int objno)
{
	struct ccan_priv *priv = netdev_priv(dev);

	ccan_write_reg32(dev, CAN_IF_ARB(iface), 0);
	priv->write_reg(dev, CAN_IF_MCONT(iface), 0);
	ccan_object_put(dev, 0, objno, IF_COMM_ARB | IF_COMM_CONTROL);

	DBG("%s: obj no %d msgval: 0x%08x\n", __func__,
		objno, ccan_read_reg32(dev, CAN_MSGVAL));

	return 0;
}

static int ccan_hard_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ccan_priv *priv = netdev_priv(dev);
	struct can_frame *frame = (struct can_frame *)skb->data;

	spin_lock_irq(&priv->can.irq_lock);

	ccan_write_object(dev, 0, frame, priv->tx_object);
#ifdef CCAN_DEBUG
	priv->bufstat[priv->tx_object]++;
#endif
	priv->tx_object++;
	if (priv->tx_object > 5)
		netif_stop_queue(dev);

	spin_unlock_irq(&priv->can.irq_lock);

	priv->can.net_stats.tx_packets++;
	priv->can.net_stats.tx_bytes += frame->can_dlc;

	dev->trans_start = jiffies;
	dev_kfree_skb(skb);

	return 0;
}

static void ccan_tx_timeout(struct net_device *dev)
{
	struct ccan_priv *priv = netdev_priv(dev);

	priv->can.net_stats.tx_errors++;
}

static int ccan_set_bittime(struct net_device *dev, struct can_bittime *br)
{
	struct ccan_priv *priv = netdev_priv(dev);
	unsigned int reg_timing, ctrl_save;
	u8 brp, sjw, tseg1, tseg2;

	if (br->type != CAN_BITTIME_STD)
		return -EINVAL;

	brp = br->std.brp - 1;
	sjw = br->std.sjw - 1;
	tseg1 = br->std.prop_seg + br->std.phase_seg1 - 1;
	tseg2 = br->std.phase_seg2 - 1;

	reg_timing = (brp & BTR_BRP_MASK) |
		     ((sjw << BTR_SJW_SHIFT) & BTR_SJW_MASK) |
		     ((tseg1 << BTR_TSEG1_SHIFT) & BTR_TSEG1_MASK) |
		     ((tseg2 << BTR_TSEG2_SHIFT) & BTR_TSEG2_MASK);

	DBG("%s: brp = %d sjw = %d seg1 = %d seg2 = %d\n", __func__,
		brp, sjw, tseg1, tseg2);
	DBG("%s: setting BTR to %04x\n", __func__, reg_timing);

	spin_lock_irq(&priv->can.irq_lock);

	ctrl_save = priv->read_reg(dev, CAN_CONTROL);
	priv->write_reg(dev, CAN_CONTROL,
			ctrl_save | CONTROL_CCE | CONTROL_INIT);
	priv->write_reg(dev, CAN_BTR, reg_timing);
	priv->write_reg(dev, CAN_CONTROL, ctrl_save);

	spin_unlock_irq(&priv->can.irq_lock);

	return 0;
}

static int ccan_set_mode(struct net_device *dev, enum can_mode mode)
{
	switch (mode) {
	case CAN_MODE_START:
		DBG("%s: CAN_MODE_START requested\n", __func__);
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static int ccan_get_state(struct net_device *dev, enum can_state *state)
{
	struct ccan_priv *priv = netdev_priv(dev);
	u32 reg_status;
#ifdef CCAN_DEBUG
	int i;
#endif

	reg_status = priv->read_reg(dev, CAN_STATUS);

	if (reg_status & STATUS_EPASS)
		*state = CAN_STATE_BUS_PASSIVE;
	else if (reg_status & STATUS_EWARN)
		*state = CAN_STATE_BUS_WARNING;
	else if (reg_status & STATUS_BOFF)
		*state = CAN_STATE_BUS_OFF;
	else
		*state = CAN_STATE_ACTIVE;
#ifdef CCAN_DEBUG
	DBG("buffer statistic:\n");
	for (i = 0; i <= MAX_OBJECT; i++)
		DBG("%d: %d\n", i, priv->bufstat[i]);
#endif
	return 0;
}

static int ccan_do_status_irq(struct net_device *dev)
{
	struct ccan_priv *priv = netdev_priv(dev);
	int status, diff;

	status = priv->read_reg(dev, CAN_STATUS);
	status &= ~(STATUS_TXOK | STATUS_RXOK);
	diff = status ^ priv->last_status;

	if (diff & STATUS_EPASS) {
		if (status & STATUS_EPASS)
			dev_info(ND2D(dev), "entered error passive state\n");
		else
			dev_info(ND2D(dev), "left error passive state\n");
	}
	if (diff & STATUS_EWARN) {
		if (status & STATUS_EWARN)
			dev_info(ND2D(dev), "entered error warning state\n");
		else
			dev_info(ND2D(dev), "left error warning state\n");
	}
	if (diff & STATUS_BOFF) {
		if (status & STATUS_BOFF)
			dev_info(ND2D(dev), "entered busoff state\n");
		else
			dev_info(ND2D(dev), "left busoff state\n");
	}

	if (diff & STATUS_LEC_MASK) {
		switch (status & STATUS_LEC_MASK) {
		case LEC_STUFF_ERROR:
			dev_info(ND2D(dev), "suffing error\n");
			break;
		case LEC_FORM_ERROR:
			dev_info(ND2D(dev), "form error\n");
			break;
		case LEC_ACK_ERROR:
			dev_info(ND2D(dev), "ack error\n");
			break;
		case LEC_BIT1_ERROR:
			dev_info(ND2D(dev), "bit1 error\n");
			break;
		}
	}

	priv->write_reg(dev, CAN_STATUS, 0);
	priv->last_status = status;

	return diff ? 1 : 0;
}

static void ccan_do_object_irq(struct net_device *dev, u16 irqstatus)
{
	struct ccan_priv *priv = netdev_priv(dev);
	int i;
	u32 val;

	if (irqstatus > MAX_TRANSMIT_OBJECT) {
		val = ccan_read_reg32(dev, CAN_NEWDAT);
		while (val & RECEIVE_OBJECT_BITS) {
			for (i = MAX_TRANSMIT_OBJECT + 1; i <= MAX_OBJECT; i++)
				if (val & (1<<i))
					ccan_read_object(dev, 0, i);
			val = ccan_read_reg32(dev, CAN_NEWDAT);
		}
	} else {
		ccan_inval_object(dev, 0, irqstatus - 1);
		val = ccan_read_reg32(dev, CAN_TXRQST);
		if (!val) {
			priv->tx_object = 0;
			netif_wake_queue(dev);
		}
	}
}

static void do_statuspoll(struct work_struct *work)
{
	struct ccan_priv *priv = container_of(((struct delayed_work *) work),
					      struct ccan_priv, work);

	priv->write_reg(priv->dev, CAN_CONTROL,
			CONTROL_SIE | CONTROL_EIE | CONTROL_IE);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
static irqreturn_t ccan_isr(int irq, void *dev_id, struct pt_regs *regs)
#else
static irqreturn_t ccan_isr(int irq, void *dev_id)
#endif
{
	struct net_device *dev = (struct net_device *) dev_id;
	struct ccan_priv *priv = netdev_priv(dev);
	u16 irqstatus;
	unsigned long flags;

	spin_lock_irqsave(&priv->can.irq_lock, flags);

	irqstatus = priv->read_reg(dev, CAN_IR);
	while (irqstatus) {
		if (irqstatus == 0x8000) {
			if (ccan_do_status_irq(dev)) {
				/* The c_can core tends to flood us with
				 * interrupts when certain error states don't
				 * disappear. Disable interrupts and see if it's
				 * getting better later. This is at least the
				 * case on the Magnachip h7202.
				 */
				priv->write_reg(dev, CAN_CONTROL, CONTROL_EIE |
						CONTROL_IE);
				schedule_delayed_work(&priv->work, HZ / 10);
				goto exit;
			}
		} else {
			ccan_do_object_irq(dev, irqstatus);
		}
		irqstatus = priv->read_reg(dev, CAN_IR);
	}

exit:
	spin_unlock_irqrestore(&priv->can.irq_lock, flags);

	return IRQ_HANDLED;
}

static int ccan_open(struct net_device *dev)
{
	struct ccan_priv *priv = netdev_priv(dev);

	if (request_irq(dev->irq, &ccan_isr, 0, dev->name, dev)) {
		dev_err(ND2D(dev), "failed to attach interrupt\n");
		return -EAGAIN;
	}

	priv->write_reg(dev, CAN_CONTROL,
			CONTROL_EIE | CONTROL_SIE | CONTROL_IE);

	netif_wake_queue(dev);

	return 0;
}

static int ccan_stop(struct net_device *dev)
{
	struct ccan_priv *priv = netdev_priv(dev);
	unsigned long flags;

	netif_stop_queue(dev);

	cancel_delayed_work(&priv->work);
	flush_scheduled_work();

	/* mask all IRQs */
	spin_lock_irqsave(&priv->can.irq_lock, flags);
	priv->write_reg(dev, CAN_CONTROL, 0);
	spin_unlock_irqrestore(&priv->can.irq_lock, flags);

	free_irq(dev->irq, dev);

	return 0;
}

static int ccan_chip_config(struct net_device *dev)
{
	struct ccan_priv *priv = netdev_priv(dev);
	int i;

	/* setup message objects */
	for (i = 0; i <= MAX_OBJECT; i++)
		ccan_inval_object(dev, 0, i);

	for (i = MAX_TRANSMIT_OBJECT + 1; i < MAX_OBJECT; i++)
		ccan_setup_receive_object(dev, 0, i, 0, 0,
					  IF_MCONT_RXIE | IF_MCONT_UMASK);

	ccan_setup_receive_object(dev, 0, MAX_OBJECT, 0, 0, IF_MCONT_EOB |
				  IF_MCONT_RXIE | IF_MCONT_UMASK);

#ifdef CCAN_DEBUG
	for (i = 0; i <= MAX_OBJECT; i++)
		priv->bufstat[i] = 0;
#endif

	return 0;
}

struct net_device *alloc_ccandev(int sizeof_priv)
{
	struct net_device *dev;
	struct ccan_priv *priv;

	dev = alloc_candev(sizeof_priv);
	if (!dev)
		return NULL;

	priv = netdev_priv(dev);

	dev->open = ccan_open;
	dev->stop = ccan_stop;
	dev->hard_start_xmit = ccan_hard_start_xmit;
	dev->tx_timeout = ccan_tx_timeout;

	priv->can.bitrate = 500000;

	priv->can.do_set_bittime = ccan_set_bittime;
	priv->can.do_get_state = ccan_get_state;
	priv->can.do_set_mode = ccan_set_mode;

	priv->dev = dev;
	priv->tx_object = 0;

	return dev;
}
EXPORT_SYMBOL(alloc_ccandev);

void free_ccandev(struct net_device *dev)
{
	free_candev(dev);
}
EXPORT_SYMBOL(free_ccandev);

int register_ccandev(struct net_device *dev)
{
	struct ccan_priv *priv = netdev_priv(dev);

	ccan_set_mode(dev, CAN_MODE_START);

	ccan_chip_config(dev);
	INIT_DELAYED_WORK(&priv->work, do_statuspoll);

	return register_netdev(dev);
}
EXPORT_SYMBOL(register_ccandev);

void unregister_ccandev(struct net_device *dev)
{
	struct ccan_priv *priv = netdev_priv(dev);

	ccan_set_mode(dev, CAN_MODE_START);

	cancel_delayed_work(&priv->work);
	flush_scheduled_work();

	unregister_netdev(dev);
}
EXPORT_SYMBOL(unregister_ccandev);


MODULE_AUTHOR("Sascha Hauer <s.hauer@pengutronix.de>");
MODULE_AUTHOR("Simon Kallweit <simon.kallweit@intefo.ch>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("CAN port driver for C_CAN based chips");
