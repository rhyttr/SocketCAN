/*
* drivers/net/can/softing/softing_main.c
*
* Copyright (C) 2008
*
* - Kurt Van Dijck, EIA Electronics
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
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
*/

#include <linux/module.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/firmware.h>
#include <linux/interrupt.h>
#include <linux/mutex.h>
#include <linux/io.h>

#include "softing.h"

/* this is the worst thing on the softing API
 * 2 busses are driven together, I don't know how
 * to recover a single of them.
 * Therefore, when one bus is modified, the other
 * is flushed too
 */
void softing_flush_echo_skb(struct softing_priv *priv)
{
	can_close_cleanup(priv->netdev);
	priv->tx.pending = 0;
	priv->tx.echo_put = 0;
	priv->tx.echo_get = 0;
}

/*softing_unlocked_tx_run:*/
/*trigger the tx queue-ing*/
/*no locks are grabbed, so be sure to have the spin spinlock*/
static int netdev_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct softing_priv *priv = (struct softing_priv *)dev->priv;
	struct softing *card = priv->card;
	int ret;
	int bhlock;
	u8 *ptr;
	u8 cmd;
	unsigned int fifo_wr;
	struct can_frame msg;

	ret = -ENOTTY;
	if (in_interrupt()) {
		bhlock = 0;
		spin_lock(&card->spin);
	} else {
		bhlock = 1;
		spin_lock_bh(&card->spin);
	}
	if (!card->fw.up) {
		ret = -EIO;
		goto xmit_done;
	}
	if (netif_carrier_ok(priv->netdev) <= 0) {
		ret = -EBADF;
		goto xmit_done;
	}
	if (card->tx.pending >= TXMAX) {
		ret = -EBUSY;
		goto xmit_done;
	}
	if (priv->tx.pending >= CAN_ECHO_SKB_MAX) {
		ret = -EBUSY;
		goto xmit_done;
	}
	fifo_wr = card->dpram.tx->wr;
	if (fifo_wr == card->dpram.tx->rd) {
		/*fifo full */
		ret = -EAGAIN;
		goto xmit_done;
	}
	memcpy(&msg, skb->data, sizeof(msg));
	ptr = &card->dpram.tx->fifo[fifo_wr][0];
	cmd = CMD_TX;
	if (msg.can_id & CAN_RTR_FLAG)
		cmd |= CMD_RTR;
	if (msg.can_id & CAN_EFF_FLAG)
		cmd |= CMD_XTD;
	if (priv->index)
		cmd |= CMD_BUS2;
	*ptr++ = cmd;
	*ptr++ = msg.can_dlc;
	*ptr++ = (msg.can_id >> 0);
	*ptr++ = (msg.can_id >> 8);
	if (msg.can_id & CAN_EFF_FLAG) {
		*ptr++ = (msg.can_id >> 16);
		*ptr++ = (msg.can_id >> 24);
	} else {
		/*increment 1, not 2 as you might think */
		ptr += 1;
	}
	if (!(msg.can_id & CAN_RTR_FLAG))
		memcpy_toio(ptr, &msg.data[0], msg.can_dlc);
	if (++fifo_wr >=
		 sizeof(card->dpram.tx->fifo) /
		 sizeof(card->dpram.tx->fifo[0]))
		fifo_wr = 0;
	card->dpram.tx->wr = fifo_wr;
	ret = 0;
	++card->tx.pending;
	++priv->tx.pending;
	can_put_echo_skb(skb, dev, priv->tx.echo_put);
	++priv->tx.echo_put;
	if (priv->tx.echo_put >= CAN_ECHO_SKB_MAX)
		priv->tx.echo_put = 0;
	/* clear pointer, so don't erase later */
	skb = 0;
xmit_done:
	if (bhlock)
		spin_unlock_bh(&card->spin);
	else
		spin_unlock(&card->spin);
	if (card->tx.pending >= TXMAX) {
		struct softing_priv *bus;
		int j;
		for (j = 0; j < card->nbus; ++j) {
			bus = card->bus[j];
			if (!bus)
				continue;
			netif_stop_queue(bus->netdev);
		}
	}

	/* free skb, if not handled by the driver */
	if (skb)
		dev_kfree_skb(skb);
	return ret;
}

static int softing_dev_svc_once(struct softing *card)
{
	int j;
	struct softing_priv *bus;
	struct sk_buff *skb;
	struct can_frame msg;

	unsigned int fifo_rd;
	unsigned int cnt = 0;
	struct net_device_stats *stats;

	memset(&msg, 0, sizeof(msg));
	if (card->dpram.rx->lost_msg) {
		/*reset condition */
		card->dpram.rx->lost_msg = 0;
		/* prepare msg */
		msg.can_id = CAN_ERR_FLAG | CAN_ERR_CRTL;
		msg.can_dlc = CAN_ERR_DLC;
		msg.data[1] = CAN_ERR_CRTL_RX_OVERFLOW;
		/*service to both busses, we don't know which one generated */
		for (j = 0; j < card->nbus; ++j) {
			bus = card->bus[j];
			if (!bus)
				continue;
			if (!netif_carrier_ok(bus->netdev))
				continue;
			++bus->can.can_stats.data_overrun;
			skb = dev_alloc_skb(sizeof(msg));
			if (!skb)
				return -ENOMEM;
			skb->dev = bus->netdev;
			skb->protocol = htons(ETH_P_CAN);
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			memcpy(skb_put(skb, sizeof(msg)), &msg, sizeof(msg));
			if (netif_rx(skb))
				dev_kfree_skb_irq(skb);
		}
		memset(&msg, 0, sizeof(msg));
		++cnt;
	}

	fifo_rd = card->dpram.rx->rd;
	if (++fifo_rd >=
		 sizeof(card->dpram.rx->fifo) / sizeof(card->dpram.rx->fifo[0]))
		fifo_rd = 0;
	if (card->dpram.rx->wr != fifo_rd) {
		u8 *ptr;
		u32 tmp;
		u8 cmd;
		int do_skb;

		ptr = &card->dpram.rx->fifo[fifo_rd][0];

		cmd = *ptr++;
		if (cmd == 0xff) {
			/*not quite usefull, probably the card has got out */
			mod_alert("got cmd 0x%02x, I suspect the card is lost"
				, cmd);
		}
		/*mod_trace("0x%02x", cmd);*/
		bus = card->bus[0];
		if (cmd & CMD_BUS2)
			bus = card->bus[1];

		stats = bus->netdev->get_stats(bus->netdev);
		if (cmd & CMD_ERR) {
			u8 can_state;
			u8 state;
			state = *ptr++;

			msg.can_id = CAN_ERR_FLAG;
			msg.can_dlc = CAN_ERR_DLC;

			if (state & 0x80) {
				can_state = CAN_STATE_BUS_OFF;
				msg.can_id |= CAN_ERR_BUSOFF;
				state = 2;
			} else if (state & 0x60) {
				can_state = CAN_STATE_BUS_PASSIVE;
				msg.can_id |= CAN_ERR_BUSERROR;
				state = 1;
			} else {
				can_state = CAN_STATE_ACTIVE;
				state = 0;
				do_skb = 0;
			}
			/*update DPRAM */
			if (!bus->index)
				card->dpram.info->bus_state = state;
			else
				card->dpram.info->bus_state2 = state;
			/*timestamp */
			tmp =	 (ptr[0] <<  0)
				|(ptr[1] <<  8)
				|(ptr[2] << 16)
				|(ptr[3] << 24);
			ptr += 4;
			/*msg.time = */ softing_time2usec(card, tmp);
			/*trigger dual port RAM */
			mb();
			card->dpram.rx->rd = fifo_rd;
			/*update internal status */
			if (can_state != bus->can.state) {
				bus->can.state = can_state;
				if (can_state == 1)
					bus->can.can_stats.error_passive += 1;
			}
			bus->can.can_stats.bus_error += 1;

			/*trigger socketcan */
			if (state == 2) {
				/* this calls can_close_cleanup() */
				softing_flush_echo_skb(bus);
				can_bus_off(bus->netdev);
				netif_stop_queue(bus->netdev);
			}
			if ((state == CAN_STATE_BUS_OFF)
				 || (state == CAN_STATE_BUS_PASSIVE)) {
				skb = dev_alloc_skb(sizeof(msg));
				if (!skb)
					return -ENOMEM;
				skb->dev = bus->netdev;
				skb->protocol = htons(ETH_P_CAN);
				skb->ip_summed = CHECKSUM_UNNECESSARY;
				memcpy(skb_put(skb, sizeof(msg)), &msg,
						 sizeof(msg));
				if (netif_rx(skb))
					dev_kfree_skb_irq(skb);
			}
		} else {
			if (cmd & CMD_RTR)
				msg.can_id |= CAN_RTR_FLAG;
			/* acknowledge, was tx msg
			 * no real tx flag to set
			if (cmd & CMD_ACK) {
			}
			 */
			msg.can_dlc = *ptr++;
			if (msg.can_dlc > 8)
				msg.can_dlc = 8;
			if (cmd & CMD_XTD) {
				msg.can_id |= CAN_EFF_FLAG;
				msg.can_id |=
						(ptr[0] << 0)
					 | (ptr[1] << 8)
					 | (ptr[2] << 16)
					 | (ptr[3] << 24);
				ptr += 4;
			} else {
				msg.can_id |= (ptr[0] << 0) | (ptr[1] << 8);
				ptr += 2;
			}
			tmp = (ptr[0] << 0)
				 | (ptr[1] << 8)
				 | (ptr[2] << 16)
				 | (ptr[3] << 24);
			ptr += 4;
			/*msg.time = */ softing_time2usec(card, tmp);
			memcpy_fromio(&msg.data[0], ptr, 8);
			ptr += 8;
			/*trigger dual port RAM */
			mb();
			card->dpram.rx->rd = fifo_rd;
			/*update socket */
			if (cmd & CMD_ACK) {
				can_get_echo_skb(bus->netdev, bus->tx.echo_get);
				++bus->tx.echo_get;
				if (bus->tx.echo_get >= CAN_ECHO_SKB_MAX)
					bus->tx.echo_get = 0;
				if (bus->tx.pending)
					--bus->tx.pending;
				if (card->tx.pending)
					--card->tx.pending;
				stats->tx_packets += 1;
				stats->tx_bytes += msg.can_dlc;
			} else {
				stats->rx_packets += 1;
				stats->rx_bytes += msg.can_dlc;
				bus->netdev->last_rx = jiffies;
				skb = dev_alloc_skb(sizeof(msg));
				if (skb) {
					skb->dev = bus->netdev;
					skb->protocol = htons(ETH_P_CAN);
					skb->ip_summed = CHECKSUM_UNNECESSARY;
					memcpy(skb_put(skb, sizeof(msg)), &msg,
							 sizeof(msg));
					if (netif_rx(skb))
						dev_kfree_skb_irq(skb);
				}
			}
		}
		++cnt;
	}
	return cnt;
}

static void softing_dev_svc(unsigned long param)
{
	struct softing *card = (struct softing *)param;
	struct softing_priv *bus;
	int j;
	int offset;

	spin_lock(&card->spin);
	while (softing_dev_svc_once(card) > 0)
		++card->irq.svc_count;
	/*resume tx queue's */
	offset = card->tx.last_bus;
	for (j = 0; j < card->nbus; ++j) {
		if (card->tx.pending >= TXMAX)
			break;
		bus = card->bus[(j + offset) % card->nbus];
		if (netif_carrier_ok(bus->netdev))
			netif_wake_queue(bus->netdev);
	}
	spin_unlock(&card->spin);
}

static void card_seems_down(struct softing *card)
{
	/* free interrupt, but probably
	 * in wrong (interrupt) context
	if (card->irq.requested) {
		free_irq(card->irq.nr, card);
		card->irq.requested = 0;
		card->fw.up = 0;
	}
	*/
	mod_alert("I think the card is vanished");
}

static
irqreturn_t dev_interrupt_shared(int irq, void *dev_id)
{
	struct softing *card = (struct softing *)dev_id;
	unsigned char ir;
	ir = card->dpram.virt[0xe02];
	card->dpram.virt[0xe02] = 0;
	if (card->dpram.rx->rd == 0xffff) {
		card_seems_down(card);
		return IRQ_NONE;
	}
	if (ir == 1) {
		tasklet_schedule(&card->irq.bh);
		return IRQ_HANDLED;
	} else if (ir == 0x10) {
		return IRQ_NONE;
	} else {
		return IRQ_NONE;
	}
}

static
irqreturn_t dev_interrupt_nshared(int irq, void *dev_id)
{
	struct softing *card = (struct softing *)dev_id;
	unsigned char irq_host;
	irq_host = card->dpram.irq->to_host;
	/* make sure we have a copy, before clearing the variable in DPRAM */
	rmb();
	card->dpram.irq->to_host = 0;
	/* make sure we cleared it */
	wmb();
	mod_trace("0x%02x", irq_host);
	if (card->dpram.rx->rd == 0xffff) {
		card_seems_down(card);
		return IRQ_NONE;
	}
	tasklet_schedule(&card->irq.bh);
	return IRQ_HANDLED;
}

static int netdev_open(struct net_device *ndev)
{
	struct softing_priv *priv = netdev_priv(ndev);
	struct softing *card = priv->card;
	int fw;
	int ret;

	mod_trace("%s", ndev->name);
	/* determine and set bittime */
	ret = can_set_bittiming(ndev);
	if (ret)
		return ret;
	if (mutex_lock_interruptible(&card->fw.lock))
		return -ERESTARTSYS;
	fw = card->fw.up;
	if (fw)
		softing_reinit(card
			, (card->bus[0] == priv) ? 1 : -1
			, (card->bus[1] == priv) ? 1 : -1);
	mutex_unlock(&card->fw.lock);
	if (!fw)
		return -EIO;
	netif_start_queue(ndev);
	return 0;
}

static int netdev_stop(struct net_device *ndev)
{
	struct softing_priv *priv = netdev_priv(ndev);
	struct softing *card = priv->card;
	int fw;

	mod_trace("%s", ndev->name);
	netif_stop_queue(ndev);
	netif_carrier_off(ndev);
	softing_flush_echo_skb(priv);
	can_close_cleanup(ndev);
	if (mutex_lock_interruptible(&card->fw.lock))
		return -ERESTARTSYS;
	fw = card->fw.up;
	if (fw)
		softing_reinit(card
			, (card->bus[0] == priv) ? 0 : -1
			, (card->bus[1] == priv) ? 0 : -1);
	mutex_unlock(&card->fw.lock);
	if (!fw)
		return -EIO;
	return 0;
}

static int candev_get_state(struct net_device *ndev, enum can_state *state)
{
	struct softing_priv *priv = netdev_priv(ndev);
	mod_trace("%s", ndev->name);
	if (priv->netdev->flags & IFF_UP)
		*state = CAN_STATE_STOPPED;
	else if (priv->can.state == CAN_STATE_STOPPED)
		*state = CAN_STATE_STOPPED;
	else
		*state = CAN_STATE_ACTIVE;
	return 0;
}

static int candev_set_mode(struct net_device *ndev, enum can_mode mode)
{
	struct softing_priv *priv = netdev_priv(ndev);
	struct softing *card = priv->card;
	mod_trace("%s %u", ndev->name, mode);
	switch (mode) {
	case CAN_MODE_START:
		/*recovery from busoff? */
		if (mutex_lock_interruptible(&card->fw.lock))
			return -ERESTARTSYS;
		softing_reinit(card, -1, -1);
		mutex_unlock(&card->fw.lock);
		break;
	case CAN_MODE_STOP:
	case CAN_MODE_SLEEP:
		return -EOPNOTSUPP;
	}
	return 0;
}

/*assume the card->lock is held*/

int softing_card_irq(struct softing *card, int enable)
{
	int ret;
	if (!enable) {
		if (card->irq.requested && card->irq.nr) {
			free_irq(card->irq.nr, card);
			card->irq.requested = 0;
		}
		return 0;
	}
	if (!card->irq.requested && (card->irq.nr)) {
		irqreturn_t(*fn) (int, void *);
		unsigned int flags;
		flags = IRQF_DISABLED | IRQF_SHARED;/*| IRQF_TRIGGER_LOW; */
		fn = dev_interrupt_nshared;
		if (card->desc->generation >= 2)
			fn = dev_interrupt_shared;
		ret = request_irq(card->irq.nr, fn, flags, card->id.name, card);
		if (ret) {
			mod_alert("%s, request_irq(%u) failed"
				, card->id.name, card->irq.nr
				);
			return ret;
		}
		card->irq.requested = 1;
	}
	return 0;
}

static void shutdown_card(struct softing *card)
{
	int fw_up = 0;
	mod_trace("%s", card->id.name);
	if (mutex_lock_interruptible(&card->fw.lock))
		/* return -ERESTARTSYS*/;
	fw_up = card->fw.up;
	card->fw.up = 0;

	if (card->irq.requested && card->irq.nr) {
		free_irq(card->irq.nr, card);
		card->irq.requested = 0;
	}
	if (fw_up) {
		if (card->fn.enable_irq)
			card->fn.enable_irq(card, 0);
		if (card->fn.reset)
			card->fn.reset(card, 1);
	}
	mutex_unlock(&card->fw.lock);
	tasklet_kill(&card->irq.bh);
}

static int boot_card(struct softing *card)
{
	mod_trace("%s", card->id.name);
	if (mutex_lock_interruptible(&card->fw.lock))
		return -ERESTARTSYS;
	if (card->fw.up) {
		mutex_unlock(&card->fw.lock);
		return 0;
	}
	/*reset board */

	if (card->fn.enable_irq)
		card->fn.enable_irq(card, 1);
	/*boot card */
	if (card->fn.reset)
		card->fn.reset(card, 1);
	/*test dp ram */
	if (card->dpram.virt) {
		unsigned char *lp;
		static const unsigned char stream[]
		= { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, };
		unsigned char back[sizeof(stream)];
		for (lp = card->dpram.virt;
			  &lp[sizeof(stream)] <= card->dpram.end;
			  lp += sizeof(stream)) {
			memcpy_toio(lp, stream, sizeof(stream));
			/* flush IO cache */
			mb();
			memcpy_fromio(back, lp, sizeof(stream));

			if (memcmp(back, stream, sizeof(stream))) {
				char line[3 * sizeof(stream)
					/ sizeof(stream[0]) + 1];
				char *pline = line;
				unsigned char *addr = lp;
				for (lp = back; lp < &back[sizeof(stream)
						/ sizeof(stream[0])]; ++lp)
					pline += sprintf(pline, " %02x", *lp);

				mod_alert("write to dpram failed at 0x%p, %s"
					, addr, line);
				goto open_failed;
			}
		}
		/*fill dpram with 0x55 */
		/*for (lp = card->dpram.virt; lp <= card->dpram.end; ++lp) {
		 *lp = 0x55;
		 }*/
		wmb();
	} else {
		goto open_failed;
	}
	/*load boot firmware */
	if (softing_load_fw(card->desc->boot.fw, card, card->dpram.virt,
				 card->dpram.size,
				 card->desc->boot.offs -
				 card->desc->boot.addr))
		goto open_failed;
	/*load load firmware */
	if (softing_load_fw(card->desc->load.fw, card, card->dpram.virt,
				 card->dpram.size,
				 card->desc->load.offs -
				 card->desc->load.addr))
		goto open_failed;

	if (card->fn.reset)
		card->fn.reset(card, 0);
	if (softing_bootloader_command(card, 0, "card boot"))
		goto open_failed;
	if (softing_load_app_fw(card->desc->app.fw, card))
		goto open_failed;
	/*reset chip */
	card->dpram.info->reset_rcv_fifo = 0;
	card->dpram.info->reset = 1;
	/*sync */
	if (softing_fct_cmd(card, 99, 0x55, "sync-a"))
		goto open_failed;
	if (softing_fct_cmd(card, 99, 0xaa, "sync-a"))
		goto open_failed;
	/*reset chip */
	if (softing_fct_cmd(card, 0, 0, "reset_chip"))
		goto open_failed;
	/*get_serial */
	if (softing_fct_cmd(card, 43, 0, "get_serial_number"))
		goto open_failed;
	card->id.serial =
		 (u16) card->dpram.fct->param[1] +
		 (((u16) card->dpram.fct->param[2]) << 16);
	/*get_version */
	if (softing_fct_cmd(card, 12, 0, "get_version"))
		goto open_failed;
	card->id.fw = (u16) card->dpram.fct->param[1];
	card->id.hw = (u16) card->dpram.fct->param[2];
	card->id.lic = (u16) card->dpram.fct->param[3];
	card->id.chip[0] = (u16) card->dpram.fct->param[4];
	card->id.chip[1] = (u16) card->dpram.fct->param[5];

	mod_info("%s, card booted, "
			"serial %u, fw %u, hw %u, lic %u, chip (%u,%u)",
		  card->id.name, card->id.serial, card->id.fw, card->id.hw,
		  card->id.lic, card->id.chip[0], card->id.chip[1]);

	card->fw.up = 1;
	mutex_unlock(&card->fw.lock);
	return 0;
open_failed:
	card->fw.up = 0;
	if (card->fn.enable_irq)
		card->fn.enable_irq(card, 0);
	if (card->fn.reset)
		card->fn.reset(card, 1);
	mutex_unlock(&card->fw.lock);
	return EINVAL;
}

/*sysfs stuff*/

/* Because the struct softing may be used by pcmcia devices
 * as well as pci devices, * we have no clue how to get
 * from a struct device * towards the struct softing *.
 * It may go over a pci_device->priv or over a pcmcia_device->priv.
 * Therefore, provide the struct softing pointer within the attribute.
 * Then we don't need driver/bus specific things in these attributes
 */
struct softing_attribute {
	struct device_attribute dev;
	ssize_t (*show) (struct softing *card, char *buf);
	ssize_t (*store)(struct softing *card, const char *buf, size_t count);
	struct softing *card;
};

static ssize_t rd_card_attr(struct device *dev, struct device_attribute *attr
		, char *buf) {
	struct softing_attribute *cattr
		= container_of(attr, struct softing_attribute, dev);
	return cattr->show ? cattr->show(cattr->card, buf) : 0;
}
static ssize_t wr_card_attr(struct device *dev, struct device_attribute *attr
		, const char *buf, size_t count) {
	struct softing_attribute *cattr
		= container_of(attr, struct softing_attribute, dev);
	return cattr->store ? cattr->store(cattr->card, buf, count) : 0;
}

#define declare_attr(_name, _mode, _show, _store) { \
	.dev = { \
		.attr = { \
			.name = __stringify(_name), \
			.mode = _mode, \
		}, \
		.show = rd_card_attr, \
		.store = wr_card_attr, \
	}, \
	.show =	_show, \
	.store = _store, \
}

#define CARD_SHOW(name, member) \
static ssize_t show_##name(struct softing *card, char *buf) { \
	return sprintf(buf, "%u\n", card->member); \
}
CARD_SHOW(serial	, id.serial);
CARD_SHOW(firmware	, id.fw);
CARD_SHOW(hardware	, id.hw);
CARD_SHOW(license	, id.lic);
CARD_SHOW(freq		, id.freq);
CARD_SHOW(txpending	, tx.pending);

static const struct softing_attribute card_attr_proto [] = {
	declare_attr(serial	, 0444, show_serial	, 0),
	declare_attr(firmware	, 0444, show_firmware	, 0),
	declare_attr(hardware	, 0444, show_hardware	, 0),
	declare_attr(license	, 0444, show_license	, 0),
	declare_attr(freq	, 0444, show_freq	, 0),
	declare_attr(txpending	, 0644, show_txpending	, 0),
};

static int mk_card_sysfs(struct softing *card)
{
	int size;
	int j;

	size = sizeof(card_attr_proto)/sizeof(card_attr_proto[0]);
	card->attr = kmalloc((size+1)*sizeof(card->attr[0]), GFP_KERNEL);
	if (!card->attr)
		goto attr_mem_failed;
	memcpy(card->attr, card_attr_proto, size * sizeof(card->attr[0]));
	memset(&card->attr[size], 0, sizeof(card->attr[0]));

	card->grp  = kmalloc((size+1)*sizeof(card->grp [0]), GFP_KERNEL);
	if (!card->grp)
		goto grp_mem_failed;

	for (j = 0; j < size; ++j) {
		card->attr[j].card = card;
		card->grp[j] = &card->attr[j].dev.attr;
		if (!card->attr[j].show)
			card->attr[j].dev.attr.mode &= ~(S_IRUGO);
		if (!card->attr[j].store)
			card->attr[j].dev.attr.mode &= ~(S_IWUGO);
	}
	card->grp[size] = 0;
	card->sysfs.name	= "softing";
	card->sysfs.attrs = card->grp;
	if (sysfs_create_group(&card->dev->kobj, &card->sysfs) < 0)
		goto sysfs_failed;

	return 0;

sysfs_failed:
	kfree(card->grp);
grp_mem_failed:
	kfree(card->attr);
attr_mem_failed:
	return -1;
}
static void rm_card_sysfs(struct softing *card)
{
	sysfs_remove_group(&card->dev->kobj, &card->sysfs);
	kfree(card->grp);
	kfree(card->attr);
}

static ssize_t show_chip(struct device *dev
		, struct device_attribute *attr, char *buf)
{
	struct net_device *ndev = to_net_dev(dev);
	struct softing_priv *priv = netdev2softing(ndev);
	return sprintf(buf, "%i\n", priv->chip);
}

static ssize_t show_output(struct device *dev
		, struct device_attribute *attr, char *buf)
{
	struct net_device *ndev = to_net_dev(dev);
	struct softing_priv *priv = netdev2softing(ndev);
	return sprintf(buf, "0x%02x\n", priv->output);
}

static ssize_t store_output(struct device *dev
		, struct device_attribute *attr
		, const char *buf, size_t count)
{
	struct net_device *ndev = to_net_dev(dev);
	struct softing_priv *priv = netdev2softing(ndev);
	struct softing *card = priv->card;

	u8 v = simple_strtoul(buf, NULL, 10) & 0xFFU;

	if (mutex_lock_interruptible(&card->fw.lock))
		return -ERESTARTSYS;
	if (ndev->flags & IFF_UP) {
		int j;
		/* we will need a restart */
		for (j = 0; j < card->nbus; ++j) {
			if (j == priv->index)
				/* me, myself & I */
				continue;
			if (card->bus[j]->netdev->flags & IFF_UP) {
				mutex_unlock(&card->fw.lock);
				return -EBUSY;
			}
		}
		priv->output = v;
		softing_reinit(card, -1, -1);
	} else {
		priv->output = v;
	}
	mutex_unlock(&card->fw.lock);
	return count;
}
/* TODO
 * the latest softing cards support sleep mode too
 */

static const DEVICE_ATTR(chip, S_IRUGO, show_chip, 0);
static const DEVICE_ATTR(output, S_IRUGO | S_IWUSR, show_output, store_output);

static const struct attribute *const netdev_sysfs_entries [] = {
	&dev_attr_chip		.attr,
	&dev_attr_output	.attr,
	0,
};
static const struct attribute_group netdev_sysfs = {
	.name  = 0,
	.attrs = (struct attribute **)netdev_sysfs_entries,
};

static int mk_netdev_sysfs(struct softing_priv *priv)
{
	if (!priv->netdev->dev.kobj.sd) {
		mod_alert("sysfs_create_group would fail");
		return ENODEV;
	}
	return sysfs_create_group(&priv->netdev->dev.kobj, &netdev_sysfs);
}
static void rm_netdev_sysfs(struct softing_priv *priv)
{
	sysfs_remove_group(&priv->netdev->dev.kobj, &netdev_sysfs);
}

static struct softing_priv *mk_netdev(struct softing *card, u16 chip_id)
{
	struct net_device *ndev;
	struct softing_priv *priv;

	ndev = alloc_candev(sizeof(*priv));
	if (!ndev) {
		mod_alert("alloc_candev failed");
		return 0;
	}
	priv = netdev_priv(ndev);
	priv->netdev		= ndev;
	priv->card		= card;
	memcpy(&priv->btr_const, &softing_btr_const, sizeof(priv->btr_const));
	priv->btr_const.brp_max = card->desc->max_brp;
	priv->btr_const.sjw_max = card->desc->max_sjw;
	priv->can.bittiming_const = &priv->btr_const;
	priv->can.bittiming.clock = 8000000;
	priv->chip		= chip_id;
	priv->output = softing_default_output(card, priv);
	SET_NETDEV_DEV(ndev, card->dev);

	ndev->flags |= IFF_ECHO;
	ndev->open		= netdev_open;
	ndev->stop		= netdev_stop;
	ndev->hard_start_xmit	= netdev_start_xmit;
	priv->can.do_get_state	= candev_get_state;
	priv->can.do_set_mode	= candev_set_mode;

	return priv;
}

static void rm_netdev(struct softing_priv *priv)
{
	free_candev(priv->netdev);
}

static int reg_netdev(struct softing_priv *priv)
{
	int ret;
	netif_carrier_off(priv->netdev);
	ret = register_netdev(priv->netdev);
	if (ret) {
		mod_alert("%s, register failed", priv->card->id.name);
		goto reg_failed;
	}
	ret = mk_netdev_sysfs(priv);
	if (ret) {
		mod_alert("%s, sysfs failed", priv->card->id.name);
		goto sysfs_failed;
	}
	return 0;
sysfs_failed:
	unregister_netdev(priv->netdev);
reg_failed:
	return EINVAL;
}

static void unreg_netdev(struct softing_priv *priv)
{
	rm_netdev_sysfs(priv);
	unregister_netdev(priv->netdev);
}

void rm_softing(struct softing *card)
{
	int j;

	/*first, disable card*/
	shutdown_card(card);

	for (j = 0; j < card->nbus; ++j) {
		unreg_netdev(card->bus[j]);
		rm_netdev(card->bus[j]);
	}

	rm_card_sysfs(card);

	iounmap(card->dpram.virt);
}
EXPORT_SYMBOL(rm_softing);

int mk_softing(struct softing *card)
{
	int j;

	/* try_module_get(THIS_MODULE); */
	mutex_init(&card->fw.lock);
	spin_lock_init(&card->spin);
	tasklet_init(&card->irq.bh, softing_dev_svc, (unsigned long)card);

	card->desc = softing_lookup_desc(card->id.manf, card->id.prod);
	if (!card->desc) {
		mod_alert("0x%04x:0x%04x not supported\n", card->id.manf,
			  card->id.prod);
		goto lookup_failed;
	}
	card->id.name = card->desc->name;
	mod_trace("can (%s)", card->id.name);

	card->dpram.virt = ioremap(card->dpram.phys, card->dpram.size);
	if (!card->dpram.virt) {
		mod_alert("dpram ioremap failed\n");
		goto ioremap_failed;
	}

	card->dpram.size = card->desc->dpram_size;
	card->dpram.end = &card->dpram.virt[card->dpram.size];
	/*initialize_board */
	card->dpram.rx = (struct softing_rx *)&card->dpram.virt[0x0000];
	card->dpram.tx = (struct softing_tx *)&card->dpram.virt[0x0400];
	card->dpram.fct = (struct softing_fct *)&card->dpram.virt[0x0300];
	card->dpram.info = (struct softing_info *)&card->dpram.virt[0x0330];
	card->dpram.command = (unsigned short *)&card->dpram.virt[0x07e0];
	card->dpram.receipt = (unsigned short *)&card->dpram.virt[0x07f0];
	card->dpram.irq = (struct softing_irq *)&card->dpram.virt[0x07fe];

	/*reset card */
	if (card->fn.reset)
		card->fn.reset(card, 1);
	if (boot_card(card)) {
		mod_alert("%s, failed to boot", card->id.name);
		goto boot_failed;
	}

	/*only now, the chip's are known */
	card->id.freq = card->desc->freq * 1000000UL;

	if (mk_card_sysfs(card)) {
		mod_alert("%s, sysfs failed", card->id.name);
		goto sysfs_failed;
	}

	if (card->nbus > (sizeof(card->bus) / sizeof(card->bus[0]))) {
		card->nbus = sizeof(card->bus) / sizeof(card->bus[0]);
		mod_alert("%s, going for %u busses", card->id.name, card->nbus);
	}

	for (j = 0; j < card->nbus; ++j) {
		card->bus[j] = mk_netdev(card, card->id.chip[j]);
		if (!card->bus[j]) {
			mod_alert("%s: failed to make can[%i]", card->id.name,
				  j);
			goto netdev_failed;
		}
		card->bus[j]->index = j;
	}
	for (j = 0; j < card->nbus; ++j) {
		if (reg_netdev(card->bus[j])) {
			mod_alert("%s: failed to register can[%i]",
				  card->id.name, j);
			goto reg_failed;
		}
	}
	mod_trace("card initialised");
	return 0;

reg_failed:
	for (j = 0; j < card->nbus; ++j)
		unreg_netdev(card->bus[j]);
netdev_failed:
	for (j = 0; j < card->nbus; ++j) {
		if (card->bus[j])
			rm_netdev(card->bus[j]);
	}
	rm_card_sysfs(card);
sysfs_failed:
	shutdown_card(card);
boot_failed:
	iounmap(card->dpram.virt);
	card->dpram.virt = 0;
	card->dpram.end = 0;
ioremap_failed:
lookup_failed:
	tasklet_kill(&card->irq.bh);
	return EINVAL;
}
EXPORT_SYMBOL(mk_softing);

static int __init mod_start(void)
{
	mod_trace("");
	return 0;
}

static void __exit mod_stop(void)
{
	mod_trace("");
}

module_init(mod_start);
module_exit(mod_stop);

MODULE_DESCRIPTION("socketcan softing driver");
MODULE_AUTHOR("Kurt Van Dijck <kurt.van.dijck@eia.be>");
MODULE_LICENSE("GPL");

int softing_debug = 1;
EXPORT_SYMBOL(softing_debug);
module_param(softing_debug, int , S_IRUGO | S_IWUSR | S_IWGRP);
MODULE_PARM_DESC(softing_debug, "trace softing functions");
