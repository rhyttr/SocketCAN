/*
 * $Id$
 *
 * mscan.c
 *
 * DESCRIPTION:
 *  CAN bus driver for the alone generic (as possible as) MSCAN controller.
 *
 * AUTHOR:
 *  Andrey Volkov <avolkov@varma-el.com>
 *
 * COPYRIGHT:
 *  2005-2006, Varma Electronics Oy
 *
 * LICENCE:
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/can/can.h>
#include <linux/list.h>
#include <asm/io.h>

#include <linux/can/dev.h>
#include "mscan.h"

#define MSCAN_NORMAL_MODE	0
#define MSCAN_SLEEP_MODE	 MSCAN_SLPRQ
#define MSCAN_INIT_MODE		(MSCAN_INITRQ | MSCAN_SLPRQ)
#define MSCAN_POWEROFF_MODE	(MSCAN_CSWAI | MSCAN_SLPRQ)

#define BTR0_BRP_MASK	0x3f
#define BTR0_SJW_SHIFT	6
#define BTR0_SJW_MASK	(0x3 << BTR0_SJW_SHIFT)

#define BTR1_TSEG1_MASK  0xf
#define BTR1_TSEG2_SHIFT 4
#define BTR1_TSEG2_MASK  (0x7 << BTR1_TSEG2_SHIFT)
#define BTR1_SAM_SHIFT   7

#define BTR0_SET_BRP(brp)	(((brp)-1)&BTR0_BRP_MASK)
#define BTR0_SET_SJW(sjw)	((((sjw)-1)<<BTR0_SJW_SHIFT)&BTR0_SJW_MASK)

#define BTR1_SET_TSEG1(tseg1) (((tseg1)-1)&BTR1_TSEG1_MASK)
#define BTR1_SET_TSEG2(tseg2) ((((tseg2)-1)<<BTR1_TSEG2_SHIFT)&BTR1_TSEG2_MASK)
#define BTR1_SET_SAM(sam)	  (((sam)&1)<<BTR1_SAM_SHIFT)

struct mscan_state {
	u8 mode;
	u8 canrier;
	u8 cantier;
};

#define TX_QUEUE_SIZE	3

typedef struct {
	struct list_head list;
	u8 mask;
} tx_queue_entry_t;

struct mscan_priv {
	volatile unsigned long flags;
	u8 shadow_statflg;
	u8 shadow_canrier;
	u8 cur_pri;
	u8 tx_active;

	struct list_head tx_head;
	tx_queue_entry_t tx_queue[TX_QUEUE_SIZE];
};

#define F_RX_PROGRESS	0
#define F_TX_PROGRESS	1
#define F_TX_WAIT_ALL	2

static int mscan_set_mode(struct can_device *can, u8 mode)
{
	struct mscan_regs *regs = (struct mscan_regs *)(CAN2ND(can)->base_addr);
	int ret = 0;
	int i;
	u8 canctl1;

	if( mode != MSCAN_NORMAL_MODE ) {
		canctl1 = in_8(&regs->canctl1);
		if ((mode & MSCAN_SLPRQ) && (canctl1 & MSCAN_SLPAK) == 0) {
			out_8( &regs->canctl0, in_8(&regs->canctl0) | MSCAN_SLPRQ );
			for (i = 0; i < 255; i++ ) {
				if ( in_8(&regs->canctl1) & MSCAN_SLPAK )
					break;
				udelay(100);
			}
			if(i>255)
			   ret=-ENODEV;
		}

		if ( !ret && (mode & MSCAN_INITRQ) && (canctl1 & MSCAN_INITAK) == 0) {
			out_8( &regs->canctl0, in_8( &regs->canctl0 ) | MSCAN_INITRQ);
			for (i = 0; i < 255; i++ ) {
				if ( in_8(&regs->canctl1) & MSCAN_INITAK )
					break;
			}
			if(i>255)
				ret=-ENODEV;
		}

		if ( !ret && (mode & MSCAN_CSWAI) )
			out_8( &regs->canctl0, in_8(&regs->canctl0) | MSCAN_CSWAI);

	} else  {
		canctl1 = in_8(&regs->canctl1);
		if ( canctl1 & (MSCAN_SLPAK | MSCAN_INITAK) ) {
			out_8(&regs->canctl0, in_8(&regs->canctl0) &
			      ~(MSCAN_SLPRQ | MSCAN_INITRQ));
			for (i = 0; i < 255; i++ ) {
				canctl1 = in_8(&regs->canctl1);
				if ( (canctl1 & (MSCAN_INITAK | MSCAN_SLPAK)) ==0 )
					break;
			}
			if(i>255)
				ret=-ENODEV;
		}
	}
	return ret;
}

static void mscan_push_state(struct can_device *can, struct mscan_state *state)
{
	struct mscan_regs *regs = (struct mscan_regs *)(CAN2ND(can)->base_addr);

	state->mode = in_8(&regs->canctl0) &
					(MSCAN_SLPRQ | MSCAN_INITRQ | MSCAN_CSWAI);
	state->canrier = in_8(&regs->canrier);
	state->cantier = in_8(&regs->cantier);
}

static int mscan_pop_state(struct can_device *can, struct mscan_state *state)
{
	struct mscan_regs *regs = (struct mscan_regs *)(CAN2ND(can)->base_addr);
	int ret;
	ret = mscan_set_mode(can, state->mode);
	if (!ret) {
		out_8( &regs->canrier, state->canrier);
		out_8( &regs->cantier, state->cantier);
	}
	return ret;
}

static int mscan_hard_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct can_frame *frame = (struct can_frame *)skb->data;
	struct can_device *can = ND2CAN(ndev);
	struct mscan_regs *regs = (struct mscan_regs *)(CAN2ND(can)->base_addr);
	struct mscan_priv *priv = can->priv;
	int i, rtr, buf_id;
	u32 can_id;

	if ( frame->can_dlc > 8 )
		return -EINVAL;

	dev_dbg( ND2D(ndev), "%s\n", __FUNCTION__);
	out_8(&regs->cantier, 0);

	i = ~priv->tx_active & MSCAN_TXE;
	buf_id = ffs(i) - 1;
	switch ( hweight8(i) ) {
		case 0:
			netif_stop_queue(ndev);
			dev_err( ND2D(ndev), "BUG! Tx Ring full when queue awake!\n" );
			return NETDEV_TX_BUSY;
		case 1:
			/* if buf_id < 3, then current frame will be send out of order,
			   since  buffer with lower id have higher priority (hell..) */
			if(buf_id < 3 )
				priv->cur_pri++;
			if(priv->cur_pri==0xff)
				set_bit(F_TX_WAIT_ALL, &priv->flags);
			netif_stop_queue(ndev);
		case 2:
			set_bit(F_TX_PROGRESS, &priv->flags);
	}
	out_8(&regs->cantbsel, i);

	rtr = frame->can_id & CAN_RTR_FLAG;

	if (frame->can_id & CAN_EFF_FLAG) {
		dev_dbg(ND2D(ndev), "sending extended frame\n");

		can_id = (frame->can_id & CAN_EFF_MASK) << 1;
		if( rtr )
			can_id |= 1;
		out_be16(&regs->tx.idr3_2, can_id);

		can_id>>=16;
		can_id = (can_id & 0x7) | ((can_id<<2) & 0xffe0) | (3<<3);
	} else {
		dev_dbg(ND2D(ndev), "sending standard frame\n");
		can_id = (frame->can_id & CAN_SFF_MASK) << 5;
		if( rtr )
			can_id |= 1<<4;
	}
	out_be16(&regs->tx.idr1_0, can_id);

	if ( !rtr ) {
		volatile void __iomem *data = &regs->tx.dsr1_0;
		u16 *payload = (u16 *)frame->data;
		/*Its safe to write into dsr[dlc+1]*/
		for (i=0; i<(frame->can_dlc+1)/2; i++) {
			out_be16(data, *payload++);
		    data += 2+_MSCAN_RESERVED_DSR_SIZE;
		}
	}

	out_8(&regs->tx.dlr, frame->can_dlc);
	out_8(&regs->tx.tbpr, priv->cur_pri);

	/* Start transmission. */
	out_8(&regs->cantflg, 1<<buf_id);

	if ( ! test_bit(F_TX_PROGRESS, &priv->flags) )
		ndev->trans_start = jiffies;

	list_add_tail( &priv->tx_queue[buf_id].list, &priv->tx_head);

	dev_kfree_skb (skb);

	/* Enable interrupt. */
	priv->tx_active |= 1<<buf_id;
	out_8( &regs->cantier, priv->tx_active);

	return NETDEV_TX_OK;
}


static void mscan_tx_timeout(struct net_device *ndev)
{
	struct sk_buff *skb;
	struct can_device *can = ND2CAN(ndev);
	struct mscan_regs *regs = (struct mscan_regs *)(CAN2ND(can)->base_addr);
	struct mscan_priv *priv = can->priv;
	struct can_frame *frame;
	u8 mask;

	printk ("%s\n", __FUNCTION__);

	out_8(&regs->cantier, 0);

	mask = list_entry( priv->tx_head.next, tx_queue_entry_t, list)->mask;
	ndev->trans_start = jiffies;
	out_8(&regs->cantarq, mask);
	out_8(&regs->cantier, priv->tx_active);

	skb = dev_alloc_skb(sizeof(struct can_frame));
	if (!skb) {
		if(printk_ratelimit())
			dev_notice(ND2D(ndev), "TIMEOUT packet dropped\n");
		return;
	}
	frame = (struct can_frame *)skb_put(skb,sizeof(struct can_frame));

	frame->can_id = CAN_ERR_FLAG | CAN_ERR_TX_TIMEOUT;
	frame->can_dlc = CAN_ERR_DLC;

	skb->dev = ndev;
	skb->protocol = __constant_htons(ETH_P_CAN);
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	netif_rx(skb);

}

static can_state_t state_map[] = {
	CAN_STATE_ACTIVE,
	CAN_STATE_BUS_WARNING,
	CAN_STATE_BUS_PASSIVE,
	CAN_STATE_BUS_OFF
};

static inline int check_set_state(struct can_device *can, u8 canrflg)
{
 can_state_t state;
 int ret = 0;

 if ( !(canrflg & MSCAN_CSCIF) || can->state > CAN_STATE_BUS_OFF)
	return 0;

 state = state_map[max( MSCAN_STATE_RX(canrflg), MSCAN_STATE_TX(canrflg))];
 if(can->state < state)
	ret = 1;
 if(state == CAN_STATE_BUS_OFF)
	netif_carrier_off(CAN2ND(can));
 else if(can->state == CAN_STATE_BUS_OFF && state != CAN_STATE_BUS_OFF)
	netif_carrier_on(CAN2ND(can));
 can->state = state;
 return ret;
}

static int mscan_rx_poll(struct net_device *ndev, int *budget)
{
	struct can_device *can = ND2CAN(ndev);
	struct mscan_regs *regs = (struct mscan_regs *)(CAN2ND(can)->base_addr);
	struct mscan_priv *priv = can->priv;
	int npackets = 0, quota = min(ndev->quota, *budget);
	int ret = 1;
	struct sk_buff *skb;
	struct can_frame *frame;
	u32 can_id;
	u8  canrflg;
	int i;

	while ( npackets < quota &&
	( (canrflg = in_8(&regs->canrflg)) & (MSCAN_RXF | MSCAN_ERR_IF) )) {

		skb = dev_alloc_skb(sizeof(struct can_frame));
		if (!skb) {
			if(printk_ratelimit())
				dev_notice(ND2D(ndev), "packet dropped\n");
			can->net_stats.rx_dropped++;
			out_8(&regs->canrflg, canrflg);
			continue;
		}

		frame = (struct can_frame *)skb_put(skb,sizeof(struct can_frame));

		if (canrflg & MSCAN_RXF) {
			can_id = in_be16( &regs->rx.idr1_0 );
			if (can_id & (1<<3) ) {
			   frame->can_id = CAN_EFF_FLAG;
			   can_id = (can_id << 16) | in_be16(&regs->rx.idr3_2);
			   can_id = ((can_id & 0xffe00000) | ((can_id & 0x7ffff) << 2 ))>>2;
			}
			else  {
				can_id >>= 4;
				frame->can_id = 0;
			}

			frame->can_id |= can_id>>1;
			if(can_id & 1)
				frame->can_id |= CAN_RTR_FLAG;
			frame->can_dlc = in_8(&regs->rx.dlr) & 0xf;

			if( !(frame->can_id & CAN_RTR_FLAG ) ) {
				volatile void __iomem * data = &regs->rx.dsr1_0;
				u16 *payload = (u16 *)frame->data;
				for (i=0; i<(frame->can_dlc+1)/2; i++) {
					*payload++ = in_be16(data);
				    data += 2+_MSCAN_RESERVED_DSR_SIZE;
				}
			}

			dev_dbg(ND2D(ndev), "received pkt: id: %u dlc: %u data: ",
				frame->can_id,frame->can_dlc);
#ifdef DEBUG
			for(i=0; i<frame->can_dlc && !(frame->can_id & CAN_FLAG_RTR ); i++)
				printk( "%2x ",frame->data[i]);
			printk("\n");
#endif

			out_8(&regs->canrflg, MSCAN_RXF);
			ndev->last_rx = jiffies;
			can->net_stats.rx_packets++;
			can->net_stats.rx_bytes += frame->can_dlc;
		}
		else if (canrflg & MSCAN_ERR_IF ) {
			frame->can_id = CAN_ERR_FLAG;

			if (canrflg & MSCAN_OVRIF) {
				frame->can_id |= CAN_ERR_CRTL;
				frame->data[1] = CAN_ERR_CRTL_RX_OVERFLOW;
				can->net_stats.rx_over_errors++;
			}
			else
				frame->data[1] = 0;

			if ( check_set_state(can, canrflg)) {
			  frame->can_id |= CAN_ERR_CRTL;
			  switch( can->state )  {
				  case CAN_STATE_BUS_WARNING:
					if( (priv->shadow_statflg & MSCAN_RSTAT_MSK) <
					    (canrflg & MSCAN_RSTAT_MSK))
						frame->data[1] |= CAN_ERR_CRTL_RX_WARNING;

					if( (priv->shadow_statflg & MSCAN_TSTAT_MSK) <
					    (canrflg & MSCAN_TSTAT_MSK))
						frame->data[1] |= CAN_ERR_CRTL_TX_WARNING;
					break;
				  case CAN_STATE_BUS_PASSIVE:
					frame->data[1] |= CAN_ERR_CRTL_PASSIVE;
					break;
				  case CAN_STATE_BUS_OFF:
					frame->can_id |= CAN_ERR_BUSOFF;
					frame->can_id &= ~CAN_ERR_CRTL;
					break;
			  }
			}
			priv->shadow_statflg = canrflg & MSCAN_STAT_MSK;
			frame->can_dlc = CAN_ERR_DLC;
			out_8(&regs->canrflg, MSCAN_ERR_IF);
		}

		npackets++;
		skb->dev = ndev;
		skb->protocol = __constant_htons(ETH_P_CAN);
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		netif_receive_skb(skb);
	}

  *budget -= npackets;
  ndev->quota -= npackets;

  if ( !(in_8(&regs->canrflg) & (MSCAN_RXF | MSCAN_ERR_IF))) {
	netif_rx_complete(ndev);
	clear_bit(F_RX_PROGRESS, &priv->flags);
	out_8(&regs->canrier, in_8(&regs->canrier) | MSCAN_ERR_IF | MSCAN_RXFIE);
	ret = 0;
  }
  return ret;
}

static irqreturn_t
mscan_isr(int irq, void *dev_id, struct pt_regs *r)
{
	struct net_device *ndev = (struct net_device *) dev_id;
	struct can_device *can = ND2CAN(ndev);
	struct mscan_regs *regs = (struct mscan_regs *)(ndev->base_addr);
	struct mscan_priv *priv = can->priv;
	u8 cantflg, canrflg;
	irqreturn_t ret = IRQ_NONE;

	if ( in_8(&regs->cantier) & MSCAN_TXE )
	{
		struct list_head *tmp, *pos;

		cantflg = in_8(&regs->cantflg) & MSCAN_TXE;

		list_for_each_safe(pos, tmp, &priv->tx_head)  {
			tx_queue_entry_t *entry = list_entry(pos, tx_queue_entry_t, list);
			u8 mask = entry->mask;

			if( !(cantflg & mask) )
				continue;

			if ( in_8(&regs->cantaak) & mask ) {
				can->net_stats.tx_dropped++;
				can->net_stats.tx_aborted_errors++;
			}
			else {
				out_8(&regs->cantbsel, mask);
				can->net_stats.tx_bytes += in_8(&regs->tx.dlr);
				can->net_stats.tx_packets++;
			}
			priv->tx_active &= ~mask;
			list_del(pos);
		}

		if ( list_empty(&priv->tx_head) ) {
			clear_bit(F_TX_WAIT_ALL, &priv->flags);
			clear_bit(F_TX_PROGRESS, &priv->flags);
			priv->cur_pri = 0;
		}
		else
			ndev->trans_start = jiffies;

		if( !test_bit(F_TX_WAIT_ALL, &priv->flags) )
			netif_wake_queue(ndev);

		out_8( &regs->cantier, priv->tx_active );
		ret = IRQ_HANDLED;
	}

	if ( !test_and_set_bit(F_RX_PROGRESS, &priv->flags) &&
		(((canrflg = in_8(&regs->canrflg)) & ~MSCAN_STAT_MSK))) {
		if ( check_set_state(can, canrflg) ) {
			out_8(&regs->canrflg, MSCAN_CSCIF);
			ret = IRQ_HANDLED;
		}
		if (canrflg & ~MSCAN_STAT_MSK) {
			priv->shadow_canrier = in_8(&regs->canrier);
			out_8(&regs->canrier, 0);
			netif_rx_schedule(ndev);
			ret = IRQ_HANDLED;
		}
		else
			clear_bit(F_RX_PROGRESS, &priv->flags);
	}
	return ret;
}

static int mscan_do_set_mode(struct can_device *can, can_mode_t mode)
{
	switch (mode) {
	case CAN_MODE_SLEEP:
	case CAN_MODE_STOP:
		netif_stop_queue(CAN2ND(can));
		mscan_set_mode(can,
					(mode==CAN_MODE_STOP)? MSCAN_INIT_MODE: MSCAN_SLEEP_MODE);
		break;
	case CAN_MODE_START:
		printk("%s: CAN_MODE_START requested\n",__FUNCTION__);
		mscan_set_mode(can, MSCAN_NORMAL_MODE);
		netif_wake_queue(CAN2ND(can));
		break;

	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

static
int mscan_do_set_bit_time(struct can_device *can, struct can_bittime *bt)
{
	int ret = 0;
	u8 reg;
	struct mscan_state state;
	struct mscan_regs *regs = (struct mscan_regs *)(CAN2ND(can)->base_addr);

	if(bt->type != CAN_BITTIME_STD)
		return -EINVAL;

	spin_lock_irq(&can->irq_lock);

	mscan_push_state(can, &state);
    ret = mscan_set_mode(can, MSCAN_INIT_MODE);
    if (! ret) {
		reg = BTR0_SET_BRP(bt->std.brp) | BTR0_SET_SJW(bt->std.sjw);
		out_8(&regs->canbtr0, reg);

		reg = BTR1_SET_TSEG1(bt->std.prop_seg + bt->std.phase_seg1) |
			  BTR1_SET_TSEG2(bt->std.phase_seg2) | BTR1_SET_SAM(bt->std.sam);
		out_8(&regs->canbtr1, reg);

	    ret = mscan_pop_state(can, &state);
    }

	spin_unlock_irq(&can->irq_lock);
	return ret;
}

static int mscan_open(struct net_device *ndev)
{
	int ret = 0;
	struct can_device *can = ND2CAN(ndev);
	struct mscan_regs *regs = (struct mscan_regs *)(CAN2ND(can)->base_addr);
	struct mscan_priv *priv = can->priv;

	if((ret = request_irq(ndev->irq, mscan_isr, SA_SHIRQ, ndev->name, ndev)) < 0) {
		printk(KERN_ERR "%s - failed to attach interrupt\n", ndev->name);
		return ret;
	}

	INIT_LIST_HEAD(&priv->tx_head);
	/* acceptance mask/acceptance code (accept everything) */
	out_be16(&regs->canidar1_0, 0);
	out_be16(&regs->canidar3_2, 0);
	out_be16(&regs->canidar5_4, 0);
	out_be16(&regs->canidar7_6, 0);

	out_be16(&regs->canidmr1_0, 0xffff);
	out_be16(&regs->canidmr3_2, 0xffff);
	out_be16(&regs->canidmr5_4, 0xffff);
	out_be16(&regs->canidmr7_6, 0xffff);
	/* Two 32 bit Acceptance Filters */
	out_8(&regs->canidac, MSCAN_AF_32BIT);

	out_8(&regs->canctl1, in_8(&regs->canctl1) & ~MSCAN_LISTEN);
	mscan_set_mode( can, MSCAN_NORMAL_MODE);

	priv->shadow_statflg = in_8(&regs->canrflg) & MSCAN_STAT_MSK;
	priv->cur_pri = 0;
	priv->tx_active = 0;

	out_8(&regs->cantier, 0);
	/* Enable receive interrupts. */
	out_8(&regs->canrier, MSCAN_OVRIE | MSCAN_RXFIE | MSCAN_CSCIE |
	      MSCAN_RSTATE1 | MSCAN_RSTATE0 |
	      MSCAN_TSTATE1 | MSCAN_TSTATE0);

	netif_start_queue(ndev);

	return 0;
}

static int mscan_close(struct net_device *ndev)
{
  struct can_device *can = ND2CAN(ndev);
  struct mscan_regs *regs = (struct mscan_regs *)(CAN2ND(can)->base_addr);

  netif_stop_queue(ndev);

  /* disable interrupts */
  out_8(&regs->cantier, 0);
  out_8(&regs->canrier, 0);
  free_irq(ndev->irq, ndev);

  mscan_set_mode( can, MSCAN_INIT_MODE);
  return 0;
}

int mscan_register(struct can_device *can, int clock_src)
{
  struct mscan_regs *regs = (struct mscan_regs *)(CAN2ND(can)->base_addr);
  u8 ctl1;

  ctl1 = in_8(&regs->canctl1);
  if(clock_src)
	ctl1 |= MSCAN_CLKSRC;
  else
	ctl1 &= ~MSCAN_CLKSRC;

  ctl1 |= MSCAN_CANE;
  out_8(&regs->canctl1, ctl1);
  udelay(100);

  mscan_set_mode( can, MSCAN_INIT_MODE );

  return register_netdev(CAN2ND(can));
}
EXPORT_SYMBOL(mscan_register);

void mscan_unregister(struct can_device *can)
{
  struct mscan_regs *regs = (struct mscan_regs *)(CAN2ND(can)->base_addr);
  mscan_set_mode( can, MSCAN_INIT_MODE );
  out_8(&regs->canctl1, in_8(&regs->canctl1) & ~MSCAN_CANE);
  unregister_netdev(CAN2ND(can));
}

EXPORT_SYMBOL(mscan_unregister);

struct can_device *alloc_mscandev()
{
  struct can_device *can;
  struct net_device *ndev;
  struct mscan_priv *priv;
  int i;

  can = alloc_candev(sizeof(struct mscan_priv));
  if(!can)
		return NULL;
  ndev = CAN2ND(can);
  priv = can->priv;

  ndev->watchdog_timeo	= MSCAN_WATCHDOG_TIMEOUT;
  ndev->open			= mscan_open;
  ndev->stop			= mscan_close;
  ndev->hard_start_xmit	= mscan_hard_start_xmit;
  ndev->tx_timeout     	= mscan_tx_timeout;

  ndev->poll     		= mscan_rx_poll;
  ndev->weight     		= 8;

  can->do_set_bit_time	= mscan_do_set_bit_time;
  can->do_set_mode		= mscan_do_set_mode;

  for(i=0; i< TX_QUEUE_SIZE; i++)
	priv->tx_queue[i].mask = 1<<i;

  return can;
}

EXPORT_SYMBOL(alloc_mscandev);

MODULE_AUTHOR("Andrey Volkov <avolkov@varma-el.com>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("CAN port driver for a mscan based chips");
