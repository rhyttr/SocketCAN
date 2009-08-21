/*
 * at91_can.c -  CAN network driver for AT91 SoC CAN controller
 *
 * (C) 2007 by Hans J. Koch <hjk@linutronix.de>
 * (C) 2008 by Marc Kleine-Budde <kernel@pengutronix.de>
 *
 * This software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2 as distributed in the 'COPYING'
 * file from the main directory of the linux kernel source.
 *
 * Send feedback to <socketcan-users@lists.berlios.de>
 *
 */

#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/clk.h>

#include <socketcan/can.h>
#include <socketcan/can/error.h>
#include <socketcan/can/dev.h>

#include <mach/board.h>

#define DRV_NAME		"at91_can"
#define MAX_INTERRUPT_WORK	4

/*
 * RX/TX Mailbox split
 * don't dare to touch
 */
#define AT91_MB_RX_NUM		12
#define AT91_MB_TX_SHIFT	2

#define AT91_MB_RX_FIRST	0
#define AT91_MB_RX_LAST		(AT91_MB_RX_FIRST + AT91_MB_RX_NUM - 1)
#define AT91_MB_RX_BANKS	3
#define AT91_MB_RX_BANK_WIDTH	(AT91_MB_RX_NUM / AT91_MB_RX_BANKS)
#define AT91_MB_RX_BANK_MASK(i)	(((1 << AT91_MB_RX_BANK_WIDTH) - 1) << \
				(AT91_MB_RX_BANK_WIDTH * (i)))

#define AT91_MB_TX_NUM		(1 << AT91_MB_TX_SHIFT)
#define AT91_MB_TX_FIRST	(AT91_MB_RX_LAST + 1)
#define AT91_MB_TX_LAST		(AT91_MB_TX_FIRST + AT91_MB_TX_NUM - 1)

/* Common registers */
enum at91_reg {
	AT91_MR		= 0x000,
	AT91_IER	= 0x004,
	AT91_IDR	= 0x008,
	AT91_IMR	= 0x00C,
	AT91_SR		= 0x010,
	AT91_BR		= 0x014,
	AT91_TIM	= 0x018,
	AT91_TIMESTP	= 0x01C,
	AT91_ECR	= 0x020,
	AT91_TCR	= 0x024,
	AT91_ACR	= 0x028,
};

/* Mailbox registers (0 <= i <= 15) */
#define AT91_MMR(i)		(enum at91_reg)(0x200 + ((i) * 0x20))
#define AT91_MAM(i)		(enum at91_reg)(0x204 + ((i) * 0x20))
#define AT91_MID(i)		(enum at91_reg)(0x208 + ((i) * 0x20))
#define AT91_MFID(i)		(enum at91_reg)(0x20C + ((i) * 0x20))
#define AT91_MSR(i)		(enum at91_reg)(0x210 + ((i) * 0x20))
#define AT91_MDL(i)		(enum at91_reg)(0x214 + ((i) * 0x20))
#define AT91_MDH(i)		(enum at91_reg)(0x218 + ((i) * 0x20))
#define AT91_MCR(i)		(enum at91_reg)(0x21C + ((i) * 0x20))

/* Register bits */
#define AT91_MR_AT91EN		(1 << 0)
#define AT91_MR_LPM		(1 << 1)
#define AT91_MR_ABM		(1 << 2)
#define AT91_MR_OVL		(1 << 3)
#define AT91_MR_TEOF		(1 << 4)
#define AT91_MR_TTM		(1 << 5)
#define AT91_MR_TIMFRZ		(1 << 6)
#define AT91_MR_DRPT		(1 << 7)

#define AT91_SR_RBSY		(1 << 29)

#define AT91_MMR_PRIO_SHIFT	16

#define AT91_MID_MIDE		(1 << 29)

#define AT91_MSR_MRTR		(1 << 20)
#define AT91_MSR_MABT		(1 << 22)
#define AT91_MSR_MRDY		(1 << 23)
#define AT91_MSR_MMI		(1 << 24)

#define AT91_MCR_MRTR		(1 << 20)
#define AT91_MCR_MTCR		(1 << 23)

/* Mailbox Modes */
enum at91_mb_mode {
	AT91_MB_MODE_DISABLED	= 0,
	AT91_MB_MODE_RX		= 1,
	AT91_MB_MODE_RX_OVRWR	= 2,
	AT91_MB_MODE_TX		= 3,
	AT91_MB_MODE_CONSUMER	= 4,
	AT91_MB_MODE_PRODUCER	= 5,
};

/* Interrupt mask bits */
#define AT91_IRQ_MB_RX		((1 << (AT91_MB_RX_LAST + 1)) \
				- (1 << AT91_MB_RX_FIRST))
#define AT91_IRQ_MB_TX		((1 << (AT91_MB_TX_LAST + 1)) \
				- (1 << AT91_MB_TX_FIRST))
#define AT91_IRQ_MB_AL		(AT91_IRQ_MB_RX | AT91_IRQ_MB_TX)

#define AT91_IRQ_ERRA		(1 << 16)
#define AT91_IRQ_WARN		(1 << 17)
#define AT91_IRQ_ERRP		(1 << 18)
#define AT91_IRQ_BOFF		(1 << 19)
#define AT91_IRQ_SLEEP		(1 << 20)
#define AT91_IRQ_WAKEUP		(1 << 21)
#define AT91_IRQ_TOVF		(1 << 22)
#define AT91_IRQ_TSTP		(1 << 23)
#define AT91_IRQ_CERR		(1 << 24)
#define AT91_IRQ_SERR		(1 << 25)
#define AT91_IRQ_AERR		(1 << 26)
#define AT91_IRQ_FERR		(1 << 27)
#define AT91_IRQ_BERR		(1 << 28)

#define	AT91_IRQ_ERR_ALL	0x1fff0000
#define AT91_IRQ_ERR_CANFRAME	(AT91_IRQ_CERR | AT91_IRQ_SERR | \
				 AT91_IRQ_AERR | AT91_IRQ_FERR | AT91_IRQ_BERR)
#define AT91_IRQ_ERR_LINE	(AT91_IRQ_ERRA | AT91_IRQ_WARN | \
				 AT91_IRQ_ERRP | AT91_IRQ_BOFF)

struct at91_priv {
	struct can_priv		can;	/* must be the first member! */

	struct clk		*clk;
	struct at91_can_data	*pdata;

#define AT91_NEXT_PRIO_SHIFT	(AT91_MB_TX_SHIFT)
#define AT91_NEXT_PRIO_MASK	(0xf << AT91_MB_TX_SHIFT)
#define AT91_NEXT_MB_MASK	(AT91_MB_TX_NUM - 1)
#define AT91_NEXT_MASK		((AT91_MB_TX_NUM - 1) | AT91_NEXT_PRIO_MASK)
	unsigned int		tx_next;
	unsigned int		tx_echo;

	unsigned int		rx_bank;
	void __iomem		*reg_base; /* ioremap'ed address to registers */
};


static struct can_bittiming_const at91_bittiming_const = {
	.tseg1_min = 4,
	.tseg1_max = 16,
	.tseg2_min = 2,
	.tseg2_max = 8,
	.sjw_max = 4,
	.brp_min = 2,
	.brp_max = 128,
	.brp_inc = 1,
};


static inline int get_tx_next_mb(struct at91_priv *priv)
{
	return (priv->tx_next & AT91_NEXT_MB_MASK) + AT91_MB_TX_FIRST;
}

static inline int get_tx_next_prio(struct at91_priv *priv)
{
	return (priv->tx_next >> AT91_NEXT_PRIO_SHIFT) & 0xf;
}

static inline int get_tx_echo_mb(struct at91_priv *priv)
{
	return (priv->tx_echo & AT91_NEXT_MB_MASK) + AT91_MB_TX_FIRST;
}


static inline u32 at91_read(struct net_device *dev, enum at91_reg reg)
{
	struct at91_priv *priv = netdev_priv(dev);
	return readl(priv->reg_base + reg);
}

static inline void
at91_write(struct net_device *dev, enum at91_reg reg, u32 value)
{
	struct at91_priv *priv = netdev_priv(dev);
	writel(value, priv->reg_base + reg);
}


static inline void
set_mb_mode_prio(struct net_device *dev, int mb, enum at91_mb_mode mode,
		int prio)
{
	at91_write(dev, AT91_MMR(mb),
		   (mode << 24) |
		   (prio << 16));
}

static inline void
set_mb_mode(struct net_device *dev, int mb, enum at91_mb_mode mode)
{
	set_mb_mode_prio(dev, mb, mode, 0);
}


/*
 * Enable or disable transceiver
 */
static void enable_can_transceiver(struct at91_priv *priv, int enable)
{
	if (priv->pdata && priv->pdata->transceiver_enable)
		priv->pdata->transceiver_enable(enable);
}


/*
 * theory of operation:
 *
 * Accoring to the datasheet priority 0 is the highest priority, 15 is
 * the lowest. If two mailboxes have the same priority level the
 * message of the mailbox with the lowest number is sent first.
 *
 * We use the first TX mailbox mailbox (AT91_MB_TX_FIRST) with prio 0,
 * then the next mailbox with prio 0, and so on, until all mailboxes
 * are used. Then we start from the beginning with mailbox
 * AT91_MB_TX_FIRST, but with prio 1, mailbox AT91_MB_TX_FIRST + 1
 * prio 1. When we reach the last mailbox with prio 15, we have to
 * stop sending, waiting for all messages to be delivered, than start
 * again with mailbox AT91_MB_TX_FIRST prio 0.
 *
 * We use the priv->tx_next as counter for the next transmission
 * mailbox, but without the offset AT91_MB_TX_FIRST. The lower bits
 * encode the mailbox number, the upper 4 bits the mailbox priority:
 *
 * priv->tx_next = (prio << AT91_NEXT_PRIO_SHIFT) ||
 *                 (mb - AT91_MB_TX_FIRST);
 *
 */
static int at91_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct at91_priv *priv = netdev_priv(dev);
	struct net_device_stats *stats = &dev->stats;
	struct can_frame *cf = (struct can_frame *)skb->data;
	u32 reg_mid, reg_mcr;
	int mb, prio;

	mb = get_tx_next_mb(priv);
	prio = get_tx_next_prio(priv);

	if (!(at91_read(dev, AT91_MSR(mb)) & AT91_MSR_MRDY)) {
		BUG();
		/* FIXME: kfree? stats? */
		return -EBUSY;
	}

	if (cf->can_id & CAN_EFF_FLAG)
		reg_mid = (cf->can_id & CAN_EFF_MASK) | AT91_MID_MIDE;
	else
		reg_mid = (cf->can_id & CAN_SFF_MASK) << 18;

	reg_mcr = ((cf->can_id & CAN_RTR_FLAG) ? AT91_MCR_MRTR : 0 ) |
		(cf->can_dlc << 16) |
		AT91_MCR_MTCR;

	/* disable MB while writing ID (see datasheet) */
	set_mb_mode(dev, mb, AT91_MB_MODE_DISABLED);
	at91_write(dev, AT91_MID(mb), reg_mid);
	set_mb_mode_prio(dev, mb, AT91_MB_MODE_TX, prio);

	at91_write(dev, AT91_MDL(mb), *(u32 *)(cf->data + 0));
	at91_write(dev, AT91_MDH(mb), *(u32 *)(cf->data + 4));

	/* This triggers transmission */
	wmb();
	at91_write(dev, AT91_MCR(mb), reg_mcr);

	stats->tx_bytes += cf->can_dlc;
	dev->trans_start = jiffies;

	/* _NOTE_: substract AT91_MB_TX_FIRST offset from mb! */
	can_put_echo_skb(skb, dev, mb - AT91_MB_TX_FIRST);

	/*
	 * we have to stop the queue and deliver all messages in case
	 * of a prio+mb counter wrap around. This is the case if
	 * tx_next buffer prio and mailbox equals 0.
	 *
	 * also stop the queue if next buffer is still in use
	 * (== not ready)
	 */
	priv->tx_next++;
	if (!(at91_read(dev, AT91_MSR(get_tx_next_mb(priv))) &
	      AT91_MSR_MRDY) ||
	    (priv->tx_next & AT91_NEXT_MASK) == 0) {
		netif_stop_queue(dev);
		dev_dbg(ND2D(dev),
			"stopping netif_queue, priv->tx_next=%d, "
			"prio=%d, mb=%d\n",
			priv->tx_next,
			get_tx_next_prio(priv),
			get_tx_next_mb(priv));
	}

	/* Enable interrupt for this mailbox */
	at91_write(dev, AT91_IER, 1 << mb);

	return 0;
}


/**
 * at91_clear_bank - clear and reactive bank
 * @dev: net device
 * @bank: bank to clear
 *
 * Clears and reenables IRQs on given bank in order to enable
 * reception of new CAN messages
 */
static void at91_clear_bank(struct net_device *dev, int bank)
{
	int last, i;
	u32 mask;

	last = AT91_MB_RX_BANK_WIDTH * (bank + 1);
	for (i = AT91_MB_RX_BANK_WIDTH * bank; i < last; i++)
		at91_write(dev, AT91_MCR(i), AT91_MCR_MTCR);

	mask = AT91_MB_RX_BANK_MASK(bank);
	at91_write(dev, AT91_IER, mask);
}


/**
 * at91_read_mb - read CAN msg from mailbox (lowlevel impl)
 * @dev: net device
 * @mb: mailbox number to read from
 * @cf: can frame where to store message
 *
 * Reads a CAN message from the given mailbox and stores data into
 * given can frame. "mb" and "cf" must be valid.
 */
static void at91_read_mb(struct net_device *dev, int mb, struct can_frame *cf)
{
	u32 reg_msr, reg_mid, reg_mdl, reg_mdh;

	reg_mid = at91_read(dev, AT91_MID(mb));
	if (reg_mid & AT91_MID_MIDE)
		cf->can_id = ((reg_mid >>  0) & CAN_EFF_MASK) | CAN_EFF_FLAG;
	else
		cf->can_id =  (reg_mid >> 18) & CAN_SFF_MASK;

	reg_msr = at91_read(dev, AT91_MSR(mb));
	if (reg_msr & AT91_MSR_MRTR)
		cf->can_id |= CAN_RTR_FLAG;
	cf->can_dlc = (reg_msr >> 16) & 0xf;

	reg_mdl = at91_read(dev, AT91_MDL(mb));
	reg_mdh = at91_read(dev, AT91_MDH(mb));

	*(u32 *)(cf->data + 0) = reg_mdl;
	*(u32 *)(cf->data + 4) = reg_mdh;

	/*  FIXME: take care about AT91_MB_MODE_RX_OVRWR mb */
}


/**
 * at91_read_msg - read CAN message from mailbox
 * @dev: net device
 * @mb: mail box to read from
 *
 * Reads a CAN message from given mailbox, and put into linux network
 * RX queue, does all housekeeping chores (stats, ...)
 */
static void at91_read_msg(struct net_device *dev, int mb)
{
	struct net_device_stats *stats = &dev->stats;
	struct can_frame *cf;
	struct sk_buff *skb;

	skb = netdev_alloc_skb(dev, sizeof(struct can_frame));
	if (unlikely(!skb)) {
		if (net_ratelimit())
			dev_warn(ND2D(dev),
				 "Memory squeeze, dropping packet.\n");
		stats->rx_dropped++;
		return;
	}
	skb->protocol = htons(ETH_P_CAN);
	cf = (struct can_frame *)skb_put(skb, sizeof(struct can_frame));

	at91_read_mb(dev, mb, cf);

	netif_rx(skb);

	dev->last_rx = jiffies;
	stats->rx_packets++;
	stats->rx_bytes += cf->can_dlc;
}


/*
 * theory of operation
 *
 * 12 of the 16 mailboxes on the chip are reserved for RX. we split
 * them into 3 groups (3 x 4 mbs) a.k.a banks.
 *
 * like it or not, but the chip always saves a received CAN message
 * into the first free mailbox it finds. This makes it very difficult
 * to read the messages in the right order from the chip. This is how
 * we work around that problem:
 *
 * The first message goes into mb nr. 0 and issues an interrupt. We
 * read it, do _not_ reenable the mb (to receive another message), but
 * disable the interrupt though. This is done for the first bank
 * (i.e. mailbox 0-3).
 *
 *   bank0    bank1    bank2
 *   __^__    __^__    __^__
 *  /     \  /     \  /     \
 * +-+-+-+-++-+-+-+-++-+-+-+-+
 * |x|x|x|x|| | | | || | | | |
 * +-+-+-+-++-+-+-+-++-+-+-+-+
 *  0 0 0 0  0 0 0 0  0 0 1 1  \ mail
 *  0 1 2 3  4 5 6 7  8 9 0 1  / box
 *
 * Then we switch to bank 1. If this bank is full, too, we reenable
 * bank number 0, and switch to bank 2. Imagine bank 2 like an overflow
 * bank, which takes CAN messages if bank 1 is full, but bank 0 not
 * cleared yet. In other words: from the reception of a message into
 * mb 7, we have the "four mailboxes" (of bank 2) time to enter the
 * interrupt service routine and reenable bank 0.
 *
 * Nevertheless, after reenabling bank 0, we look at bank 2 first, to
 * see if there are some messages. Then we reactivate bank 1 and 2,
 * and switch to bank 0.
 *
 */
static void at91_irq_rx(struct net_device *dev, u32 reg_sr)
{
	struct at91_priv *priv = netdev_priv(dev);
	unsigned long *addr = (unsigned long *)&reg_sr;
	int mb;

	/* masking of reg_sr not needed, already done by at91_irq */

	mb = find_next_bit(addr, AT91_MB_RX_NUM,
			   AT91_MB_RX_BANK_WIDTH * priv->rx_bank);
	while (mb < AT91_MB_RX_NUM) {
		dev_dbg(ND2D(dev),
			"%s: SR=0x%08x, mb=%d, mb_bit=0x%04x, rx_bank=%d\n",
			__func__, reg_sr, mb, 1 << mb, priv->rx_bank);

		at91_read_msg(dev, mb);

		/* disable interrupt */
		at91_write(dev, AT91_IDR, 1 << mb);

		/* find next pending mailbox */
		mb = find_next_bit(addr, AT91_MB_RX_NUM, mb + 1);
	}

	switch (priv->rx_bank) {
	case 0:
		if (!(at91_read(dev, AT91_IMR) & AT91_MB_RX_BANK_MASK(0)))
			priv->rx_bank = 1;
		break;
	case 1:
		if (!(at91_read(dev, AT91_IMR) & AT91_MB_RX_BANK_MASK(1))) {
			at91_clear_bank(dev, 0);
			priv->rx_bank = 2;
		}
		break;
	case 2:
		at91_clear_bank(dev, 1);
		at91_clear_bank(dev, 2);
		priv->rx_bank = 0;
		break;
	}
}


/*
 * theory of operation:
 *
 * priv->tx_echo holds the number of the oldest can_frame put for
 * transmission into the hardware, but not yet ACKed by the CAN tx
 * complete IRQ.
 *
 * We iterate from priv->tx_echo to priv->tx_next and check if the
 * packet has been transmitted, echo it back to the CAN framework. If
 * we discover a not yet transmitted package, stop looking for more.
 *
 */
static void at91_irq_tx(struct net_device *dev, u32 reg_sr)
{
	struct at91_priv *priv = netdev_priv(dev);
	u32 reg_msr;
	int mb;

	/* masking of reg_sr not needed, already done by at91_irq */

	for (/* nix */; priv->tx_echo < priv->tx_next; priv->tx_echo++) {
		mb = get_tx_echo_mb(priv);

		/* no event in mailbox? */
		if (!(reg_sr & (1 << mb)))
			break;

		reg_msr = at91_read(dev, AT91_MSR(mb));

		/* FIXME: BUGON no ready | abort */

		dev_dbg(ND2D(dev),
			"%s: SR=0x%08x, mb=%d, mb_bit=0x%04x, mb status: %s, "
			"tx_next=%d, tx_echo=%d\n",
			__func__, reg_sr, mb, 1 << mb,
			reg_msr & AT91_MSR_MRDY ? "MRDY" : "MABT",
			priv->tx_next, priv->tx_echo);

		/* Disable irq for this TX mailbox */
		at91_write(dev, AT91_IDR, 1 << mb);

		/*
		 * only echo if mailbox signals us a transfer
		 * complete (MSR_MRDY). Otherwise it's a tansfer
		 * abort. "can_bus_off()" takes care about the skbs
		 * parked in the echo queue.
		 */
		if (likely(reg_msr & AT91_MSR_MRDY)) {
			/* _NOTE_: substract AT91_MB_TX_FIRST offset from mb! */
			can_get_echo_skb(dev, mb - AT91_MB_TX_FIRST);
			dev->stats.tx_packets++;
		}
	}

	/*
	 * restart queue if we don't have a wrap around but restart if
	 * we get a TX int for the last can frame directly before a
	 * wrap around.
	 */
	if ((priv->tx_next & AT91_NEXT_MASK) != 0 ||
	    (priv->tx_echo & AT91_NEXT_MASK) == 0)
		netif_wake_queue(dev);
}


static void at91_irq_err_canframe(struct net_device *dev, u32 reg_sr)
{
	/* CRC error */
	if (reg_sr & AT91_IRQ_CERR)
		dev_dbg(ND2D(dev), "CERR irq\n");

	/* stuffing error */
	if (reg_sr & AT91_IRQ_SERR)
		dev_dbg(ND2D(dev), "SERR irq\n");

	/* Acknowledgement error */
	if (reg_sr & AT91_IRQ_AERR)
		dev_dbg(ND2D(dev), "AERR irq\n");

	/* form error */
	if (reg_sr & AT91_IRQ_FERR)
		dev_dbg(ND2D(dev), "FERR irq\n");

	/* bit error */
	if (reg_sr & AT91_IRQ_BERR)
		dev_dbg(ND2D(dev), "BERR irq\n");
}


static void at91_irq_err(struct net_device *dev, u32 reg_sr_masked)
{
	struct at91_priv *priv = netdev_priv(dev);
	enum can_state new_state;
	u32 reg_sr, reg_ecr, reg_idr, reg_ier;
	u8 tec, rec;

	reg_sr = at91_read(dev, AT91_SR);
	reg_ecr = at91_read(dev, AT91_ECR);
	tec = reg_ecr >> 16;
	rec = reg_ecr & 0xff;

	dev_dbg(ND2D(dev), "%s: TEC=%3d%s, REC=%3d, bits set: %s%s%s%s\n",
		__func__,
		tec,
		reg_sr & AT91_IRQ_BOFF ? " (bus-off!)" : "",
		rec,
		reg_sr & AT91_IRQ_ERRA ? "ERRA " : "",
		reg_sr & AT91_IRQ_WARN ? "WARN " : "",
		reg_sr & AT91_IRQ_ERRP ? "ERRP " : "",
		reg_sr & AT91_IRQ_BOFF ? "BOFF " : "");

	/* we need to look at the unmasked reg_sr */
	if (unlikely(reg_sr & AT91_IRQ_BOFF))
		new_state = CAN_STATE_BUS_OFF;
	else if (unlikely(reg_sr & AT91_IRQ_ERRP))
		new_state = CAN_STATE_ERROR_PASSIVE;
	else if (unlikely(reg_sr & AT91_IRQ_WARN))
		new_state = CAN_STATE_ERROR_WARNING;
	else if (likely(reg_sr & AT91_IRQ_ERRA))
		new_state = CAN_STATE_ERROR_ACTIVE;
	else {
		BUG();	/* FIXME */
		return;
	}

	/* state hasn't changed, no error in canframe */
	if (new_state == priv->can.state &&
	    !(reg_sr_masked & AT91_IRQ_ERR_CANFRAME))
		return;


	switch (priv->can.state) {
	case CAN_STATE_ERROR_ACTIVE:
		/*
		 * from: ACTIVE
		 * to  : BUS_WARNING, BUS_PASSIVE, BUS_OFF
		 * =>  : there was a warning int
		 */
		if (new_state >= CAN_STATE_ERROR_WARNING &&
		    new_state <= CAN_STATE_BUS_OFF)
			priv->can.can_stats.error_warning++;
	case CAN_STATE_ERROR_WARNING:	/* fallthrough */
		/*
		 * from: ACTIVE, BUS_WARNING
		 * to  : BUS_PASSIVE, BUS_OFF
		 * =>  : error passive int
		 */
		if (new_state >= CAN_STATE_ERROR_PASSIVE &&
		    new_state <= CAN_STATE_BUS_OFF)
			priv->can.can_stats.error_passive++;
		break;
	case CAN_STATE_BUS_OFF:
		/*
		 * this is a crude chip, happens very often that it is
		 * in BUS_OFF but still tries to send a package. on
		 * success it leaves bus off. so we have to reenable
		 * the carrier.
		 */
		if (new_state <= CAN_STATE_ERROR_PASSIVE)
			netif_carrier_on(dev);
		break;
	default:
		break;
	}


	/* process state changes depending on the new state */
	switch (new_state) {
	case CAN_STATE_ERROR_ACTIVE:
		/*
		 * actually we want to enable AT91_IRQ_WARN here, but
		 * it screws up the system under certain
		 * circumstances. so just enable AT91_IRQ_ERRP, thus
		 * the "fallthrough"
		 */
	case CAN_STATE_ERROR_WARNING:	/* fallthrough */
		reg_idr = AT91_IRQ_ERRA | AT91_IRQ_WARN | AT91_IRQ_BOFF;
		reg_ier = AT91_IRQ_ERRP;
		break;
	case CAN_STATE_ERROR_PASSIVE:
		reg_idr = AT91_IRQ_ERRA | AT91_IRQ_WARN | AT91_IRQ_ERRP;
		reg_ier = AT91_IRQ_BOFF;
		break;
	case CAN_STATE_BUS_OFF:
		reg_idr = AT91_IRQ_ERRA | AT91_IRQ_ERRP |
			AT91_IRQ_WARN | AT91_IRQ_BOFF;
		reg_ier = 0;

		/*
		 * FIXME: really abort?
		 *
		 * a somewhat "special" chip, even in BUS_OFF mode, it
		 * accesses the bus. this is a no-no. we try to abort
		 * transfers on all mailboxes. but the chip doesn't
		 * seem to handle this correctly. a stuck-in-transfer
		 * message isn't aborted. after bringing the CAN bus
		 * back xin shape again, the stuck-in-transfer message
		 * is tranferred and its MRDY bit is set. all other
		 * queued messages are aborted (not send) their MABT
		 * bit in MSR is _not_ set but the MRDY bit, too.
		 */
		dev_dbg(ND2D(dev), "%s: aborting transfers, due to BUS OFF\n",
			__func__);

		at91_write(dev, AT91_ACR, AT91_IRQ_MB_TX);

		can_bus_off(dev);
		break;
	default:
		break;
	}

	dev_dbg(ND2D(dev), "%s: writing IDR=0x%08x, IER=0x%08x\n",
		__func__, reg_idr, reg_ier);
	at91_write(dev, AT91_IDR, reg_idr);
	at91_write(dev, AT91_IER, reg_ier);


	{
		struct sk_buff *skb;
		struct can_frame *cf;

		skb = netdev_alloc_skb(dev, sizeof(struct can_frame));
		if (unlikely(!skb))
			goto out;

		skb->protocol = htons(ETH_P_CAN);
		cf = (struct can_frame *)skb_put(skb, sizeof(struct can_frame));
		memset(cf, 0, sizeof(struct can_frame));

		cf->can_id  = CAN_ERR_FLAG;
		cf->can_dlc = CAN_ERR_DLC;

		switch (new_state) {
		case CAN_STATE_ERROR_WARNING:
		case CAN_STATE_ERROR_PASSIVE:
			cf->can_id |= CAN_ERR_CRTL;

			if (new_state == CAN_STATE_ERROR_WARNING)
				cf->data[1] = (tec > rec) ?
					CAN_ERR_CRTL_TX_WARNING :
					CAN_ERR_CRTL_RX_WARNING;
			else
				cf->data[1] = (tec > rec) ?
					CAN_ERR_CRTL_TX_PASSIVE :
					CAN_ERR_CRTL_RX_PASSIVE;

			break;
		case CAN_STATE_BUS_OFF:
			cf->can_id |= CAN_ERR_BUSOFF;
			break;
		default:
			break;
		}


		netif_rx(skb);

		dev->last_rx = jiffies;
		dev->stats.rx_packets++;
		dev->stats.rx_bytes += cf->can_dlc;
	}

 out:
	priv->can.state = new_state;
}


/*
 * interrupt handler
 */
static irqreturn_t at91_irq(int irq, void *ndev_id)
{
	struct net_device *dev = ndev_id;
	irqreturn_t handled = IRQ_NONE;
	u32 reg_sr, reg_imr;
	int boguscnt = MAX_INTERRUPT_WORK;

	do {
		reg_sr = at91_read(dev, AT91_SR);
		reg_imr = at91_read(dev, AT91_IMR);
		dev_dbg(ND2D(dev), "%s: SR=0x%08x, IMR=0x%08x, [0x%08x]\n",
			__func__,
			reg_sr, reg_imr, reg_sr & reg_imr);

		/* Ignore masked interrupts */
		reg_sr &= reg_imr;
		if (!reg_sr)
			goto exit;

		handled = IRQ_HANDLED;

		if (reg_sr & AT91_IRQ_MB_RX) {
			/* receive interrupt */
			at91_irq_rx(dev, reg_sr);
		}

		if (reg_sr & AT91_IRQ_MB_TX) {
			/* transmission complete interrupt */
			at91_irq_tx(dev, reg_sr);
		}

		at91_irq_err(dev, reg_sr);

	} while (--boguscnt > 0);

	if (unlikely(boguscnt <= 0)) {
		dev_warn(ND2D(dev), "Too much work at interrupt, "
			 "status (at enter): 0x%08x, now: 0x%08x\n",
			 reg_sr,
			 at91_read(dev, AT91_SR) & at91_read(dev, AT91_IMR));

		/* Clear all interrupt sources. */
		/* FIXME: do it? */
	}

 exit:
	return handled;
}


static void at91_setup_mailboxes(struct net_device *dev)
{
	struct at91_priv *priv = netdev_priv(dev);
	int i;

	/*
	 * The first 12 mailboxes are used as a reception FIFO. The
	 * last mailbox is configured with overwrite option. The
	 * overwrite flag indicates a FIFO overflow.
	 */
	/* FIXME: clear accept regs (MID/MAM) */
	for (i = AT91_MB_RX_FIRST; i < AT91_MB_RX_LAST; i++)
		set_mb_mode(dev, i, AT91_MB_MODE_RX);
	set_mb_mode(dev, AT91_MB_RX_LAST, AT91_MB_MODE_RX_OVRWR);

	/* The last 4 mailboxes are used for transmitting. */
	for (i = AT91_MB_TX_FIRST; i <= AT91_MB_TX_LAST; i++)
		set_mb_mode_prio(dev, i, AT91_MB_MODE_TX, 0);


	/* reset both tx and rx helper pointers */
	priv->tx_next = priv->tx_echo = priv->rx_bank = 0;
}

static int at91_set_bittiming(struct net_device *dev)
{
	struct at91_priv *priv = netdev_priv(dev);
	struct can_bittiming *bt = &priv->can.bittiming;
	u32 reg_br;

	reg_br = ((priv->can.ctrlmode & CAN_CTRLMODE_3_SAMPLES) << 24) |
		((bt->brp        - 1) << 16) |
		((bt->sjw        - 1) << 12) |
		((bt->prop_seg   - 1) <<  8) |
		((bt->phase_seg1 - 1) <<  4) |
		((bt->phase_seg2 - 1) <<  0);

	dev_dbg(ND2D(dev), "writing AT91_BR: 0x%08x, can_sys_clock: %d\n",
		  reg_br, priv->can.clock.freq);
	at91_write(dev, AT91_BR, reg_br);

	return 0;
}


static void at91_chip_start(struct net_device *dev)
{
	struct at91_priv *priv = netdev_priv(dev);
	u32 reg_mr, reg_ier;

	/* disable interrupts */
	at91_write(dev, AT91_IDR, 0x1fffffff);

	/* disable chip */
	reg_mr = at91_read(dev, AT91_MR);
	at91_write(dev, AT91_MR, reg_mr & ~AT91_MR_AT91EN);
	wmb();

	at91_setup_mailboxes(dev);

	enable_can_transceiver(priv, 1);

	/* enable chip */
	reg_mr = at91_read(dev, AT91_MR);
	at91_write(dev, AT91_MR, reg_mr | AT91_MR_AT91EN);

	priv->can.state = CAN_STATE_ERROR_ACTIVE;

	/* Enable interrupts */
	reg_ier =
		AT91_IRQ_MB_RX |
		AT91_IRQ_ERRP;	/* AT91_IRQ_WARN screws up system */
/* 		AT91_IRQ_CERR | AT91_IRQ_SERR |	AT91_IRQ_AERR | */
/* 		AT91_IRQ_FERR |	AT91_IRQ_BERR; */
	at91_write(dev, AT91_IDR, 0x1fffffff);
	at91_write(dev, AT91_IER, reg_ier);
}


static void at91_chip_stop(struct net_device *dev)
{
	struct at91_priv *priv = netdev_priv(dev);
	u32 reg_mr;

	/* disable interrupts */
	at91_write(dev, AT91_IDR, 0x1fffffff);

	reg_mr = at91_read(dev, AT91_MR);
	at91_write(dev, AT91_MR, reg_mr & ~AT91_MR_AT91EN);

	priv->can.state = CAN_STATE_STOPPED;
	enable_can_transceiver(priv, 0);
}


static int at91_open(struct net_device *dev)
{
	struct at91_priv *priv = netdev_priv(dev);
	int err;

	clk_enable(priv->clk);

	/* check or determine and set bittime */
	err = open_candev(dev);
	if (err)
		goto out;

	/* register interrupt handler */
	if (request_irq(dev->irq, at91_irq, IRQF_SHARED,
			dev->name, dev)) {
		err = -EAGAIN;
		goto out_close;
	}

	/* start chip and queuing */
	at91_chip_start(dev);
	netif_start_queue(dev);

	return 0;

 out_close:
	close_candev(dev);
 out:
	clk_disable(priv->clk);

	return err;
}


/*
 * stop CAN bus activity
 */
static int at91_close(struct net_device *dev)
{
	struct at91_priv *priv = netdev_priv(dev);

	netif_stop_queue(dev);

	at91_chip_stop(dev);
	free_irq(dev->irq, dev);
	clk_disable(priv->clk);

	close_candev(dev);

	return 0;
}


static int at91_set_mode(struct net_device *dev, u32 _mode)
{
	enum can_mode mode = _mode;

	switch (mode) {
	case CAN_MODE_START:
		dev_dbg(ND2D(dev), "%s: CAN_MODE_START requested\n", __func__);

		at91_chip_start(dev);
		netif_wake_queue(dev);
		break;

	default:
		return -EOPNOTSUPP;
	}

	return 0;
}


#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,28)
static const struct net_device_ops at91_netdev_ops = {
	.ndo_open	= at91_open,
	.ndo_stop	= at91_close,
	.ndo_start_xmit	= at91_start_xmit,
};
#endif

static int __init at91_can_probe(struct platform_device *pdev)
{
	struct net_device *dev;
	struct at91_priv *priv;
	struct resource *res;
	struct clk *clk;
	void __iomem *addr;
	int err, irq;

	clk = clk_get(&pdev->dev, "can_clk");
	if (IS_ERR(clk)) {
		dev_err(&pdev->dev, "no clock defined\n");
		err = -ENODEV;
		goto exit;
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	irq = platform_get_irq(pdev, 0);
	if (!res || !irq) {
		err = -ENODEV;
		goto exit_put;
	}

	if (!request_mem_region(res->start,
				res->end - res->start + 1,
				pdev->name)) {
		err = -EBUSY;
		goto exit_put;
	}

	addr = ioremap_nocache(res->start, res->end - res->start + 1);
	if (!addr) {
		err = -ENOMEM;
		goto exit_release;
	}

	dev = alloc_candev(sizeof(struct at91_priv));
	if (!dev) {
		err = -ENOMEM;
		goto exit_iounmap;
	}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,28)
	dev->netdev_ops		= &at91_netdev_ops;
#else
	dev->open		= at91_open;
	dev->stop		= at91_close;
	dev->hard_start_xmit	= at91_start_xmit;
#endif
	dev->irq		= irq;
	dev->flags		|= IFF_ECHO;

	priv = netdev_priv(dev);
	priv->can.clock.freq		= clk_get_rate(clk);
	priv->can.bittiming_const	= &at91_bittiming_const;
	priv->can.do_set_bittiming	= at91_set_bittiming;
	priv->can.do_set_mode		= at91_set_mode;
	priv->clk			= clk;
	priv->reg_base			= addr;

	priv->pdata		= pdev->dev.platform_data;

	dev_set_drvdata(&pdev->dev, dev);
	SET_NETDEV_DEV(dev, &pdev->dev);

	err = register_candev(dev);
	if (err) {
		dev_err(&pdev->dev, "registering netdev failed\n");
		goto exit_free;
	}


	dev_info(&pdev->dev, "device registered (reg_base=%#p, irq=%d)\n",
		 priv->reg_base, dev->irq);

	return 0;

 exit_free:
	free_netdev(dev);
 exit_iounmap:
	iounmap(addr);
 exit_release:
	release_mem_region(res->start, res->end - res->start + 1);
 exit_put:
	clk_put(clk);
 exit:
	return err;
}


static int __devexit at91_can_remove(struct platform_device *pdev)
{
	struct net_device *dev = platform_get_drvdata(pdev);
	struct at91_priv *priv = netdev_priv(dev);
	struct resource *res;

	unregister_netdev(dev);

	platform_set_drvdata(pdev, NULL);

	free_netdev(dev);

	iounmap(priv->reg_base);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	release_mem_region(res->start, res->end - res->start + 1);

	clk_put(priv->clk);

	return 0;
}

#ifdef CONFIG_PM
static int at91_can_suspend(struct platform_device *pdev,
			    pm_message_t mesg)
{
	struct net_device *net_dev = platform_get_drvdata(pdev);
	struct at91_priv *priv = netdev_priv(net_dev);

	if (netif_running(net_dev)) {
		/* TODO Disable IRQ? */
		netif_stop_queue(net_dev);
		netif_device_detach(net_dev);
		enable_can_transceiver(priv, 0);
		clk_disable(priv->clk);
	}
	return 0;
}


static int at91_can_resume(struct platform_device *pdev)
{
	struct net_device *net_dev = platform_get_drvdata(pdev);
	struct at91_priv *priv = netdev_priv(net_dev);

	if (netif_running(net_dev)) {
		clk_enable(priv->clk);
		enable_can_transceiver(priv, 1);
		netif_device_attach(net_dev);
		netif_start_queue(net_dev);
		/* TODO Enable IRQ? */
	}
	return 0;
}
#else
#define at91_can_suspend	NULL
#define at91_can_resume		NULL
#endif

static struct platform_driver at91_can_driver = {
	.probe		= at91_can_probe,
	.remove		= __devexit_p(at91_can_remove),
	.suspend	= at91_can_suspend,
	.resume		= at91_can_resume,
	.driver		= {
		.name	= DRV_NAME,
		.owner	= THIS_MODULE,
	},
};

static int __init at91_can_module_init(void)
{
	printk(KERN_INFO "%s netdevice driver\n", DRV_NAME);
	return platform_driver_register(&at91_can_driver);
}

static void __exit at91_can_module_exit(void)
{
	platform_driver_unregister(&at91_can_driver);
	printk(KERN_INFO "%s: driver removed\n", DRV_NAME);
}

module_init(at91_can_module_init);
module_exit(at91_can_module_exit);

MODULE_AUTHOR("Marc Kleine-Budde <mkl@pengutronix.de>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("LLCF/socketcan '" DRV_NAME "' network device driver");

