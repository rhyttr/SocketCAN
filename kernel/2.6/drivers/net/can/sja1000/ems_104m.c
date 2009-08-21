/*
 * Copyright (C) 2009 Sebastian Haas <haas@ems-wuensche.com>
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

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/isa.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/delay.h>
#include <socketcan/can.h>
#include <socketcan/can/dev.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
#include <linux/io.h>
#else
#include <asm/io.h>
#endif

#include "sja1000.h"

#define DRV_NAME  "ems_104m"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
#error This driver does not support Kernel versions < 2.6.16
#endif

MODULE_AUTHOR("Sebastian Haas <haas@ems-wuenche.com>");
MODULE_DESCRIPTION("Socket-CAN driver for EMS CPC-104M cards");
MODULE_SUPPORTED_DEVICE("EMS CPC-104M CAN card");
MODULE_LICENSE("GPL v2");

#define EMS_104M_MAX_DEV  4

static unsigned long __devinitdata mem[EMS_104M_MAX_DEV];
static int __devinitdata irq[EMS_104M_MAX_DEV];

module_param_array(mem, ulong, NULL, S_IRUGO);
MODULE_PARM_DESC(mem, "I/O memory address");

module_param_array(irq, int, NULL, S_IRUGO);
MODULE_PARM_DESC(irq, "IRQ number");

#define EMS_104M_MAX_CHAN 4

struct ems_104m_card {
	int channels;

	struct net_device *net_dev[EMS_104M_MAX_CHAN];

	void __iomem *base;
	int irq;
};

#define EMS_104M_CAN_CLOCK (16000000 / 2)

/*
 * The board configuration is probably following:
 * RX1 is connected to ground.
 * TX1 is not connected.
 * CLKO is not connected.
 * Setting the OCR register to 0xDA is a good idea.
 * This means  normal output mode , push-pull and the correct polarity.
 */
#define EMS_104M_OCR         (OCR_TX0_PUSHPULL | OCR_TX1_PUSHPULL)

/*
 * In the CDR register, you should set CBP to 1.
 * You will probably also want to set the clock divider value to 7
 * (meaning direct oscillator output) because the second SJA1000 chip
 * is driven by the first one CLKOUT output.
 */
#define EMS_104M_CDR             (CDR_CBP | CDR_CLKOUT_MASK)
#define EMS_104M_MEM_SIZE        0x2000 /* Size of the remapped io-memory */
#define EMS_104M_CAN_BASE_OFFSET 0x100  /* Offset where controllers starts */
#define EMS_104M_CAN_CTRL_SIZE   0x80   /* Memory size for each controller */

#define EMS_104M_CARD_REG_IRQ_CTRL    7
#define EMS_104M_CARD_REG_IRQ_STATUS  8
#define EMS_104M_CARD_REG_VERSION     9

#define EMS_104M_CARD_REG_CONTROL     4
#define EMS_104M_CARD_REG_STATUS      6

#define EMS_CMD_RESET 0x00  /* Perform a reset of the card */
#define EMS_CMD_MAP   0x03  /* Map CAN controllers into card' memory */
#define EMS_CMD_UMAP  0x02  /* Unmap CAN controllers from card' memory */

static u8 ems_104m_read_reg(const struct sja1000_priv *priv, int port)
{
	return readb(priv->reg_base + port);
}

static void ems_104m_write_reg(const struct sja1000_priv *priv,
				 int port, u8 val)
{
	writeb(val, priv->reg_base + port);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
static irqreturn_t ems_104m_interrupt(int irq, void *dev_id,
					struct pt_regs *regs)
#else
static irqreturn_t ems_104m_interrupt(int irq, void *dev_id)
#endif
{
	struct ems_104m_card *card = dev_id;
	struct net_device *dev;
	irqreturn_t retval = IRQ_NONE;
	int i, again;

	do {
		again = 0;

		/* Check interrupt for each channel */
		for (i = 0; i < EMS_104M_MAX_CHAN; i++) {
			dev = card->net_dev[i];
			if (!dev)
				continue;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
			if (sja1000_interrupt(irq, dev, regs) == IRQ_HANDLED)
					again = 1;
#else
			if (sja1000_interrupt(irq, dev) == IRQ_HANDLED)
					again = 1;
#endif
		}

		/* At least one channel handled the interrupt */
		if (again)
			retval = IRQ_HANDLED;
	} while (again);

	return retval;
}

/*
 * Check if a CAN controller is present at the specified location
 * by trying to set 'em into the PeliCAN mode
 */
static inline int ems_104m_check_chan(struct sja1000_priv *priv)
{
	unsigned char res;

	/* Make sure SJA1000 is in reset mode */
	ems_104m_write_reg(priv, REG_MOD, 1);

	ems_104m_write_reg(priv, REG_CDR, CDR_PELICAN);

	/* read reset-values */
	res = ems_104m_read_reg(priv, REG_CDR);

	if (res == CDR_PELICAN)
		return 1;

	return 0;
}

/*
 * Probe ISA device for EMS CAN signature and register each available
 * CAN channel to SJA1000 Socket-CAN subsystem.
 */
static int __devinit ems_104m_probe(struct device *pdev, unsigned int idx)
{
	struct sja1000_priv *priv;
	struct net_device *dev;
	struct ems_104m_card *card;

	int err, i;

	/* Allocating card structures to hold addresses, ... */
	card = kzalloc(sizeof(struct ems_104m_card), GFP_KERNEL);
	if (card == NULL) {
		dev_err(pdev, "couldn't allocate memory\n");
		return -ENOMEM;
	}

	dev_set_drvdata(pdev, card);

	card->channels = 0;
	card->irq = irq[idx];

	card->base = ioremap_nocache(mem[idx], EMS_104M_MEM_SIZE);
	if (card->base == NULL) {
		dev_err(pdev, "couldn't map memory\n");
		err = -ENOMEM;
		goto failure_cleanup;
	}

	/* Check for unique EMS CAN signature */
	if (readw(card->base) != 0xAA55) {
		dev_err(pdev, "No EMS CPC Card hardware found.\n");

		err = -ENODEV;
		goto failure_cleanup;
	}

	writeb(EMS_CMD_RESET, card->base);

	/* Wait for reset to finish */
	i = 0;
	while (readb(card->base + EMS_104M_CARD_REG_STATUS) == 0x01) {
		/* Check for timeout (50ms.) */
		if (i >= 50) {
			dev_err(pdev, "couldn't reset card.\n");

			err = -EBUSY;
			goto failure_cleanup;
		}

		msleep(1);
	}

	/* Make sure CAN controllers are mapped into card's memory space */
	writeb(EMS_CMD_MAP, card->base);
	writeb(EMS_CMD_MAP, card->base); /* Second call to workaround bug */

	/* Detect available channels */
	for (i = 0; i < EMS_104M_MAX_CHAN; i++) {
		dev = alloc_sja1000dev(0);
		if (dev == NULL) {
			err = -ENOMEM;
			goto failure_cleanup;
		}

		card->net_dev[i] = dev;
		priv = netdev_priv(dev);
		priv->priv = card;
		SET_NETDEV_DEV(dev, pdev);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
		priv->irq_flags = SA_SHIRQ;
#else
		priv->irq_flags = IRQF_SHARED;
#endif
		dev->irq = irq[idx];
		priv->reg_base = card->base + EMS_104M_CAN_BASE_OFFSET
					+ (i * EMS_104M_CAN_CTRL_SIZE);

		/* Check if channel is present */
		if (ems_104m_check_chan(priv)) {
			priv->read_reg  = ems_104m_read_reg;
			priv->write_reg = ems_104m_write_reg;
			priv->can.clock.freq = EMS_104M_CAN_CLOCK;
			priv->ocr = EMS_104M_OCR;
			priv->cdr = EMS_104M_CDR;
			priv->flags |= SJA1000_CUSTOM_IRQ_HANDLER;

			/* Register SJA1000 device */
			err = register_sja1000dev(dev);
			if (err) {
				dev_err(pdev, "registering device failed"
				    " (err=%d)\n", err);
				free_sja1000dev(dev);
				goto failure_cleanup;
			}

			/* Enable interrupts of this channel */
			writeb(0x3 << (i * 2),
			    card->base + EMS_104M_CARD_REG_IRQ_CTRL);

			card->channels++;

			dev_info(pdev, "registered %s on channel at 0x%p,"
			    " irq %d\n", dev->name, priv->reg_base, dev->irq);
		} else {
			free_sja1000dev(dev);
		}
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
	err = request_irq(card->irq, &ems_104m_interrupt, SA_SHIRQ,
		DRV_NAME, (void *)card);
#else
	err = request_irq(card->irq, &ems_104m_interrupt, IRQF_SHARED,
		DRV_NAME, (void *)card);
#endif

	if (err) {
		dev_err(pdev, "registering device failed (err=%d)\n", err);
		goto failure_cleanup;
	}

	return 0;

failure_cleanup:
	dev_err(pdev, "error: %d. Cleaning Up.\n", err);

	if (card->base)
		iounmap(card->base);

	kfree(card);

	return err;
}

/*
 * Release claimed resources
 */
static int __devexit ems_104m_remove(struct device *pdev, unsigned int idx)
{
	struct ems_104m_card *card = dev_get_drvdata(pdev);
	struct net_device *dev;
	int i = 0;

	if (!card)
		return 0;

	free_irq(card->irq, card);

	for (i = 0; i < card->channels; i++) {
		dev = card->net_dev[i];

		if (!dev)
			continue;

		dev_info(pdev, "removing %s on channel #%d\n", dev->name, i);
		unregister_sja1000dev(dev);
		free_sja1000dev(dev);
	}

	writeb(EMS_CMD_UMAP, card->base);

	if (card->base != NULL)
		iounmap(card->base);

	kfree(card);

	dev_set_drvdata(pdev, NULL);

	return 0;
}

static int __devinit ems_104m_match(struct device *pdev, unsigned int idx)
{
	if (!mem[idx])
		return 0;

	if (!irq[idx]) {
		dev_err(pdev, "insufficient parameters supplied\n");
		return 0;
	}

	return 1;
}

static struct isa_driver ems_104m_driver = {
	.match = ems_104m_match,
	.probe = ems_104m_probe,
	.remove = __devexit_p(ems_104m_remove),

	.driver = {
		.name = DRV_NAME,
	},
};

static int __init ems_104m_init(void)
{
	int err = isa_register_driver(&ems_104m_driver, EMS_104M_MAX_DEV);

	if (!err)
		printk(KERN_INFO
		       "Legacy %s driver for max. %d devices registered\n",
		       DRV_NAME, EMS_104M_MAX_DEV);

	return err;
}

static void __exit ems_104m_exit(void)
{
	isa_unregister_driver(&ems_104m_driver);
}

module_init(ems_104m_init);
module_exit(ems_104m_exit);

