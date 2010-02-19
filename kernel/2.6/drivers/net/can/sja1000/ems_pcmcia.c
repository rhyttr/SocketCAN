/*
 * Copyright (C) 2008 Sebastian Haas <haas@ems-wuensche.com>
 * Copyright (C) 2010 Markus Plessing <plessing@ems-wuensche.com>
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
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/delay.h>
#include <socketcan/can.h>
#include <socketcan/can/dev.h>
#include <asm/io.h>

#include <pcmcia/cs_types.h>
#include <pcmcia/cs.h>
#include <pcmcia/cistpl.h>
#include <pcmcia/ciscode.h>
#include <pcmcia/ds.h>
#include <pcmcia/cisreg.h>

#include "sja1000.h"

#define DRV_NAME  "ems_pcmcia"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
#error This driver does not support Kernel versions < 2.6.16
#endif

MODULE_AUTHOR("Sebastian Haas <haas@ems-wuenche.com>");
MODULE_DESCRIPTION("Socket-CAN driver for EMS CPC-CARD cards");
MODULE_SUPPORTED_DEVICE("EMS CPC-CARD CAN card");
MODULE_LICENSE("GPL v2");

static int debug;

module_param(debug, int, S_IRUGO | S_IWUSR);

MODULE_PARM_DESC(debug, "Set debug level (default: 0)");

#define EMS_PCMCIA_MAX_CHAN 2

struct ems_pcmcia_card {
	int channels;

	struct pcmcia_device *pcmcia_dev;
	struct net_device *net_dev[EMS_PCMCIA_MAX_CHAN];

	void __iomem *base_addr;
};

#define EMS_PCMCIA_CAN_CLOCK (16000000 / 2)

/*
 * The board configuration is probably following:
 * RX1 is connected to ground.
 * TX1 is not connected.
 * CLKO is not connected.
 * Setting the OCR register to 0xDA is a good idea.
 * This means  normal output mode , push-pull and the correct polarity.
 */
#define EMS_PCMCIA_OCR         (OCR_TX0_PUSHPULL | OCR_TX1_PUSHPULL)

/*
 * In the CDR register, you should set CBP to 1.
 * You will probably also want to set the clock divider value to 7
 * (meaning direct oscillator output) because the second SJA1000 chip
 * is driven by the first one CLKOUT output.
 */
#define EMS_PCMCIA_CDR             (CDR_CBP | CDR_CLKOUT_MASK)
#define EMS_PCMCIA_MEM_SIZE        4096  /* Size of the remapped io-memory */
#define EMS_PCMCIA_CAN_BASE_OFFSET 0x100 /* Offset where controllers starts */
#define EMS_PCMCIA_CAN_CTRL_SIZE   0x80  /* Memory size for each controller */

#define EMS_CMD_RESET 0x00  /* Perform a reset of the card */
#define EMS_CMD_MAP   0x03  /* Map CAN controllers into card' memory */
#define EMS_CMD_UMAP  0x02  /* Unmap CAN controllers from card' memory */

static struct pcmcia_device_id ems_pcmcia_tbl[] = {
	PCMCIA_DEVICE_PROD_ID123("EMS_T_W", "CPC-Card", "V2.0", 0xeab1ea23,
				 0xa338573f, 0xe4575800),
	PCMCIA_DEVICE_NULL,
};

MODULE_DEVICE_TABLE (pcmcia, ems_pcmcia_tbl);

static void ems_pcmcia_config(struct pcmcia_device *dev);

static u8 ems_pcmcia_read_reg(const struct sja1000_priv *priv, int port)
{
	return readb(priv->reg_base + port);
}

static void ems_pcmcia_write_reg(const struct sja1000_priv *priv,
				 int port, u8 val)
{
	writeb(val, priv->reg_base + port);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
static irqreturn_t ems_pcmcia_interrupt(int irq, void *dev_id,
					struct pt_regs *regs)
#else
static irqreturn_t ems_pcmcia_interrupt(int irq, void *dev_id)
#endif
{
	struct ems_pcmcia_card *card = dev_id;
	struct net_device *dev;
	irqreturn_t retval = IRQ_NONE;
	int i, again;

	/* Card not present */
	if (readw(card->base_addr) != 0xAA55)
		return IRQ_HANDLED;

	do {
		again = 0;

		/* Check interrupt for each channel */
		for (i = 0; i < EMS_PCMCIA_MAX_CHAN; i++) {
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
static inline int ems_pcmcia_check_chan(struct sja1000_priv *priv)
{
	unsigned char res;

	/* Make sure SJA1000 is in reset mode */
	ems_pcmcia_write_reg(priv, REG_MOD, 1);

	ems_pcmcia_write_reg(priv, REG_CDR, CDR_PELICAN);

	/* read reset-values */
	res = ems_pcmcia_read_reg(priv, REG_CDR);

	if (res == CDR_PELICAN)
		return 1;

	return 0;
}

static void ems_pcmcia_del_card(struct pcmcia_device *pdev)
{
	struct ems_pcmcia_card *card = pdev->priv;
	struct net_device *dev;
	int i = 0;

	if (!card)
		return;

	free_irq(pdev->irq.AssignedIRQ, card);

	for (i = 0; i < card->channels; i++) {
		dev = card->net_dev[i];

		if (!dev)
			continue;

		printk(KERN_INFO "%s: removing %s on channel #%d\n",
		       DRV_NAME, dev->name, i);
		unregister_sja1000dev(dev);
		free_sja1000dev(dev);
	}

	writeb(EMS_CMD_UMAP, card->base_addr);

	if (card->base_addr != NULL )
		iounmap(card->base_addr);

	kfree(card);

	pdev->priv = NULL;
}

static void ems_pcmcia_card_reset(struct ems_pcmcia_card *card)
{
	/* Request board reset */
	writeb(EMS_CMD_RESET, card->base_addr);
}

/*
 * Probe PCI device for EMS CAN signature and register each available
 * CAN channel to SJA1000 Socket-CAN subsystem.
 */
static int __devinit ems_pcmcia_add_card(struct pcmcia_device *pdev,
					 unsigned long base)
{
	struct sja1000_priv *priv;
	struct net_device *dev;
	struct ems_pcmcia_card *card;
	int err, i;

	/* Allocating card structures to hold addresses, ... */
	card = kzalloc(sizeof(struct ems_pcmcia_card), GFP_KERNEL);
	if (card == NULL) {
		printk(KERN_ERR "%s: unable to allocate memory\n", DRV_NAME);
		return -ENOMEM;
	}

	pdev->priv = card;

	card->channels = 0;

	card->base_addr = ioremap(base, EMS_PCMCIA_MEM_SIZE);
	if (card->base_addr == NULL) {
		err = -ENOMEM;
		goto failure_cleanup;
	}

	/* Check for unique EMS CAN signature */
	if (readw(card->base_addr) != 0xAA55) {
		printk(KERN_ERR "%s: No EMS CPC Card hardware found.\n",
		       DRV_NAME);

		err = -ENODEV;
		goto failure_cleanup;
	}

	ems_pcmcia_card_reset(card);

	/* Make sure CAN controllers are mapped into card's memory space */
	writeb(EMS_CMD_MAP, card->base_addr);

	/* Detect available channels */
	for (i = 0; i < EMS_PCMCIA_MAX_CHAN; i++) {
		dev = alloc_sja1000dev(0);
		if (dev == NULL) {
			err = -ENOMEM;
			goto failure_cleanup;
		}

		card->net_dev[i] = dev;
		priv = netdev_priv(dev);
		priv->priv = card;
		SET_NETDEV_DEV(dev, &pdev->dev);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
		priv->irq_flags = SA_SHIRQ;
#else
		priv->irq_flags = IRQF_SHARED;
#endif
		dev->irq = pdev->irq.AssignedIRQ;
		priv->reg_base = (card->base_addr
					+ EMS_PCMCIA_CAN_BASE_OFFSET
					+ (i * EMS_PCMCIA_CAN_CTRL_SIZE));

		/* Check if channel is present */
		if (ems_pcmcia_check_chan(priv)) {
			priv->read_reg  = ems_pcmcia_read_reg;
			priv->write_reg = ems_pcmcia_write_reg;
			priv->can.clock.freq = EMS_PCMCIA_CAN_CLOCK;
			priv->ocr = EMS_PCMCIA_OCR;
			priv->cdr = EMS_PCMCIA_CDR;
			priv->flags |= SJA1000_CUSTOM_IRQ_HANDLER;

			/* Register SJA1000 device */
			err = register_sja1000dev(dev);
			if (err) {
				printk(KERN_INFO "%s: registering device "
				       "failed (err=%d)\n", DRV_NAME, err);
				free_sja1000dev(dev);
				goto failure_cleanup;
			}

			card->channels++;

			printk(KERN_INFO "%s: registered %s on channel "
			       "#%d at 0x%p, irq %d\n", DRV_NAME, dev->name,
			       i, priv->reg_base, dev->irq);
		} else {
			free_sja1000dev(dev);
		}
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
	err = request_irq(dev->irq, &ems_pcmcia_interrupt, SA_SHIRQ,
		DRV_NAME, (void *)card);
#else
	err = request_irq(dev->irq, &ems_pcmcia_interrupt, IRQF_SHARED,
		DRV_NAME, (void *)card);
#endif
	if (err) {
		printk(KERN_INFO "Registering device failed (err=%d)\n", err);

		goto failure_cleanup;
	}

	return 0;

failure_cleanup:
	printk(KERN_ERR "Error: %d. Cleaning Up.\n", err);

	ems_pcmcia_del_card(pdev);

	return err;
}

/*
 * Setup PCMCIA socket and probe for EMS CPC-CARD
 */
static int __devinit ems_pcmcia_probe(struct pcmcia_device *dev)
{
	/* The io structure describes IO port mapping */
	dev->io.NumPorts1 = 16;
	dev->io.Attributes1 = IO_DATA_PATH_WIDTH_8;
	dev->io.NumPorts2 = 16;
	dev->io.Attributes2 = IO_DATA_PATH_WIDTH_16;
	dev->io.IOAddrLines = 5;

	/* Interrupt setup */
	dev->irq.Attributes = IRQ_TYPE_DYNAMIC_SHARING;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	dev->irq.IRQInfo1 = IRQ_LEVEL_ID;
#endif

	/* General socket configuration */
	dev->conf.Attributes = CONF_ENABLE_IRQ;
	dev->conf.IntType = INT_MEMORY_AND_IO;
	dev->conf.ConfigIndex = 1;
	dev->conf.Present = PRESENT_OPTION;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	dev->win = NULL;
#else
	dev->win = 0;
#endif

	ems_pcmcia_config(dev);

	return 0;
}

/*
 * Configure PCMCIA socket
 */
static void __devinit ems_pcmcia_config(struct pcmcia_device *dev)
{
	win_req_t req;
	memreq_t mem;

	int csval;

	/* Allocate a memory window */
	req.Attributes = WIN_DATA_WIDTH_8|WIN_MEMORY_TYPE_CM|WIN_ENABLE;
	req.Base = req.Size = 0;
	req.AccessSpeed = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	csval = pcmcia_request_window(&dev, &req, &dev->win);
#else
	csval = pcmcia_request_window(dev, &req, &dev->win);
#endif
	if (csval) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		cs_error(dev, RequestWindow, csval);
#else
		dev_err(&dev->dev, "RequestWindow failed (err=%d)\n",
			csval);
#endif
		return;
	}

	mem.CardOffset = mem.Page = 0;
	mem.CardOffset = dev->conf.ConfigBase;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	csval = pcmcia_map_mem_page(dev->win, &mem);
#else
	csval = pcmcia_map_mem_page(dev, dev->win, &mem);
#endif

	if (csval) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		cs_error(dev, MapMemPage, csval);
#else
		dev_err(&dev->dev, "MapMemPage failed (err=%d)\n",
			csval);
#endif
		return;
	}

	csval = pcmcia_request_irq(dev, &dev->irq);
	if (csval) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		cs_error(dev, RequestIRQ, csval);
#else
		dev_err(&dev->dev, "RequestIRQ failed (err=%d)\n",
			csval);
#endif
		return;
	}

	/* This actually configures the PCMCIA socket */
	csval = pcmcia_request_configuration(dev, &dev->conf);
	if (csval) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
		cs_error(dev, RequestConfiguration, csval);
#else
		dev_err(&dev->dev, "RequestConfig failed (err=%d)\n",
			csval);
#endif
		return;
	}

	ems_pcmcia_add_card(dev, req.Base);
}

/*
 * Release claimed resources
 */
static void ems_pcmcia_remove(struct pcmcia_device *dev)
{
	ems_pcmcia_del_card(dev);

	pcmcia_disable_device(dev);
}

/*
 * The dev_info variable is the "key" that is used to match up this
 * device driver with appropriate cards, through the card configuration
 * database.
 */
static dev_info_t dev_info = "can-ems-pcmcia";

static struct pcmcia_driver ems_pcmcia_driver = {
	.drv = {
		.name = dev_info,
		},

	.probe = ems_pcmcia_probe,
	.remove = ems_pcmcia_remove,

	.id_table = ems_pcmcia_tbl,
};

static int __init ems_pcmcia_init(void)
{
	return pcmcia_register_driver(&ems_pcmcia_driver);
}

static void __exit ems_pcmcia_exit(void)
{
	pcmcia_unregister_driver(&ems_pcmcia_driver);
}

module_init(ems_pcmcia_init);
module_exit(ems_pcmcia_exit);

