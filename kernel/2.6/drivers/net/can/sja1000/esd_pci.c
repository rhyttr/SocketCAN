/*
 * Copyright (C) 2007 Wolfgang Grandegger <wg@grandegger.com>
 * Copyright (C) 2008 Sascha Hauer <s.hauer@pengutronix.de>, Pengutronix
 * Copyright (C) 2009 Matthias Fuchs <matthias.fuchs@esd.eu>, esd gmbh
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
#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <socketcan/can.h>
#include <socketcan/can/dev.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
#include <linux/io.h>
#else
#include <asm/io.h>
#endif

#include "sja1000.h"

#define DRV_NAME  "esd_pci"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
#error This driver does not support Kernel versions < 2.6.21
#endif

MODULE_AUTHOR("Matthias Fuchs <matthias.fuchs@esd.eu");
MODULE_DESCRIPTION("Socket-CAN driver for esd PCI/PMC/CPCI/PCIe/PCI104 " \
		   "CAN cards");
MODULE_SUPPORTED_DEVICE("esd CAN-PCI/200, CAN-PCI/266, CAN-PMC266, " \
			"CAN-PCIe/2000, CAN-CPCI/200, CAN-PCI104");
MODULE_LICENSE("GPL v2");

/* Maximum number of interfaces supported on one card. */
#define ESD_PCI_MAX_CAN 2

struct esd_pci {
	struct pci_dev *pci_dev;
	struct net_device *dev[ESD_PCI_MAX_CAN];
	void __iomem *conf_addr;
	void __iomem *base_addr;
};

#define ESD_PCI_CAN_CLOCK	(16000000 / 2)

#define ESD_PCI_OCR		(OCR_TX0_PUSHPULL | OCR_TX1_PUSHPULL)
#define ESD_PCI_CDR		0

#define CHANNEL_OFFSET		0x100

#define INTCSR_OFFSET		0x4c /* Offset in PLX9050 conf registers */
#define INTCSR_LINTI1		(1 << 0)
#define INTCSR_PCI		(1 << 6)

#define INTCSR9056_OFFSET	0x68 /* Offset in PLX9056 conf registers */
#define INTCSR9056_LINTI	(1 << 11)
#define INTCSR9056_PCI		(1 << 8)

#ifndef PCI_DEVICE_ID_PLX_9056
# define PCI_DEVICE_ID_PLX_9056 0x9056
#endif

/* PCI subsystem IDs of esd's SJA1000 based CAN cards */

/* CAN-PCI/200: PCI, 33MHz only, bridge: PLX9050 */
#define ESD_PCI_SUB_SYS_ID_PCI200	0x0004

/* CAN-PCI/266: PCI, 33/66MHz, bridge: PLX9056 */
#define ESD_PCI_SUB_SYS_ID_PCI266	0x0009

/* CAN-PMC/266: PMC module, 33/66MHz, bridge: PLX9056 */
#define ESD_PCI_SUB_SYS_ID_PMC266	0x000e

/* CAN-CPCI/200: Compact PCI, 33MHz only, bridge: PLX9030 */
#define ESD_PCI_SUB_SYS_ID_CPCI200	0x010b

/* CAN-PCIE/2000: PCI Express 1x, bridge: PEX8311 = PEX8111 + PLX9056 */
#define ESD_PCI_SUB_SYS_ID_PCIE2000	0x0200

/* CAN-PCI/104: PCI104 module, 33MHz only, bridge: PLX9030 */
#define ESD_PCI_SUB_SYS_ID_PCI104200	0x0501

static struct pci_device_id esd_pci_tbl[] = {
	{PCI_VENDOR_ID_PLX, PCI_DEVICE_ID_PLX_9050,
	 PCI_VENDOR_ID_ESDGMBH, ESD_PCI_SUB_SYS_ID_PCI200},
	{PCI_VENDOR_ID_PLX, PCI_DEVICE_ID_PLX_9056,
	 PCI_VENDOR_ID_ESDGMBH, ESD_PCI_SUB_SYS_ID_PCI266},
	{PCI_VENDOR_ID_PLX, PCI_DEVICE_ID_PLX_9056,
	 PCI_VENDOR_ID_ESDGMBH, ESD_PCI_SUB_SYS_ID_PMC266},
	{PCI_VENDOR_ID_PLX, PCI_DEVICE_ID_PLX_9030,
	 PCI_VENDOR_ID_ESDGMBH, ESD_PCI_SUB_SYS_ID_CPCI200},
	{PCI_VENDOR_ID_PLX, PCI_DEVICE_ID_PLX_9056,
	 PCI_VENDOR_ID_ESDGMBH, ESD_PCI_SUB_SYS_ID_PCIE2000},
	{PCI_VENDOR_ID_PLX, PCI_DEVICE_ID_PLX_9030,
	 PCI_VENDOR_ID_ESDGMBH, ESD_PCI_SUB_SYS_ID_PCI104200},
	{0,}
};

#define ESD_PCI_BASE_SIZE  0x200

MODULE_DEVICE_TABLE(pci, esd_pci_tbl);

static u8 esd_pci_read_reg(const struct sja1000_priv *priv, int port)
{
	return readb(priv->reg_base + port);
}

static void esd_pci_write_reg(const struct sja1000_priv *priv, int port, u8 val)
{
	writeb(val, priv->reg_base + port);
}

static void esd_pci_del_chan(struct pci_dev *pdev, struct net_device *ndev)
{
	dev_info(&pdev->dev, "Removing device %s\n", ndev->name);

	unregister_sja1000dev(ndev);

	free_sja1000dev(ndev);
}

static struct net_device * __devinit esd_pci_add_chan(struct pci_dev *pdev,
						      void __iomem *base_addr)
{
	struct net_device *ndev;
	struct sja1000_priv *priv;
	int err;

	ndev = alloc_sja1000dev(0);
	if (ndev == NULL)
		return ERR_PTR(-ENOMEM);

	priv = netdev_priv(ndev);

	priv->reg_base = base_addr;

	priv->read_reg = esd_pci_read_reg;
	priv->write_reg = esd_pci_write_reg;

	priv->can.clock.freq = ESD_PCI_CAN_CLOCK;

	priv->ocr = ESD_PCI_OCR;
	priv->cdr = ESD_PCI_CDR;

	/* Set and enable PCI interrupts */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
	priv->irq_flags = SA_SHIRQ;
#else
	priv->irq_flags = IRQF_SHARED;
#endif
	ndev->irq = pdev->irq;

	dev_dbg(&pdev->dev, "reg_base=0x%p irq=%d\n",
			priv->reg_base, ndev->irq);

	SET_NETDEV_DEV(ndev, &pdev->dev);

	err = register_sja1000dev(ndev);
	if (err) {
		dev_err(&pdev->dev, "Failed to register (err=%d)\n", err);
		goto failure;
	}

	return ndev;

failure:
	free_sja1000dev(ndev);
	return ERR_PTR(err);
}

static int __devinit esd_pci_init_one(struct pci_dev *pdev,
				       const struct pci_device_id *ent)
{
	struct esd_pci *board;
	int err;
	void __iomem *base_addr;
	void __iomem *conf_addr;

	dev_info(&pdev->dev,
		 "Initializing device %04x:%04x %04x:%04x\n",
		 pdev->vendor, pdev->device,
		 pdev->subsystem_vendor, pdev->subsystem_device);

	board = kzalloc(sizeof(*board), GFP_KERNEL);
	if (!board)
		return -ENOMEM;

	err = pci_enable_device(pdev);
	if (err)
		goto failure;

	err = pci_request_regions(pdev, DRV_NAME);
	if (err)
		goto failure;

	conf_addr = pci_iomap(pdev, 0, ESD_PCI_BASE_SIZE);
	if (conf_addr == NULL) {
		err = -ENODEV;
		goto failure_release_pci;
	}

	board->conf_addr = conf_addr;

	base_addr = pci_iomap(pdev, 2, ESD_PCI_BASE_SIZE);
	if (base_addr == NULL) {
		err = -ENODEV;
		goto failure_iounmap_conf;
	}

	board->base_addr = base_addr;

	board->dev[0] = esd_pci_add_chan(pdev, base_addr);
	if (IS_ERR(board->dev[0]))
		goto failure_iounmap_base;

	/* Check if second channel is available */
	writeb(MOD_RM, base_addr + CHANNEL_OFFSET + REG_MOD);
	writeb(CDR_CBP, base_addr + CHANNEL_OFFSET + REG_CDR);
	writeb(MOD_RM, base_addr + CHANNEL_OFFSET + REG_MOD);
	if (readb(base_addr + CHANNEL_OFFSET + REG_MOD) == 0x21) {
		writeb(MOD_SM | MOD_AFM | MOD_STM | MOD_LOM | MOD_RM,
		       base_addr + CHANNEL_OFFSET + REG_MOD);
		if (readb(base_addr + CHANNEL_OFFSET + REG_MOD) == 0x3f) {
			writeb(MOD_RM, base_addr + CHANNEL_OFFSET + REG_MOD);
			board->dev[1] =
				esd_pci_add_chan(pdev,
						 base_addr + CHANNEL_OFFSET);
			if (IS_ERR(board->dev[1]))
				goto failure_unreg_dev0;
		} else
			writeb(MOD_RM, base_addr + CHANNEL_OFFSET + REG_MOD);
	} else
		writeb(MOD_RM, base_addr + CHANNEL_OFFSET + REG_MOD);

	if ((pdev->device == PCI_DEVICE_ID_PLX_9050) ||
	    (pdev->device == PCI_DEVICE_ID_PLX_9030)) {
		/* Enable interrupts in PLX9050 */
		writel(INTCSR_LINTI1 | INTCSR_PCI,
		       board->conf_addr + INTCSR_OFFSET);
	} else {
		/* Enable interrupts in PLX9056*/
		writel(INTCSR9056_LINTI | INTCSR9056_PCI,
		       board->conf_addr + INTCSR9056_OFFSET);
	}

	pci_set_drvdata(pdev, board);

	return 0;

failure_unreg_dev0:
	esd_pci_del_chan(pdev, board->dev[0]);

failure_iounmap_base:
	pci_iounmap(pdev, board->base_addr);

failure_iounmap_conf:
	pci_iounmap(pdev, board->conf_addr);

failure_release_pci:
	pci_release_regions(pdev);

failure:
	kfree(board);

	return err;
}

static void __devexit esd_pci_remove_one(struct pci_dev *pdev)
{
	struct esd_pci *board = pci_get_drvdata(pdev);
	int i;

	if ((pdev->device == PCI_DEVICE_ID_PLX_9050) ||
	    (pdev->device == PCI_DEVICE_ID_PLX_9030)) {
		/* Disable interrupts in PLX9050*/
		writel(0, board->conf_addr + INTCSR_OFFSET);
	} else {
		/* Disable interrupts in PLX9056*/
		writel(0, board->conf_addr + INTCSR9056_OFFSET);
	}

	for (i = 0; i < ESD_PCI_MAX_CAN; i++) {
		if (!board->dev[i])
			break;
		esd_pci_del_chan(pdev, board->dev[i]);
	}

	pci_iounmap(pdev, board->base_addr);
	pci_iounmap(pdev, board->conf_addr);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);

	kfree(board);
}

static struct pci_driver esd_pci_driver = {
	.name = DRV_NAME,
	.id_table = esd_pci_tbl,
	.probe = esd_pci_init_one,
	.remove = __devexit_p(esd_pci_remove_one),
};

static int __init esd_pci_init(void)
{
	return pci_register_driver(&esd_pci_driver);
}

static void __exit esd_pci_exit(void)
{
	pci_unregister_driver(&esd_pci_driver);
}

module_init(esd_pci_init);
module_exit(esd_pci_exit);
