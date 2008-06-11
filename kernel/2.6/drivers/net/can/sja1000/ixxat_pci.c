/*
 * Copyright (C) 2007 Wolfgang Grandegger <wg@grandegger.com>
 * Copyright (C) 2008 Sascha Hauer <s.hauer@pengutronix.de>, Pengutronix
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
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/can.h>
#include <linux/can/dev.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
#include <linux/io.h>
#else
#include <asm/io.h>
#endif

#include "sja1000.h"

#define DRV_NAME  "can-ixxat-pci"

MODULE_AUTHOR("Sascha Hauer <s.hauer@pengutronix.de");
MODULE_DESCRIPTION("Socket-CAN driver for IXXAT PC-I 04/PCI PCI cards");
MODULE_SUPPORTED_DEVICE("IXXAT PC-I 04/PCI card");
MODULE_LICENSE("GPL v2");

/* Maximum number of interfaces supported on one card. Currently
 * we only support a maximum of two interfaces, which is the maximum
 * of what Ixxat sells anyway.
 */
#define IXXAT_PCI_MAX_CAN 2

struct ixxat_pci {
	struct pci_dev *pci_dev;
	struct net_device *dev[IXXAT_PCI_MAX_CAN];
	int conf_addr;
	void __iomem *base_addr;
};

#define IXXAT_PCI_CAN_CLOCK  (16000000 / 2)

#define IXXAT_PCI_OCR	     (OCR_TX0_PUSHPULL | OCR_TX0_INVERT | \
			      OCR_TX1_PUSHPULL)
#define IXXAT_PCI_CDR	     0

#define CHANNEL_RESET_OFFSET 0x110
#define CHANNEL_OFFSET      0x200

#define INTCSR_OFFSET        0x4c /* Offset in PLX9050 conf registers */
#define INTCSR_LINTI1        (1 << 0)
#define INTCSR_LINTI2        (1 << 3)
#define INTCSR_PCI           (1 << 6)

/* PCI vender, device and sub-device ID */
#define IXXAT_PCI_VENDOR_ID  0x10b5
#define IXXAT_PCI_DEVICE_ID  0x9050
#define IXXAT_PCI_SUB_SYS_ID 0x2540

#define IXXAT_PCI_BASE_SIZE  0x400

static struct pci_device_id ixxat_pci_tbl[] = {
	{IXXAT_PCI_VENDOR_ID, IXXAT_PCI_DEVICE_ID, PCI_ANY_ID, PCI_ANY_ID,},
        { 0,}
};

MODULE_DEVICE_TABLE(pci, ixxat_pci_tbl);

static u8 ixxat_pci_read_reg(struct net_device *ndev, int port)
{
	u8 val;
	val = readb((void __iomem *)(ndev->base_addr + port));
	return val;
}

static void ixxat_pci_write_reg(struct net_device *ndev, int port, u8 val)
{
	writeb(val, (void __iomem *)(ndev->base_addr + port));
}

static void ixxat_pci_del_chan(struct pci_dev *pdev, struct net_device *ndev)
{
	dev_info(&pdev->dev, "Removing device %s\n", ndev->name);

	unregister_sja1000dev(ndev);

	free_sja1000dev(ndev);
}

static struct net_device *ixxat_pci_add_chan(struct pci_dev *pdev,
		void __iomem *base_addr)
{
	struct net_device *ndev;
	struct sja1000_priv *priv;
	int err;

	ndev = alloc_sja1000dev(0);
	if (ndev == NULL)
		return ERR_PTR(-ENOMEM);

	priv = netdev_priv(ndev);

	ndev->base_addr = (unsigned long)base_addr;

	priv->read_reg = ixxat_pci_read_reg;
	priv->write_reg = ixxat_pci_write_reg;

	priv->can.can_sys_clock = IXXAT_PCI_CAN_CLOCK;

	priv->ocr = IXXAT_PCI_OCR;
	priv->cdr = IXXAT_PCI_CDR;

	/* Set and enable PCI interrupts */
	ndev->irq = pdev->irq;

	dev_dbg(&pdev->dev, "base_addr=%#lx irq=%d\n",
			ndev->base_addr, ndev->irq);

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

static int __devinit ixxat_pci_init_one(struct pci_dev *pdev,
				       const struct pci_device_id *ent)
{
	struct ixxat_pci *board;
	int err, intcsr = INTCSR_LINTI1 | INTCSR_PCI;
	u16 sub_sys_id;
	void __iomem *base_addr;

	dev_info(&pdev->dev, "Initializing device %04x:%04x\n",
	       pdev->vendor, pdev->device);

	board = kzalloc(sizeof(*board), GFP_KERNEL);
	if (!board)
		return -ENOMEM;

	if ((err = pci_enable_device(pdev)))
		goto failure;

	if ((err = pci_request_regions(pdev, DRV_NAME)))
		goto failure;

	if ((err = pci_read_config_word(pdev, 0x2e, &sub_sys_id)))
		goto failure_release_pci;

	if (sub_sys_id != IXXAT_PCI_SUB_SYS_ID)
		return -ENODEV;

	/* Enable memory and I/O space */
	if ((err = pci_write_config_word(pdev, 0x04, 0x3)))
		goto failure_release_pci;

	board->conf_addr = pci_resource_start(pdev, 1);

	base_addr = pci_iomap(pdev, 2, IXXAT_PCI_BASE_SIZE);
	if (base_addr == 0) {
		err = -ENODEV;
		goto failure_release_pci;
	}

	board->base_addr = base_addr;

	writeb(0x1, base_addr + CHANNEL_RESET_OFFSET);
	writeb(0x1, base_addr + CHANNEL_OFFSET + CHANNEL_RESET_OFFSET);
	udelay(100);

	board->dev[0] = ixxat_pci_add_chan(pdev, base_addr);
	if (IS_ERR(board->dev[0]))
		goto failure_iounmap;

	/* Check if second channel is available */
	if (readb(base_addr + CHANNEL_OFFSET + REG_MOD) == 0x21 &&
	    readb(base_addr + CHANNEL_OFFSET + REG_SR) == 0x0c &&
	    readb(base_addr + CHANNEL_OFFSET + REG_IR) == 0xe0) {
		board->dev[1] = ixxat_pci_add_chan(pdev,
				base_addr + CHANNEL_OFFSET);
		if (IS_ERR(board->dev[1]))
			goto failure_unreg_dev0;

		intcsr |= INTCSR_LINTI2;
	}

	/* enable interrupt(s) in PLX9050 */
	outb(intcsr, board->conf_addr + INTCSR_OFFSET);

	pci_set_drvdata(pdev, board);

	return 0;

failure_unreg_dev0:
	ixxat_pci_del_chan(pdev, board->dev[0]);

failure_iounmap:
	pci_iounmap(pdev, board->base_addr);

failure_release_pci:
	pci_release_regions(pdev);

failure:
	kfree(board);

	return err;
}

static void __devexit ixxat_pci_remove_one(struct pci_dev *pdev)
{
	struct ixxat_pci *board = pci_get_drvdata(pdev);
	int i;

	/* Disable interrupts in PLX9050*/
	outb(0, board->conf_addr + INTCSR_OFFSET);

	for (i = 0; i < IXXAT_PCI_MAX_CAN; i++) {
		if (!board->dev[i])
			break;
		ixxat_pci_del_chan(pdev, board->dev[i]);
	}

	pci_iounmap(pdev, board->base_addr);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);

	kfree(board);
}

static struct pci_driver ixxat_pci_driver = {
	.name = DRV_NAME,
	.id_table = ixxat_pci_tbl,
	.probe = ixxat_pci_init_one,
	.remove = __devexit_p(ixxat_pci_remove_one),
};

static int __init ixxat_pci_init(void)
{
	return pci_register_driver(&ixxat_pci_driver);
}

static void __exit ixxat_pci_exit(void)
{
	pci_unregister_driver(&ixxat_pci_driver);
}

module_init(ixxat_pci_init);
module_exit(ixxat_pci_exit);
