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
#include <linux/version.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <socketcan/can.h>
#include <socketcan/can/dev.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
#include <linux/io.h>
#else
#include <asm/io.h>
#endif

#include "sja1000.h"

#define DRV_NAME  "ixxat_pci"

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
	{0,}
};

MODULE_DEVICE_TABLE(pci, ixxat_pci_tbl);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
static inline void *kzalloc(size_t size, unsigned int __nocast flags)
{
	void *ret = kmalloc(size, flags);
	if (ret)
		memset(ret, 0, size);
	return ret;
}
#endif

static u8 ixxat_pci_read_reg(const struct sja1000_priv *priv, int port)
{
	return readb(priv->reg_base + port);
}

static void ixxat_pci_write_reg(const struct sja1000_priv *priv,
				int port, u8 val)
{
	writeb(val, priv->reg_base + port);
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

	priv->reg_base = base_addr;

	priv->read_reg = ixxat_pci_read_reg;
	priv->write_reg = ixxat_pci_write_reg;

	priv->can.clock.freq = IXXAT_PCI_CAN_CLOCK;

	priv->ocr = IXXAT_PCI_OCR;
	priv->cdr = IXXAT_PCI_CDR;

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

	err = pci_enable_device(pdev);
	if (err)
		goto failure;

	err = pci_request_regions(pdev, DRV_NAME);
	if (err)
		goto failure;

	err = pci_read_config_word(pdev, 0x2e, &sub_sys_id);
	if (err)
		goto failure_release_pci;

	if (sub_sys_id != IXXAT_PCI_SUB_SYS_ID)
		return -ENODEV;

	/* Enable memory and I/O space */
	err = pci_write_config_word(pdev, 0x04, 0x3);
	if (err)
		goto failure_release_pci;

	board->conf_addr = pci_resource_start(pdev, 1);

	base_addr = pci_iomap(pdev, 2, IXXAT_PCI_BASE_SIZE);
	if (base_addr == NULL) {
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
	if ((readb(base_addr + CHANNEL_OFFSET + REG_MOD) & 0xa1) == 0x21 &&
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
