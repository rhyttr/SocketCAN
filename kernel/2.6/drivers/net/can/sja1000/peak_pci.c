/*
 * Copyright (C) 2007 Wolfgang Grandegger <wg@grandegger.com>
 *
 * Derived from the PCAN project file driver/src/pcan_pci.c:
 *
 * Copyright (C) 2001-2006  PEAK System-Technik GmbH
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

#define DRV_NAME  "peak_pci"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
#error This driver does not support Kernel versions < 2.6.23
#endif

MODULE_AUTHOR("Wolfgang Grandegger <wg@grandegger.com>");
MODULE_DESCRIPTION("Socket-CAN driver for PEAK PCAN PCI/PCIe cards");
MODULE_SUPPORTED_DEVICE("PEAK PCAN PCI/PCIe CAN card");
MODULE_LICENSE("GPL v2");

struct peak_pci {
	int channel;
	struct pci_dev *pci_dev;
	struct net_device *slave_dev;
	volatile void __iomem *conf_addr;
};

#define PEAK_PCI_SINGLE	     0	/* single channel device */
#define PEAK_PCI_MASTER	     1	/* multi channel master device */
#define PEAK_PCI_SLAVE	     2	/* multi channel slave device */

#define PEAK_PCI_CAN_CLOCK   (16000000 / 2)

#define PEAK_PCI_CDR_SINGLE  (CDR_CBP | CDR_CLKOUT_MASK | CDR_CLK_OFF)
#define PEAK_PCI_CDR_MASTER  (CDR_CBP | CDR_CLKOUT_MASK)

#define PEAK_PCI_OCR 	     OCR_TX0_PUSHPULL

/*
 * Important PITA registers
 */
#define PITA_ICR	     0x00	/* interrupt control register */
#define PITA_GPIOICR	     0x18	/* general purpose I/O interface
					   control register */
#define PITA_MISC	     0x1C	/* miscellanoes register */

#define PCI_CONFIG_PORT_SIZE 0x1000	/* size of the config io-memory */
#define PCI_PORT_SIZE        0x0400	/* size of a channel io-memory */

#define PEAK_PCI_VENDOR_ID   0x001C	/* the PCI device and vendor IDs */
#define PEAK_PCI_DEVICE_ID   0x0001	/* PCAN PCI and PCIe slot cards */
#define PEAK_PCIE_CARD_ID    0x0002	/* PCAN ExpressCard */

/* TODO: Add LED Status support for PCAN ExpressCard */

static struct pci_device_id peak_pci_tbl[] = {
	{PEAK_PCI_VENDOR_ID, PEAK_PCI_DEVICE_ID, PCI_ANY_ID, PCI_ANY_ID,},
	{PEAK_PCI_VENDOR_ID, PEAK_PCIE_CARD_ID, PCI_ANY_ID, PCI_ANY_ID,},
	{0,}
};

MODULE_DEVICE_TABLE(pci, peak_pci_tbl);

static u8 peak_pci_read_reg(const struct sja1000_priv *priv, int port)
{
	return readb(priv->reg_base + (port << 2));
}

static void peak_pci_write_reg(const struct sja1000_priv *priv,
			       int port, u8 val)
{
	writeb(val, priv->reg_base + (port << 2));
}

static void peak_pci_post_irq(const struct sja1000_priv *priv)
{
	struct peak_pci *board = priv->priv;
	u16 icr_low;

	/* Select and clear in Pita stored interrupt */
	icr_low = readw(board->conf_addr + PITA_ICR);
	if (board->channel == PEAK_PCI_SLAVE) {
		if (icr_low & 0x0001)
			writew(0x0001, board->conf_addr + PITA_ICR);
	} else {
		if (icr_low & 0x0002)
			writew(0x0002, board->conf_addr + PITA_ICR);
	}
}

static void peak_pci_del_chan(struct net_device *dev, int init_step)
{
	struct sja1000_priv *priv = netdev_priv(dev);
	struct peak_pci *board;
	u16 icr_high;

	if (!dev)
		return;
	priv = netdev_priv(dev);
	if (!priv)
		return;
	board = priv->priv;
	if (!board)
		return;

	switch (init_step) {
	case 0:		/* Full cleanup */
		printk(KERN_INFO "Removing %s device %s\n",
		       DRV_NAME, dev->name);
		unregister_sja1000dev(dev);
	case 4:
		icr_high = readw(board->conf_addr + PITA_ICR + 2);
		if (board->channel == PEAK_PCI_SLAVE)
			icr_high &= ~0x0001;
		else
			icr_high &= ~0x0002;
		writew(icr_high, board->conf_addr + PITA_ICR + 2);
	case 3:
		iounmap(priv->reg_base);
	case 2:
		if (board->channel != PEAK_PCI_SLAVE)
			iounmap((void *)board->conf_addr);
	case 1:
		free_sja1000dev(dev);
		break;
	}

}

static int peak_pci_add_chan(struct pci_dev *pdev, int channel,
			     struct net_device **master_dev)
{
	struct net_device *dev;
	struct sja1000_priv *priv;
	struct peak_pci *board;
	u16 icr_high;
	unsigned long addr;
	int err, init_step;

	dev = alloc_sja1000dev(sizeof(struct peak_pci));
	if (dev == NULL)
		return -ENOMEM;
	init_step = 1;

	priv = netdev_priv(dev);
	board = priv->priv;

	board->pci_dev = pdev;
	board->channel = channel;

	if (channel != PEAK_PCI_SLAVE) {

		addr = pci_resource_start(pdev, 0);
		board->conf_addr = ioremap(addr, PCI_CONFIG_PORT_SIZE);
		if (board->conf_addr == 0) {
			err = -ENODEV;
			goto failure;
		}
		init_step = 2;

		/* Set GPIO control register */
		writew(0x0005, board->conf_addr + PITA_GPIOICR + 2);

		/* Enable single or dual channel */
		if (channel == PEAK_PCI_MASTER)
			writeb(0x00, board->conf_addr + PITA_GPIOICR);
		else
			writeb(0x04, board->conf_addr + PITA_GPIOICR);
		/* Toggle reset */
		writeb(0x05, board->conf_addr + PITA_MISC + 3);
		mdelay(5);
		/* Leave parport mux mode */
		writeb(0x04, board->conf_addr + PITA_MISC + 3);
	} else {
		struct sja1000_priv *master_priv = netdev_priv(*master_dev);
		struct peak_pci *master_board = master_priv->priv;
		master_board->slave_dev = dev;
		board->conf_addr = master_board->conf_addr;
	}

	addr = pci_resource_start(pdev, 1);
	if (channel == PEAK_PCI_SLAVE)
		addr += PCI_PORT_SIZE;

	priv->reg_base = ioremap(addr, PCI_PORT_SIZE);
	if (priv->reg_base == 0) {
		err = -ENOMEM;
		goto failure;
	}
	init_step = 3;

	priv->read_reg = peak_pci_read_reg;
	priv->write_reg = peak_pci_write_reg;
	priv->post_irq = peak_pci_post_irq;

	priv->can.clock.freq = PEAK_PCI_CAN_CLOCK;

	priv->ocr = PEAK_PCI_OCR;

	if (channel == PEAK_PCI_MASTER)
		priv->cdr = PEAK_PCI_CDR_MASTER;
	else
		priv->cdr = PEAK_PCI_CDR_SINGLE;

	/* Setup interrupt handling */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
	priv->irq_flags = SA_SHIRQ;
#else
	priv->irq_flags = IRQF_SHARED;
#endif
	dev->irq = pdev->irq;
	icr_high = readw(board->conf_addr + PITA_ICR + 2);
	if (channel == PEAK_PCI_SLAVE)
		icr_high |= 0x0001;
	else
		icr_high |= 0x0002;
	writew(icr_high, board->conf_addr + PITA_ICR + 2);
	init_step = 4;

	SET_NETDEV_DEV(dev, &pdev->dev);

	/* Register SJA1000 device */
	err = register_sja1000dev(dev);
	if (err) {
		printk(KERN_ERR "Registering %s device failed (err=%d)\n",
		       DRV_NAME, err);
		goto failure;
	}

	if (channel != PEAK_PCI_SLAVE)
		*master_dev = dev;

	printk(KERN_INFO "%s: %s at reg_base=0x%p conf_addr=%p irq=%d\n",
	       DRV_NAME, dev->name, priv->reg_base, board->conf_addr, dev->irq);

	return 0;

failure:
	peak_pci_del_chan(dev, init_step);
	return err;
}

static int __devinit peak_pci_init_one(struct pci_dev *pdev,
				       const struct pci_device_id *ent)
{
	int err;
	u16 sub_sys_id;
	struct net_device *master_dev = NULL;

	printk(KERN_INFO "%s: initializing device %04x:%04x\n",
	       DRV_NAME, pdev->vendor, pdev->device);

	err = pci_enable_device(pdev);
	if (err)
		goto failure;

	err = pci_request_regions(pdev, DRV_NAME);
	if (err)
		goto failure;

	err = pci_read_config_word(pdev, 0x2e, &sub_sys_id);
	if (err)
		goto failure_cleanup;

	err = pci_write_config_word(pdev, 0x44, 0);
	if (err)
		goto failure_cleanup;

	if (sub_sys_id > 3) {
		err = peak_pci_add_chan(pdev,
					PEAK_PCI_MASTER, &master_dev);
		if (err)
			goto failure_cleanup;

		err = peak_pci_add_chan(pdev,
					PEAK_PCI_SLAVE, &master_dev);
		if (err)
			goto failure_cleanup;
	} else {
		err = peak_pci_add_chan(pdev, PEAK_PCI_SINGLE,
					     &master_dev);
		if (err)
			goto failure_cleanup;
	}

	pci_set_drvdata(pdev, master_dev);
	return 0;

failure_cleanup:
	if (master_dev)
		peak_pci_del_chan(master_dev, 0);

	pci_release_regions(pdev);

failure:
	return err;

}

static void __devexit peak_pci_remove_one(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct sja1000_priv *priv = netdev_priv(dev);
	struct peak_pci *board = priv->priv;

	if (board->slave_dev)
		peak_pci_del_chan(board->slave_dev, 0);
	peak_pci_del_chan(dev, 0);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

static struct pci_driver peak_pci_driver = {
	.name = DRV_NAME,
	.id_table = peak_pci_tbl,
	.probe = peak_pci_init_one,
	.remove = __devexit_p(peak_pci_remove_one),
};

static int __init peak_pci_init(void)
{
	return pci_register_driver(&peak_pci_driver);
}

static void __exit peak_pci_exit(void)
{
	pci_unregister_driver(&peak_pci_driver);
}

module_init(peak_pci_init);
module_exit(peak_pci_exit);
