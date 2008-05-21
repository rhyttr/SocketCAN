/*
 * Copyright (C) 2007 Wolfgang Grandegger <wg@grandegger.com>
 *
 * Copyright (C) 2005 Sascha Hauer, Pengutronix
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/can.h>
#include <linux/can/dev.h>

#include <asm/io.h>

#include "sja1000.h"

#define DRV_NAME "can-pcm027"

MODULE_AUTHOR("Sascha Hauer <s.hauer@pengutronix.de>");
MODULE_DESCRIPTION("Socket-CAN driver for Phytec PCM027 board");
MODULE_SUPPORTED_DEVICE("Phytec PCM027 board");
MODULE_LICENSE("GPL v2");

#define PCM027_CAN_CLOCK  (16000000 / 2)

#define PCM027_OCR	  (OCR_TX1_PULLDOWN | OCR_TX0_PUSHPULL)
#define PCM027_CDR	  CDR_CBP

static u8 pcm027_read_reg(struct net_device *dev, int reg)
{
	return ioread8(dev->base_addr + reg);
}

static void pcm027_write_reg(struct net_device *dev, int reg, u8 val)
{
	iowrite8(val, dev->base_addr + reg);
}

static int pcm027_probe(struct platform_device *pdev)
{
	int err, irq;
	void __iomem *addr = 0;
	struct net_device *dev;
	struct sja1000_priv *priv;
	struct resource *res;

	err = -ENODEV;
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	irq = platform_get_irq(pdev, 0);
	if (!res || !irq)
		goto exit;

	err = -EBUSY;
	if (!request_mem_region(res->start, res->end - res->start + 1,
				DRV_NAME)) {
		goto exit;
	}

	err = -ENOMEM;
	addr = ioremap_nocache(res->start, res->end - res->start + 1);
	if (!addr) {
		goto exit_release;
	}

	dev = alloc_sja1000dev(0);
	if (!dev)
		goto exit_iounmap;

	priv = netdev_priv(dev);

	priv->read_reg = pcm027_read_reg;
	priv->write_reg = pcm027_write_reg;
	priv->can.can_sys_clock = PCM027_CAN_CLOCK;
	priv->ocr = PCM027_OCR;
	priv->cdr = PCM027_CDR;

	dev->irq = irq;
	dev->base_addr = (unsigned long)addr;

	dev_set_drvdata(&pdev->dev, dev);

	err = register_sja1000dev(dev);
	if (err) {
		dev_err(&pdev->dev, "registering %s failed (err=%d)\n",
			DRV_NAME, err);
		goto exit_free;
	}

	printk("%s: %s device registered (base_addr=%#lx, irq=%d)\n",
	       dev->name, DRV_NAME, dev->base_addr, dev->irq);
	return 0;

exit_free:
	free_sja1000dev(dev);
exit_iounmap:
	iounmap(addr);
exit_release:
	release_mem_region(res->start, res->end - res->start + 1);
exit:
	return err;
}

static int pcm027_remove (struct platform_device *pdev)
{
	struct net_device *dev = dev_get_drvdata(&pdev->dev);
	struct resource *res;

	dev_set_drvdata(&pdev->dev, NULL);
	unregister_sja1000dev(dev);
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	release_mem_region(res->start, res->end - res->start + 1);

	if (dev->base_addr)
		iounmap ((void *)dev->base_addr);

	free_sja1000dev(dev);

	return 0;
}

static int pcm027_suspend (struct platform_device *pdev,
				   pm_message_t state)
{
	dev_err(&pdev->dev, "suspend not implented\n");
	return 0;
}


static int pcm027_resume (struct platform_device *pdev)
{
        dev_err(&pdev->dev, "resume not implemented\n");
	return 0;
}

static struct platform_driver pcm027_driver = {
	.probe = pcm027_probe,
	.remove = pcm027_remove,
	.suspend = pcm027_suspend,
	.resume = pcm027_resume,
	.driver = {
		.name = "pcm027can",
		.owner = THIS_MODULE,
	},
};

static int __init pcm027_init(void)
{
	return platform_driver_register(&pcm027_driver);
}

static void __exit pcm027_exit(void)
{
	platform_driver_unregister(&pcm027_driver);
}

module_init(pcm027_init);
module_exit(pcm027_exit);
