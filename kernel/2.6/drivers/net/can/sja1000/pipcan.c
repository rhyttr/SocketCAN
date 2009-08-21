/*
 * Copyright (C) 2008 David Müller, <d.mueller@elsoft.ch>
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
#include <linux/version.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/delay.h>
#include <linux/platform_device.h>
#include <socketcan/can.h>
#include <socketcan/can/dev.h>
#include <linux/io.h>

#include "sja1000.h"

#define DRV_NAME "pipcan"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
#error This driver does not support Kernel versions < 2.6.20
#endif

MODULE_AUTHOR("David Müller <d.mueller@elsoft.ch>");
MODULE_DESCRIPTION("Socket-CAN driver for MPL PIPCAN module");
MODULE_SUPPORTED_DEVICE("MPL PIPCAN module");
MODULE_LICENSE("GPL v2");

#define PIPCAN_CAN_CLOCK  (16000000 / 2)

#define PIPCAN_OCR        (OCR_TX1_PUSHPULL)
#define PIPCAN_CDR        (CDR_CBP | CDR_CLK_OFF)

#define PIPCAN_IOSIZE     (0x100)

#define PIPCAN_RES        (0x804)
#define PIPCAN_RST        (0x805)

static u8 pc_read_reg(const struct sja1000_priv *priv, int reg)
{
  return inb((unsigned long)priv->reg_base + reg);
}

static void pc_write_reg(const struct sja1000_priv *priv, int reg, u8 val)
{
  outb(val, (unsigned long)priv->reg_base + reg);
}

static int __init pc_probe(struct platform_device *pdev)
{
	struct net_device *dev;
	struct sja1000_priv *priv;
	struct resource *res;
	int rc, irq;

	rc = -ENODEV;
	res = platform_get_resource(pdev, IORESOURCE_IO, 0);
	irq = platform_get_irq(pdev, 0);
	if (!res || !irq)
		goto exit;

	rc = -EBUSY;
	if (!request_region(res->start, res->end - res->start + 1, DRV_NAME))
		goto exit;

	rc = -ENOMEM;
	dev = alloc_sja1000dev(0);
	if (!dev)
		goto exit_release;

	priv = netdev_priv(dev);

	priv->read_reg = pc_read_reg;
	priv->write_reg = pc_write_reg;
	priv->can.clock.freq = PIPCAN_CAN_CLOCK;
	priv->ocr = PIPCAN_OCR;
	priv->cdr = PIPCAN_CDR;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
	priv->irq_flags = SA_SHIRQ;
#else
	priv->irq_flags = IRQF_SHARED;
#endif

	dev->irq = irq;
	dev->base_addr = res->start;
	priv->reg_base = (void __iomem *)res->start;

	dev_set_drvdata(&pdev->dev, dev);
	SET_NETDEV_DEV(dev, &pdev->dev);

	/* deactivate RST */
	outb(inb(PIPCAN_RST) & ~0x01, PIPCAN_RST);

	rc = register_sja1000dev(dev);
	if (rc) {
		dev_err(&pdev->dev, "registering %s failed (err=%d)\n",
			DRV_NAME, rc);
		goto exit_free;
	}

	dev_info(&pdev->dev, "device registered (base_addr=%#lx, irq=%d)\n",
		 dev->base_addr, dev->irq);
	return 0;

exit_free:
	free_sja1000dev(dev);

exit_release:
	release_region(res->start, res->end - res->start + 1);

exit:
	return rc;
}

static int __exit pc_remove(struct platform_device *pdev)
{
	struct net_device *dev = dev_get_drvdata(&pdev->dev);
	struct resource *res;

	dev_set_drvdata(&pdev->dev, NULL);
	unregister_sja1000dev(dev);
	res = platform_get_resource(pdev, IORESOURCE_IO, 0);

	free_sja1000dev(dev);

	release_region(res->start, res->end - res->start + 1);

	/* activate RST */
	outb(inb(PIPCAN_RST) | 0x01, PIPCAN_RST);

	return 0;
}

static struct platform_driver pc_driver = {
	.remove = __exit_p(pc_remove),
	.driver = {
		   .name = DRV_NAME,
		   .owner = THIS_MODULE,
		   },
};

static struct platform_device *pc_pdev;
static const u16 pipcan_ioport[] = {0x1000, 0x8000, 0xE000};

static int __init pc_init(void)
{
	struct resource r[2];
	int rc, addr, irq, idx;
	u8 pc_res;

	/* get PIPCAN resources from EPLD */
	pc_res = inb(PIPCAN_RES);

	idx = (pc_res & 0x0F);
	if ((idx <= 0) || (idx > ARRAY_SIZE(pipcan_ioport))) {
		printk(KERN_ERR DRV_NAME " invalid base address\n");
		return -EINVAL;
	}
	addr = pipcan_ioport[idx-1];

	irq = (pc_res >> 4) & 0x0F;
	if ((irq < 3) || (irq == 8) || (irq == 13)) {
		printk(KERN_ERR DRV_NAME " invalid IRQ\n");
		return -EINVAL;
	}

	/* fill in resources */
	memset(&r, 0, sizeof(r));
	r[0].start = addr;
	r[0].end = addr + PIPCAN_IOSIZE - 1;
	r[0].name = DRV_NAME;
	r[0].flags = IORESOURCE_IO;
	r[1].start = r[1].end = irq;
	r[1].name = DRV_NAME;
	r[1].flags = IORESOURCE_IRQ;

	pc_pdev = platform_device_register_simple(DRV_NAME, 0, r,
						  ARRAY_SIZE(r));
	if (IS_ERR(pc_pdev))
		return PTR_ERR(pc_pdev);

	rc = platform_driver_probe(&pc_driver, pc_probe);
	if (rc) {
		platform_device_unregister(pc_pdev);
		printk(KERN_ERR DRV_NAME
		       " platform_driver_probe() failed (%d)\n", rc);
	}

	return rc;
}

static void __exit pc_exit(void)
{
	platform_driver_unregister(&pc_driver);
	platform_device_unregister(pc_pdev);
}

module_init(pc_init);
module_exit(pc_exit);
