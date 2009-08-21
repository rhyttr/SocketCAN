/*
 * drivers/can/h7202_can.c
 *
 * Copyright (C) 2007
 *
 * - Sascha Hauer, Marc Kleine-Budde, Pengutronix
 * - Simon Kallweit, intefo AG
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
#include <linux/platform_device.h>
#include <linux/netdevice.h>
#include <socketcan/can.h>
#include <socketcan/can/dev.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
#include <linux/io.h>
#else
#include <asm/io.h>
#endif
#include <asm/hardware.h>

#include "ccan.h"

#define DRV_NAME      "h7202can"
#define DELAY         5
#define CAN_ENABLE    0x0e

static u16 h7202can_read_reg(struct net_device *dev, enum c_regs reg)
{
	u16 val;
	volatile int i;

	/* The big kernel lock is used to prevent any other AMBA devices from
	 * interfering with the current register read operation. The register
	 * is read twice because of braindamaged hynix cpu.
	 */
	lock_kernel();
	val = inw(dev->base_addr + (reg<<1));
	for (i = 0; i < DELAY; i++);
	val = inw(dev->base_addr + (reg<<1));
	for (i = 0; i < DELAY; i++);
	unlock_kernel();

	return val;
}

static void h7202can_write_reg(struct net_device *dev, enum c_regs reg, u16 val)
{
	volatile int i;

	lock_kernel();
	outw(val, dev->base_addr + (reg<<1));
	for (i = 0; i < DELAY; i++);
	unlock_kernel();
}

static int h7202can_drv_probe(struct platform_device *pdev)
{
	struct net_device *dev;
	struct ccan_priv *priv;
	struct resource *mem;
	u32 mem_size;
	int ret = -ENODEV;

	dev = alloc_ccandev(sizeof(struct ccan_priv));
	if (!dev)
		return -ENOMEM;

	mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	dev->irq = platform_get_irq(pdev, 0);
	if (!mem || !dev->irq)
		goto req_error;

	mem_size = mem->end - mem->start + 1;
	if (!request_mem_region(mem->start, mem_size, pdev->dev.driver->name)) {
		dev_err(&pdev->dev, "resource unavailable\n");
		goto req_error;
	}

	SET_NETDEV_DEV(dev, &pdev->dev);

	dev->base_addr = (unsigned long)ioremap_nocache(mem->start, mem_size);

	if (!dev->base_addr) {
		dev_err(&pdev->dev, "failed to map can port\n");
		ret = -ENOMEM;
		goto fail_map;
	}

	priv = netdev_priv(dev);
	priv->can.can_sys_clock = 8000000;
	priv->read_reg = h7202can_read_reg;
	priv->write_reg = h7202can_write_reg;

	platform_set_drvdata(pdev, dev);

	/* configure ports */
	switch (mem->start) {
	case CAN0_PHYS:
		CPU_REG(GPIO_C_VIRT, GPIO_EN) &= ~(3<<1);
		CPU_REG(GPIO_C_VIRT, GPIO_DIR) &= ~(1<<1);
		CPU_REG(GPIO_C_VIRT, GPIO_DIR) |= (1<<2);
		break;
	case CAN1_PHYS:
		CPU_REG(GPIO_E_VIRT, GPIO_EN) &= ~(3<<16);
		CPU_REG(GPIO_E_VIRT, GPIO_DIR) |= (1<<16);
		CPU_REG(GPIO_E_VIRT, GPIO_DIR) &= ~(1<<17);
		break;
	}

	/* enable can */
	h7202can_write_reg(dev, CAN_ENABLE, 1);

	ret = register_ccandev(dev);
	if (ret >= 0) {
		dev_info(&pdev->dev, "probe for a port 0x%lX done\n",
			 dev->base_addr);
		return ret;
	}

	iounmap((unsigned long *)dev->base_addr);
fail_map:
	release_mem_region(mem->start, mem_size);
req_error:
	free_ccandev(dev);
	dev_err(&pdev->dev, "probe failed\n");
	return ret;
}

static int h7202can_drv_remove(struct platform_device *pdev)
{
	struct net_device *dev = platform_get_drvdata(pdev);
	struct resource *mem;

	platform_set_drvdata(pdev, NULL);
	unregister_ccandev(dev);

	iounmap((volatile void __iomem *)(dev->base_addr));
	mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	release_mem_region(mem->start, mem->end - mem->start + 1);
	free_ccandev(dev);
	return 0;
}

#ifdef CONFIG_PM
static int h7202can_drv_suspend(struct platform_device *pdev,
				pm_message_t state)
{
	return 0;
}

static int h7202can_drv_resume(struct platform_device *pdev)
{
	return 0;
}
#endif /* CONFIG_PM */

static struct platform_driver h7202can_driver = {
	.driver		= {
		.name		= DRV_NAME,
	},
	.probe		= h7202can_drv_probe,
	.remove		= h7202can_drv_remove,
#ifdef CONFIG_PM
	.suspend	= h7202can_drv_suspend,
	.resume		= h7202can_drv_resume,
#endif	/* CONFIG_PM */
};

static int __init h7202can_init(void)
{
	printk(KERN_INFO "%s initializing\n", h7202can_driver.driver.name);
	return platform_driver_register(&h7202can_driver);
}

static void __exit h7202can_cleanup(void)
{
	platform_driver_unregister(&h7202can_driver);
	printk(KERN_INFO "%s unloaded\n", h7202can_driver.driver.name);
}

module_init(h7202can_init);
module_exit(h7202can_cleanup);

MODULE_AUTHOR("Sascha Hauer <s.hauer@pengutronix.de>");
MODULE_AUTHOR("Simon Kallweit <simon.kallweit@intefo.ch>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("CAN port driver Hynix H7202 processor");
