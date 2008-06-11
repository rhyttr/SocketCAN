/*
 * DESCRIPTION:
 *  CAN bus driver for the Freescale MPC52xx embedded CPU.
 *
 * AUTHOR:
 *  Andrey Volkov <avolkov@varma-el.com>
 *
 * COPYRIGHT:
 *  2004-2005, Varma Electronics Oy
 *
 * LICENCE:
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * HISTORY:
 *	 2005-02-03 created
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/netdevice.h>
#include <linux/can.h>
#include <linux/can/dev.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
#include <linux/io.h>
#else
#include <asm/io.h>
#endif
#include <asm/mpc52xx.h>

#include "mscan.h"

#include <linux/can/version.h>	/* for RCSID. Removed by mkpatch script */

RCSID("$Id$");

#define PDEV_MAX 2

struct platform_device *pdev[PDEV_MAX];

static int __devinit mpc52xx_can_probe(struct platform_device *pdev)
{
	struct resource *mem;
	struct net_device *dev;
	struct mscan_platform_data *pdata = pdev->dev.platform_data;
	struct can_priv *can;
	u32 mem_size;
	int ret = -ENODEV;

	if (!pdata)
		return ret;

	dev = alloc_mscandev();
	if (!dev)
		return -ENOMEM;
	can = netdev_priv(dev);

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

	can->can_sys_clock = pdata->clock_frq;

	platform_set_drvdata(pdev, dev);

	ret = register_mscandev(dev, pdata->clock_src);
	if (ret >= 0) {
		dev_info(&pdev->dev, "probe for port 0x%lX done (irq=%d)\n",
			 dev->base_addr, dev->irq);
		return ret;
	}

	iounmap((unsigned long *)dev->base_addr);
      fail_map:
	release_mem_region(mem->start, mem_size);
      req_error:
	free_candev(dev);
	dev_err(&pdev->dev, "probe failed\n");
	return ret;
}

static int __devexit mpc52xx_can_remove(struct platform_device *pdev)
{
	struct net_device *dev = platform_get_drvdata(pdev);
	struct resource *mem;

	platform_set_drvdata(pdev, NULL);
	unregister_mscandev(dev);

	iounmap((volatile void __iomem *)dev->base_addr);
	mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	release_mem_region(mem->start, mem->end - mem->start + 1);
	free_candev(dev);
	return 0;
}

#ifdef CONFIG_PM
static struct mscan_regs saved_regs;
static int mpc52xx_can_suspend(struct platform_device *pdev, pm_message_t state)
{
	struct net_device *dev = platform_get_drvdata(pdev);
	struct mscan_regs *regs = (struct mscan_regs *)dev->base_addr;

	_memcpy_fromio(&saved_regs, regs, sizeof(*regs));

	return 0;
}

static int mpc52xx_can_resume(struct platform_device *pdev)
{
	struct net_device *dev = platform_get_drvdata(pdev);
	struct mscan_regs *regs = (struct mscan_regs *)dev->base_addr;

	regs->canctl0 |= MSCAN_INITRQ;
	while ((regs->canctl1 & MSCAN_INITAK) == 0)
		udelay(10);

	regs->canctl1 = saved_regs.canctl1;
	regs->canbtr0 = saved_regs.canbtr0;
	regs->canbtr1 = saved_regs.canbtr1;
	regs->canidac = saved_regs.canidac;

	/* restore masks, buffers etc. */
	_memcpy_toio(&regs->canidar1_0, (void *)&saved_regs.canidar1_0,
		     sizeof(*regs) - offsetof(struct mscan_regs, canidar1_0));

	regs->canctl0 &= ~MSCAN_INITRQ;
	regs->cantbsel = saved_regs.cantbsel;
	regs->canrier = saved_regs.canrier;
	regs->cantier = saved_regs.cantier;
	regs->canctl0 = saved_regs.canctl0;

	return 0;
}
#endif

static struct platform_driver mpc52xx_can_driver = {
	.driver = {
		   .name = "mpc52xx-mscan",
		   },
	.probe = mpc52xx_can_probe,
	.remove = __devexit_p(mpc52xx_can_remove),
#ifdef CONFIG_PM
	.suspend = mpc52xx_can_suspend,
	.resume = mpc52xx_can_resume,
#endif
};

#ifdef CONFIG_PPC_MERGE
static int __init mpc52xx_of_to_pdev(void)
{
	struct device_node *np = NULL;
	unsigned int i;
	int err = -ENODEV;

	for (i = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
 	     (np = of_find_compatible_node(np, "mscan", "mpc5200-mscan"));
#else
	     (np = of_find_compatible_node(np, NULL, "fsl,mpc5200-mscan"));
#endif
	     i++) {
		struct resource r[2] = { };
		struct mscan_platform_data pdata;

		if (i >= PDEV_MAX) {
			printk(KERN_WARNING "%s: increase PDEV_MAX for more "
			       "than %i devices\n", __func__, PDEV_MAX);
			break;
		}

		err = of_address_to_resource(np, 0, &r[0]);
		if (err)
			break;

		of_irq_to_resource(np, 0, &r[1]);

		pdev[i] =
		    platform_device_register_simple("mpc52xx-mscan", i, r, 2);
		if (IS_ERR(pdev[i])) {
			err = PTR_ERR(pdev[i]);
			break;
		}

		pdata.clock_src = MSCAN_CLKSRC_BUS;
		pdata.clock_frq = mpc52xx_find_ipb_freq(np);
		err = platform_device_add_data(pdev[i], &pdata, sizeof(pdata));
		if (err)
			break;
	}
	return err;
}
#endif

int __init mpc52xx_can_init(void)
{
#ifdef CONFIG_PPC_MERGE
	int err = mpc52xx_of_to_pdev();

	if (err) {
		printk(KERN_ERR "%s init failed with err=%d\n",
		       mpc52xx_can_driver.driver.name, err);
		return err;
	}
#endif
	return platform_driver_register(&mpc52xx_can_driver);
}

void __exit mpc52xx_can_exit(void)
{
	int i;
	platform_driver_unregister(&mpc52xx_can_driver);
	for (i = 0; i < PDEV_MAX; i++)
		platform_device_unregister(pdev[i]);
	printk(KERN_INFO "%s unloaded\n", mpc52xx_can_driver.driver.name);
}

module_init(mpc52xx_can_init);
module_exit(mpc52xx_can_exit);

MODULE_AUTHOR("Andrey Volkov <avolkov@varma-el.com>");
MODULE_DESCRIPTION("Freescale MPC5200 CAN driver");
MODULE_LICENSE("GPL v2");
