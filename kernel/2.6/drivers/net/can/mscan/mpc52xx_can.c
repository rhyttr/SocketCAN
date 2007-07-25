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
#include <asm/io.h>
#include <asm/mpc52xx.h>

#include "mscan.h"

#include <linux/can/version.h>	/* for RCSID. Removed by mkpatch script */

RCSID("$Id$");

#define PDEV_MAX 2

struct platform_device *pdev[PDEV_MAX];

static int __devinit mpc52xx_can_probe(struct platform_device *pdev)
{
	struct can_device *can;
	struct resource *mem;
	struct net_device *ndev;
	struct mscan_platform_data *pdata = pdev->dev.platform_data;
	u32 mem_size;
	int ret = -ENODEV;

	if (!pdata)
		return ret;

	can = alloc_mscandev();
	if (!can)
		return -ENOMEM;

	ndev = CAN2ND(can);

	mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	ndev->irq = platform_get_irq(pdev, 0);
	if (!mem || !ndev->irq)
		goto req_error;

	mem_size = mem->end - mem->start + 1;
	if (!request_mem_region(mem->start, mem_size, pdev->dev.driver->name)) {
		dev_err(&pdev->dev, "resource unavailable\n");
		goto req_error;
	}

	SET_NETDEV_DEV(ndev, &pdev->dev);
	SET_MODULE_OWNER(THIS_MODULE);

	ndev->base_addr = (unsigned long)ioremap_nocache(mem->start, mem_size);

	if (!ndev->base_addr) {
		dev_err(&pdev->dev, "failed to map can port\n");
		ret = -ENOMEM;
		goto fail_map;
	}

	can->can_sys_clock = pdata->clock_frq;

	platform_set_drvdata(pdev, can);

	ret = mscan_register(can, pdata->clock_src);
	if (ret >= 0) {
		dev_info(&pdev->dev, "probe for a port 0x%lX done\n",
			 ndev->base_addr);
		return ret;
	}

	iounmap((unsigned long *)ndev->base_addr);
      fail_map:
	release_mem_region(mem->start, mem_size);
      req_error:
	free_candev(can);
	dev_err(&pdev->dev, "probe failed\n");
	return ret;
}

static int __devexit mpc52xx_can_remove(struct platform_device *pdev)
{
	struct can_device *can = platform_get_drvdata(pdev);
	struct resource *mem;

	platform_set_drvdata(pdev, NULL);
	mscan_unregister(can);

	iounmap((volatile void __iomem *)(CAN2ND(can)->base_addr));
	mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	release_mem_region(mem->start, mem->end - mem->start + 1);
	free_candev(can);
	return 0;
}

#ifdef CONFIG_PM
static struct mscan_regs saved_regs;
static int mpc52xx_can_suspend(struct platform_device *pdev, pm_message_t state)
{
	struct can_device *can = platform_get_drvdata(pdev);
	struct mscan_regs *regs = (struct mscan_regs *)(CAN2ND(can)->base_addr);

	_memcpy_fromio(&saved_regs, regs, sizeof(*regs));

	return 0;
}

static int mpc52xx_can_resume(struct platform_device *pdev)
{
	struct can_device *can = platform_get_drvdata(pdev);
	struct mscan_regs *regs = (struct mscan_regs *)(CAN2ND(can)->base_addr);

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
	int ret;

	for (i = 0;
	     (np = of_find_compatible_node(np, "mscan", "mpc5200-mscan"));
	     i++) {
		struct resource r[2] = { };
		struct mscan_platform_data pdata;

		if (i >= PDEV_MAX) {
			printk(KERN_WARNING "%s: increase PDEV_MAX for more "
			       "than %i devices\n", __func__, PDEV_MAX);
			break;
		}

		ret = of_address_to_resource(np, 0, &r[0]);
		if (ret)
			goto err;

		of_irq_to_resource(np, 0, &r[1]);

		pdev[i] =
		    platform_device_register_simple("mpc52xx-mscan", i, r, 2);
		if (IS_ERR(pdev[i])) {
			ret = PTR_ERR(pdev[i]);
			goto err;
		}

		pdata.clock_src = MSCAN_CLKSRC_BUS;
		pdata.clock_frq = mpc52xx_find_ipb_freq(np);
		ret = platform_device_add_data(pdev[i], &pdata, sizeof(pdata));
		if (ret)
			goto err;
	}
	return 0;
      err:
	return ret;
}
#else
#define mscan_of_to_pdev()
#endif

int __init mpc52xx_can_init(void)
{
	mpc52xx_of_to_pdev();
	printk(KERN_INFO "%s initializing\n", mpc52xx_can_driver.driver.name);
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
