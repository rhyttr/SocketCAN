/*
 * CAN bus driver for the Freescale MPC52xx embedded CPU.
 *
 * Copyright (C) 2004-2005 Andrey Volkov <avolkov@varma-el.com>,
 *                         Varma Electronics Oy
 * Copyright (C) 2008-2009 Wolfgang Grandegger <wg@grandegger.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the version 2 of the GNU General Public License
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
#include <linux/of_platform.h>
#include <sysdev/fsl_soc.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
#include <linux/io.h>
#else
#include <asm/io.h>
#endif
#include <asm/mpc52xx.h>

#include "mscan.h"

#include <socketcan/can/version.h>	/* for RCSID. Removed by mkpatch script */

RCSID("$Id$");

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)

#define PDEV_MAX 2

struct platform_device *pdev[PDEV_MAX];

static int __devinit mpc52xx_can_probe(struct platform_device *pdev)
{
	struct resource *mem;
	struct net_device *dev;
	struct mscan_platform_data *pdata = pdev->dev.platform_data;
	struct mscan_priv *priv;
	u32 mem_size;
	int ret = -ENODEV;

	if (!pdata)
		return ret;

	dev = alloc_mscandev();
	if (!dev)
		return -ENOMEM;
	priv = netdev_priv(dev);

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

	priv->reg_base = ioremap_nocache(mem->start, mem_size);
	if (!priv->reg_base) {
		dev_err(&pdev->dev, "failed to map can port\n");
		ret = -ENOMEM;
		goto fail_map;
	}

	priv->can.clock.freq = pdata->clock_frq;

	platform_set_drvdata(pdev, dev);

	ret = register_mscandev(dev, pdata->clock_src);
	if (ret >= 0) {
		dev_info(&pdev->dev, "probe for port 0x%p done (irq=%d)\n",
			 priv->reg_base, dev->irq);
		return ret;
	}

	iounmap(priv->reg_base);

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
	struct mscan_priv *priv = netdev_priv(dev);
	struct resource *mem;

	platform_set_drvdata(pdev, NULL);
	unregister_mscandev(dev);

	iounmap(priv->reg_base);
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
	struct mscan_priv *priv = netdev_priv(dev);
	struct mscan_regs *regs = (struct mscan_regs *)priv->reg_base;

	_memcpy_fromio(&saved_regs, regs, sizeof(*regs));

	return 0;
}

static int mpc52xx_can_resume(struct platform_device *pdev)
{
	struct net_device *dev = platform_get_drvdata(pdev);
	struct mscan_priv *priv = netdev_priv(dev);
	struct mscan_regs *regs = (struct mscan_regs *)priv->reg_base;

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
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28) */
#define DRV_NAME "mpc52xx_can"

static struct of_device_id mpc52xx_cdm_ids[] __devinitdata = {
	{ .compatible = "fsl,mpc5200-cdm", },
	{ .compatible = "fsl,mpc5200b-cdm", },
	{}
};

/*
 * Get the frequency of the external oscillator clock connected
 * to the SYS_XTAL_IN pin, or retrun 0 if it cannot be determined.
 */
static unsigned int  __devinit mpc52xx_can_xtal_freq(struct device_node *np)
{
	struct mpc52xx_cdm  __iomem *cdm;
	struct device_node *np_cdm;
	unsigned int freq;
	u32 val;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
	freq = mpc52xx_find_ipb_freq(np);
#else
	freq = mpc5xxx_get_bus_frequency(np);
#endif
	if (!freq)
		return 0;

	/*
	 * Detemine SYS_XTAL_IN frequency from the clock domain settings
	 */
	np_cdm = of_find_matching_node(NULL, mpc52xx_cdm_ids);
	cdm = of_iomap(np_cdm, 0);
	of_node_put(np_cdm);
	if (!np_cdm) {
		printk(KERN_ERR "%s() failed abnormally\n", __func__);
		return 0;
	}

	if (in_8(&cdm->ipb_clk_sel) & 0x1)
		freq *= 2;
	val  = in_be32(&cdm->rstcfg);
	if (val & (1 << 5))
		freq *= 8;
	else
		freq *= 4;
	if (val & (1 << 6))
		freq /= 12;
	else
		freq /= 16;

	iounmap(cdm);

	return freq;
}

/*
 * Get frequency of the MSCAN clock source
 *
 * Either the oscillator clock (SYS_XTAL_IN) or the IP bus clock (IP_CLK)
 * can be selected. According to the MPC5200 user's manual, the oscillator
 * clock is the better choice as it has less jitter but due to a hardware
 * bug, it can not be selected for the old MPC5200 Rev. A chips.
 */

static unsigned int  __devinit mpc52xx_can_clock_freq(struct device_node *np,
						      int clock_src)
{
	unsigned int pvr;

	pvr = mfspr(SPRN_PVR);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
	if (clock_src == MSCAN_CLKSRC_BUS || pvr == 0x80822011)
		return mpc52xx_find_ipb_freq(np);
#else
	if (clock_src == MSCAN_CLKSRC_BUS || pvr == 0x80822011)
		return mpc5xxx_get_bus_frequency(np);
#endif

	return mpc52xx_can_xtal_freq(np);
}

static int __devinit mpc52xx_can_probe(struct of_device *ofdev,
				       const struct of_device_id *id)
{
	struct device_node *np = ofdev->node;
	struct net_device *dev;
	struct mscan_priv *priv;
	struct resource res;
	void __iomem *base;
	int err, irq, res_size, clock_src;

	err = of_address_to_resource(np, 0, &res);
	if (err) {
		dev_err(&ofdev->dev, "invalid address\n");
		return err;
	}

	res_size = res.end - res.start + 1;

	if (!request_mem_region(res.start, res_size, DRV_NAME)) {
		dev_err(&ofdev->dev, "couldn't request %#x..%#x\n",
			res.start, res.end);
		return -EBUSY;
	}

	base = ioremap_nocache(res.start, res_size);
	if (!base) {
		dev_err(&ofdev->dev, "couldn't ioremap %#x..%#x\n",
			res.start, res.end);
		err = -ENOMEM;
		goto exit_release_mem;
	}

	irq = irq_of_parse_and_map(np, 0);
	if (irq == NO_IRQ) {
		dev_err(&ofdev->dev, "no irq found\n");
		err = -ENODEV;
		goto exit_unmap_mem;
	}

	dev = alloc_mscandev();
	if (!dev) {
		err = -ENOMEM;
		goto exit_dispose_irq;
	}

	priv = netdev_priv(dev);

	priv->reg_base = base;
	dev->irq = irq;

	/*
	 * Either the oscillator clock (SYS_XTAL_IN) or the IP bus clock
	 * (IP_CLK) can be selected as MSCAN clock source. According to
	 * the MPC5200 user's manual, the oscillator clock is the better
	 * choice as it has less jitter. For this reason, it is selected
	 * by default.
	 */
	if (of_get_property(np, "clock-ipb", NULL))
		clock_src = MSCAN_CLKSRC_BUS;
	else
		clock_src = MSCAN_CLKSRC_XTAL;
	priv->can.clock.freq = mpc52xx_can_clock_freq(np, clock_src);
	if (!priv->can.clock.freq) {
		dev_err(&ofdev->dev, "couldn't get MSCAN clock frequency\n");
		err = -ENODEV;
		goto exit_free_mscan;
	}

	SET_NETDEV_DEV(dev, &ofdev->dev);

	err = register_mscandev(dev, clock_src);
	if (err) {
		dev_err(&ofdev->dev, "registering %s failed (err=%d)\n",
			DRV_NAME, err);
		goto exit_free_mscan;
	}

	dev_set_drvdata(&ofdev->dev, dev);

	dev_info(&ofdev->dev, "MSCAN at 0x%p, irq %d, clock %d Hz\n",
		 priv->reg_base, dev->irq, priv->can.clock.freq);

	return 0;

exit_free_mscan:
	free_candev(dev);
exit_dispose_irq:
	irq_dispose_mapping(irq);
exit_unmap_mem:
	iounmap(base);
exit_release_mem:
	release_mem_region(res.start, res_size);

	return err;
}

static int __devexit mpc52xx_can_remove(struct of_device *ofdev)
{
	struct net_device *dev = dev_get_drvdata(&ofdev->dev);
	struct mscan_priv *priv = netdev_priv(dev);
	struct device_node *np = ofdev->node;
	struct resource res;

	dev_set_drvdata(&ofdev->dev, NULL);

	unregister_mscandev(dev);
	iounmap(priv->reg_base);
	irq_dispose_mapping(dev->irq);
	free_candev(dev);

	of_address_to_resource(np, 0, &res);
	release_mem_region(res.start, res.end - res.start + 1);

	return 0;
}

#ifdef CONFIG_PM
static struct mscan_regs saved_regs;
static int mpc52xx_can_suspend(struct of_device *ofdev, pm_message_t state)
{
	struct net_device *dev = dev_get_drvdata(&ofdev->dev);
	struct mscan_priv *priv = netdev_priv(dev);
	struct mscan_regs *regs = (struct mscan_regs *)priv->reg_base;

	_memcpy_fromio(&saved_regs, regs, sizeof(*regs));

	return 0;
}

static int mpc52xx_can_resume(struct of_device *ofdev)
{
	struct net_device *dev = dev_get_drvdata(&ofdev->dev);
	struct mscan_priv *priv = netdev_priv(dev);
	struct mscan_regs *regs = (struct mscan_regs *)priv->reg_base;

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

static struct of_device_id __devinitdata mpc52xx_can_table[] = {
	{.compatible = "fsl,mpc5200-mscan"},
	{.compatible = "fsl,mpc5200b-mscan"},
	{},
};

static struct of_platform_driver mpc52xx_can_driver = {
	.owner = THIS_MODULE,
	.name = "mpc52xx_can",
	.probe = mpc52xx_can_probe,
	.remove = __devexit_p(mpc52xx_can_remove),
#ifdef CONFIG_PM
	.suspend = mpc52xx_can_suspend,
	.resume = mpc52xx_can_resume,
#endif
	.match_table = mpc52xx_can_table,
};

static int __init mpc52xx_can_init(void)
{
	return of_register_platform_driver(&mpc52xx_can_driver);
}
module_init(mpc52xx_can_init);

static void __exit mpc52xx_can_exit(void)
{
	return of_unregister_platform_driver(&mpc52xx_can_driver);
};
module_exit(mpc52xx_can_exit);

MODULE_AUTHOR("Wolfgang Grandegger <wg@grandegger.com>");
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28) */
MODULE_DESCRIPTION("Freescale MPC5200 CAN driver");
MODULE_LICENSE("GPL v2");
