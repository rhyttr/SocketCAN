/*
 * Driver for CC770 CAN controllers on the OpenFirmware platform bus
 *
 * Copyright (C) 2009 Wolfgang Grandegger <wg@grandegger.com>
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

/* This is a generic driver for CC770 chips on the OpenFirmware platform
 * bus found on embedded PowerPC systems. You need a CC770 CAN node
 * definition in your flattened device tree source (DTS) file similar to:
 *
 *   can@3,100 {
 *           compatible = "bosch,cc770";
 *           reg = <3 0x100 0x80>;
 *           interrupts = <2 0>;
 *           interrupt-parent = <&mpic>;
 *           bosch,external-clock-frequency = <16000000>;
 *   };
 *
 * See "Documentation/powerpc/dts-bindings/can/cc770.txt" for further
 * information.
 */

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/delay.h>
#include <socketcan/can.h>
#include <socketcan/can/dev.h>

#include <linux/of_platform.h>
#include <asm/prom.h>

#include "cc770.h"

#define DRV_NAME "cc770_of_platform"

MODULE_AUTHOR("Wolfgang Grandegger <wg@grandegger.com>");
MODULE_DESCRIPTION("Socket-CAN driver for CC770 on the OF platform bus");
MODULE_LICENSE("GPL v2");

#define CC770_OFP_CAN_CLOCK  16000000

static u8 cc770_ofp_read_reg(const struct cc770_priv *priv, int reg)
{
	return in_8(priv->reg_base + reg);
}

static void cc770_ofp_write_reg(const struct cc770_priv *priv, int reg, u8 val)
{
	out_8(priv->reg_base + reg, val);
}

static int __devexit cc770_ofp_remove(struct of_device *ofdev)
{
	struct net_device *dev = dev_get_drvdata(&ofdev->dev);
	struct cc770_priv *priv = netdev_priv(dev);
	struct resource res;

	dev_set_drvdata(&ofdev->dev, NULL);

	unregister_cc770dev(dev);
	iounmap(priv->reg_base);
	/* irq_dispose_mapping(dev->irq);*/ /* will not work for shared IRQs */
	free_cc770dev(dev);

	of_address_to_resource(ofdev->node, 0, &res);
	release_mem_region(res.start, resource_size(&res));

	return 0;
}

static int __devinit cc770_ofp_probe(struct of_device *ofdev,
				     const struct of_device_id *id)
{
	struct device_node *np = ofdev->node;
	struct net_device *dev;
	struct cc770_priv *priv;
	struct resource res;
	const u32 *prop;
	u32 clkext;
	int err, irq, res_size, prop_size;
	void __iomem *base;

	err = of_address_to_resource(np, 0, &res);
	if (err) {
		dev_err(&ofdev->dev, "invalid address\n");
		return err;
	}

	res_size = resource_size(&res);

	if (!request_mem_region(res.start, res_size, DRV_NAME)) {
		dev_err(&ofdev->dev, "couldn't request %#llx..%#llx\n",
			(unsigned long long)res.start,
			(unsigned long long)res.end);
		return -EBUSY;
	}

	base = ioremap_nocache(res.start, res_size);
	if (!base) {
		dev_err(&ofdev->dev, "couldn't ioremap %#llx..%#llx\n",
			(unsigned long long)res.start,
			(unsigned long long)res.end);
		err = -ENOMEM;
		goto exit_release_mem;
	}

	irq = irq_of_parse_and_map(np, 0);
	if (irq == NO_IRQ) {
		dev_err(&ofdev->dev, "no irq found\n");
		err = -ENODEV;
		goto exit_unmap_mem;
	}

	dev = alloc_cc770dev(0);
	if (!dev) {
		err = -ENOMEM;
		goto exit_dispose_irq;
	}

	priv = netdev_priv(dev);

	priv->read_reg = cc770_ofp_read_reg;
	priv->write_reg = cc770_ofp_write_reg;

	prop = of_get_property(np, "bosch,external-clock-frequency",
			       &prop_size);
	if (prop && (prop_size ==  sizeof(u32)))
		clkext = *prop;
	else
		clkext = CC770_OFP_CAN_CLOCK; /* default */
	priv->can.clock.freq = clkext;

	/* The system clock may not exceed 10 MHz */
	if (priv->can.clock.freq > 10000000) {
		priv->cpu_interface |= CPUIF_DSC;
		priv->can.clock.freq /= 2;
	}

	/* The memory clock may not exceed 8 MHz */
	if (priv->can.clock.freq > 8000000)
		priv->cpu_interface |= CPUIF_DMC;

	if (of_get_property(np, "bosch,divide-memory-clock", NULL))
		priv->cpu_interface |= CPUIF_DMC;
	if (of_get_property(np, "bosch,iso-low-speed-mux", NULL))
		priv->cpu_interface |= CPUIF_MUX;

	if (of_get_property(np, "bosch,comperator-bypass", NULL))
		priv->bus_config |= BUSCFG_CBY;
	if (of_get_property(np, "bosch,disconnect-rx0-input", NULL))
		priv->bus_config |= BUSCFG_DR0;
	if (of_get_property(np, "bosch,disconnect-rx1-input", NULL))
		priv->bus_config |= BUSCFG_DR1;
	if (of_get_property(np, "bosch,disconnect-tx1-output", NULL))
		priv->bus_config |= BUSCFG_DT1;
	if (of_get_property(np, "bosch,polarity-dominant", NULL))
		priv->bus_config |= BUSCFG_POL;

	prop = of_get_property(np, "bosch,clock-out-frequency", &prop_size);
	if (prop && (prop_size == sizeof(u32)) && *prop > 0) {
		u32 cdv = clkext / *prop;
		int slew;

		if (cdv > 0 && cdv < 16) {
			priv->cpu_interface |= CPUIF_CEN;
			priv->clkout |= (cdv - 1) & CLKOUT_CD_MASK;

			prop = of_get_property(np, "bosch,slew-rate",
					       &prop_size);
			if (prop && (prop_size == sizeof(u32))) {
				slew = *prop;
			} else {
				/* Determine default slew rate */
				slew = (CLKOUT_SL_MASK >> CLKOUT_SL_SHIFT) -
					((cdv * clkext - 1) / 8000000);
				if (slew < 0)
					slew = 0;
			}
			priv->clkout |= (slew << CLKOUT_SL_SHIFT) &
				CLKOUT_SL_MASK;
		} else {
			dev_dbg(ND2D(dev), "invalid clock-out-frequency\n");
		}

	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
	priv->irq_flags = SA_SHIRQ;
#else
	priv->irq_flags = IRQF_SHARED;
#endif
	priv->reg_base = base;

	dev->irq = irq;

	dev_info(&ofdev->dev,
		 "reg_base=0x%p irq=%d clock=%d cpu_interface=0x%02x "
		 "bus_config=0x%02x clkout=0x%02x\n",
		 priv->reg_base, dev->irq, priv->can.clock.freq,
		 priv->cpu_interface, priv->bus_config, priv->clkout);

	dev_set_drvdata(&ofdev->dev, dev);
	SET_NETDEV_DEV(dev, &ofdev->dev);

	err = register_cc770dev(dev);
	if (err) {
		dev_err(&ofdev->dev, "registering %s failed (err=%d)\n",
			DRV_NAME, err);
		goto exit_free_cc770;
	}

	return 0;

exit_free_cc770:
	free_cc770dev(dev);
exit_dispose_irq:
	/* irq_dispose_mapping(dev->irq);*/ /* will not work for shared IRQs */
exit_unmap_mem:
	iounmap(base);
exit_release_mem:
	release_mem_region(res.start, res_size);

	return err;
}

static struct of_device_id __devinitdata cc770_ofp_table[] = {
	{.compatible = "bosch,cc770"}, /* CC770 from Bosch */
	{.compatible = "intc,82527"},  /* AN82527 from Intel CP */
	{},
};

static struct of_platform_driver cc770_ofp_driver = {
	.owner = THIS_MODULE,
	.name = DRV_NAME,
	.probe = cc770_ofp_probe,
	.remove = __devexit_p(cc770_ofp_remove),
	.match_table = cc770_ofp_table,
};

static int __init cc770_ofp_init(void)
{
	return of_register_platform_driver(&cc770_ofp_driver);
}
module_init(cc770_ofp_init);

static void __exit cc770_ofp_exit(void)
{
	return of_unregister_platform_driver(&cc770_ofp_driver);
};
module_exit(cc770_ofp_exit);
