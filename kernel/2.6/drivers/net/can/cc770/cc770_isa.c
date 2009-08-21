/*
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/isa.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/delay.h>
#include <linux/irq.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
#include <linux/io.h>
#else
#include <asm/io.h>
#endif
#include <socketcan/can.h>
#include <socketcan/can/dev.h>

#include "cc770.h"

#define DRV_NAME "cc770_isa"

#define MAXDEV 8

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
#error This driver does not support Kernel versions < 2.6.16
#endif

MODULE_AUTHOR("Wolfgang Grandegger <wg@grandegger.com>");
MODULE_DESCRIPTION("Socket-CAN driver for CC770 on the ISA bus");
MODULE_LICENSE("GPL v2");

#define CLK_DEFAULT	16000000	/* 16 MHz */
#define BCR_DEFAULT	0x00
#define COR_DEFAULT	0x00

static unsigned long port[MAXDEV];
static unsigned long mem[MAXDEV];
static int __devinitdata irq[MAXDEV];
static int __devinitdata clk[MAXDEV];
static char __devinitdata cir[MAXDEV] = {[0 ... (MAXDEV - 1)] = -1};
static char __devinitdata bcr[MAXDEV] = {[0 ... (MAXDEV - 1)] = -1};
static char __devinitdata cor[MAXDEV] = {[0 ... (MAXDEV - 1)] = -1};
static char __devinitdata indirect[MAXDEV] = {[0 ... (MAXDEV - 1)] = -1};

module_param_array(port, ulong, NULL, S_IRUGO);
MODULE_PARM_DESC(port, "I/O port number");

module_param_array(mem, ulong, NULL, S_IRUGO);
MODULE_PARM_DESC(mem, "I/O memory address");

module_param_array(indirect, byte, NULL, S_IRUGO);
MODULE_PARM_DESC(indirect, "Indirect access via address and data port");

module_param_array(irq, int, NULL, S_IRUGO);
MODULE_PARM_DESC(irq, "IRQ number");

module_param_array(clk, int, NULL, S_IRUGO);
MODULE_PARM_DESC(clk, "External oscillator clock frequency "
		 "(default=16000000 [16 MHz])");

module_param_array(cir, byte, NULL, S_IRUGO);
MODULE_PARM_DESC(cdr, "CPU interface register (default=0x40 [CPU_DSC])");

module_param_array(bcr, byte, NULL, S_IRUGO);
MODULE_PARM_DESC(ocr, "Bus configuration register (default=0x00)");

module_param_array(cor, byte, NULL, S_IRUGO);
MODULE_PARM_DESC(cor, "Clockout register (default=0x00)");

#define CC770_IOSIZE          0x20
#define CC770_IOSIZE_INDIRECT 0x02

static u8 cc770_isa_mem_read_reg(const struct cc770_priv *priv, int reg)
{
	return readb(priv->reg_base + reg);
}

static void cc770_isa_mem_write_reg(const struct cc770_priv *priv,
				      int reg, u8 val)
{
	writeb(val, priv->reg_base + reg);
}

static u8 cc770_isa_port_read_reg(const struct cc770_priv *priv, int reg)
{
	return inb((unsigned long)priv->reg_base + reg);
}

static void cc770_isa_port_write_reg(const struct cc770_priv *priv,
				       int reg, u8 val)
{
	outb(val, (unsigned long)priv->reg_base + reg);
}

static u8 cc770_isa_port_read_reg_indirect(const struct cc770_priv *priv,
					     int reg)
{
	unsigned long base = (unsigned long)priv->reg_base;

	outb(reg, base);
	return inb(base + 1);
}

static void cc770_isa_port_write_reg_indirect(const struct cc770_priv *priv,
						int reg, u8 val)
{
	unsigned long base = (unsigned long)priv->reg_base;

	outb(reg, base);
	outb(val, base + 1);
}

static int __devinit cc770_isa_match(struct device *pdev, unsigned int idx)
{
	if (port[idx] || mem[idx]) {
		if (irq[idx])
			return 1;
	} else if (idx)
		return 0;

	dev_err(pdev, "insufficient parameters supplied\n");
	return 0;
}

static int __devinit cc770_isa_probe(struct device *pdev, unsigned int idx)
{
	struct net_device *dev;
	struct cc770_priv *priv;
	void __iomem *base = NULL;
	int iosize = CC770_IOSIZE;
	int err;
	u32 clktmp;

	if (mem[idx]) {
		if (!request_mem_region(mem[idx], iosize, DRV_NAME)) {
			err = -EBUSY;
			goto exit;
		}
		base = ioremap_nocache(mem[idx], iosize);
		if (!base) {
			err = -ENOMEM;
			goto exit_release;
		}
	} else {
		if (indirect[idx] > 0 ||
		    (indirect[idx] == -1 && indirect[0] > 0))
			iosize = CC770_IOSIZE_INDIRECT;
		if (!request_region(port[idx], iosize, DRV_NAME)) {
			err = -EBUSY;
			goto exit;
		}
	}

	dev = alloc_cc770dev(0);
	if (!dev) {
		err = -ENOMEM;
		goto exit_unmap;
	}
	priv = netdev_priv(dev);

	dev->irq = irq[idx];
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
	priv->irq_flags = SA_SHIRQ;
#else
	priv->irq_flags = IRQF_SHARED;
#endif
	if (mem[idx]) {
		priv->reg_base = base;
		dev->base_addr = mem[idx];
		priv->read_reg = cc770_isa_mem_read_reg;
		priv->write_reg = cc770_isa_mem_write_reg;
	} else {
		priv->reg_base = (void __iomem *)port[idx];
		dev->base_addr = port[idx];

		if (iosize == CC770_IOSIZE_INDIRECT) {
			priv->read_reg = cc770_isa_port_read_reg_indirect;
			priv->write_reg = cc770_isa_port_write_reg_indirect;
		} else {
			priv->read_reg = cc770_isa_port_read_reg;
			priv->write_reg = cc770_isa_port_write_reg;
		}
	}

	if (clk[idx])
		clktmp = clk[idx];
	else if (clk[0])
		clktmp = clk[0];
	else
		clktmp = CLK_DEFAULT;
	priv->can.clock.freq = clktmp;

	if (cir[idx] != -1) {
		priv->cpu_interface = cir[idx] & 0xff;
	} else if (cir[0] != -1) {
		priv->cpu_interface = cir[0] & 0xff;
	} else {
		/* The system clock may not exceed 10 MHz */
		if (clktmp > 10000000) {
			priv->cpu_interface |= CPUIF_DSC;
			clktmp /= 2;
		}
		/* The memory clock may not exceed 8 MHz */
		if (clktmp > 8000000)
			priv->cpu_interface |= CPUIF_DMC;
	}

	if (priv->cpu_interface & CPUIF_DSC)
		priv->can.clock.freq /= 2;

	if (bcr[idx] != -1)
		priv->bus_config = bcr[idx] & 0xff;
	else if (bcr[0] != -1)
		priv->bus_config = bcr[0] & 0xff;
	else
		priv->bus_config = BCR_DEFAULT;

	if (cor[idx] != -1)
		priv->clkout = cor[idx] & 0xff;
	else if (cor[0] != -1)
		priv->clkout = cor[0] & 0xff;
	else
		priv->clkout = COR_DEFAULT;

	dev_set_drvdata(pdev, dev);
	SET_NETDEV_DEV(dev, pdev);

	err = register_cc770dev(dev);
	if (err) {
		dev_err(pdev, "registering %s failed (err=%d)\n",
			DRV_NAME, err);
		goto exit_unmap;
	}

	dev_info(pdev, "%s device registered (reg_base=0x%p, irq=%d)\n",
		 DRV_NAME, priv->reg_base, dev->irq);
	return 0;

 exit_unmap:
	if (mem[idx])
		iounmap(base);
 exit_release:
	if (mem[idx])
		release_mem_region(mem[idx], iosize);
	else
		release_region(port[idx], iosize);
 exit:
	return err;
}

static int __devexit cc770_isa_remove(struct device *pdev, unsigned int idx)
{
	struct net_device *dev = dev_get_drvdata(pdev);
	struct cc770_priv *priv = netdev_priv(dev);

	unregister_cc770dev(dev);
	dev_set_drvdata(pdev, NULL);

	if (mem[idx]) {
		iounmap(priv->reg_base);
		release_mem_region(mem[idx], CC770_IOSIZE);
	} else {
		if (priv->read_reg == cc770_isa_port_read_reg_indirect)
			release_region(port[idx], CC770_IOSIZE_INDIRECT);
		else
			release_region(port[idx], CC770_IOSIZE);
	}
	free_cc770dev(dev);

	return 0;
}

static struct isa_driver cc770_isa_driver = {
	.match = cc770_isa_match,
	.probe = cc770_isa_probe,
	.remove = __devexit_p(cc770_isa_remove),
	.driver = {
		.name = DRV_NAME,
	},
};

static int __init cc770_isa_init(void)
{
	int err = isa_register_driver(&cc770_isa_driver, MAXDEV);

	if (!err)
		printk(KERN_INFO
		       "Legacy %s driver for max. %d devices registered\n",
		       DRV_NAME, MAXDEV);
	return err;
}

static void __exit cc770_isa_exit(void)
{
	isa_unregister_driver(&cc770_isa_driver);
}

module_init(cc770_isa_init);
module_exit(cc770_isa_exit);
