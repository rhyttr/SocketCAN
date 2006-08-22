/*
 * $Id$
 *
 * mem.c - Philips SJA1000 network device driver for IOMEM
 *
 * Copyright (c) 2002-2005 Volkswagen Group Electronic Research
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, the following disclaimer and
 *    the referenced file 'COPYING'.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Volkswagen nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2 as distributed in the 'COPYING'
 * file from the main directory of the linux kernel source.
 *
 * The provided data structures and external interfaces from this code
 * are not restricted to be used by modules with a GPL compatible license.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * Send feedback to <socketcan-users@lists.berlios.de>
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/ioport.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <asm/io.h>

#include <linux/can/can.h>
#include <linux/can/can_ioctl.h> /* for struct can_device_stats */
#include "sja1000.h"

#define MAX_CAN		8
#define CAN_DEV_NAME	"can%d"
#define DRV_NAME        "sja1000-mem"

#define DEFAULT_KBIT_PER_SEC 500
#define SJA1000_HW_CLOCK 16000000

/* driver and version information */
static const char *drv_name	= DRV_NAME;
static const char *drv_version	= "0.0.1";
static const char *drv_reldate	= "2006-08-22";
static const char *chip_name	= SJA1000_CHIP_NAME;

MODULE_AUTHOR("Oliver Hartkopp <oliver.hartkopp@volkswagen.de>, Pavel Pisa <pisa@cmp.felk.cvut.cz>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("LLCF SJA1000 network device driver '" DRV_NAME "'");

/* module parameters */
static uint32_t base_addr[MAX_CAN] = { (uint32_t)0xda000L, 0};

static int irq[MAX_CAN] = { 9, 0 };

static int speed[MAX_CAN] = { DEFAULT_KBIT_PER_SEC, DEFAULT_KBIT_PER_SEC, 0};

static int btr[MAX_CAN] = { 0 };
static int rx_probe[MAX_CAN] = { 0 };

static int clk = SJA1000_HW_CLOCK;
static int debug = 0;
static int restart_ms = 100;

/* array of all can chips */
static struct net_device	*can_dev[MAX_CAN];

static int base_addr_n;
static int irq_n;
static int speed_n;
static int btr_n;
static int rx_probe_n;

module_param_array(base_addr, int, &base_addr_n, 0);
module_param_array(irq, int, &irq_n, 0);
module_param_array(speed, int, &speed_n, 0);
module_param_array(btr, int, &btr_n, 0);
module_param_array(rx_probe, int, &rx_probe_n, 0);

module_param(clk, int, 0);
module_param(debug, int, 0);
module_param(restart_ms, int, 0);

/* special functions to access the chips registers */
static uint8_t reg_read(struct net_device *dev, int reg)
{
	static uint8_t val;
	void __iomem *addr = (void __iomem *)dev->base_addr + reg;

	val = (uint8_t)readw(addr);
	rmb();

	return val;
}

static void reg_write(struct net_device *dev, int reg, uint8_t val)
{
	void __iomem *addr = (void __iomem *)dev->base_addr + reg;

	writew(val, addr);
	wmb();
}

static struct net_device* sja1000_mem_probe(uint32_t base, int irq, int speed,
					    int btr, int rx_probe, int clk,
					    int debug, int restart_ms)
{
	struct net_device	*dev;
	struct can_priv		*priv;

	if (!(dev = alloc_netdev(sizeof(struct can_priv), CAN_DEV_NAME,
				 sja1000_setup))) {
		printk(KERN_ERR "%s: out of memory\n", chip_name);
		return NULL;
	}

	printk(KERN_INFO "%s: base 0x%X / irq %d / speed %d / btr 0x%X / rx_probe %d\n",
	       chip_name, base, irq, speed, btr, rx_probe);

	/* fill net_device structure */

	priv             = netdev_priv(dev);

	dev->irq         = irq;
	dev->base_addr   = base;

	priv->reg_read   = reg_read;
	priv->reg_write  = reg_write;

	priv->speed      = speed;
	priv->btr        = btr;
	priv->rx_probe   = rx_probe;
	priv->clock      = clk;
	priv->restart_ms = restart_ms;
	priv->debug      = debug;

	if (REG_READ(0) == 0xFF)
		goto free_dev;

	/* set chip into reset mode */
	set_reset_mode(dev);

	/* go into Pelican mode, disable clkout, disable comparator */
	REG_WRITE(REG_CDR, 0xCF);

	/* output control */
	/* connected to external transceiver */
	REG_WRITE(REG_OCR, 0x1A);

	printk(KERN_INFO "%s: %s found at 0x%X, irq is %d\n",
	       dev->name, chip_name, (uint32_t)dev->base_addr, dev->irq);

	if (register_netdev(dev) == 0)
		return dev;

	printk(KERN_INFO "%s: probing failed\n", chip_name);
 free_dev:
	free_netdev(dev);
	return NULL;
}

static __exit void sja1000_mem_cleanup_module(void)
{
	int i;

	for (i = 0; i < MAX_CAN; i++) {
		if (can_dev[i] != NULL) {
			struct can_priv *priv = netdev_priv(can_dev[i]);
			unregister_netdev(can_dev[i]);
			del_timer(&priv->timer);
			iounmap((void __iomem *)can_dev[i]->base_addr);
			release_mem_region(base_addr[i], SJA1000_IO_SIZE_BASIC);
			free_netdev(can_dev[i]);
		}
	}
	sja1000_proc_delete(drv_name);
}

static __init int sja1000_mem_init_module(void)
{
	int i;

	if (clk < 1000 ) /* MHz command line value */
		clk *= 1000000;

	if (clk < 1000000 ) /* kHz command line value */
		clk *= 1000;

	printk(KERN_INFO "%s - %s driver v%s (%s)\n",
	       chip_name, drv_name, drv_version, drv_reldate);
	printk(KERN_INFO "%s - options [clk %d.%06d MHz] [restart_ms %dms] [debug %d]\n",
	       chip_name, clk/1000000, clk%1000000, restart_ms, debug);

	for (i = 0; base_addr[i]; i++) {

		struct net_device *dev = NULL;
		void *base;

		printk(KERN_DEBUG "%s: checking for %s on address 0x%X ...\n",
		       chip_name, chip_name, base_addr[i]);
		if (!request_mem_region(base_addr[i], SJA1000_IO_SIZE_BASIC, chip_name)) {
			printk(KERN_ERR "%s: memory already in use\n", chip_name);
			sja1000_mem_cleanup_module();
			return -EBUSY;
		}

		base = ioremap(base_addr[i], SJA1000_IO_SIZE_BASIC);
		if (base)
			dev = sja1000_mem_probe((uint32_t)base, irq[i], speed[i], btr[i], rx_probe[i], clk, debug, restart_ms);
		if (dev != NULL) {
			can_dev[i] = dev;
			sja1000_proc_init(drv_name, can_dev, MAX_CAN);
		} else {
			can_dev[i] = NULL;
			iounmap(base);
			release_mem_region(base_addr[i], SJA1000_IO_SIZE_BASIC);
		}
	}
	return 0;
}

module_init(sja1000_mem_init_module);
module_exit(sja1000_mem_cleanup_module);
