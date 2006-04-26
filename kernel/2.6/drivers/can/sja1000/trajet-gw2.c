/*
 * $Id: trajet-gw2.c,v 2.0 2006/04/13 10:37:22 ethuerm Exp $
 *
 * trajet-gw2.c - Philips SJA1000 network device driver for TRAJET.GW2
 *
 * Copyright (c) 2003 Matthias Brukner, Trajet Gmbh, Rebenring 33,
 * 38106 Braunschweig, GERMANY
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
 * Send feedback to <llcf@volkswagen.de>
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

#include <net/can/can.h>
#include <net/can/can_ioctl.h> /* for struct can_device_stats */
#include "sja1000.h"

#define MAX_CAN		8
#define CAN_DEV_NAME	"can%d"
#define DRV_NAME        "sja1000-gw2"

#define DEFAULT_KBIT_PER_SEC 500
#define SJA1000_HW_CLOCK 20000000
#define ADDR_GAP	1
#define RSIZE		(SJA1000_IO_SIZE_PELICAN * (ADDR_GAP + 1))

/* driver and version information */
static const char *drv_name	= DRV_NAME;
static const char *drv_version	= "0.0.11";
static const char *drv_reldate	= "2005-10-11";
static const char *chip_name	= SJA1000_CHIP_NAME;

MODULE_AUTHOR("Matthias Brukner <M.Brukner@trajet.de>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("LLCF SJA1000 network device driver '" DRV_NAME "'");

/* module parameters */
static uint32_t base_addr[MAX_CAN] = {
	(uint32_t)0xf0100200L,
	(uint32_t)0xf0100300L,
	(uint32_t)0xf0100400L,
	(uint32_t)0xf0100500L,
	0
};
static int irq[MAX_CAN] = { 26, 26, 26, 26, 0 };
static int speed[MAX_CAN] = {
	DEFAULT_KBIT_PER_SEC, DEFAULT_KBIT_PER_SEC,
	DEFAULT_KBIT_PER_SEC, DEFAULT_KBIT_PER_SEC,
	0
};
static int btr[MAX_CAN] = { 0 };
static int rx_probe[MAX_CAN] = { 0 };

static int clk = SJA1000_HW_CLOCK;
static int debug = 0;
static int restart_ms = 100;

/* array of all can chips */
static struct net_device	*can_dev[MAX_CAN];


/* special functions to access the chips registers */
static uint8_t reg_read(struct net_device *dev, int reg)
{
	static uint8_t val;

	val = (uint8_t)readw(dev->base_addr + reg * (ADDR_GAP + 1) + ADDR_GAP);
	rmb();

	return val;
}

static void reg_write(struct net_device *dev, int reg, uint8_t val)
{
	writew(val, dev->base_addr + reg * 2 + 1);
	wmb();
}

MODULE_PARM(base_addr, "1-" __MODULE_STRING(MAX_CAN)"i");
MODULE_PARM(irq,       "1-" __MODULE_STRING(MAX_CAN)"i");
MODULE_PARM(speed,     "1-" __MODULE_STRING(MAX_CAN)"i");
MODULE_PARM(btr,       "1-" __MODULE_STRING(MAX_CAN)"i");
MODULE_PARM(rx_probe,  "1-" __MODULE_STRING(MAX_CAN)"i");
MODULE_PARM(clk, "i");
MODULE_PARM(debug, "i");
MODULE_PARM(restart_ms, "i");

static struct net_device* sja1000_gw2_probe(uint32_t base, int irq, int speed,
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

static __exit void sja1000_gw2_cleanup_module(void)
{
	int i;

	for (i = 0; i < MAX_CAN; i++) {
		if (can_dev[i] != NULL) {
			struct can_priv *priv = netdev_priv(can_dev[i]);
			unregister_netdev(can_dev[i]);
			del_timer(&priv->timer);
			iounmap((void*)can_dev[i]->base_addr);
			release_mem_region(base_addr[i], RSIZE);
			free_netdev(can_dev[i]);
		}
	}
	sja1000_proc_delete(drv_name);
}

static __init int sja1000_gw2_init_module(void)
{
	int i;
	struct net_device *dev;
	void *base;

	if (clk < 1000 ) /* MHz command line value */
		clk *= 1000000;

	if (clk < 1000000 ) /* kHz command line value */
		clk *= 1000;

	printk(KERN_INFO "%s - %s driver v%s (%s)\n",
	       chip_name, drv_name, drv_version, drv_reldate);
	printk(KERN_INFO "%s - options [clk %d.%06d MHz] [restart_ms %dms] [debug %d]\n",
	       chip_name, clk/1000000, clk%1000000, restart_ms, debug);

	for (i = 0; base_addr[i]; i++) {
		printk(KERN_DEBUG "%s: checking for %s on address 0x%X ...\n",
		       chip_name, chip_name, base_addr[i]);
		if (!request_mem_region(base_addr[i], RSIZE, chip_name)) {
			printk(KERN_ERR "%s: memory already in use\n", chip_name);
			sja1000_gw2_cleanup_module();
			return -EBUSY;
		}
		base = ioremap(base_addr[i], RSIZE);
		dev = sja1000_gw2_probe((uint32_t)base, irq[i], speed[i], btr[i], rx_probe[i], clk, debug, restart_ms);
		if (dev != NULL) {
			can_dev[i] = dev;
			sja1000_proc_init(drv_name, can_dev, MAX_CAN);
		} else {
			can_dev[i] = NULL;
			iounmap(base);
			release_mem_region(base_addr[i], RSIZE);
		}
	}
	return 0;
}

module_init(sja1000_gw2_init_module);
module_exit(sja1000_gw2_cleanup_module);
