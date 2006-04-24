/*
 * $Id: mscan_net.c,v 1.1 2006/03/09 13:17:16 hartko Exp $
 *
 * mscan_net.c - Motorola MPC52xx MSCAN network device driver
 *
 * Copyright (c) 2002-2006 Volkswagen Group Electronic Research
 * All rights reserved.
 *
 * Copyright (c) 2003 Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 *
 * Copyright (c) 2005 Felix Daners, Plugit AG, felix.daners@plugit.ch
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
#include <linux/proc_fs.h>
#include <asm/io.h>
#include "af_can.h"

#include <linux/netdevice.h>
#include <linux/skbuff.h>

#include "can.h"
#include "can_ioctl.h" /* for struct can_device_stats */
#include <asm/mpc5xxx.h>
#include <asm/ppcboot.h>
#include "mscan.h"

/* driver and version information */
static const char *drv_name	= DRV_NAME;
static const char *drv_version	= "0.0.1";
static const char *drv_reldate	= "2006-03-07";

MODULE_AUTHOR("Oliver Hartkopp <oliver.hartkopp@volkswagen.de>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("LLCF Motorola MPC52xx MSCAN network device driver '" DRV_NAME "'");

/* module parameters */
static struct mpc5xxx_mscan *regs[MAX_CAN] = {(struct mpc5xxx_mscan *)MPC5xxx_MSCAN1, (struct mpc5xxx_mscan *)MPC5xxx_MSCAN2};
static int irq[MAX_CAN] = { MPC5xxx_CAN1_IRQ, MPC5xxx_CAN2_IRQ};

static int speed[MAX_CAN] = {DEFAULT_KBIT_PER_SEC, DEFAULT_KBIT_PER_SEC};
static int btr[MAX_CAN] = { 0 };

static int debug = 0;
static int clk = MSCAN_DEFAULT_CLOCK;
static char *pins = NULL;

/* array of all can chips */
struct net_device *can_dev[MAX_CAN];

static __init int  mscan_init(void);
static __exit void mscan_exit(void);

module_init(mscan_init);
module_exit(mscan_exit);

MODULE_PARM(speed,     "1-" __MODULE_STRING(MAX_CAN)"i");
MODULE_PARM_DESC(speed, "The CAN bitrate in bits/second");
MODULE_PARM(btr,       "1-" __MODULE_STRING(MAX_CAN)"i");
MODULE_PARM_DESC(btr, "The CAN bitrate defined as bit timing register value");
MODULE_PARM(debug, "i");
MODULE_PARM_DESC(debug, "Verbose debug messages");
MODULE_PARM(clk,"i");
MODULE_PARM_DESC(clk, "The clock for Freescale PPC5200 on chip MSCAN controller");
MODULE_PARM(pins,"s");
MODULE_PARM_DESC(pins, "The pins for Freescale PPC5200 on chip MSCAN controller (psc2,i2c1/tmr01)");

int mscan_init(void)
{
    int	i;

    if (clk < 1000 ) /* MHz command line value */
	clk *= 1000000;

    if (clk < 1000000 ) /* kHz command line value */
	clk *= 1000;

    printk(KERN_INFO "%s driver v%s (%s)\n",
	   drv_name, drv_version, drv_reldate);
    printk(KERN_INFO "%s - options [clk %d.%06d MHz] [debug %d]\n",
	   drv_name, clk/1000000, clk%1000000, debug);

    for (i = 0; i < MAX_CAN; i++) {
	can_dev[i] = mscan_register(regs[i], irq[i], speed[i], btr[i], clk, debug);

	if (can_dev[i])
	    printk(KERN_DEBUG "%s: registered MSCAN%d on address 0x%p as %s.\n",
		   drv_name, i+1, regs[i], can_dev[i]->name);
	else {
	    printk(KERN_DEBUG "%s: had problems with MSCAN%d on address 0x%p.\n",
		   drv_name, i+1, regs[i]);
	    goto mscan_init_out;
	}
    }

    if (pins) {
	struct mpc5xxx_gpio *gpio = (struct mpc5xxx_gpio *) MPC5xxx_GPIO;

	if(!strncmp(pins,"psc2",5)) {
	    gpio->port_config &= ~0x10000070; // clear ALT 01
	    gpio->port_config |= 0x00000010;   // set PSC2 function to CAN
	}
	else if(!strncmp(pins,"i2c1/tmr01",11))
	    gpio->port_config |= 0x10000000;  // set ALT for CAN, leave PSC2 untouched 
	else
	    printk(KERN_ERR "\n!!!Invalid kernel module parameter \"%s\" ignored."
		   " Use \"psc2\" or \"i2c1/tmr01\"\n", pins);
    }

    mscan_init_proc();

    return 0;

 mscan_init_out:

    for (i = 0; i < MAX_CAN; i++) {
	if (can_dev[i]) {
	    struct can_priv *priv = (struct can_priv*)can_dev[i]->priv;
	    unregister_netdev(can_dev[i]);
	    if (priv)
		kfree(priv);
	}
    }
    return -ENODEV;
}

void mscan_exit(void)
{
    int i;

    mscan_remove_proc();

    for (i = 0; i < MAX_CAN; i++) {
	if (can_dev[i]) {
	    struct can_priv *priv = (struct can_priv*)can_dev[i]->priv;
	    unregister_netdev(can_dev[i]);
	    if (priv)
		kfree(priv);
	}
    }
}
