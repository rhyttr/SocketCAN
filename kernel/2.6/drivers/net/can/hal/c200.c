/*
 * c200.c - low cost parallelport CAN adaptor hardware abstraction layer
 *          ( direct register access without parport subsystem support )
 *
 *          CAN200 project homepage http://private.addcom.de/horo/can200
 *
 *          This hal is based on a patch from Uwe Bonnes.
 *
 * $Id$
 *
 * Inspired by the OCAN driver http://ar.linux.it/software/#ocan
 *
 * Copyright (c) 2002-2007 Volkswagen Group Electronic Research
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

#include <linux/netdevice.h>
#include <linux/ioport.h>
#include <linux/spinlock.h>
#include <asm/io.h>
#include "hal.h"

/* init the HAL - call at driver module init */
int hal_init(void) { return 0; }

/* exit the HAL - call at driver module exit */
int hal_exit(void) { return 0; }

/* get name of this CAN HAL */
char *hal_name(void) { return "c200"; }

/* fill arrays base[] and irq[] with HAL specific defaults */
void hal_use_defaults(void)
{
	extern unsigned long base[];
	extern unsigned int  irq[];

	base[0]		= 0x378UL;
	irq[0]		= 7;
}

#define ECR_REGS_OFFSET 0x400
#define ECR_CTRL_OFFSET (ECR_REGS_OFFSET + 2)

static u8 ecr_crtl_save;

/* request controller register access space */
int hal_request_region(int dev_num,
		       unsigned int num_regs,
		       char *drv_name)
{
	extern unsigned long base[];
	extern unsigned long rbase[];

	/* set for device base_addr */
	rbase[dev_num] = base[dev_num];

	/* grab ECR control registers and set parport to 'byte mode' */
	if (request_region(rbase[dev_num] + ECR_REGS_OFFSET, 3, drv_name)) {

		ecr_crtl_save = inb(rbase[dev_num] + ECR_CTRL_OFFSET);

		outb((ecr_crtl_save & 0x1F) | 0x20,
		     rbase[dev_num] + ECR_CTRL_OFFSET);
	} else
		return 0;

	if (request_region(rbase[dev_num], 4, drv_name))
		return 1;

	release_region(rbase[dev_num] + ECR_REGS_OFFSET, 3);

	return 0;
}

/* release controller register access space */
void hal_release_region(int dev_num,
			unsigned int num_regs)
{
	extern unsigned long base[];

	release_region(base[dev_num], 4);

	/* restore original ECR control register value */
	outb(ecr_crtl_save, base[dev_num] + ECR_CTRL_OFFSET);
	release_region(base[dev_num] + ECR_REGS_OFFSET, 3);
}

/* enable non controller hardware (e.g. irq routing, etc.) */
int hw_attach(int dev_num)
{
	extern unsigned long rbase[];
	unsigned long pc = rbase[dev_num] + 2;

	/* enable irq */
	outb(inb(pc) | 0x10, pc);

	return 0;
}

/* disable non controller hardware (e.g. irq routing, etc.) */
int hw_detach(int dev_num)
{
	extern unsigned long rbase[];
	unsigned long pc = rbase[dev_num] + 2;

	/* disable irq */
	outb(inb(pc) & ~0x10, pc);

	return 0;
}

/* reset controller hardware (with specific non controller hardware) */
int hw_reset_dev(int dev_num) { return 0; }

#define WRITEP		0x01 /* inverted at port  */
#define DATASTB		0x02 /* inverted at port and at device*/
#define ADDRSTB		0x08 /* inverted at port and at device*/
#define PORTREAD	0x20

static DEFINE_SPINLOCK(c200_lock);

/* read from controller register */
u8 hw_readreg(unsigned long base, int reg)
{
	unsigned long pa = base;
	unsigned long pc = pa + 2;
	unsigned long flags;
	u8 irqstatus = (inb(pc) & 0x10) | 0x04;
	u8 val;

	spin_lock_irqsave(&c200_lock, flags);

	outb(irqstatus | ADDRSTB, pc);
	outb((reg & 0x1F) | 0x80, pa);
	outb(irqstatus, pc);
	outb(irqstatus | PORTREAD, pc);
	outb(irqstatus | DATASTB | PORTREAD, pc);
	val = inb(pa);
	outb(irqstatus, pc);

	spin_unlock_irqrestore(&c200_lock, flags);

	return val;
}

/* write to controller register */
void hw_writereg(unsigned long base, int reg, u8 val)
{
	unsigned long pa = base;
	unsigned long pc = pa + 2;
	unsigned long flags;
	u8 irqstatus = (inb(pc) & 0x10) | 0x04;

	spin_lock_irqsave(&c200_lock, flags);

	outb(irqstatus | ADDRSTB, pc);
	outb(reg & 0x1F, pa);
	outb(irqstatus, pc);
	outb(irqstatus | WRITEP, pc);
	outb(irqstatus | DATASTB | WRITEP, pc);
	outb(val, pa);
	outb(irqstatus, pc);

	spin_unlock_irqrestore(&c200_lock, flags);
}

/* hardware specific work to do at start of irq handler */
void hw_preirq(struct net_device *dev) { return; }

/* hardware specific work to do at end of irq handler */
void hw_postirq(struct net_device *dev) { return; }
