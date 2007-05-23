/*
 * esdio.c - multiplex register access CAN hardware abstraction layer
 *           for the esd 3xCAN pc104 board
 *           http://www.esd-electronics.de/products/CAN/can-pc104-200_e.htm
 *
 * $Id$
 *
 * Inspired by the OCAN driver http://ar.linux.it/software/#ocan
 *
 * Copyright (c) 2007 Fraunhofer FOKUS
 *
 * Provided that this notice is retained in full, this
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
 * History:
 * 2007-05-22 Bjoern Riemer: initial release
 */

#include <linux/netdevice.h>
#include <linux/ioport.h>
#include <asm/io.h>
#include "hal.h"

#ifdef CONFIG_CAN_DEBUG_DEVICES
#define DBG(args...) printk(args)
#else
#define DBG(args...)
#endif

//#define DBG(args...)   printk(args)

int esd_ale_offset = 1;	//default for the sja1000 chip
int esd_cs_offset = 0;	//default for the sja1000 chip

/* init the HAL - call at driver module init */
int hal_init(void *irq_handler) { return 0; }

/* exit the HAL - call at driver module exit */
int hal_exit(void) { return 0; }

/* get name of this CAN HAL */
char *hal_name(void) { return "esdio"; }

/* fill arrays base[] and irq[] with HAL specific defaults */
void hal_use_defaults(void)
{
	extern unsigned long base[];
	extern unsigned int  irq[];

	base[0]		= 0x1e8UL;
	irq[0]		= 5;
}

/* request controller register access space */
int hal_request_region(int dev_num,
		       unsigned int num_regs,
		       char *drv_name)
{
	extern unsigned long base[];
	extern unsigned long rbase[];
	
	if (!memcmp(drv_name,"i82527-esdio",sizeof("i82527-esdio"))){
		esd_ale_offset = 7; 
		esd_cs_offset = 4;
	} else if (!memcmp(drv_name,"sja1000-esdio",sizeof("sja1000-esdio"))){
		esd_ale_offset = 1;
		esd_cs_offset = 0;
	}
	
	/* set for device base_addr */
	rbase[dev_num] = base[dev_num];

	/* ignore num_regs and create the 2 register region: */
	/* address register = base + esd_ale_offset          */
	/* data register    = base + esd_cs_offset           */
	if (request_region(base[dev_num] + esd_ale_offset, 1, drv_name)){
		if (request_region(base[dev_num] + esd_cs_offset, 1,drv_name)){
			return 1;
		} else {
			release_region(base[dev_num]+esd_ale_offset, 1);
			return 0; // error
		}
	}

	return 0; // error 
}

/* release controller register access space */
void hal_release_region(int dev_num,
			unsigned int num_regs)
{
	extern unsigned long base[];

	/* ignore num_regs and create the 2 register region: */
	/* address register = base + esd_ale_offset          */
	/* data register    = base + esd_cs_offset           */
	release_region(base[dev_num] + esd_cs_offset, 1);
	release_region(base[dev_num] + esd_ale_offset, 1);
}

/* enable non controller hardware (e.g. irq routing, etc.) */
int hw_attach(int dev_num)
{
	int i, stat, i1;
	extern unsigned long base[];
	extern unsigned int  irq[];
	 
	i1 = irq[dev_num]; //get IRQ number
	DBG(KERN_INFO "esdio.c: enabling IRQ %d for dev_num %d\n",i1,dev_num);
	
	for (i=0; i<4; i++){
		stat=i; // bit 0,1 selects the latch bit to write
		if (i1 & 0x01){
			stat |= 0x80; //bit7 carrys the value of the latch bit
		}
		outb(stat,base[dev_num]+3);
		i1 = i1>>1;
	}

	outb(0x87,base[dev_num]+3); //enable irq selection
	outb(0x86,base[dev_num]+3); //enable irq tristate buffer

	return 1; 
}

/* disable non controller hardware (e.g. irq routing, etc.) */
int hw_detach(int dev_num)
{
	int i;
	extern unsigned long base[];
	
	DBG(KERN_INFO "esdio.c: diabling IRQ for dev_num %d\n",dev_num);
	
	outb(0x07,base[dev_num]+3); //disable irq selection
	outb(0x06,base[dev_num]+3); //disable irq tristate buffer
	
	for (i=0; i<4; i++)
		outb(i,base[dev_num]+3);

	return 1;
}

/* reset controller hardware (with specific non controller hardware) */
int hw_reset_dev(int dev_num) {	return 0; }

/* read from controller register */
u8 hw_readreg(unsigned long base, int reg) {	
	
	outb(reg, base + esd_ale_offset);	/* address */
	return inb(base + esd_cs_offset);	/* data */
}

/* write to controller register */
void hw_writereg(unsigned long base, int reg, u8 val) {
	
	outb(reg, base + esd_ale_offset);	/* address */
	outb(val, base + esd_cs_offset);	/* data */
}

/* hardware specific work to do at start of irq handler */
void hw_preirq(struct net_device *dev) { return; }

/* hardware specific work to do at end of irq handler */
void hw_postirq(struct net_device *dev) {	

	outb(0x86,dev->base_addr+3); //enable irq tristate buffer 
	return; 
}
