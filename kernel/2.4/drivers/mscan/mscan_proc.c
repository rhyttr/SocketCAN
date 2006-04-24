/*
 * $Id: mscan_proc.c,v 1.1 2006/03/09 13:17:16 hartko Exp $
 *
 * mscan_proc.c - Motorola MPC52xx MSCAN network device driver
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
#include <linux/proc_fs.h>
#include <asm/io.h>
#include <linux/netdevice.h>
#include <asm/mpc5xxx.h>
#include <asm/ppcboot.h>
#include "can_ioctl.h" /* for struct can_device_stats */
#include "mscan.h"

#define PROCBASE      "net/drivers" /* /proc/ ... */
#define PROCFILE      DRV_NAME
#define PROCREGSFILE  DRV_NAME"_regs"
#define PROCGPIOFILE  DRV_NAME"_gpio"
#define PROCCDMFILE   DRV_NAME"_cdm"

#define DEV_PORT_REGS_U8(reg) " " #reg " 0x%02X\n", 0xFF & (int) (regs->reg)

#define GPIO_REG_U32(reg)  " " #reg " 0x%08X\n", 0xFFFFFFFF & (int)(gpio->reg)
#define GPIO_REG_U16(reg)  " " #reg " 0x%04X\n", 0xFFFF & (int)(gpio->reg) 
#define GPIO_REG_U8(reg)   " " #reg " 0x%02X\n", 0xFF & (int)(gpio->reg) 

#define CDM_REG_U32(reg)  " " #reg " 0x%08X\n", 0xFFFFFFFF & (int)(cdm->reg)
#define CDM_REG_U16(reg)  " " #reg " 0x%04X\n", 0xFFFF & (int)(cdm->reg) 
#define CDM_REG_U8(reg)   " " #reg " 0x%02X\n", 0xFF & (int)(cdm->reg) 

extern struct net_device *can_dev[];

static struct proc_dir_entry *pde      = NULL;
static struct proc_dir_entry *pde_regs = NULL;
static struct proc_dir_entry *pde_gpio = NULL;
static struct proc_dir_entry *pde_cdm  = NULL;

/**************************************************/
/* proc read functions                            */
/**************************************************/

//----------------------------------------------------------------------------
// print out mscan config relevant registers and selected modes
static int mscan_proc_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int len = 0;
    struct net_device *dev;
    struct can_priv *priv;
    int i;

    MOD_INC_USE_COUNT;

    len += snprintf(page + len, PAGE_SIZE - len, "CAN bus device statistics:\n");
    len += snprintf(page + len, PAGE_SIZE - len, "       errwarn  overrun   wakeup   buserr   errpass  arbitr   restarts clock        baud\n");
    for (i = 0; (i < MAX_CAN) && (len < PAGE_SIZE - 200); i++) {
	if (can_dev[i]) {
	    dev = can_dev[i];
	    priv = (struct can_priv*)can_dev[i]->priv;
	    len += snprintf(page + len, PAGE_SIZE - len, "%s: %8d %8d %8d %8d %8d %8d %8d %10d %8d\n", dev->name,
			    priv->can_stats.error_warning,
			    priv->can_stats.data_overrun,
			    priv->can_stats.wakeup,
			    priv->can_stats.bus_error,
			    priv->can_stats.error_passive,
			    priv->can_stats.arbitration_lost,
			    priv->can_stats.restarts,
			    priv->clk,
			    priv->speed
			    );
	}
    }

    MOD_DEC_USE_COUNT;

    *eof = 1;
    return len;
}


static int mscan_proc_read_regs(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int len = 0;
    struct net_device *dev;
    struct can_priv *priv;
    struct mpc5xxx_mscan *regs;
    int i;

    u8 canctl0;
    u8 canctl1;

    const u8 canctl0_synch  = 0x08;
    const u8 canctl1_cane   = 0x01;
    const u8 canctl1_clksr  = 0x02;
    const u8 canctl1_loopb  = 0x04;
    const u8 canctl1_listen = 0x08;
    const u8 canctl1_wump   = 0x20;
    const u8 canctl1_slpak  = 0x40;
    const u8 canctl1_initak = 0x80; 

    MOD_INC_USE_COUNT;

    for (i = 0; (i < MAX_CAN) && (len < PAGE_SIZE - 200); i++) {
	if (can_dev[i]) {
	    dev = can_dev[i];
	    priv = (struct can_priv*)can_dev[i]->priv;
	    regs = priv->regs;

	    len += sprintf(page + len, "\n"); 
	    len += sprintf(page + len, "----------- MSCAN MODULE %s --------------\n", dev->name); 
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canctl0 ) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canctl1 ) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canbtr0 ) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canbtr1 ) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canrflg ) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canrier ) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( cantflg ) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( cantier ) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( cantarq ) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( cantaak ) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( cantbsel) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canidac ) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canrxerr) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( cantxerr) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canidar0) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canidar1) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canidar2) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canidar3) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canidmr0) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canidmr1) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canidmr2) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canidmr3) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canidar4) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canidar5) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canidar6) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canidar7) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canidmr4) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canidmr5) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canidmr6) );
	    len += sprintf(page + len, DEV_PORT_REGS_U8( canidmr7) );
	    len += sprintf(page + len, "\n" );

	    canctl0 = regs->canctl0;
	    canctl1 = regs->canctl1;

	    len += sprintf(page + len, " Enable : %s\n", canctl1 & canctl1_cane ? "Enabled" : "Disabled");
	    len += sprintf(page + len, " Clock Source : %s\n", canctl1 & canctl1_clksr ? "SYS_XTAL_IN" : "IPB CLK");
	    len += sprintf(page + len, " Loopback Selftest : %s\n", canctl1 & canctl1_loopb ? "Active" : "Off");
	    len += sprintf(page + len, " Listen  : %s\n", canctl1 & canctl1_listen ? "Listen Only" : "Normal Operation");
	    len += sprintf(page + len, " Wakeup Mode: %s\n", canctl1 & canctl1_wump ? "1" : "0");
	    len += sprintf(page + len, " Sleep Mode Ack : %s\n", canctl1 & canctl1_slpak ? "Sleep mode" : "Running");
	    len += sprintf(page + len, " Initialisation Mode : %s\n", canctl1 & canctl1_initak ? "Active" : "Running");
	    len += sprintf(page + len, " Synchronized Status : %s\n", canctl0 & canctl0_synch ? "Not synchronized" : "Synchronized");

	    len += sprintf(page + len, " MSCAN Clock : %u (use clk=<value> as kernel module parameter)\n",priv->clk);
	    len += sprintf(page + len, "---------------------------------------------\n"); 
	}
    }

    MOD_DEC_USE_COUNT;

    *eof = 1;
    return len;
}


static int mscan_proc_read_gpio(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int len = 0;
    struct mpc5xxx_gpio *gpio = (struct mpc5xxx_gpio *) MPC5xxx_GPIO;

    MOD_INC_USE_COUNT;

    len += sprintf(page + len, "\n--------------- GPIO MODULE -----------------\n"); 
    len += sprintf(page + len, GPIO_REG_U32( port_config ) );
    len += sprintf(page + len, GPIO_REG_U32( simple_gpioe ) );
    len += sprintf(page + len, GPIO_REG_U32( simple_ode ) );
    len += sprintf(page + len, GPIO_REG_U32( simple_ddr ) );
    len += sprintf(page + len, GPIO_REG_U32( simple_dvo ) );
    len += sprintf(page + len, GPIO_REG_U32( simple_ival ) );
    len += sprintf(page + len, GPIO_REG_U8 ( outo_gpioe ) );
    len += sprintf(page + len, GPIO_REG_U8 ( outo_dvo ) );
    len += sprintf(page + len, GPIO_REG_U8 ( sint_gpioe ) );
    len += sprintf(page + len, GPIO_REG_U8 ( sint_ode ) );
    len += sprintf(page + len, GPIO_REG_U8 ( sint_ddr ) );
    len += sprintf(page + len, GPIO_REG_U8 ( sint_dvo ) );
    len += sprintf(page + len, GPIO_REG_U8 ( sint_inten ) );
    len += sprintf(page + len, GPIO_REG_U16( sint_itype ) );
    len += sprintf(page + len, GPIO_REG_U8 ( gpio_control ) );
    len += sprintf(page + len, GPIO_REG_U8 ( sint_istat ) );
    len += sprintf(page + len, GPIO_REG_U8 ( sint_ival ) );
    len += sprintf(page + len, GPIO_REG_U8 ( bus_errs ) );
    len += sprintf(page + len, "\n");

    if (gpio->port_config & 0x10000000)
	len += sprintf(page + len, " CAN1 on I2C1 Pins, CAN2 on TMR0/1 Pins\n");
    else
        if (((gpio->port_config & 0x00000030)>>4) == 1)
	    len += sprintf(page + len, " CAN1&2 on PSC2 Pins\n");
	else
	    len += sprintf(page + len, " CAN1&2 not routed to any IO Pin.\n");

    len += sprintf(page + len, "---------------------------------------------\n"); 

    MOD_DEC_USE_COUNT;

    *eof = 1;
    return len;
}

static int mscan_proc_read_cdm(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int len = 0;
    struct mpc5xxx_cdm *cdm = (struct mpc5xxx_cdm *) MPC5xxx_CDM;

    MOD_INC_USE_COUNT;

    len += sprintf(page + len, "\n--------------- CDM MODULE ------------------\n"); 
    len += sprintf(page + len, CDM_REG_U32 ( jtag_id ) );
    len += sprintf(page + len, CDM_REG_U32 ( rstcfg ) );
    len += sprintf(page + len, CDM_REG_U32 ( breadcrumb ) );

    len += sprintf(page + len, CDM_REG_U8  ( mem_clk_sel ) );
    len += sprintf(page + len, CDM_REG_U8  ( xlb_clk_sel ) );
    len += sprintf(page + len, CDM_REG_U8  ( ipg_clk_sel ) );
    len += sprintf(page + len, CDM_REG_U8  ( pci_clk_sel ) );

    len += sprintf(page + len, CDM_REG_U8  ( ext_48mhz_en ) );
    len += sprintf(page + len, CDM_REG_U8  ( fd_enable ) );
    len += sprintf(page + len, CDM_REG_U16 ( fd_counters ) );

    len += sprintf(page + len, CDM_REG_U32 ( clk_enables ) );

    len += sprintf(page + len, CDM_REG_U8  ( osc_disable ) );

    len += sprintf(page + len, CDM_REG_U8  ( ccs_sleep_enable ) );
    len += sprintf(page + len, CDM_REG_U8  ( osc_sleep_enable ) );
    len += sprintf(page + len, CDM_REG_U8  ( ccs_qreq_test ) );

    len += sprintf(page + len, CDM_REG_U8  ( soft_reset ) );
    len += sprintf(page + len, CDM_REG_U8  ( no_ckstp ) );

    len += sprintf(page + len, CDM_REG_U8  ( pll_lock ) );
    len += sprintf(page + len, CDM_REG_U8  ( pll_looselock ) );
    len += sprintf(page + len, CDM_REG_U8  ( pll_sm_lockwin ) );

    len += sprintf(page + len, CDM_REG_U16 ( mclken_div_psc1 ) );

    len += sprintf(page + len, CDM_REG_U16 ( mclken_div_psc2 ) );

    len += sprintf(page + len, CDM_REG_U16 ( mclken_div_psc3 ) );

    len += sprintf(page + len, CDM_REG_U32 ( mclken_div_psc6 ) );
    len += sprintf(page + len, "\n");

    len += sprintf(page + len,           " System Clock (@ XTAL 27.0   33.0 MHz)\n");
    switch (((cdm->rstcfg)>>6) & 0x3) { // sys_pll_cfg[0:1]
	case 0: len += sprintf(page + len, "                      432    528  MHz\n");break; 
	case 1: len += sprintf(page + len, "                      324    396  MHz\n"); break;
	case 2: len += sprintf(page + len, "                     (486    528  MHz, invalid)\n");break; 
	case 3: len += sprintf(page + len, "                      324    396  MHz\n");break; 
    }

    len += sprintf(page + len, " XLB Clock  = %s System Clock \n", cdm->xlb_clk_sel ? "1/4" : "1/8");
    len += sprintf(page + len, " IPB Clock  = 1/%i System Clock \n", 0x4<<(((cdm->xlb_clk_sel?1:0) + (cdm->ipg_clk_sel?1:0))));
    len += sprintf(page + len, " PCI Clock  = 1/%i System Clock \n", 0x8<<(((cdm->xlb_clk_sel?1:0) + (cdm->pci_clk_sel?1:0))));
  
    len += sprintf(page + len, "---------------------------------------------\n"); 

    MOD_DEC_USE_COUNT;

    *eof = 1;
    return len;
}

/**************************************************/
/* procfs init / remove                           */
/**************************************************/

void mscan_init_proc(void)
{
    /* procfs init */

    pde      = create_proc_read_entry(PROCBASE"/"PROCFILE, 0444, NULL, mscan_proc_read, NULL);
    pde_regs = create_proc_read_entry(PROCBASE"/"PROCREGSFILE, 0444, NULL, mscan_proc_read_regs, NULL);
    pde_gpio = create_proc_read_entry(PROCBASE"/"PROCGPIOFILE, 0444, NULL, mscan_proc_read_gpio, NULL);
    pde_cdm  = create_proc_read_entry(PROCBASE"/"PROCCDMFILE, 0444, NULL, mscan_proc_read_cdm, NULL);

}

void mscan_remove_proc(void)
{
    /* procfs remove */

    if (pde) {
	remove_proc_entry(PROCBASE"/"PROCFILE, NULL);
    }

    if (pde_regs) {
	remove_proc_entry(PROCBASE"/"PROCREGSFILE, NULL);
    }

    if (pde_gpio) {
	remove_proc_entry(PROCBASE"/"PROCGPIOFILE, NULL);
    }

    if (pde_cdm) {
	remove_proc_entry(PROCBASE"/"PROCCDMFILE, NULL);
    }
}
