/*
 * $Id: mscan.h,v 1.1 2006/03/09 13:17:16 hartko Exp $
 *
 * mscan.h - Motorola MPC52xx MSCAN network device driver
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

#ifndef __MSCAN_H__
#define __MSCAN_H__

#define DRV_NAME      "mscan"
#define CAN_DEV_NAME  "can%d"
#define MAX_CAN	      2

#define DEFAULT_KBIT_PER_SEC 500
#define MSCAN_DEFAULT_CLOCK  132000000
#define TX_TIMEOUT           (HZ/20) /* 50ms */ 

/* private data structure */

struct can_priv {
    struct net_device_stats stats;
    struct can_device_stats can_stats;
    struct mpc5xxx_mscan *regs;
    int	clk;
    int	debug;
    int	speed;
    int	btr;
    int	state;
};

#define STATE_UNINITIALIZED	0
#define STATE_PROBE		1
#define STATE_ACTIVE		2
#define STATE_ERROR_ACTIVE	3
#define STATE_ERROR_PASSIVE	4
#define STATE_BUS_OFF		5
#define STATE_RESET_MODE	6

struct net_device* mscan_register(struct mpc5xxx_mscan *regs, int irq, int speed, int btr, int clk, int debug);
void mscan_init_proc(void);
void mscan_remove_proc(void);

#endif /* __MSCAN_H__ */
