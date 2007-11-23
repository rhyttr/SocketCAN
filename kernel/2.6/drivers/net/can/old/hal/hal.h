/*
 * hal.h - definitions for CAN controller hardware abstraction layer
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
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Volkswagen nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
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

#ifndef CAN_HAL_H
#define CAN_HAL_H

#include <linux/types.h>
#include <linux/netdevice.h>

/* Number of supported CAN devices for each HAL (default) */
#define MAXDEV 8

/* general function prototypes for CAN HAL */

/* init the HAL - call at driver module init */
int hal_init(void);

/* exit the HAL - call at driver module exit */
int hal_exit(void);

/* get name of this CAN HAL */
char *hal_name(void);

/* fill arrays base[] and irq[] with HAL specific defaults */
void hal_use_defaults(void);

/* request controller register access space */
int hal_request_region(int dev_num,
		       unsigned int num_regs,
		       char *drv_name);

/* release controller register access space */
void hal_release_region(int dev_num,
			unsigned int num_regs);

/* enable non controller hardware (e.g. irq routing, etc.) */
int hw_attach(int dev_num);

/* disable non controller hardware (e.g. irq routing, etc.) */
int hw_detach(int dev_num);

/* reset controller hardware (with specific non controller hardware) */
int hw_reset_dev(int dev_num);

/* read from controller register */
u8 hw_readreg(unsigned long base, int reg);

/* write to controller register */
void hw_writereg(unsigned long base, int reg, u8 val);

/* hardware specific work to do at start of irq handler */
void hw_preirq(struct net_device *dev);

/* hardware specific work to do at end of irq handler */
void hw_postirq(struct net_device *dev);

#endif /* CAN_HAL_H */
