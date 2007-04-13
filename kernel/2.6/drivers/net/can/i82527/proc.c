/*
 * $Id$
 *
 * proc.c -  proc file system functions for I82527 CAN driver.
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

#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/netdevice.h>

#include <linux/can.h>
#include <linux/can/ioctl.h>
#include "i82527.h"
#include "hal.h"

extern struct net_device *can_dev[];

static struct proc_dir_entry *pde       = NULL;
static struct proc_dir_entry *pde_regs  = NULL;
static struct proc_dir_entry *pde_reset = NULL;

static int can_proc_read_stats(char *page, char **start, off_t off,
			       int count, int *eof, void *data)
{
	int len = 0;
	int i;

	len += snprintf(page + len, PAGE_SIZE - len,
			"CAN bus device statistics:\n");
	len += snprintf(page + len, PAGE_SIZE - len,
			"       errwarn  overrun   wakeup   buserr   "
			"errpass  arbitr   restarts clock        baud\n");
	for (i = 0; (i < MAXDEV) && (len < PAGE_SIZE - 200); i++) {
		if (can_dev[i]) {
			struct net_device *dev = can_dev[i];
			struct can_priv *priv  = netdev_priv(dev);
			len += snprintf(page + len, PAGE_SIZE - len,
					"%s: %8d %8d %8d %8d %8d "
					"%8d %8d %10d %8d\n", dev->name,
					priv->can_stats.error_warning,
					priv->can_stats.data_overrun,
					priv->can_stats.wakeup,
					priv->can_stats.bus_error,
					priv->can_stats.error_passive,
					priv->can_stats.arbitration_lost,
					priv->can_stats.restarts,
					priv->clock,
					priv->speed
				);

		}
	}

	*eof = 1;
	return len;
}


static int can_proc_dump_regs(char *page, int len, struct net_device *dev)
{
	int r,s;
	struct can_priv	*priv = netdev_priv(dev);
	int regs = priv->hw_regs;

	len += snprintf(page + len, PAGE_SIZE - len,
			"%s registers:\n", dev->name);

	for (r = 0; r < regs; r += 0x10) {
		len += snprintf(page + len, PAGE_SIZE - len, "%02X: ", r);
		for (s = 0; s < 0x10; s++) {
			if (r+s < regs)
				len += snprintf(page + len, PAGE_SIZE-len,
						"%02X ",
						hw_readreg(dev->base_addr,
							   r+s));
		}
		len += snprintf(page + len, PAGE_SIZE - len, "\n");
	}

        return len;
}

static int can_proc_read_regs(char *page, char **start, off_t off,
				  int count, int *eof, void *data)
{
	int len = 0;
	int i;

	for (i = 0; (i < MAXDEV) && (len < PAGE_SIZE - 200); i++) {
		if (can_dev[i])
			len = can_proc_dump_regs(page, len, can_dev[i]);
	}

	*eof = 1;
	return len;
}

static int can_proc_read_reset(char *page, char **start, off_t off,
				   int count, int *eof, void *data)
{
	int len = 0;
	struct net_device *dev;
	int i;
	struct can_priv   *priv;

	len += snprintf(page + len, PAGE_SIZE - len, "resetting ");
	for (i = 0; (i < MAXDEV) && (len < PAGE_SIZE - 200); i++) {
		if (can_dev[i]) {
			dev = can_dev[i];
			priv = netdev_priv(can_dev[i]);
			if ((priv->state != STATE_UNINITIALIZED)
			    && (priv->state != STATE_RESET_MODE)) {
				len += snprintf(page + len, PAGE_SIZE - len,
						"%s ", dev->name);
				dev->stop(dev);
				dev->open(dev);
				/* count number of restarts */
				priv->can_stats.restarts++;

			} else {
				len += snprintf(page + len, PAGE_SIZE - len,
						"(%s|%d) ", dev->name,
						priv->state);
			}
		}
	}

	len += snprintf(page + len, PAGE_SIZE - len, "done\n");

	*eof = 1;
	return len;
}

void can_proc_create(const char *drv_name)
{
	char fname[256];

	if (pde == NULL) {
		sprintf(fname, PROCBASE "/%s_stats", drv_name);
		pde = create_proc_read_entry(fname, 0644, NULL,
					     can_proc_read_stats, NULL);
	}
	if (pde_regs == NULL) {
		sprintf(fname, PROCBASE "/%s_regs", drv_name);
		pde_regs = create_proc_read_entry(fname, 0644, NULL,
						  can_proc_read_regs, NULL);
	}
	if (pde_reset == NULL) {
		sprintf(fname, PROCBASE "/%s_reset", drv_name);
		pde_reset = create_proc_read_entry(fname, 0644, NULL,
						   can_proc_read_reset, NULL);
	}
}

void can_proc_remove(const char *drv_name)
{
	char fname[256];

	if (pde) {
		sprintf(fname, PROCBASE "/%s_stats", drv_name);
		remove_proc_entry(fname, NULL);
	}
	if (pde_regs) {
		sprintf(fname, PROCBASE "/%s_regs", drv_name);
		remove_proc_entry(fname, NULL);
	}
	if (pde_reset) {
		sprintf(fname, PROCBASE "/%s_reset", drv_name);
		remove_proc_entry(fname, NULL);
	}
}
