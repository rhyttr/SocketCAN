/*
 * $Id: proc.c,v 2.0 2006/04/13 10:37:21 ethuerm Exp $
 *
 * proc.c -  proc file system functions for SJA1000 CAN driver.
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

#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/netdevice.h>

#include "can.h"
#include "can_ioctl.h"
#include "sja1000.h"

static struct proc_dir_entry *pde       = NULL;
static struct proc_dir_entry *pde_regs  = NULL;
static struct proc_dir_entry *pde_reset = NULL;

static struct net_device **can_dev;
static int max_devices;

static int sja1000_proc_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	int len = 0;
	struct net_device *dev;
	int i;
	struct can_priv *priv;
	unsigned char stat;

	len += snprintf(page + len, PAGE_SIZE - len, "CAN bus device statistics:\n");
	len += snprintf(page + len, PAGE_SIZE - len, "       errwarn  overrun   wakeup   buserr   errpass  arbitr   restarts clock        baud\n");
	for (i = 0; (i < max_devices) && (len < PAGE_SIZE - 200); i++) {
		if (can_dev[i]) {
			dev = can_dev[i];
			stat = REG_READ(REG_SR);
			priv = netdev_priv(can_dev[i]);
			len += snprintf(page + len, PAGE_SIZE - len, "can%d: %8d %8d %8d %8d %8d %8d %8d %10d %8d\n", i,
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
			if (stat & 0x80) {
				len += snprintf(page + len, PAGE_SIZE - len, "can%d: bus status: BUS OFF, ", i);
			} else if (stat & 0x40) {
				len += snprintf(page + len, PAGE_SIZE - len, "can%d: bus status: ERROR PASSIVE, ", i);
			} else {
				len += snprintf(page + len, PAGE_SIZE - len, "can%d: bus status: OK, ", i);
			}
			len += snprintf(page + len, PAGE_SIZE - len, "RXERR: %d, TXERR: %d\n", REG_READ(REG_RXERR), REG_READ(REG_TXERR));
		}
	}

	*eof = 1;
	return len;
}

static int sja1000_proc_read_regs(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	int len = 0;
	struct net_device *dev;
	int i;
	struct can_priv	  *priv;

	len = sprintf(page, "SJA1000 registers:\n");
	for (i = 0; (i < max_devices) && (len < PAGE_SIZE - 200); i++) {
		if (can_dev[i]) {
			dev = can_dev[i];
			len += snprintf(page + len, PAGE_SIZE - len, "can%d SJA1000 registers:\n", i);

			priv = netdev_priv(can_dev[i]);
			len += snprintf(page + len, PAGE_SIZE - len, "00: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
				       REG_READ(0x00),
				       REG_READ(0x01),
				       REG_READ(0x02),
				       REG_READ(0x03),
				       REG_READ(0x04),
				       REG_READ(0x05),
				       REG_READ(0x06),
				       REG_READ(0x07),
				       REG_READ(0x08),
				       REG_READ(0x09),
				       REG_READ(0x0a),
				       REG_READ(0x0b),
				       REG_READ(0x0c),
				       REG_READ(0x0d),
				       REG_READ(0x0e),
				       REG_READ(0x0f)
				       );
			len += snprintf(page + len, PAGE_SIZE - len, "10: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
				       REG_READ(0x10),
				       REG_READ(0x11),
				       REG_READ(0x12),
				       REG_READ(0x13),
				       REG_READ(0x14),
				       REG_READ(0x15),
				       REG_READ(0x16),
				       REG_READ(0x17),
				       REG_READ(0x18),
				       REG_READ(0x19),
				       REG_READ(0x1a),
				       REG_READ(0x1b),
				       REG_READ(0x1c),
				       REG_READ(0x1d),
				       REG_READ(0x1e),
				       REG_READ(0x1f)
				       );
		}
	}

	*eof = 1;
	return len;
}

static int sja1000_proc_read_reset(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	int len = 0;
	struct net_device *dev;
	int i;
	struct can_priv   *priv;

	len += snprintf(page + len, PAGE_SIZE - len, "resetting ");
	for (i = 0; (i < max_devices) && (len < PAGE_SIZE - 200); i++) {
		if (can_dev[i]) {
			dev = can_dev[i];
			priv = netdev_priv(can_dev[i]);
			if ((priv->state != STATE_UNINITIALIZED) && (priv->state != STATE_RESET_MODE)) {
				len += snprintf(page + len, PAGE_SIZE - len, "%s ", dev->name);
                                dev->stop(dev);
                                dev->open(dev);
				/* count number of restarts */
				priv->can_stats.restarts++;

			} else {
			  len += snprintf(page + len, PAGE_SIZE - len, "(%s|%d) ", dev->name, priv->state);
			}
		}
	}

	len += snprintf(page + len, PAGE_SIZE - len, "done\n");

	*eof = 1;
	return len;
}

void sja1000_proc_init(const char *drv_name, struct net_device **dev, int max)
{
	char fname[256];

	can_dev     = dev;
	max_devices = max;

	if (pde == NULL) {
		sprintf(fname, PROCBASE "/%s", drv_name);
		pde = create_proc_read_entry(fname, 0644, NULL,
					     sja1000_proc_read, NULL);
	}
	if (pde_regs == NULL) {
		sprintf(fname, PROCBASE "/%s_regs", drv_name);
		pde_regs = create_proc_read_entry(fname, 0644, NULL,
					     sja1000_proc_read_regs, NULL);
	}
	if (pde_reset == NULL) {
		sprintf(fname, PROCBASE "/%s_reset", drv_name);
		pde_reset = create_proc_read_entry(fname, 0644, NULL,
					     sja1000_proc_read_reset, NULL);
	}
}

void sja1000_proc_delete(const char *drv_name)
{
	char fname[256];

	if (pde) {
		sprintf(fname, PROCBASE "/%s", drv_name);
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
