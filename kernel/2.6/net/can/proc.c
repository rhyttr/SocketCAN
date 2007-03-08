/*
 * proc.c - procfs support for Protocol family CAN core module
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

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/rcupdate.h>

#include <linux/can/core.h>
#include <linux/can/version.h>

#include "af_can.h"

RCSID("$Id$");

/* proc filenames */

#define CAN_PROC_VERSION     "version"
#define CAN_PROC_STATS       "stats"
#define CAN_PROC_RESET_STATS "reset_stats"
#define CAN_PROC_RCVLIST_ALL "rcvlist_all"
#define CAN_PROC_RCVLIST_FIL "rcvlist_fil"
#define CAN_PROC_RCVLIST_INV "rcvlist_inv"
#define CAN_PROC_RCVLIST_SFF "rcvlist_sff"
#define CAN_PROC_RCVLIST_EFF "rcvlist_eff"
#define CAN_PROC_RCVLIST_ERR "rcvlist_err"

static void can_init_stats(int caller);
static void can_stat_update(unsigned long data);

static struct proc_dir_entry *can_create_proc_readentry(const char *name,
	mode_t mode, read_proc_t* read_proc, void *data);
static void can_remove_proc_readentry(const char *name);
static unsigned long calc_rate(unsigned long oldjif, unsigned long newjif,
			       unsigned long count);

static int can_proc_read_version(char *page, char **start, off_t off,
				     int count, int *eof, void *data);
static int can_proc_read_stats(char *page, char **start, off_t off,
				     int count, int *eof, void *data);
static int can_proc_read_reset_stats(char *page, char **start, off_t off,
				     int count, int *eof, void *data);
static int can_proc_read_rcvlist_all(char *page, char **start, off_t off,
				     int count, int *eof, void *data);
static int can_proc_read_rcvlist_fil(char *page, char **start, off_t off,
				     int count, int *eof, void *data);
static int can_proc_read_rcvlist_inv(char *page, char **start, off_t off,
				     int count, int *eof, void *data);
static int can_proc_read_rcvlist_sff(char *page, char **start, off_t off,
				     int count, int *eof, void *data);
static int can_proc_read_rcvlist_eff(char *page, char **start, off_t off,
				     int count, int *eof, void *data);
static int can_proc_read_rcvlist_err(char *page, char **start, off_t off,
				     int count, int *eof, void *data);

static struct proc_dir_entry *can_dir         = NULL;
static struct proc_dir_entry *pde_version     = NULL;
static struct proc_dir_entry *pde_stats       = NULL;
static struct proc_dir_entry *pde_reset_stats = NULL;
static struct proc_dir_entry *pde_rcvlist_all = NULL;
static struct proc_dir_entry *pde_rcvlist_fil = NULL;
static struct proc_dir_entry *pde_rcvlist_inv = NULL;
static struct proc_dir_entry *pde_rcvlist_sff = NULL;
static struct proc_dir_entry *pde_rcvlist_eff = NULL;
static struct proc_dir_entry *pde_rcvlist_err = NULL;

struct timer_list stattimer; /* timer for statistics update */

struct s_stats  stats; /* statistics */
struct s_pstats pstats;

extern struct hlist_head rx_dev_list;    /* rx dispatcher structures */
extern int stats_timer;                  /* module parameter. default: on */

/**************************************************/
/* procfs init / remove                           */
/**************************************************/

void can_init_proc(void)
{

	/* procfs init */

	/* create /proc/can directory */
	can_dir = proc_mkdir(CAN_PROC_DIR, NULL);

	if (!can_dir) {
		printk(KERN_INFO "CAN: failed to create CAN_PROC_DIR. "
		       "CONFIG_PROC_FS missing?\n");
		return;
	}

	can_dir->owner = THIS_MODULE;

	/* own procfs entries from the AF_CAN core */
	pde_version     = can_create_proc_readentry(
		CAN_PROC_VERSION, 0644, can_proc_read_version, NULL);
	pde_stats       = can_create_proc_readentry(
		CAN_PROC_STATS, 0644, can_proc_read_stats, NULL);
	pde_reset_stats = can_create_proc_readentry(
		CAN_PROC_RESET_STATS, 0644, can_proc_read_reset_stats, NULL);
	pde_rcvlist_all = can_create_proc_readentry(
		CAN_PROC_RCVLIST_ALL, 0644, can_proc_read_rcvlist_all, NULL);
	pde_rcvlist_fil = can_create_proc_readentry(
		CAN_PROC_RCVLIST_FIL, 0644, can_proc_read_rcvlist_fil, NULL);
	pde_rcvlist_inv = can_create_proc_readentry(
		CAN_PROC_RCVLIST_INV, 0644, can_proc_read_rcvlist_inv, NULL);
	pde_rcvlist_sff = can_create_proc_readentry(
		CAN_PROC_RCVLIST_SFF, 0644, can_proc_read_rcvlist_sff, NULL);
	pde_rcvlist_eff = can_create_proc_readentry(
		CAN_PROC_RCVLIST_EFF, 0644, can_proc_read_rcvlist_eff, NULL);
	pde_rcvlist_err = can_create_proc_readentry(
		CAN_PROC_RCVLIST_ERR, 0644, can_proc_read_rcvlist_err, NULL);

	if (stats_timer) {
		/* the statistics are updated every second (timer triggered) */
		stattimer.function = can_stat_update;
		stattimer.data = 0;
		stattimer.expires = jiffies + HZ; /* every second */
		add_timer(&stattimer); /* start statistics timer */
	}
}

void can_remove_proc(void)
{
	/* procfs remove */
	if (pde_version)
		can_remove_proc_readentry(CAN_PROC_VERSION);

	if (pde_stats)
		can_remove_proc_readentry(CAN_PROC_STATS);

	if (pde_reset_stats)
		can_remove_proc_readentry(CAN_PROC_RESET_STATS);

	if (pde_rcvlist_all)
		can_remove_proc_readentry(CAN_PROC_RCVLIST_ALL);

	if (pde_rcvlist_fil)
		can_remove_proc_readentry(CAN_PROC_RCVLIST_FIL);

	if (pde_rcvlist_inv)
		can_remove_proc_readentry(CAN_PROC_RCVLIST_INV);

	if (pde_rcvlist_sff)
		can_remove_proc_readentry(CAN_PROC_RCVLIST_SFF);

	if (pde_rcvlist_eff)
		can_remove_proc_readentry(CAN_PROC_RCVLIST_EFF);

	if (pde_rcvlist_err)
		can_remove_proc_readentry(CAN_PROC_RCVLIST_ERR);

	if (can_dir)
		remove_proc_entry(CAN_PROC_DIR, NULL);
}

/**************************************************/
/* proc read functions                            */
/**************************************************/

static int can_print_rcvlist(char *page, int len, struct hlist_head *rx_list,
			     struct net_device *dev)
{
	struct receiver *r;
	struct hlist_node *n;

	rcu_read_lock();
	hlist_for_each_entry_rcu(r, n, rx_list, list) {
		char *fmt = r->can_id & CAN_EFF_FLAG ? /* EFF & CAN_ID_ALL */
			"   %-5s  %08X  %08x  %08x  %08x  %8ld  %s\n" :
			"   %-5s     %03X    %08x  %08x  %08x  %8ld  %s\n";

		len += snprintf(page + len, PAGE_SIZE - len, fmt,
				DNAME(dev), r->can_id, r->mask,
				(unsigned int)r->func, (unsigned int)r->data,
				r->matches, r->ident);

		/* does a typical line fit into the current buffer? */
		/* 100 Bytes before end of buffer */
		if (len > PAGE_SIZE - 100) {
			/* mark output cut off */
			len += snprintf(page + len, PAGE_SIZE - len,
					"   (..)\n");
			break;
		}
	}
	rcu_read_unlock();

	return len;
}

static int can_print_recv_banner(char *page, int len)
{
	/*                  can1.  00000000  00000000  00000000
			   .......          0  tp20 */
	len += snprintf(page + len, PAGE_SIZE - len,
			"  device   can_id   can_mask  function"
			"  userdata   matches  ident\n");

	return len;
}

static int can_proc_read_stats(char *page, char **start, off_t off,
			       int count, int *eof, void *data)
{
	int len = 0;

	len += snprintf(page + len, PAGE_SIZE - len, "\n");
	len += snprintf(page + len, PAGE_SIZE - len,
			" %8ld transmitted frames (TXF)\n", stats.tx_frames);
	len += snprintf(page + len, PAGE_SIZE - len,
			" %8ld received frames (RXF)\n", stats.rx_frames);
	len += snprintf(page + len, PAGE_SIZE - len,
			" %8ld matched frames (RXMF)\n", stats.matches);

	len += snprintf(page + len, PAGE_SIZE - len, "\n");

	len += snprintf(page + len, PAGE_SIZE - len,
			" %8ld %% total match ratio (RXMR)\n",
			stats.total_rx_match_ratio);

	len += snprintf(page + len, PAGE_SIZE - len,
			" %8ld frames/s total tx rate (TXR)\n",
			stats.total_tx_rate);
	len += snprintf(page + len, PAGE_SIZE - len,
			" %8ld frames/s total rx rate (RXR)\n",
			stats.total_rx_rate);

	len += snprintf(page + len, PAGE_SIZE - len, "\n");

	len += snprintf(page + len, PAGE_SIZE - len,
			" %8ld %% current match ratio (CRXMR)\n",
			stats.current_rx_match_ratio);

	len += snprintf(page + len, PAGE_SIZE - len,
			" %8ld frames/s current tx rate (CTXR)\n",
			stats.current_tx_rate);
	len += snprintf(page + len, PAGE_SIZE - len,
			" %8ld frames/s current rx rate (CRXR)\n",
			stats.current_rx_rate);

	len += snprintf(page + len, PAGE_SIZE - len, "\n");

	len += snprintf(page + len, PAGE_SIZE - len,
			" %8ld %% max match ratio (MRXMR)\n",
			stats.max_rx_match_ratio);

	len += snprintf(page + len, PAGE_SIZE - len,
			" %8ld frames/s max tx rate (MTXR)\n",
			stats.max_tx_rate);
	len += snprintf(page + len, PAGE_SIZE - len,
			" %8ld frames/s max rx rate (MRXR)\n",
			stats.max_rx_rate);

	len += snprintf(page + len, PAGE_SIZE - len, "\n");

	len += snprintf(page + len, PAGE_SIZE - len,
			" %8ld current receive list entries (CRCV)\n",
			pstats.rcv_entries);
	len += snprintf(page + len, PAGE_SIZE - len,
			" %8ld maximum receive list entries (MRCV)\n",
			pstats.rcv_entries_max);

	if (pstats.stats_reset)
		len += snprintf(page + len, PAGE_SIZE - len,
				"\n %8ld statistic resets (STR)\n",
				pstats.stats_reset);

	len += snprintf(page + len, PAGE_SIZE - len, "\n");

	*eof = 1;
	return len;
}

static int can_proc_read_reset_stats(char *page, char **start, off_t off,
				     int count, int *eof, void *data)
{
	int len = 0;

	can_init_stats(1);

	len += snprintf(page + len, PAGE_SIZE - len,
			"CAN statistic reset #%ld done.\n",
			pstats.stats_reset);

	*eof = 1;
	return len;
}

static int can_proc_read_version(char *page, char **start, off_t off,
				 int count, int *eof, void *data)
{
	int len = 0;

	len += snprintf(page + len, PAGE_SIZE - len,
			"%06X [ Volkswagen Group - Low Level CAN Framework"
			" (LLCF) v%s ]\n", LLCF_VERSION_CODE, VERSION);
	*eof = 1;
	return len;
}

static int can_proc_read_rcvlist_all(char *page, char **start, off_t off,
				     int count, int *eof, void *data)
{
	int len = 0;
	struct dev_rcv_lists *d;
	struct hlist_node *n;

	/* RX_ALL */
	len += snprintf(page + len, PAGE_SIZE - len,
			"\nreceive list 'rx_all':\n");

	/* find receive list for this device */
	rcu_read_lock();
	hlist_for_each_entry_rcu(d, n, &rx_dev_list, list) {

		if (!hlist_empty(&d->rx_all)) {
			len = can_print_recv_banner(page, len);
			len = can_print_rcvlist(page, len, &d->rx_all, d->dev);
		} else
			len += snprintf(page + len, PAGE_SIZE - len,
					"  (%s: no entry)\n", DNAME(d->dev));

		if (len > PAGE_SIZE - 100)
			break; /* exit on end of buffer */
	}
	rcu_read_unlock();

	len += snprintf(page + len, PAGE_SIZE - len, "\n");

	*eof = 1;
	return len;
}

static int can_proc_read_rcvlist_fil(char *page, char **start, off_t off,
				     int count, int *eof, void *data)
{
	int len = 0;
	struct dev_rcv_lists *d;
	struct hlist_node *n;

	/* RX_FIL */
	len += snprintf(page + len, PAGE_SIZE - len,
			"\nreceive list 'rx_fil':\n");

	/* find receive list for this device */
	rcu_read_lock();
	hlist_for_each_entry_rcu(d, n, &rx_dev_list, list) {

		if (!hlist_empty(&d->rx_fil)) {
			len = can_print_recv_banner(page, len);
			len = can_print_rcvlist(page, len, &d->rx_fil, d->dev);
		} else
			len += snprintf(page + len, PAGE_SIZE - len,
					"  (%s: no entry)\n", DNAME(d->dev));

		if (len > PAGE_SIZE - 100)
			break; /* exit on end of buffer */
	}
	rcu_read_unlock();

	len += snprintf(page + len, PAGE_SIZE - len, "\n");

	*eof = 1;
	return len;
}

static int can_proc_read_rcvlist_inv(char *page, char **start, off_t off,
				     int count, int *eof, void *data)
{
	int len = 0;
	struct dev_rcv_lists *d;
	struct hlist_node *n;

	/* RX_INV */
	len += snprintf(page + len, PAGE_SIZE - len,
			"\nreceive list 'rx_inv':\n");

	/* find receive list for this device */
	rcu_read_lock();
	hlist_for_each_entry_rcu(d, n, &rx_dev_list, list) {

		if (!hlist_empty(&d->rx_inv)) {
			len = can_print_recv_banner(page, len);
			len = can_print_rcvlist(page, len, &d->rx_inv, d->dev);
		} else
			len += snprintf(page + len, PAGE_SIZE - len,
					"  (%s: no entry)\n", DNAME(d->dev));

		if (len > PAGE_SIZE - 100)
			break; /* exit on end of buffer */
	}
	rcu_read_unlock();

	len += snprintf(page + len, PAGE_SIZE - len, "\n");

	*eof = 1;
	return len;
}

static int can_proc_read_rcvlist_sff(char *page, char **start, off_t off,
				     int count, int *eof, void *data)
{
	int len = 0;
	struct dev_rcv_lists *d;
	struct hlist_node *n;

	/* RX_SFF */
	len += snprintf(page + len, PAGE_SIZE - len,
			"\nreceive list 'rx_sff':\n");

	/* find receive list for this device */
	rcu_read_lock();
	hlist_for_each_entry_rcu(d, n, &rx_dev_list, list) {
		int i, all_empty = 1;
		/* check wether at least one list is non-empty */
		for (i = 0; i < 0x800; i++)
			if (!hlist_empty(&d->rx_sff[i])) {
				all_empty = 0;
				break;
			}

		if (!all_empty) {
			len = can_print_recv_banner(page, len);
			for (i = 0; i < 0x800; i++) {
				if (!hlist_empty(&d->rx_sff[i]) &&
				    len < PAGE_SIZE - 100)
					len = can_print_rcvlist(page, len,
								&d->rx_sff[i],
								d->dev);
			}
		} else
			len += snprintf(page + len, PAGE_SIZE - len,
					"  (%s: no entry)\n", DNAME(d->dev));

		if (len > PAGE_SIZE - 100)
			break; /* exit on end of buffer */
	}
	rcu_read_unlock();

	len += snprintf(page + len, PAGE_SIZE - len, "\n");

	*eof = 1;
	return len;
}

static int can_proc_read_rcvlist_eff(char *page, char **start, off_t off,
				     int count, int *eof, void *data)
{
	int len = 0;
	struct dev_rcv_lists *d;
	struct hlist_node *n;

	/* RX_EFF */
	len += snprintf(page + len, PAGE_SIZE - len,
			"\nreceive list 'rx_eff':\n");

	/* find receive list for this device */
	rcu_read_lock();
	hlist_for_each_entry_rcu(d, n, &rx_dev_list, list) {

		if (!hlist_empty(&d->rx_eff)) {
			len = can_print_recv_banner(page, len);
			len = can_print_rcvlist(page, len, &d->rx_eff, d->dev);
		} else
			len += snprintf(page + len, PAGE_SIZE - len,
					"  (%s: no entry)\n", DNAME(d->dev));

		if (len > PAGE_SIZE - 100)
			break; /* exit on end of buffer */
	}
	rcu_read_unlock();

	len += snprintf(page + len, PAGE_SIZE - len, "\n");

	*eof = 1;
	return len;
}

static int can_proc_read_rcvlist_err(char *page, char **start, off_t off,
				     int count, int *eof, void *data)
{
	int len = 0;
	struct dev_rcv_lists *d;
	struct hlist_node *n;

	/* RX_ERR */
	len += snprintf(page + len, PAGE_SIZE - len,
			"\nreceive list 'rx_err':\n");

	/* find receive list for this device */
	rcu_read_lock();
	hlist_for_each_entry_rcu(d, n, &rx_dev_list, list) {

		if (!hlist_empty(&d->rx_err)) {
			len = can_print_recv_banner(page, len);
			len = can_print_rcvlist(page, len, &d->rx_err, d->dev);
		} else
			len += snprintf(page + len, PAGE_SIZE - len,
					"  (%s: no entry)\n", DNAME(d->dev));

		if (len > PAGE_SIZE - 100)
			break; /* exit on end of buffer */
	}
	rcu_read_unlock();

	len += snprintf(page + len, PAGE_SIZE - len, "\n");

	*eof = 1;
	return len;
}

/**************************************************/
/* proc utility functions                         */
/**************************************************/

static struct proc_dir_entry *can_create_proc_readentry(const char *name,
							mode_t mode,
							read_proc_t* read_proc,
							void *data)
{
	if (can_dir)
		return create_proc_read_entry(name, mode, can_dir, read_proc,
					      data);
	else
		return NULL;
}

static void can_remove_proc_readentry(const char *name)
{
	if (can_dir)
		remove_proc_entry(name, can_dir);
}

static unsigned long calc_rate(unsigned long oldjif, unsigned long newjif,
			       unsigned long count)
{
	unsigned long ret = 0;

	if (oldjif == newjif)
		return 0;

	/* see can_rcv() - this should NEVER happen! */
	if (count > (ULONG_MAX / HZ)) {
		printk(KERN_ERR "CAN: calc_rate: count exceeded! %ld\n",
		       count);
		return 99999999;
	}

	ret = (count * HZ) / (newjif - oldjif);

	return ret;
}

/**************************************************/
/* af_can statistics stuff                        */
/**************************************************/

static void can_init_stats(int caller)
{
	memset(&stats, 0, sizeof(stats));
	stats.jiffies_init  = jiffies;
	pstats.stats_reset++;
}

static void can_stat_update(unsigned long data)
{
	unsigned long j = jiffies; /* snapshot */

	//DBG("CAN: can_stat_update() jiffies = %ld\n", j);

	if (j < stats.jiffies_init) /* jiffies overflow */
		can_init_stats(2);

	/* stats.rx_frames is the definitively max. statistic value */

	/* prevent overflow in calc_rate() */
	if (stats.rx_frames > (ULONG_MAX / HZ))
		can_init_stats(3); /* restart */

	/* matches overflow - very improbable */
	if (stats.matches > (ULONG_MAX / 100))
		can_init_stats(4);

	/* calc total values */
	if (stats.rx_frames)
		stats.total_rx_match_ratio = (stats.matches * 100) / 
						stats.rx_frames;

	stats.total_tx_rate = calc_rate(stats.jiffies_init, j,
					stats.tx_frames);
	stats.total_rx_rate = calc_rate(stats.jiffies_init, j,
					stats.rx_frames);

	/* calc current values */
	if (stats.rx_frames_delta)
		stats.current_rx_match_ratio =
			(stats.matches_delta * 100) / stats.rx_frames_delta;

	stats.current_tx_rate = calc_rate(0, HZ, stats.tx_frames_delta);
	stats.current_rx_rate = calc_rate(0, HZ, stats.rx_frames_delta);

	/* check / update maximum values */
	if (stats.max_tx_rate < stats.current_tx_rate)
		stats.max_tx_rate = stats.current_tx_rate;

	if (stats.max_rx_rate < stats.current_rx_rate)
		stats.max_rx_rate = stats.current_rx_rate;

	if (stats.max_rx_match_ratio < stats.current_rx_match_ratio)
		stats.max_rx_match_ratio = stats.current_rx_match_ratio;

	/* clear values for 'current rate' calculation */
	stats.tx_frames_delta = 0;
	stats.rx_frames_delta = 0;
	stats.matches_delta   = 0;

	/* restart timer */
	stattimer.expires = jiffies + HZ; /* every second */
	add_timer(&stattimer);
}
