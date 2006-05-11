/*
 * af_can_proc.c
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
#include <linux/proc_fs.h>

#include <linux/can/af_can.h>

#include "version.h"

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

static void can_init_stats(int caller);
static void can_stat_update(unsigned long data);

static struct proc_dir_entry *can_create_proc_read_entry(const char *name, mode_t mode, read_proc_t* read_proc, void *data);
static void can_remove_proc_entry(const char *name);
static unsigned long calc_rate(unsigned long oldjif, unsigned long newjif, unsigned long count);

static int can_proc_read_version(char *page, char **start, off_t off, int count, int *eof, void *data);
static int can_proc_read_stats(char *page, char **start, off_t off, int count, int *eof, void *data);
static int can_proc_read_reset_stats(char *page, char **start, off_t off, int count, int *eof, void *data);
static int can_proc_read_rcvlist_all(char *page, char **start, off_t off, int count, int *eof, void *data);
static int can_proc_read_rcvlist_fil(char *page, char **start, off_t off, int count, int *eof, void *data);
static int can_proc_read_rcvlist_inv(char *page, char **start, off_t off, int count, int *eof, void *data);
static int can_proc_read_rcvlist_sff(char *page, char **start, off_t off, int count, int *eof, void *data);
static int can_proc_read_rcvlist_eff(char *page, char **start, off_t off, int count, int *eof, void *data);

static struct proc_dir_entry *can_dir         = NULL;
static struct proc_dir_entry *pde_version     = NULL;
static struct proc_dir_entry *pde_stats       = NULL;
static struct proc_dir_entry *pde_reset_stats = NULL;
static struct proc_dir_entry *pde_rcvlist_all = NULL;
static struct proc_dir_entry *pde_rcvlist_fil = NULL;
static struct proc_dir_entry *pde_rcvlist_inv = NULL;
static struct proc_dir_entry *pde_rcvlist_sff = NULL;
static struct proc_dir_entry *pde_rcvlist_eff = NULL;

struct timer_list stattimer; /* timer for statistics update */

struct s_stats  stats; /* statistics */
struct s_pstats pstats;

extern struct rcv_dev_list *rx_dev_list; /* rx dispatcher structures */
extern int stats_timer;                  /* module parameter. default: on */

/**************************************************/
/* procfs init / remove                           */
/**************************************************/

void can_init_proc(void)
{

    /* procfs init */

    /* create /proc/can directory */
    can_dir = proc_mkdir(CAN_PROC_DIR, NULL);

    if (can_dir) {

	can_dir->owner = THIS_MODULE;

	/* own procfs entries from the AF_CAN core */
	pde_version     = can_create_proc_read_entry(CAN_PROC_VERSION, 0644, can_proc_read_version, NULL);
	pde_stats       = can_create_proc_read_entry(CAN_PROC_STATS, 0644, can_proc_read_stats, NULL);
	pde_reset_stats = can_create_proc_read_entry(CAN_PROC_RESET_STATS, 0644, can_proc_read_reset_stats, NULL);
	pde_rcvlist_all = can_create_proc_read_entry(CAN_PROC_RCVLIST_ALL, 0644, can_proc_read_rcvlist_all, NULL);
	pde_rcvlist_fil = can_create_proc_read_entry(CAN_PROC_RCVLIST_FIL, 0644, can_proc_read_rcvlist_fil, NULL);
	pde_rcvlist_inv = can_create_proc_read_entry(CAN_PROC_RCVLIST_INV, 0644, can_proc_read_rcvlist_inv, NULL);
	pde_rcvlist_sff = can_create_proc_read_entry(CAN_PROC_RCVLIST_SFF, 0644, can_proc_read_rcvlist_sff, NULL);
	pde_rcvlist_eff = can_create_proc_read_entry(CAN_PROC_RCVLIST_EFF, 0644, can_proc_read_rcvlist_eff, NULL);

	if (stats_timer) {
	    /* the statistics are updated every second (timer triggered) */
	    stattimer.function = can_stat_update;
	    stattimer.data = 0;
	    stattimer.expires = jiffies + HZ; /* every second */
	    add_timer(&stattimer); /* start statistics timer */
	}
    } else
	printk(KERN_INFO "af_can: failed to create CAN_PROC_DIR. CONFIG_PROC_FS missing?\n");
}

void can_remove_proc(void)
{
    /* procfs remove */
    if (pde_version) {
	can_remove_proc_entry(CAN_PROC_VERSION);
    }

    if (pde_stats) {
	can_remove_proc_entry(CAN_PROC_STATS);
    }

    if (pde_reset_stats) {
	can_remove_proc_entry(CAN_PROC_RESET_STATS);
    }

    if (pde_rcvlist_all) {
	can_remove_proc_entry(CAN_PROC_RCVLIST_ALL);
    }

    if (pde_rcvlist_fil) {
	can_remove_proc_entry(CAN_PROC_RCVLIST_FIL);
    }

    if (pde_rcvlist_inv) {
	can_remove_proc_entry(CAN_PROC_RCVLIST_INV);
    }

    if (pde_rcvlist_sff) {
	can_remove_proc_entry(CAN_PROC_RCVLIST_SFF);
    }

    if (pde_rcvlist_eff) {
	can_remove_proc_entry(CAN_PROC_RCVLIST_EFF);
    }

    if (can_dir) {
	remove_proc_entry(CAN_PROC_DIR, NULL);
    }
}

/**************************************************/
/* proc read functions                            */
/**************************************************/

int can_print_recv_list(char *page, int len, struct rcv_list *rx_list, struct net_device *dev)
{
    struct rcv_list *p;

    if (rx_list) {
	for (p = rx_list; p; p = p->next) {

	    /*                             can1.  00000000  00000000  00000000  .......0  tp20 */
	    if (p->can_id & CAN_EFF_FLAG) /* EFF & CAN_ID_ALL */
		len += snprintf(page + len, PAGE_SIZE - len, "   %-5s  %08X  %08x  %08x  %08x  %8ld  %s\n",
			       dev->name, p->can_id, p->mask, (unsigned int)p->func,
			       (unsigned int)p->data, p->matches, p->ident);
	    else
		len += snprintf(page + len, PAGE_SIZE - len, "   %-5s     %03X    %08x  %08x  %08x  %8ld  %s\n",
			       dev->name, p->can_id, p->mask, (unsigned int)p->func,
			       (unsigned int)p->data, p->matches, p->ident);

	    /* does a typical line fit into the current buffer? */
	    if (len > PAGE_SIZE - 100) { /* 100 Bytes before end of buffer */
		len += snprintf(page + len, PAGE_SIZE - len, "   (..)\n"); /* mark output cutted off */
		return len;
	    }
	}
    }

    return len;
}

static int can_print_recv_banner(char *page, int len)
{
    /*                  can1.  00000000  00000000  00000000  .......0  tp20 */
    len += snprintf(page + len, PAGE_SIZE - len,
		    "  device   can_id   can_mask  function  userdata   matches  ident\n");

    return len;
}

int can_proc_read_stats(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int len = 0;

    len += snprintf(page + len, PAGE_SIZE - len, "\n");
    len += snprintf(page + len, PAGE_SIZE - len, " %8ld transmitted frames (TXF)\n",
		    stats.tx_frames);
    len += snprintf(page + len, PAGE_SIZE - len, " %8ld received frames (RXF)\n",
		    stats.rx_frames);
    len += snprintf(page + len, PAGE_SIZE - len, " %8ld matched frames (RXMF)\n",
		    stats.matches);

    len += snprintf(page + len, PAGE_SIZE - len, "\n");

    len += snprintf(page + len, PAGE_SIZE - len, " %8ld %% total match ratio (RXMR)\n",
		    stats.total_rx_match_ratio);

    len += snprintf(page + len, PAGE_SIZE - len, " %8ld frames/s total tx rate (TXR)\n",
		    stats.total_tx_rate);
    len += snprintf(page + len, PAGE_SIZE - len, " %8ld frames/s total rx rate (RXR)\n",
		    stats.total_rx_rate);

    len += snprintf(page + len, PAGE_SIZE - len, "\n");

    len += snprintf(page + len, PAGE_SIZE - len, " %8ld %% current match ratio (CRXMR)\n",
		    stats.current_rx_match_ratio);

    len += snprintf(page + len, PAGE_SIZE - len, " %8ld frames/s current tx rate (CTXR)\n",
		    stats.current_tx_rate);
    len += snprintf(page + len, PAGE_SIZE - len, " %8ld frames/s current rx rate (CRXR)\n",
		    stats.current_rx_rate);

    len += snprintf(page + len, PAGE_SIZE - len, "\n");

    len += snprintf(page + len, PAGE_SIZE - len, " %8ld %% max match ratio (MRXMR)\n",
		    stats.max_rx_match_ratio);

    len += snprintf(page + len, PAGE_SIZE - len, " %8ld frames/s max tx rate (MTXR)\n",
		    stats.max_tx_rate);
    len += snprintf(page + len, PAGE_SIZE - len, " %8ld frames/s max rx rate (MRXR)\n",
		    stats.max_rx_rate);

    len += snprintf(page + len, PAGE_SIZE - len, "\n");

    len += snprintf(page + len, PAGE_SIZE - len, " %8ld current receive list entries (CRCV)\n", pstats.rcv_entries);
    len += snprintf(page + len, PAGE_SIZE - len, " %8ld maximum receive list entries (MRCV)\n", pstats.rcv_entries_max);

    if (pstats.stats_reset)
	len += snprintf(page + len, PAGE_SIZE - len, "\n %8ld statistic resets (STR)\n", pstats.stats_reset);

    len += snprintf(page + len, PAGE_SIZE - len, "\n");

    *eof = 1;
    return len;
}

int can_proc_read_reset_stats(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int len = 0;

    can_init_stats(1);

    len += snprintf(page + len, PAGE_SIZE - len, "CAN statistic reset #%ld done.\n", pstats.stats_reset);

    *eof = 1;
    return len;
}

int can_proc_read_version(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int len = 0;

    len += snprintf(page + len, PAGE_SIZE - len,
		    "%06X [ Volkswagen AG - Low Level CAN Framework (LLCF) v%s ]\n",
		    LLCF_VERSION_CODE, VERSION);

    *eof = 1;
    return len;
}

int can_proc_read_rcvlist_all(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int len = 0;
    struct rcv_dev_list *p;

    /* RX_ALL */
    len += snprintf(page + len, PAGE_SIZE - len, "\nreceive list 'rx_all':\n");

    /* find receive list for this device */
    for (p = rx_dev_list; p; p = p->next) {

	if (p->rx_all) {
	    len = can_print_recv_banner(page, len);
	    len = can_print_recv_list(page, len, p->rx_all, p->dev);
	} else
	    if (p->dev)
		len += snprintf(page + len, PAGE_SIZE - len, "  (%s: no entry)\n", p->dev->name);
    }

    len += snprintf(page + len, PAGE_SIZE - len, "\n");

    *eof = 1;
    return len;
}

int can_proc_read_rcvlist_fil(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int len = 0;
    struct rcv_dev_list *p;

    /* RX_FIL */
    len += snprintf(page + len, PAGE_SIZE - len, "\nreceive list 'rx_fil':\n");

    /* find receive list for this device */
    for (p = rx_dev_list; p; p = p->next) {

	if (p->rx_fil) {
	    len = can_print_recv_banner(page, len);
	    len = can_print_recv_list(page, len, p->rx_fil, p->dev);
	} else
	    if (p->dev)
		len += snprintf(page + len, PAGE_SIZE - len, "  (%s: no entry)\n", p->dev->name);
    }

    len += snprintf(page + len, PAGE_SIZE - len, "\n");

    *eof = 1;
    return len;
}

int can_proc_read_rcvlist_inv(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int len = 0;
    struct rcv_dev_list *p;

    /* RX_INV */
    len += snprintf(page + len, PAGE_SIZE - len, "\nreceive list 'rx_inv':\n");

    /* find receive list for this device */
    for (p = rx_dev_list; p; p = p->next) {

	if (p->rx_inv) {
	    len = can_print_recv_banner(page, len);
	    len = can_print_recv_list(page, len, p->rx_inv, p->dev);
	} else
	    if (p->dev)
		len += snprintf(page + len, PAGE_SIZE - len, "  (%s: no entry)\n", p->dev->name);
    }

    len += snprintf(page + len, PAGE_SIZE - len, "\n");

    *eof = 1;
    return len;
}

int can_proc_read_rcvlist_sff(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int len = 0;
    unsigned long id = 0;
    int i;
    struct rcv_dev_list *p;

    /* RX_SFF */
    len += snprintf(page + len, PAGE_SIZE - len, "\nreceive list 'rx_sff':\n");

    /* find receive list for this device */
    for (p = rx_dev_list; p; p = p->next) {

	for(i=0; i<0x800; i++)
	    id |= (unsigned long) p->rx_sff[i]; /* check if any entry available */

	if (id) {
	    len = can_print_recv_banner(page, len);
	    for(i=0; i<0x800; i++) {
		if ((p->rx_sff[i]) && (len < PAGE_SIZE - 100))
		    len = can_print_recv_list(page, len, p->rx_sff[i], p->dev);
	    }
	} else
	    if (p->dev)
		len += snprintf(page + len, PAGE_SIZE - len, "  (%s: no entry)\n", p->dev->name);
    }

    len += snprintf(page + len, PAGE_SIZE - len, "\n");

    *eof = 1;
    return len;
}

int can_proc_read_rcvlist_eff(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int len = 0;
    struct rcv_dev_list *p;

    /* RX_EFF */
    len += snprintf(page + len, PAGE_SIZE - len, "\nreceive list 'rx_eff':\n");

    /* find receive list for this device */
    for (p = rx_dev_list; p; p = p->next) {

	if (p->rx_eff) {
	    len = can_print_recv_banner(page, len);
	    len = can_print_recv_list(page, len, p->rx_eff, p->dev);
	} else
	    if (p->dev)
		len += snprintf(page + len, PAGE_SIZE - len, "  (%s: no entry)\n", p->dev->name);
    }

    len += snprintf(page + len, PAGE_SIZE - len, "\n");

    *eof = 1;
    return len;
}

/**************************************************/
/* proc utility functions                         */
/**************************************************/

static struct proc_dir_entry *can_create_proc_read_entry(const char *name, mode_t mode, read_proc_t* read_proc, void *data)
{
    if (can_dir)
	return create_proc_read_entry(name, mode, can_dir, read_proc, data);
    else
	return NULL;
}

static void can_remove_proc_entry(const char *name)
{
    if (can_dir)
	remove_proc_entry(name, can_dir);
}

static unsigned long calc_rate(unsigned long oldjif, unsigned long newjif, unsigned long count){

    unsigned long ret = 0;

    if (oldjif == newjif)
	return 0;

    if (count > (ULONG_MAX / HZ)) { /* see can_rcv() - this should NEVER happen! */
	printk(KERN_ERR "af_can: calc_rate: count exceeded! %ld\n", count);
	return 99999999;
    }

    ret = ((count * HZ) / (newjif - oldjif));

    return ret;
};

/**************************************************/
/* af_can statistics stuff                        */
/**************************************************/

static void can_init_stats(int caller){

    memset(&stats, 0, sizeof(stats));
    stats.jiffies_init  = jiffies;
    pstats.stats_reset++;
};

static void can_stat_update(unsigned long data){

    unsigned long j = jiffies; /* snapshot */

    //DBG("af_can: can_stat_update() jiffies = %ld\n", j);

    if (j < stats.jiffies_init) /* jiffies overflow */
	can_init_stats(2);

    /* stats.rx_frames is the definitively max. statistic value */
    if (stats.rx_frames > (ULONG_MAX / HZ)) /* prevent overflow in calc_rate() */
	can_init_stats(3); /* restart */

    if (stats.matches > (ULONG_MAX / 100)) /* matches overflow - very improbable */
	can_init_stats(4);

    /* calc total values */
    if (stats.rx_frames)
	 stats.total_rx_match_ratio = (stats.matches * 100) / stats.rx_frames;

    stats.total_tx_rate = calc_rate(stats.jiffies_init, j, stats.tx_frames);
    stats.total_rx_rate = calc_rate(stats.jiffies_init, j, stats.rx_frames);

    /* calc current values */
    if (stats.rx_frames_delta)
	stats.current_rx_match_ratio = (stats.matches_delta * 100) / stats.rx_frames_delta;

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
};

/**************************************************/
/* EOF                                            */
/**************************************************/
