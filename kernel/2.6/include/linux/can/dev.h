/*
 * linux/can/dev.h
 *
 * Definitions for CAN controller network devices lib (work in progress)
 *
 * $Id$
 *
 * Author: Andrey Volkov <avolkov@varma-el.com>
 * Copyright (c) 2006 Varma Electronics Oy
 *
 */

#ifndef CAN_DEVICE_H
#define CAN_DEVICE_H

#include <linux/version.h>
#include <linux/can/error.h>
#include <linux/can/ioctl.h>

struct can_device {
	struct net_device_stats net_stats;
	struct net_device       *net_dev;

	struct can_device_stats can_stats;

	/* can-bus oscillator frequency, in Hz,
	   BE CAREFUL! SOME CONTROLLERS (LIKE SJA1000)
	   FOOLISH ABOUT THIS FRQ (for sja1000 as ex. this
	   clock must be xtal clock divided by 2). */
	u32	can_sys_clock;

	/* by default max_brp is equal 64,
	   but for a Freescale TouCAN, as ex., it can be 255*/
	u32	max_brp;
	/* For the mostly all controllers, max_sjw is equal 4, but
	   some, hmm, CAN implementations hardwared it to 1 */
	u8	max_sjw;

	u32	baudrate;	/* in bauds */
	struct can_bittime	bit_time;

	spinlock_t irq_lock;
	/* Please hold this lock when touching net_stats/can_stats*/
	spinlock_t stats_lock;

	can_state_t state;
	can_mode_t  mode;
	can_ctrlmode_t ctrlmode;

	int (*do_set_bit_time)(struct can_device *dev, struct can_bittime *br);
	int (*do_get_state)(struct can_device *dev,	can_state_t *state);
	int (*do_set_mode)(struct can_device *dev, can_mode_t mode);
	int (*do_set_ctrlmode)(struct can_device *dev, can_ctrlmode_t ctrlmode);
	int (*do_get_ctrlmode)(struct can_device *dev, can_ctrlmode_t *ctrlmode);

	void *priv;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
#define ND2D(_ndev)		(_ndev->class_dev.dev)
#else
#define ND2D(_ndev)		(_ndev->dev.parent)
#endif
#define CAN2ND(can)		((can)->net_dev)
#define ND2CAN(ndev)	((struct can_device *)netdev_priv(ndev))

struct can_device *alloc_candev(int sizeof_priv);
void free_candev(struct can_device *);

int can_calc_bit_time(struct can_device *can, u32 baudrate,
		      struct can_bittime_std *bit_time);

#endif /* CAN_DEVICE_H */
