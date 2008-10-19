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

/*
 * CAN bitrate and bit-timing
 */
struct can_bittiming {
	u32 bitrate;
	u32 sample_point;
	u32 tq;
	u32 prop_seg;
	u32 phase_seg1;
	u32 phase_seg2;
	u32 sjw;
	u32 clock;
	u32 brp;
};

struct can_bittiming_const {
	u32 tseg1_min;
	u32 tseg1_max;
	u32 tseg2_min;
	u32 tseg2_max;
	u32 sjw_max;
	u32 brp_min;
	u32 brp_max;
	u32 brp_inc;
};

/*
 * CAN mode
 */
enum can_mode {
	CAN_MODE_STOP = 0,
	CAN_MODE_START,
	CAN_MODE_SLEEP
};

/*
 * CAN controller mode
 */
#define CAN_CTRLMODE_LOOPBACK	0x1
#define CAN_CTRLMODE_LISTENONLY	0x2
#define CAN_CTRLMODE_3_SAMPLES	0x4 /* Triple sampling mode */

/*
 * CAN operational and error states
 */
enum can_state {
	CAN_STATE_ACTIVE = 0,
	CAN_STATE_BUS_WARNING,
	CAN_STATE_BUS_PASSIVE,
	CAN_STATE_BUS_OFF,
	CAN_STATE_STOPPED,
	CAN_STATE_SLEEPING
};

/*
 * CAN device statistics
 */
struct can_device_stats {
	unsigned long error_warning;
	unsigned long data_overrun;
	unsigned long wakeup;
	unsigned long bus_error;
	unsigned long error_passive;
	unsigned long arbitration_lost;
	unsigned long restarts;
	unsigned long bus_error_at_init;
};

/*
 * CAN common private data
 */
#define CAN_ECHO_SKB_MAX  4

struct can_priv {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
	struct net_device_stats net_stats;
#endif
	struct can_device_stats can_stats;

	struct can_bittiming bittiming;
	struct can_bittiming_const *bittiming_const;

	spinlock_t irq_lock;
	/* Please hold this lock when touching net_stats/can_stats */
	spinlock_t stats_lock;

	enum can_state state;
	u32 ctrlmode;

	int restart_ms;
	struct timer_list timer;

	struct sk_buff *echo_skb[CAN_ECHO_SKB_MAX];

	int (*do_set_bittiming)(struct net_device *dev);
	int (*do_get_state)(struct net_device *dev, enum can_state *state);
	int (*do_set_mode)(struct net_device *dev, enum can_mode mode);
	int (*do_set_ctrlmode)(struct net_device *dev, u32 ctrlmode);
	int (*do_get_ctrlmode)(struct net_device *dev, u32 *ctrlmode);
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
#define ND2D(_ndev)	(_ndev->class_dev.dev)
#else
#define ND2D(_ndev)	(_ndev->dev.parent)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#define IFF_ECHO IFF_LOOPBACK
#endif

struct net_device *alloc_candev(int sizeof_priv);
void free_candev(struct net_device *dev);

int can_set_bittiming(struct net_device *dev);

int can_restart_now(struct net_device *dev);

void can_bus_off(struct net_device *dev);

void can_close_cleanup(struct net_device *dev);

void can_put_echo_skb(struct sk_buff *skb, struct net_device *dev, int idx);
void can_get_echo_skb(struct net_device *dev, int idx);

int can_sample_point(struct can_bittiming *bt);

#endif /* CAN_DEVICE_H */
