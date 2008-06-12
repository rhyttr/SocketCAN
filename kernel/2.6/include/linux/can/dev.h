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
 * CAN bitrate
 */
#define CAN_BITRATE_UNCONFIGURED	((__u32) 0xFFFFFFFFU)
#define CAN_BITRATE_UNKNOWN		0
#define CAN_BITRATE_DEFAULT		500000

/*
 * CAN custom bit time
 */
enum can_bittimes {
	CAN_BITTIME_STD,
	CAN_BITTIME_BTR
};

/* TSEG1 of controllers usually is a sum of synch_seg (always 1),
 * prop_seg and phase_seg1, TSEG2 = phase_seg2 */

struct can_bittime_std {
	__u32 brp;        /* baud rate prescaler */
	__u8  prop_seg;   /* from 1 to 8 */
	__u8  phase_seg1; /* from 1 to 8 */
	__u8  phase_seg2; /* from 1 to 8 */
	__u8  sjw:7;      /* from 1 to 4 */
	__u8  sam:1;      /* 1 - enable triple sampling */
};

struct can_bittime_btr {
	__u8  btr0;
	__u8  btr1;
};

struct can_bittime {
	enum can_bittimes type;
	union {
		struct can_bittime_std std;
		struct can_bittime_btr btr;
	};
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
#define CAN_CTRLMODE_LOOPBACK   0x1
#define CAN_CTRLMODE_LISTENONLY 0x2

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
	int error_warning;
	int data_overrun;
	int wakeup;
	int bus_error;
	int error_passive;
	int arbitration_lost;
	int restarts;
	int bus_error_at_init;
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

	/*
	 * CAN bus oscillator frequency, in Hz, BE CAREFUL! SOME
	 * CONTROLLERS (LIKE SJA1000) FOOLISH ABOUT THIS FRQ (for
	 * sja1000 as ex. this clock must be xtal clock divided by 2).
	 */
	u32 can_sys_clock;
	/*
	 * By default max_brp is equal 64, but for a Freescale TouCAN,
	 * as ex., it can be 255.
	 */
	u32 max_brp;
	/*
	 * For the mostly all controllers, max_sjw is equal 4, but some,
	 * hmm, CAN implementations hardwared it to 1.
	 */
	u8 max_sjw;

	u32 bitrate;
	struct can_bittime bittime;

	spinlock_t irq_lock;
	/* Please hold this lock when touching net_stats/can_stats */
	spinlock_t stats_lock;

	enum can_state state;
	u32 ctrlmode;

	int restart_ms;
	struct timer_list timer;

	struct sk_buff *echo_skb[CAN_ECHO_SKB_MAX];

	int (*do_set_bittime)(struct net_device *dev,
			      struct can_bittime *br);
	int (*do_get_state)(struct net_device *dev, u32 *state);
	int (*do_set_mode)(struct net_device *dev, u32 mode);
	int (*do_set_ctrlmode)(struct net_device *dev, u32 ctrlmode);
	int (*do_get_ctrlmode)(struct net_device *dev, u32*ctrlmode);
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

int can_restart_now(struct net_device *dev);
int can_set_bitrate(struct net_device *dev, u32 bitrate);

void can_bus_off(struct net_device *dev);

void can_close_cleanup(struct net_device *dev);

void can_put_echo_skb(struct sk_buff *skb, struct net_device *dev, int idx);
void can_get_echo_skb(struct net_device *dev, int idx);

#endif /* CAN_DEVICE_H */
