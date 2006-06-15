/*
 * $Id$
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

#ifndef CAN_IOCTL_H
#define CAN_IOCTL_H

#include <linux/sockios.h>


/* max. 16 private ioctls */

#define SIOCSCANBAUDRATE	(SIOCDEVPRIVATE+0)
#define SIOCGCANBAUDRATE	(SIOCDEVPRIVATE+1)

#define SIOCSCANCUSTOMBITTIME   (SIOCDEVPRIVATE+2)
#define SIOCGCANCUSTOMBITTIME   (SIOCDEVPRIVATE+3)

#define SIOCSCANMODE		(SIOCDEVPRIVATE+4)
#define SIOCGCANMODE		(SIOCDEVPRIVATE+5)

#define SIOCSCANCTRLMODE	(SIOCDEVPRIVATE+6)
#define SIOCGCANCTRLMODE	(SIOCDEVPRIVATE+7)

#define SIOCSCANFILTER		(SIOCDEVPRIVATE+8)
#define SIOCGCANFILTER		(SIOCDEVPRIVATE+9)

#define SIOCGCANSTATE		(SIOCDEVPRIVATE+10)
#define SIOCGCANSTATS		(SIOCDEVPRIVATE+11)

/* parameters for ioctls */

/* SIOC[SG]CANBAUDRATE */
/* baudrate for CAN-controller in bits per second. */
/* 0 = Scan for baudrate (Autobaud) */

typedef __u32 can_baudrate_t;


/* SIOC[SG]CANCUSTOMBITTIME */

typedef enum CAN_BITTIME_TYPE {
	CAN_BITTIME_STD,
	CAN_BITTIME_BTR
} can_bittime_type_t;

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
	can_bittime_type_t type;
	union {
		struct can_bittime_std std;
		struct can_bittime_btr btr;
	};
};
#define CAN_BAUDRATE_UNCONFIGURED	((__u32)-1)
#define CAN_BAUDRATE_UNKNOWN		0

/* SIOC[SG]CANMODE */

typedef __u32 can_mode_t;

#define CAN_MODE_STOP	0
#define CAN_MODE_START	1
#define CAN_MODE_SLEEP	2


/* SIOC[SG]CANCTRLMODE */

typedef __u32 can_ctrlmode_t;

#define CAN_CTRLMODE_LOOPBACK   0x1
#define CAN_CTRLMODE_LISTENONLY 0x2


/* SIOCGCANFILTER */

typedef __u32 can_filter_t;

/* filter modes (may vary due to controller specific capabilities) */
#define CAN_FILTER_CAPAB       0  /* get filter type capabilities (32 Bit value) */
#define CAN_FILTER_MASK_VALUE  1  /* easy bit filter (see struct can_filter) */
#define CAN_FILTER_SFF_BITMASK 2  /* bitfield with 2048 bit SFF filter */
                                  /* filters 3 - 31 currently undefined */

#define CAN_FILTER_MAX         31 /* max. filter type value */


/* SIOCGCANSTATE */

typedef __u32 can_state_t;

#define CAN_STATE_ACTIVE		0
#define CAN_STATE_BUS_WARNING		1
#define CAN_STATE_BUS_PASSIVE		2
#define CAN_STATE_BUS_OFF		3
#define CAN_STATE_SCANNING_BAUDRATE	4
#define CAN_STATE_STOPPED		5
#define CAN_STATE_SLEEPING		6


/* SIOCGCANSTATS */

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

#endif /* CAN_IOCTL_H */
