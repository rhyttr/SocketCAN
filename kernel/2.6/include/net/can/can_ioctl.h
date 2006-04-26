/*
 * can_ioctl_h
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

#ifdef __KERNEL__
#include "version.h"
RCSID("$Id: can_ioctl.h,v 2.0 2006/04/13 10:37:19 ethuerm Exp $");
#endif

#include <linux/sockios.h>


/* max. 16 private ioctls */

#define SIOCSRATE      (SIOCDEVPRIVATE+0)
#define SIOCGRATE      (SIOCDEVPRIVATE+1)

#define SIOCSMODE      (SIOCDEVPRIVATE+2)
#define SIOCGMODE      (SIOCDEVPRIVATE+3)

#define SIOCSFILTER    (SIOCDEVPRIVATE+4)
#define SIOCGFILTER    (SIOCDEVPRIVATE+5)

#define SIOCSTRX       (SIOCDEVPRIVATE+6)
#define SIOCGTRX       (SIOCDEVPRIVATE+7)

#define SIOCGSTATUS    (SIOCDEVPRIVATE+8)
#define SIOCGTRXSTATUS (SIOCDEVPRIVATE+9)

#define SIOCGSTATS     (SIOCDEVPRIVATE+10)

/* parameters for ioctls */

/* baudrate for CAN-controller */
#define RATE_SPEED 0 /* parameter is in bits/second (speed 0: autoprobe) */
#define RATE_BTREG 1 /* parameter is controller specific bit-timing register */

/* operation modes for CAN-controller */
#define MODE_OFFLINE 0
#define MODE_RX      1
#define MODE_TX      2
#define MODE_TRX     (MODE_TX | MODE_RX)
#define MODE_LISTEN  4 /* no acknowledge on CAN layer */

/* filter modes (may vary due to controller specific capabilities) */
#define FILTER_CAPAB       0  /* get filter type capabilities (32 Bit value) */
#define FILTER_MASK_VALUE  1  /* easy bit filter (see struct can_filter) */  
#define FILTER_SFF_BITMASK 2  /* bitfield with 2048 bit SFF filter */

                              /* filters 3 - 31 currently undefined */

#define FILTER_MAX         31 /* max. filter type value */

/* operation modes for CAN-transceiver */
#define TRX_OPERATE 0 /* normal operation */
#define TRX_STANDBY 1 /* standby */
#define TRX_SLEEP   2 /* goto sleep */

/* operating status of CAN-controller */
#define STATUS_OK            0
#define STATUS_WARNING       1 /* see parameter for additional info */
#define STATUS_ERROR         2 /* see parameter for additional info */
#define STATUS_ERROR_PASSIVE 3
#define STATUS_BUS_OFF       4

/* additional info for STATUS_ERROR */
#define STATUS_ERR_BIT   0x00
#define STATUS_ERR_FORM  0x01
#define STATUS_ERR_STUFF 0x02
#define STATUS_ERR_CRC   0x04
#define STATUS_ERR_ACK   0x08
#define STATUS_ERR_OTHER 0x10

/* operating status of CAN-transceiver */
#define TRXSTATUS_OK                 0x000
#define TRXSTATUS_SLEEP              0x001
#define TRXSTATUS_CANH_NO_WIRE       0x002
#define TRXSTATUS_CANH_SHORT_TO_BAT  0x004
#define TRXSTATUS_CANH_SHORT_TO_VCC  0x008
#define TRXSTATUS_CANH_SHORT_TO_GND  0x010
#define TRXSTATUS_CANL_NO_WIRE       0x020
#define TRXSTATUS_CANL_SHORT_TO_BAT  0x040
#define TRXSTATUS_CANL_SHORT_TO_VCC  0x080
#define TRXSTATUS_CANL_SHORT_TO_GND  0x100
#define TRXSTATUS_CANL_SHORT_TO_CANH 0x200

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
