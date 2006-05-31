/*
 * $Id:$
 *
 * Copyright (C) 2005 Marc Kleine-Budde, Pengutronix
 * Copyright (C) 2006 Andrey Volkov, Varma Electronics
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the version 2 of the GNU General Public License
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/can/can.h>
#include <linux/can/can_device.h>

/*
 Abstract:
	Baud rate calculated with next formula:
	baud = frq/(brp*(1 + prop_seg+ phase_seg1 + phase_seg2))

	This calc function based on work of Florian Hartwich and Armin Bassemi
	"The Configuration of the CAN Bit Timing"
	(http://www.semiconductors.bosch.de/pdf/CiA99Paper.pdf)

 Parameters:
  [in]
    bit_time_nsec - expected bit time in nanosecs

  [out]
	bit_time	- calculated time segments, for meaning of
				  each field read CAN standart.
*/

#define DEFAULT_MAX_BRP			64U
#define DEFAULT_MAX_SJW			4U

/* All below values in tq units */
#define MAX_BIT_TIME	25U
#define MIN_BIT_TIME	8U
#define MAX_PROP_SEG	8U
#define MAX_PHASE_SEG1	8U
#define MAX_PHASE_SEG2	8U

int can_calc_bit_time(struct can_device *can, u32 bit_time_nsec,
					  struct can_bittime_std *bit_time)
{
	unsigned best_error = UINT_MAX; /* Ariphmetic error */
	int df, best_df = -1; /* oscillator's tolerance range, greater is better*/
	u32 quanta;	/*in tq units*/
	u32 brp, phase_seg1, phase_seg2, sjw, prop_seg;
	u32 brp_min, brp_max, brp_expected;

	/* bit time range [1KHz,1MHz] */
	if (bit_time_nsec > 1000000UL || bit_time_nsec < 1000)
		return -EINVAL;

	brp_expected = can->can_sys_clock * bit_time_nsec;

	brp_min = brp_expected/(1000*MAX_BIT_TIME);
	if(brp_min == 0)
		brp_min = 1;
	if(brp_min > can->max_brp)
		return -ERANGE;

	brp_max = (brp_expected+500*MIN_BIT_TIME)/(1000*MIN_BIT_TIME);
	if(brp_max == 0)
		brp_max = 1;
	if(brp_max > can->max_brp)
		brp_max = can->max_brp;

	for(brp = brp_min; brp <= brp_max; brp++)
	{
		quanta = brp_expected/(brp*1000);
		if(quanta<MAX_BIT_TIME && quanta*brp*1000 != brp_expected)
			quanta++;
		if(quanta<MIN_BIT_TIME || quanta>MAX_BIT_TIME)
			continue;

		phase_seg2 = min( (quanta-3)/2, MAX_PHASE_SEG2);
		for(sjw = can->max_sjw; sjw > 0; sjw--)
		{
			for(; phase_seg2>sjw; phase_seg2--)
			{
				u32 err1, err2;
				phase_seg1 = (phase_seg2%2)?phase_seg2-1:phase_seg2;
				prop_seg = quanta-1-phase_seg2-phase_seg1;
				/* FIXME: support of longer lines (i.e. bigger prop_seg)
				is more prefered than support of cheap oscillators
				(i.e. bigger df/phase_seg1/phase_seg2)
				*/
				if( prop_seg < phase_seg1)
						continue;
				if( prop_seg > MAX_PROP_SEG )
						goto next_brp;

				err1 = phase_seg1*brp*500*1000/
					   (13*brp_expected-phase_seg2*brp*1000);
				err2 = sjw*brp*50*1000/brp_expected;

				df = min(err1,err2);
				if(df>=best_df) {
					unsigned error = abs(brp_expected*10/
							   (brp*(1+prop_seg+phase_seg1+phase_seg2))-10000);

					if( error > best_error )
						continue;

					if( error == best_error && prop_seg < bit_time->prop_seg )
						continue;

					best_error = error;
					best_df = df;
					bit_time->brp = brp;
					bit_time->prop_seg = prop_seg;
					bit_time->phase_seg1 = phase_seg1;
					bit_time->phase_seg2 = phase_seg2;
					bit_time->sjw = sjw;
					bit_time->sam = ( bit_time->phase_seg1 > 3 )? 1 : 0;
				}
			}
		}
	next_brp:	;
	}

	if(best_error>=10)
		return -EDOM;
	return 0;
}
EXPORT_SYMBOL(can_calc_bit_time);

static struct net_device_stats *can_get_stats(struct net_device *dev)
{
	return &ND2CAN(dev)->stats;
}

static int can_ioctl(struct net_device *ndev, struct ifreq *ifr, int cmd)
{
	struct can_device *can = ND2CAN(ndev);
	struct can_bittime	*bt = (struct can_bittime *)&ifr->ifr_ifru;
	union can_settings	*settings = (union can_settings *)&ifr->ifr_ifru;
	int ret = -EOPNOTSUPP;
	ulong *baudrate = (ulong *)&ifr->ifr_ifru;

	dev_dbg(ND2D(ndev), "(%s) 0x%08x %p\n", __FUNCTION__, cmd, &ifr->ifr_ifru);

	switch (cmd) {
	case SIOCSCANCUSTOMBITTIME:
		if (can->do_set_bit_time)
			return can->do_set_bit_time(can, bt);
		break;
	case SIOCSCANBAUDRATE:
	   if (!can->do_set_bit_time)
			break;
	   if ( *baudrate >= 1000UL && *baudrate <= 1000000UL)
	   {
			struct can_bittime bit_time;
			u32 bit_time_nsec = (2000000000UL+(*baudrate))/(2*(*baudrate));
			ret = can_calc_bit_time(can, bit_time_nsec, &bit_time.std);
			if (ret != 0)
				break;
			bit_time.type = CAN_BITTIME_STD;
			return can->do_set_bit_time(can, &bit_time);
		}
		else
			ret = -EINVAL;
		break;
	case SIOCGCANCUSTOMBITTIME:
		*bt = can->bit_time;
		break;
	case SIOCGCANBAUDRATE:
	    *baudrate = can->baudrate;
		ret = 0;
		break;
	case SIOCSCANMODE:
		if(can->do_set_mode)
			return can->do_set_mode(can, settings->mode);
		break;
	case SIOCGCANSTATE:
		if(can->do_get_state)
			return can->do_get_state(can, &settings->state);
		break;
	}

  return ret;
}

static void can_setup(struct net_device *dev)
{
	dev->type = ARPHRD_CAN;

	dev->change_mtu			= NULL;
	dev->hard_header		= NULL;
	dev->rebuild_header		= NULL;
	dev->set_mac_address		= NULL;
	dev->hard_header_cache		= NULL;
	dev->header_cache_update	= NULL;
	dev->hard_header_parse		= NULL;

	dev->hard_header_len = 0;

	dev->get_stats	= can_get_stats;
	dev->mtu		= sizeof(struct can_frame);
	dev->do_ioctl   = can_ioctl;
	dev->addr_len	= 0;
	dev->tx_queue_len	= 10;

	/* New-style flags. */
	dev->flags		= IFF_NOARP;
	dev->features  	= NETIF_F_NO_CSUM;
}

/*
 * Funciton  alloc_candev
 * 	Allocates and sets up an CAN device in a manner similar to
 * 	alloc_etherdev.
 */
struct can_device *alloc_candev(int sizeof_priv)
{
  struct net_device *ndev;
  struct can_device *can;

  ndev = alloc_netdev(sizeof_priv+sizeof(struct can_device),
  					  "can%d", can_setup);
  if(!ndev)
		return NULL;
  can = netdev_priv(ndev);

  can->net_dev = ndev;
  if(sizeof_priv)
	  can->priv = &can[1];

  can->baudrate = CAN_BAUD_UNCONFIGURED;
  can->max_brp = DEFAULT_MAX_BRP;
  can->max_sjw = DEFAULT_MAX_SJW;
  can->baudrate = CAN_BAUD_UNCONFIGURED;
  spin_lock_init(&can->irq_lock);

  return can;
}
EXPORT_SYMBOL(alloc_candev);

void free_candev(struct can_device *can)
{
	free_netdev(can->net_dev);
}
EXPORT_SYMBOL(free_candev);
