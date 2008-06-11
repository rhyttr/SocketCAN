/*
 * $Id: dev.c 542 2007-11-07 13:57:16Z thuermann $
 *
 * Copyright (C) 2007 Wolfgang Grandegger <wg@grandegger.com>
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

#include <linux/capability.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <net/sock.h>
#include <linux/rtnetlink.h>

#include <linux/can.h>
#include <linux/can/dev.h>

#include "sysfs.h"

#ifdef CONFIG_SYSFS
/*
 * Functions to set/get CAN properties used by SYSFS
 *
 * FIXME: we may want to check for capabilities!
 *
 *        if (!capable(CAP_NET_ADMIN))
 *        	return -EPERM;
 */
static int can_get_bitrate(struct net_device *dev, u32 *bitrate)
{
	struct can_priv *priv = netdev_priv(dev);
	*bitrate = priv->bitrate;

	return 0;
}

static int can_set_custombittime(struct net_device *dev,
				 struct can_bittime *bt)
{
	struct can_priv *priv = netdev_priv(dev);
	int err = -ENOTSUPP;

	if (priv->state != CAN_STATE_STOPPED)
		return -EBUSY;

	if (priv->do_set_bittime) {
		err = priv->do_set_bittime(dev, bt);
		if (err)
			goto out;
		priv->bittime = *bt;
		if (bt->type == CAN_BITTIME_STD && bt->std.brp) {
			priv->bitrate = priv->can_sys_clock /
				(bt->std.brp * (1 + bt->std.prop_seg +
						bt->std.phase_seg1 +
						bt->std.phase_seg2));
		} else
			priv->bitrate = CAN_BITRATE_UNKNOWN;
	}
out:
	return err;
}

static int can_get_custombittime(struct net_device *dev,
				 struct can_bittime *bt)
{
	struct can_priv *priv = netdev_priv(dev);

	*bt = priv->bittime;
	return 0;
}

static int can_set_ctrlmode(struct net_device *dev, u32 ctrlmode)
{
	struct can_priv *priv = netdev_priv(dev);

	if (!priv->do_set_ctrlmode)
		return -ENOTSUPP;
	if (priv->state != CAN_STATE_STOPPED)
		return -EBUSY;

	return priv->do_set_ctrlmode(dev, ctrlmode);
}

static int can_get_ctrlmode(struct net_device *dev, u32 *ctrlmode)
{
	struct can_priv *priv = netdev_priv(dev);

	*ctrlmode = priv->ctrlmode;
	return 0;
}

static int can_get_state(struct net_device *dev, enum can_state *state)
{
	struct can_priv *priv = netdev_priv(dev);

	if (priv->do_get_state) {
		int err = priv->do_get_state(dev, state);
		if (err)
			return err;
		priv->state = *state;
	} else
		*state = priv->state;
	return 0;
}

static int can_set_clock(struct net_device *dev, u32 clock)
{
	struct can_priv *priv = netdev_priv(dev);

	if (priv->state != CAN_STATE_STOPPED)
		return -EBUSY;

	priv->can_sys_clock = clock;
	return 0;
}

static int can_get_clock(struct net_device *dev, u32 *clock)
{
	struct can_priv *priv = netdev_priv(dev);

	*clock = priv->can_sys_clock;
	return 0;
}

static int can_set_restart_ms(struct net_device *dev, int ms)
{
	struct can_priv *priv = netdev_priv(dev);

	if (priv->restart_ms < 0)
		return -EOPNOTSUPP;
	priv->restart_ms = ms;
	return 0;
}

static int can_get_restart_ms(struct net_device *dev, int *ms)
{
	struct can_priv *priv = netdev_priv(dev);

	*ms = priv->restart_ms;
	return 0;
}

static int can_set_echo(struct net_device *dev, int on)
{
	if (on)
		dev->flags |= IFF_ECHO;
	else
		dev->flags &= ~IFF_ECHO;
	return 0;
}

static int can_get_echo(struct net_device *dev, int *on)
{
	*on = dev->flags & IFF_ECHO ? 1 : 0;
	return 0;
}

/*
 * SYSFS access functions and attributes.
 * Use same locking as net/core/net-sysfs.c
 */
static inline int dev_isalive(const struct net_device *dev)
{
	return dev->reg_state <= NETREG_REGISTERED;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#define CAN_ATTR(_name, _func, _type, _fmt)				\
static ssize_t can_show_##_func(struct device *dev,			\
				struct device_attribute *attr,		\
				char *buf)				\
{									\
	struct net_device *ndev = to_net_dev(dev);			\
	_type val;							\
	int ret = -EINVAL;						\
	read_lock(&dev_base_lock);					\
	if (dev_isalive(ndev)) {					\
		can_get_##_func(ndev, &val);				\
		ret = snprintf(buf, PAGE_SIZE, _fmt "\n", val);		\
	}								\
	read_unlock(&dev_base_lock);					\
	return ret;							\
}									\
static ssize_t can_store_##_func(struct device *dev,			\
				 struct device_attribute *attr,		\
				 const char *buf, size_t count)		\
{									\
	struct net_device *ndev = to_net_dev(dev);			\
	char *endp;							\
	_type val;							\
	int ret = -EINVAL;						\
	val = simple_strtoul(buf, &endp, 0);				\
	if (endp == buf)						\
		return ret;						\
	rtnl_lock();							\
	if (dev_isalive(ndev)) {					\
		if ((ret = can_set_##_func(ndev, val)) == 0)		\
			ret = count;					\
	}								\
	rtnl_unlock();							\
	return ret;							\
}									\
static DEVICE_ATTR(_name, S_IRUGO | S_IWUSR, 				\
		   can_show_##_func, can_store_##_func)

#else /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25) */
#define CAN_ATTR(_name, _func, _type, _fmt)				\
static ssize_t can_show_##_func(struct device *dev,			\
				struct device_attribute *attr,		\
				char *buf)				\
{									\
	struct net_device *ndev = to_net_dev(dev);			\
	_type val;							\
	int ret = -EINVAL;						\
	read_lock(&dev_base_lock);					\
	if (dev_isalive(ndev)) {					\
		can_get_##_func(ndev, &val);				\
		ret = snprintf(buf, PAGE_SIZE, _fmt "\n", val);		\
	}								\
	read_unlock(&dev_base_lock);					\
	return ret;							\
}									\
static ssize_t can_store_##_func(struct device *dev,			\
				 struct device_attribute *attr,		\
				 const char *buf, size_t count)		\
{									\
	struct net_device *ndev = to_net_dev(dev);			\
	_type val;							\
	unsigned long input;						\
	int ret = -EINVAL;						\
	ret = strict_strtoul(buf, 0, &input);				\
	if (ret)							\
		return ret;						\
	val = (_type)input;						\
	rtnl_lock();							\
	if (dev_isalive(ndev)) {					\
		ret = can_set_##_func(ndev, val);			\
		if (ret == 0)						\
			ret = count;					\
	}								\
	rtnl_unlock();							\
	return ret;							\
}									\
static DEVICE_ATTR(_name, S_IRUGO | S_IWUSR, 				\
		   can_show_##_func, can_store_##_func)
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25) */

CAN_ATTR(can_bitrate, bitrate, u32, "%d");
CAN_ATTR(can_restart_ms, restart_ms, int, "%d");
CAN_ATTR(can_clock, clock, u32, "%d");
CAN_ATTR(can_echo, echo, int, "%d");

#define CAN_STATS_ATTR(_name)						\
static ssize_t can_stats_show_##_name(struct device *dev,		\
				      struct device_attribute *attr,	\
				      char *buf)			\
{									\
	struct net_device *ndev = to_net_dev(dev);			\
	struct can_priv *priv = netdev_priv(ndev);			\
	int ret = -EINVAL;						\
	read_lock(&dev_base_lock);					\
	if (dev_isalive(ndev)) {					\
		ret = snprintf(buf, PAGE_SIZE, "%d\n",			\
			      priv->can_stats._name);			\
	}								\
	read_unlock(&dev_base_lock);					\
	return ret;							\
}									\
static DEVICE_ATTR(_name, S_IRUGO, can_stats_show_##_name, NULL)

#define CAN_CREATE_FILE(_dev, _name)					\
	if (device_create_file(&_dev->dev, &dev_attr_##_name))		\
		dev_err(ND2D(_dev),					\
			"Couldn't create device file for ##_name\n")

#define CAN_REMOVE_FILE(_dev, _name)					\
	device_remove_file(&_dev->dev, &dev_attr_##_name)		\

CAN_STATS_ATTR(error_warning);
CAN_STATS_ATTR(error_passive);
CAN_STATS_ATTR(bus_error);
CAN_STATS_ATTR(arbitration_lost);
CAN_STATS_ATTR(data_overrun);
CAN_STATS_ATTR(wakeup);
CAN_STATS_ATTR(restarts);

static ssize_t can_store_restart(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct net_device *ndev = to_net_dev(dev);
	int ret = -EINVAL;

	rtnl_lock();
	if (dev_isalive(ndev)) {
		ret = can_restart_now(ndev);
		if (!ret)
			ret = count;
	}
	rtnl_unlock();
	return ret;
}

static DEVICE_ATTR(can_restart, S_IWUSR, NULL, can_store_restart);

static const char *can_state_names[] = {
	"active", "bus-warn", "bus-pass" , "bus-off",
	"stopped", "sleeping", "unkown"
};

static ssize_t can_show_state(struct device *dev,
			     struct device_attribute *attr,
			     char *buf)
{
	struct net_device *ndev = to_net_dev(dev);
	enum can_state state;
	int ret = -EINVAL;

	read_lock(&dev_base_lock);
	if (dev_isalive(ndev)) {
		can_get_state(ndev, &state);

		if (state >= ARRAY_SIZE(can_state_names))
			state = ARRAY_SIZE(can_state_names) - 1;
		ret = snprintf(buf, PAGE_SIZE, "%s\n", can_state_names[state]);
	}
	read_unlock(&dev_base_lock);
	return ret;
}

static DEVICE_ATTR(can_state, S_IRUGO, can_show_state, NULL);

static ssize_t can_show_ctrlmode(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	struct net_device *ndev = to_net_dev(dev);
	u32 ctrlmode;
	int ret = -EINVAL;

	read_lock(&dev_base_lock);
	if (dev_isalive(ndev)) {
		can_get_ctrlmode(ndev, &ctrlmode);
		ret = 0;
		if (ctrlmode & CAN_CTRLMODE_LISTENONLY)
			ret += sprintf(buf + ret, "listenonly");
		if (ret)
			ret += sprintf(buf + ret, " ");
		if (ctrlmode & CAN_CTRLMODE_LOOPBACK)
			ret += sprintf(buf + ret, "loopback");
		if (ret)
			ret += sprintf(buf + ret, "\n");
	}
	read_unlock(&dev_base_lock);
	return ret;
}

static ssize_t can_store_ctrlmode(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct net_device *ndev = to_net_dev(dev);
	u32 ctrlmode = 0;
	int ret = -EINVAL;

	if (strstr(buf, "listenonly"))
		ctrlmode |= CAN_CTRLMODE_LISTENONLY;
	if (strstr(buf, "loopback"))
		ctrlmode |= CAN_CTRLMODE_LOOPBACK;

	rtnl_lock();
	if (dev_isalive(ndev) && count) {
		ret = can_set_ctrlmode(ndev, ctrlmode);
		if (!ret)
			ret = count;
	}
	rtnl_unlock();
	return ret;
}

static DEVICE_ATTR(can_ctrlmode, S_IRUGO | S_IWUSR,
		   can_show_ctrlmode, can_store_ctrlmode);

static ssize_t can_show_custombittime(struct device *dev,
				      struct device_attribute *attr,
				      char *buf)
{
	struct net_device *ndev = to_net_dev(dev);
	struct can_bittime bt;
	int ret = -EINVAL;

	read_lock(&dev_base_lock);
	if (dev_isalive(ndev)) {
		can_get_custombittime(ndev, &bt);

		if (bt.type == CAN_BITTIME_STD)
			ret = snprintf(buf, PAGE_SIZE,
				       "std %#x %#x %#x %#x %#x %#x\n",
				       bt.std.brp, bt.std.prop_seg,
				       bt.std.phase_seg1, bt.std.phase_seg2,
				       bt.std.sjw, bt.std.sam);
		else if (bt.type == CAN_BITTIME_BTR)
			ret = snprintf(buf, PAGE_SIZE,
					"btr %#x %#x\n",
					bt.btr.btr0, bt.btr.btr1);
		else
			ret = snprintf(buf, PAGE_SIZE, "undefined\n");
	}
	read_unlock(&dev_base_lock);
	return ret;
}

static ssize_t can_store_custombittime(struct device *dev,
				       struct device_attribute *attr,
				       const char *buf, size_t count)
{
	struct net_device *ndev = to_net_dev(dev);
	struct can_bittime bt;
	u32 val[6];
	int ret = -EINVAL;

	if (!strncmp(buf, "std", 3)) {

		if (sscanf(buf + 4, "%i %i %i %i %i %i",
			   val, val + 1, val + 2, val + 3,
			   val + 4, val + 5) == 6) {
			bt.type = CAN_BITTIME_STD;
			bt.std.brp = val[0];
			bt.std.prop_seg = val[1];
			bt.std.phase_seg1 = val[2];
			bt.std.phase_seg2 = val[3];
			bt.std.sjw = val[4];
			bt.std.sam = val[5];
		}

	} else if (!strncmp(buf, "btr", 3)) {

		if (sscanf(buf + 4, "%i %i", val, val + 1) == 2) {
			bt.type = CAN_BITTIME_BTR;
			bt.btr.btr0 = val[0];
			bt.btr.btr1 = val[1];
		}

	} else
		goto out;

	rtnl_lock();
	if (dev_isalive(ndev)) {
		ret = can_set_custombittime(ndev, &bt);
		if (!ret)
			ret = count;
	}
	rtnl_unlock();
out:
	return ret;
}

static DEVICE_ATTR(can_custombittime, S_IRUGO | S_IWUSR,
		   can_show_custombittime, can_store_custombittime);

static struct attribute *can_stats_attrs[] = {
	&dev_attr_error_warning.attr,
	&dev_attr_error_passive.attr,
	&dev_attr_bus_error.attr,
	&dev_attr_arbitration_lost.attr,
	&dev_attr_data_overrun.attr,
	&dev_attr_wakeup.attr,
	&dev_attr_restarts.attr,
	NULL
};

static struct attribute_group can_stats_group = {
	.name = "can_statistics",
	.attrs = can_stats_attrs,
};

void can_create_sysfs(struct net_device *dev)
{
	int err;

	CAN_CREATE_FILE(dev, can_bitrate);
	CAN_CREATE_FILE(dev, can_custombittime);
	CAN_CREATE_FILE(dev, can_restart);
	CAN_CREATE_FILE(dev, can_ctrlmode);
	CAN_CREATE_FILE(dev, can_state);
	CAN_CREATE_FILE(dev, can_restart_ms);
	CAN_CREATE_FILE(dev, can_clock);
	CAN_CREATE_FILE(dev, can_echo);

	err = sysfs_create_group(&(dev->dev.kobj), &can_stats_group);
	if (err) {
		printk(KERN_EMERG
		       "couldn't create sysfs group for CAN stats\n");
	}
}

void can_remove_sysfs(struct net_device *dev)
{
	CAN_REMOVE_FILE(dev, can_bitrate);
	CAN_REMOVE_FILE(dev, can_custombittime);
	CAN_REMOVE_FILE(dev, can_restart);
	CAN_REMOVE_FILE(dev, can_ctrlmode);
	CAN_REMOVE_FILE(dev, can_state);
	CAN_REMOVE_FILE(dev, can_clock);
	CAN_REMOVE_FILE(dev, can_echo);

	sysfs_remove_group(&(dev->dev.kobj), &can_stats_group);
}

#endif /* CONFIG_SYSFS */



