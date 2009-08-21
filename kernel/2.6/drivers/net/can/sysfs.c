/*
 * $Id: dev.c 542 2007-11-07 13:57:16Z thuermann $
 *
 * Copyright (C) 2007-2008 Wolfgang Grandegger <wg@grandegger.com>
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
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <net/sock.h>
#include <linux/rtnetlink.h>

#include <socketcan/can.h>
#include <socketcan/can/dev.h>

#include "sysfs.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
int strict_strtoul(const char *cp, unsigned int base, unsigned long *res)
{
	char *tail;
	unsigned long val;
	size_t len;

	*res = 0;
	len = strlen(cp);
	if (len == 0)
		return -EINVAL;

	val = simple_strtoul(cp, &tail, base);
	if ((*tail == '\0') ||
		((len == (size_t)(tail - cp) + 1) && (*tail == '\n'))) {
		*res = val;
		return 0;
	}

	return -EINVAL;
}
#endif

#ifdef CONFIG_SYSFS

/*
 * SYSFS access functions and attributes. Use same locking as
 * net/core/net-sysfs.c does.
 */
static inline int dev_isalive(const struct net_device *dev)
{
	return dev->reg_state <= NETREG_REGISTERED;
}

/* use same locking rules as GIF* ioctl's */
static ssize_t can_dev_show(struct device *d,
			    struct device_attribute *attr, char *buf,
			    ssize_t (*fmt)(struct net_device *, char *))
{
	struct net_device *dev = to_net_dev(d);
	ssize_t ret = -EINVAL;

	read_lock(&dev_base_lock);
	if (dev_isalive(dev))
		ret = (*fmt)(dev, buf);
	read_unlock(&dev_base_lock);

	return ret;
}

/* generate a show function for simple field */
#define CAN_DEV_SHOW(field, fmt_string)					\
static ssize_t fmt_can_##field(struct net_device *dev, char *buf)	\
{									\
	struct can_priv *priv = netdev_priv(dev);			\
	return sprintf(buf, fmt_string, priv->field);			\
}									\
static ssize_t show_can_##field(struct device *d,			\
				struct device_attribute *attr,		\
				char *buf)				\
{									\
	return can_dev_show(d, attr, buf, fmt_can_##field);		\
}

/* use same locking and permission rules as SIF* ioctl's */
static ssize_t can_dev_store(struct device *d, struct device_attribute *attr,
			     const char *buf, size_t len,
			     int (*set)(struct net_device *, unsigned long))
{
	struct net_device *dev = to_net_dev(d);
	unsigned long new;
	int ret = -EINVAL;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	ret = strict_strtoul(buf, 0, &new);
	if (ret)
		goto out;

	rtnl_lock();
	if (dev_isalive(dev)) {
		ret = (*set)(dev, new);
		if (!ret)
			ret = len;
	}
	rtnl_unlock();
out:
	return ret;
}

#define CAN_CREATE_FILE(_dev, _name)					\
	if (device_create_file(&_dev->dev, &dev_attr_##_name))		\
		dev_err(ND2D(_dev),					\
			"Couldn't create device file for ##_name\n")

#define CAN_REMOVE_FILE(_dev, _name)					\
	device_remove_file(&_dev->dev, &dev_attr_##_name)		\

CAN_DEV_SHOW(ctrlmode, "0x%x\n");

static int change_can_ctrlmode(struct net_device *dev, unsigned long ctrlmode)
{
	struct can_priv *priv = netdev_priv(dev);

	if (priv->state != CAN_STATE_STOPPED)
		return -EBUSY;

	priv->ctrlmode = ctrlmode;

	return 0;
}

static ssize_t store_can_ctrlmode(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t len)
{
	return can_dev_store(dev, attr, buf, len, change_can_ctrlmode);
}

static DEVICE_ATTR(can_ctrlmode, S_IRUGO | S_IWUSR,
		   show_can_ctrlmode, store_can_ctrlmode);

static const char *can_state_names[] = {
	"active", "bus-warn", "bus-pass" , "bus-off",
	"stopped", "sleeping", "unkown"
};

static ssize_t printf_can_state(struct net_device *dev, char *buf)
{
	struct can_priv *priv = netdev_priv(dev);
	enum can_state state;
	int err = 0;

	if (priv->do_get_state) {
		err = priv->do_get_state(dev, &state);
		if (err)
			goto out;
		priv->state = state;
	} else
		state = priv->state;

	if (state >= ARRAY_SIZE(can_state_names))
		state = ARRAY_SIZE(can_state_names) - 1;
	err = sprintf(buf, "%s\n", can_state_names[state]);
out:
	return err;
}

static ssize_t show_can_state(struct device *d,
			      struct device_attribute *attr, char *buf)
{
	return can_dev_show(d, attr, buf, printf_can_state);
}

static DEVICE_ATTR(can_state, S_IRUGO, show_can_state, NULL);

CAN_DEV_SHOW(restart_ms, "%d\n");

static int change_can_restart_ms(struct net_device *dev, unsigned long ms)
{
	struct can_priv *priv = netdev_priv(dev);

	if (priv->restart_ms < 0)
		return -EOPNOTSUPP;
	if (priv->state != CAN_STATE_STOPPED)
		return -EBUSY;
	priv->restart_ms = ms;
	return 0;
}

static ssize_t store_can_restart_ms(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t len)
{
	return can_dev_store(dev, attr, buf, len, change_can_restart_ms);
}

static DEVICE_ATTR(can_restart_ms, S_IRUGO | S_IWUSR,
		   show_can_restart_ms, store_can_restart_ms);

static ssize_t printf_can_echo(struct net_device *dev, char *buf)
{
	return sprintf(buf, "%d\n", dev->flags & IFF_ECHO ? 1 : 0);
}

static ssize_t show_can_echo(struct device *d,
			  struct device_attribute *attr, char *buf)
{
	return can_dev_show(d, attr, buf, printf_can_echo);
}

static int change_can_echo(struct net_device *dev, unsigned long on)
{
	if (on)
		dev->flags |= IFF_ECHO;
	else
		dev->flags &= ~IFF_ECHO;
	return 0;
}

static ssize_t store_can_echo(struct device *dev,
			      struct device_attribute *attr,
			      const char *buf, size_t len)
{
	return can_dev_store(dev, attr, buf, len, change_can_echo);
}

static DEVICE_ATTR(can_echo, S_IRUGO | S_IWUSR, show_can_echo, store_can_echo);

static int change_can_restart(struct net_device *dev, unsigned long on)
{
	return can_restart_now(dev);
}

static ssize_t store_can_restart(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t len)
{
	return can_dev_store(dev, attr, buf, len, change_can_restart);
}

static DEVICE_ATTR(can_restart, S_IWUSR, NULL, store_can_restart);

/* Show a given attribute if the CAN bittiming group */
static ssize_t can_btc_show(const struct device *d,
			    struct device_attribute *attr, char *buf,
			    unsigned long offset)
{
	struct net_device *dev = to_net_dev(d);
	struct can_priv *priv = netdev_priv(dev);
	struct can_bittiming_const *btc = priv->bittiming_const;
	ssize_t ret = -EINVAL;

	WARN_ON(offset >= sizeof(struct can_bittiming_const) ||
		offset % sizeof(u32) != 0);

	read_lock(&dev_base_lock);
	if (dev_isalive(dev) && btc)
		ret = sprintf(buf, "%d\n",
			      *(u32 *)(((u8 *)btc) + offset));

	read_unlock(&dev_base_lock);
	return ret;
}

/* Generate a read-only bittiming const attribute */
#define CAN_BT_CONST_ENTRY(name)					\
static ssize_t show_##name(struct device *d,				\
			   struct device_attribute *attr, char *buf) 	\
{									\
	return can_btc_show(d, attr, buf,				\
			    offsetof(struct can_bittiming_const, name));\
}									\
static DEVICE_ATTR(hw_##name, S_IRUGO, show_##name, NULL)

CAN_BT_CONST_ENTRY(tseg1_min);
CAN_BT_CONST_ENTRY(tseg1_max);
CAN_BT_CONST_ENTRY(tseg2_min);
CAN_BT_CONST_ENTRY(tseg2_max);
CAN_BT_CONST_ENTRY(sjw_max);
CAN_BT_CONST_ENTRY(brp_min);
CAN_BT_CONST_ENTRY(brp_max);
CAN_BT_CONST_ENTRY(brp_inc);

static ssize_t can_bt_show(const struct device *d,
			   struct device_attribute *attr, char *buf,
			   unsigned long offset)
{
	struct net_device *dev = to_net_dev(d);
	struct can_priv *priv = netdev_priv(dev);
	struct can_bittiming *bt = &priv->bittiming;
	ssize_t ret = -EINVAL;
	u32 *ptr, val;

	WARN_ON(offset >= sizeof(struct can_bittiming) ||
		offset % sizeof(u32) != 0);

	read_lock(&dev_base_lock);
	if (dev_isalive(dev)) {
		ptr = (u32 *)(((u8 *)bt) + offset);
		if (ptr == &bt->sample_point &&
		    priv->state != CAN_STATE_STOPPED)
			val = can_sample_point(bt);
		else
			val = *ptr;
		ret = sprintf(buf, "%d\n", val);
	}
	read_unlock(&dev_base_lock);
	return ret;
}

static ssize_t can_bt_store(const struct device *d,
			    struct device_attribute *attr,
			    const char *buf, size_t count,
			    unsigned long offset)
{
	struct net_device *dev = to_net_dev(d);
	struct can_priv *priv = netdev_priv(dev);
	struct can_bittiming *bt = &priv->bittiming;
	unsigned long new;
	ssize_t ret = -EINVAL;
	u32 *ptr;

	if (priv->state != CAN_STATE_STOPPED)
		return -EBUSY;

	WARN_ON(offset >= sizeof(struct can_bittiming) ||
		offset % sizeof(u32) != 0);

	ret = strict_strtoul(buf, 0, &new);
	if (ret)
		goto out;

	ptr = (u32 *)(((u8 *)bt) + offset);
	rtnl_lock();
	if (dev_isalive(dev)) {
		*ptr = (u32)new;

		if ((ptr == &bt->bitrate) || (ptr == &bt->sample_point)) {
			bt->tq = 0;
			bt->brp = 0;
			bt->sjw = 0;
			bt->prop_seg = 0;
			bt->phase_seg1 = 0;
			bt->phase_seg2 = 0;
		} else {
			bt->bitrate = 0;
			bt->sample_point = 0;
		}
		ret = count;
	}
	rtnl_unlock();
out:
	return ret;
}

static ssize_t fmt_can_clock(struct net_device *dev, char *buf)
{
	struct can_priv *priv = netdev_priv(dev);

	return sprintf(buf, "%d\n", priv->clock.freq);
}

static ssize_t show_can_clock(struct device *d,
			      struct device_attribute *attr,
			      char *buf)
{
	return can_dev_show(d, attr, buf, fmt_can_clock);
}
static DEVICE_ATTR(hw_clock, S_IRUGO, show_can_clock, NULL);

#define CAN_BT_ENTRY(name)						\
static ssize_t show_##name(struct device *d,				\
			   struct device_attribute *attr, char *buf) 	\
{									\
	return can_bt_show(d, attr, buf,				\
			   offsetof(struct can_bittiming, name));	\
}									\
static ssize_t store_##name(struct device *d,				\
			    struct device_attribute *attr,		\
			    const char *buf, size_t count)		\
{									\
	return can_bt_store(d, attr, buf, count,			\
			    offsetof(struct can_bittiming, name));	\
}									\
static DEVICE_ATTR(name, S_IRUGO | S_IWUSR, show_##name, store_##name)

CAN_BT_ENTRY(bitrate);
CAN_BT_ENTRY(sample_point);
CAN_BT_ENTRY(tq);
CAN_BT_ENTRY(prop_seg);
CAN_BT_ENTRY(phase_seg1);
CAN_BT_ENTRY(phase_seg2);
CAN_BT_ENTRY(sjw);

static struct attribute *can_bittiming_attrs[] = {
	&dev_attr_hw_tseg1_min.attr,
	&dev_attr_hw_tseg1_max.attr,
	&dev_attr_hw_tseg2_max.attr,
	&dev_attr_hw_tseg2_min.attr,
	&dev_attr_hw_sjw_max.attr,
	&dev_attr_hw_brp_min.attr,
	&dev_attr_hw_brp_max.attr,
	&dev_attr_hw_brp_inc.attr,
	&dev_attr_hw_clock.attr,
	&dev_attr_bitrate.attr,
	&dev_attr_sample_point.attr,
	&dev_attr_tq.attr,
	&dev_attr_prop_seg.attr,
	&dev_attr_phase_seg1.attr,
	&dev_attr_phase_seg2.attr,
	&dev_attr_sjw.attr,
	NULL
};

/* Minimal number of attributes to support intelligent CAN controllers */
static struct attribute *can_bittiming_min_attrs[] = {
	&dev_attr_bitrate.attr,
	NULL
};

static struct attribute_group can_bittiming_group = {
	.name = "can_bittiming",
	.attrs = can_bittiming_attrs,
};

/* Show a given attribute in the CAN statistics group */
static ssize_t can_stat_show(const struct device *d,
			     struct device_attribute *attr, char *buf,
			     unsigned long offset)
{
	struct net_device *dev = to_net_dev(d);
	struct can_priv *priv = netdev_priv(dev);
	struct can_device_stats *stats = &priv->can_stats;
	ssize_t ret = -EINVAL;

	WARN_ON(offset >= sizeof(struct can_device_stats) ||
		offset % sizeof(unsigned long) != 0);

	read_lock(&dev_base_lock);
	if (dev_isalive(dev))
		ret = sprintf(buf, "%d\n",
			      *(u32 *)(((u8 *)stats) + offset));

	read_unlock(&dev_base_lock);
	return ret;
}

/* Generate a read-only CAN statistics attribute */
#define CAN_STAT_ENTRY(name)						\
static ssize_t show_##name(struct device *d,				\
			   struct device_attribute *attr, char *buf) 	\
{									\
	return can_stat_show(d, attr, buf,				\
			     offsetof(struct can_device_stats, name));	\
}									\
static DEVICE_ATTR(name, S_IRUGO, show_##name, NULL)

CAN_STAT_ENTRY(error_warning);
CAN_STAT_ENTRY(error_passive);
CAN_STAT_ENTRY(bus_off);
CAN_STAT_ENTRY(bus_error);
CAN_STAT_ENTRY(arbitration_lost);
CAN_STAT_ENTRY(restarts);

static struct attribute *can_statistics_attrs[] = {
	&dev_attr_error_warning.attr,
	&dev_attr_error_passive.attr,
	&dev_attr_bus_off.attr,
	&dev_attr_bus_error.attr,
	&dev_attr_arbitration_lost.attr,
	&dev_attr_restarts.attr,
	NULL
};

static struct attribute_group can_statistics_group = {
	.name = "can_statistics",
	.attrs = can_statistics_attrs,
};

void can_create_sysfs(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);
	int err;

	CAN_CREATE_FILE(dev, can_ctrlmode);
	CAN_CREATE_FILE(dev, can_echo);
	CAN_CREATE_FILE(dev, can_restart);
	CAN_CREATE_FILE(dev, can_state);
	CAN_CREATE_FILE(dev, can_restart_ms);

	err = sysfs_create_group(&(dev->dev.kobj),
				 &can_statistics_group);
	if (err) {
		printk(KERN_EMERG
		       "couldn't create sysfs group for CAN statistics\n");
	}

	if (!priv->bittiming_const)
		can_bittiming_group.attrs = can_bittiming_min_attrs;
	err = sysfs_create_group(&(dev->dev.kobj), &can_bittiming_group);
	if (err) {
		printk(KERN_EMERG "couldn't create sysfs "
		       "group for CAN bittiming\n");
	}
}

void can_remove_sysfs(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);

	CAN_REMOVE_FILE(dev, can_ctrlmode);
	CAN_REMOVE_FILE(dev, can_echo);
	CAN_REMOVE_FILE(dev, can_state);
	CAN_REMOVE_FILE(dev, can_restart);
	CAN_REMOVE_FILE(dev, can_restart_ms);

	sysfs_remove_group(&(dev->dev.kobj), &can_statistics_group);
	if (priv->bittiming_const)
		sysfs_remove_group(&(dev->dev.kobj), &can_bittiming_group);
}

#endif /* CONFIG_SYSFS */



