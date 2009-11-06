/*
* drivers/net/can/softing/softing_sysfs.c
*
* Copyright (C) 2009
*
* - Kurt Van Dijck, EIA Electronics
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
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
*/

#include <linux/version.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/mutex.h>

#include "softing.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
#error This driver does not support Kernel versions < 2.6.23
#endif

/*sysfs stuff*/

/* Because the struct softing may be used by pcmcia devices
 * as well as pci devices, * we have no clue how to get
 * from a struct device * towards the struct softing *.
 * It may go over a pci_device->priv or over a pcmcia_device->priv.
 * Therefore, provide the struct softing pointer within the attribute.
 * Then we don't need driver/bus specific things in these attributes
 */
struct softing_attribute {
	struct device_attribute dev;
	ssize_t (*show) (struct softing *card, char *buf);
	ssize_t (*store)(struct softing *card, const char *buf, size_t count);
	struct softing *card;
};

static ssize_t rd_card_attr(struct device *dev, struct device_attribute *attr
		, char *buf) {
	struct softing_attribute *cattr
		= container_of(attr, struct softing_attribute, dev);
	return cattr->show ? cattr->show(cattr->card, buf) : 0;
}
static ssize_t wr_card_attr(struct device *dev, struct device_attribute *attr
		, const char *buf, size_t count) {
	struct softing_attribute *cattr
		= container_of(attr, struct softing_attribute, dev);
	return cattr->store ? cattr->store(cattr->card, buf, count) : 0;
}

#define declare_attr(_name, _mode, _show, _store) { \
	.dev = { \
		.attr = { \
			.name = __stringify(_name), \
			.mode = _mode, \
		}, \
		.show = rd_card_attr, \
		.store = wr_card_attr, \
	}, \
	.show =	_show, \
	.store = _store, \
}

#define CARD_SHOW(name, member) \
static ssize_t show_##name(struct softing *card, char *buf) { \
	return sprintf(buf, "%u\n", card->member); \
}
CARD_SHOW(serial	, id.serial);
CARD_SHOW(firmware	, id.fw);
CARD_SHOW(hardware	, id.hw);
CARD_SHOW(license	, id.lic);
CARD_SHOW(freq		, id.freq);
CARD_SHOW(txpending	, tx.pending);

static const struct softing_attribute card_attr_proto[] = {
	declare_attr(serial	, 0444, show_serial	, 0),
	declare_attr(firmware	, 0444, show_firmware	, 0),
	declare_attr(hardware	, 0444, show_hardware	, 0),
	declare_attr(license	, 0444, show_license	, 0),
	declare_attr(freq	, 0444, show_freq	, 0),
	declare_attr(txpending	, 0644, show_txpending	, 0),
};

int softing_card_sysfs_create(struct softing *card)
{
	int size;
	int j;

	size = sizeof(card_attr_proto)/sizeof(card_attr_proto[0]);
	card->attr = kmalloc((size+1)*sizeof(card->attr[0]), GFP_KERNEL);
	if (!card->attr)
		goto attr_mem_failed;
	memcpy(card->attr, card_attr_proto, size * sizeof(card->attr[0]));
	memset(&card->attr[size], 0, sizeof(card->attr[0]));

	card->grp  = kmalloc((size+1)*sizeof(card->grp[0]), GFP_KERNEL);
	if (!card->grp)
		goto grp_mem_failed;

	for (j = 0; j < size; ++j) {
		card->attr[j].card = card;
		card->grp[j] = &card->attr[j].dev.attr;
		if (!card->attr[j].show)
			card->attr[j].dev.attr.mode &= ~(S_IRUGO);
		if (!card->attr[j].store)
			card->attr[j].dev.attr.mode &= ~(S_IWUGO);
	}
	card->grp[size] = 0;
	card->sysfs.name	= "softing";
	card->sysfs.attrs = card->grp;
	if (sysfs_create_group(&card->dev->kobj, &card->sysfs) < 0)
		goto sysfs_failed;

	return 0;

sysfs_failed:
	kfree(card->grp);
grp_mem_failed:
	kfree(card->attr);
attr_mem_failed:
	return -1;
}
void softing_card_sysfs_remove(struct softing *card)
{
	sysfs_remove_group(&card->dev->kobj, &card->sysfs);
	kfree(card->grp);
	kfree(card->attr);
}

static ssize_t show_channel(struct device *dev
		, struct device_attribute *attr, char *buf)
{
	struct net_device *ndev = to_net_dev(dev);
	struct softing_priv *priv = netdev2softing(ndev);
	return sprintf(buf, "%i\n", priv->index);
}

static ssize_t show_chip(struct device *dev
		, struct device_attribute *attr, char *buf)
{
	struct net_device *ndev = to_net_dev(dev);
	struct softing_priv *priv = netdev2softing(ndev);
	return sprintf(buf, "%i\n", priv->chip);
}

static ssize_t show_output(struct device *dev
		, struct device_attribute *attr, char *buf)
{
	struct net_device *ndev = to_net_dev(dev);
	struct softing_priv *priv = netdev2softing(ndev);
	return sprintf(buf, "0x%02x\n", priv->output);
}

static ssize_t store_output(struct device *dev
		, struct device_attribute *attr
		, const char *buf, size_t count)
{
	struct net_device *ndev = to_net_dev(dev);
	struct softing_priv *priv = netdev2softing(ndev);
	struct softing *card = priv->card;
	unsigned long val;
	int ret;

	ret = strict_strtoul(buf, 0, &val);
	if (ret < 0)
		return ret;
	val &= 0xFF;

	ret = mutex_lock_interruptible(&card->fw.lock);
	if (ret)
		return -ERESTARTSYS;
	if (netif_running(ndev)) {
		mutex_unlock(&card->fw.lock);
		return -EBUSY;
	}
	priv->output = val;
	mutex_unlock(&card->fw.lock);
	return count;
}
/* TODO
 * the latest softing cards support sleep mode too
 */

static const DEVICE_ATTR(channel, S_IRUGO, show_channel, 0);
static const DEVICE_ATTR(chip, S_IRUGO, show_chip, 0);
static const DEVICE_ATTR(output, S_IRUGO | S_IWUSR, show_output, store_output);

static const struct attribute *const netdev_sysfs_entries[] = {
	&dev_attr_channel	.attr,
	&dev_attr_chip		.attr,
	&dev_attr_output	.attr,
	0,
};
static const struct attribute_group netdev_sysfs = {
	.name  = 0,
	.attrs = (struct attribute **)netdev_sysfs_entries,
};

int softing_bus_sysfs_create(struct softing_priv *priv)
{
	if (!priv->netdev->dev.kobj.sd) {
		dev_alert(priv->card->dev, "sysfs_create_group would fail\n");
		return ENODEV;
	}
	return sysfs_create_group(&priv->netdev->dev.kobj, &netdev_sysfs);
}
void softing_bus_sysfs_remove(struct softing_priv *priv)
{
	sysfs_remove_group(&priv->netdev->dev.kobj, &netdev_sysfs);
}

