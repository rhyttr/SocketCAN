/*
 * gw.c - CAN frame Gateway/Router/Bridge with netlink interface
 *
 * Copyright (c) 2002-2010 Volkswagen Group Electronic Research
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Volkswagen nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
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
 * Send feedback to <socketcan-users@lists.berlios.de>
 *
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <socketcan/can.h>
#include <socketcan/can/core.h>
#include <socketcan/can/gw.h>
#include <net/rtnetlink.h>
#include <net/net_namespace.h>

#include <socketcan/can/version.h> /* for RCSID. Removed by mkpatch script */
RCSID("$Id$");

#define CAN_GW_VERSION "20100218"
static __initdata const char banner[] =
	KERN_INFO "can: netlink gateway (rev " CAN_GW_VERSION ")\n";

MODULE_DESCRIPTION("PF_CAN netlink gateway");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Oliver Hartkopp <oliver.hartkopp@volkswagen.de>");

HLIST_HEAD(can_gw_list);
static DEFINE_SPINLOCK(can_gw_list_lock);
static struct notifier_block notifier;

static struct kmem_cache *gw_cache __read_mostly;

#define GW_SK_MAGIC ((void *)(&notifier))

/*
 * So far we just support CAN -> CAN routing and frame modifications.
 *
 * The internal can_can_gw structure contains optional attributes for
 * a CAN -> CAN gateway job.
 */
struct can_can_gw {
	struct can_filter filter;
	struct {
		struct can_frame and;
		struct can_frame or;
		struct can_frame xor;
		struct can_frame set;
	} modframe;
	void (*modfunc[MAX_MODFUNCTIONS])(struct can_frame *cf,
					  struct can_can_gw *mod);
};

/* list entry for CAN gateways jobs */
struct gw_job {
	struct hlist_node list;
	struct rcu_head rcu;
	struct net_device *src_dev;
	struct net_device *dst_dev;
	u32 flags;
	u32 handled_frames;
	u32 dropped_frames;
	union {
		struct can_can_gw ccgw;
		/* tbc */
	};
};

/* content of u32 gwjob.flags */
#define CAN_TX_LOOPBACK 0x00000001

/* modification functions that are invoked in the hot path in gw_rcv */
void mod_and_id (struct can_frame *cf, struct can_can_gw *mod) {
	cf->can_id &= mod->modframe.and.can_id;
}
void mod_and_dlc (struct can_frame *cf, struct can_can_gw *mod) {
	cf->can_dlc &= mod->modframe.and.can_dlc;
}
void mod_and_data (struct can_frame *cf, struct can_can_gw *mod) {
	*(u64 *)cf->data &= *(u64 *)mod->modframe.and.data;
}
void mod_or_id (struct can_frame *cf, struct can_can_gw *mod) {
	cf->can_id |= mod->modframe.or.can_id;
}
void mod_or_dlc (struct can_frame *cf, struct can_can_gw *mod) {
	cf->can_dlc |= mod->modframe.or.can_dlc;
}
void mod_or_data (struct can_frame *cf, struct can_can_gw *mod) {
	*(u64 *)cf->data |= *(u64 *)mod->modframe.or.data;
}
void mod_xor_id (struct can_frame *cf, struct can_can_gw *mod) {
	cf->can_id ^= mod->modframe.xor.can_id;
}
void mod_xor_dlc (struct can_frame *cf, struct can_can_gw *mod) {
	cf->can_dlc ^= mod->modframe.xor.can_dlc;
}
void mod_xor_data (struct can_frame *cf, struct can_can_gw *mod) {
	*(u64 *)cf->data ^= *(u64 *)mod->modframe.xor.data;
}
void mod_set_id (struct can_frame *cf, struct can_can_gw *mod) {
	cf->can_id = mod->modframe.set.can_id;
}
void mod_set_dlc (struct can_frame *cf, struct can_can_gw *mod) {
	cf->can_dlc = mod->modframe.set.can_dlc;
}
void mod_set_data (struct can_frame *cf, struct can_can_gw *mod) {
	*(u64 *)cf->data = *(u64 *)mod->modframe.set.data;
}


/* the receive & process & send function */
static void gw_rcv(struct sk_buff *skb, void *data)
{
	struct gw_job *gwj = (struct gw_job *)data;
	struct can_frame *cf;
	struct sk_buff *nskb;
	int modidx = 0;

	/* do not handle already routed frames */
	if (skb->sk == GW_SK_MAGIC)
		return;

	if (!netif_running(gwj->dst_dev)) {
		gwj->dropped_frames++;
		return;
	}

	/*
	 * clone the given skb, which has not been done in can_rv()
	 *
	 * When there is at least one modification function activated,
	 * we need to copy the skb as we want to modify skb->data.
	 */
	if (gwj->ccgw.modfunc[0])
		nskb = skb_copy(skb, GFP_ATOMIC);
	else
		nskb = skb_clone(skb, GFP_ATOMIC);

	if (!nskb) {
		gwj->dropped_frames++;
		return;
	}

	/* mark routed frames with a 'special' sk value */
	nskb->sk = GW_SK_MAGIC;
	nskb->dev = gwj->dst_dev;

	/* pointer to modifiable CAN frame */
	cf = (struct can_frame *)nskb->data;

	/* perform preprocessed modification functions if there are any */
	while (modidx < MAX_MODFUNCTIONS && gwj->ccgw.modfunc[modidx])
		(*gwj->ccgw.modfunc[modidx++])(cf, &gwj->ccgw);

	/* send to netdevice */
	if (can_send(nskb, gwj->flags & CAN_TX_LOOPBACK))
		gwj->dropped_frames++;
	else
		gwj->handled_frames++;
}

static inline int can_gw_register_filter(struct gw_job *gwj)
{
	return can_rx_register(gwj->src_dev, gwj->ccgw.filter.can_id,
			       gwj->ccgw.filter.can_mask, gw_rcv, gwj, "gw");
}

static inline void can_gw_unregister_filter(struct gw_job *gwj)
{
	can_rx_unregister(gwj->src_dev, gwj->ccgw.filter.can_id,
			  gwj->ccgw.filter.can_mask, gw_rcv, gwj);
}

static int gw_notifier(struct notifier_block *nb,
			unsigned long msg, void *data)
{
	struct net_device *dev = (struct net_device *)data;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
	if (!net_eq(dev_net(dev), &init_net))
		return NOTIFY_DONE;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	if (dev->nd_net != &init_net)
		return NOTIFY_DONE;
#endif
	if (dev->type != ARPHRD_CAN)
		return NOTIFY_DONE;

	if (msg == NETDEV_UNREGISTER) {

		struct gw_job *gwj = NULL;
		struct hlist_node *n, *nx;

		spin_lock(&can_gw_list_lock);

		hlist_for_each_entry_safe(gwj, n, nx, &can_gw_list, list) {

			if (gwj->src_dev == dev || gwj->dst_dev == dev) { 
				hlist_del(&gwj->list);
				can_gw_unregister_filter(gwj);
				kfree(gwj);
			}
		}

		spin_unlock(&can_gw_list_lock);
	}

	return NOTIFY_DONE;
}

/*
 * Dump information about all ports, in response to GETROUTE
 */
static int gw_dump_jobs(struct sk_buff *skb, struct netlink_callback *cb)
{
	printk(KERN_INFO "%s (TODO)\n", __FUNCTION__);

	return 0;
}

static int gw_create_job(struct sk_buff *skb,  struct nlmsghdr *nlh, void *arg)
{

	struct rtcanmsg *r;
	struct nlattr *tb[CGW_MAX+1];
	struct gw_job *gwj;
	u8 buf[CGW_MODATTR_LEN];
	int modidx = 0;
	int err = 0;

	printk(KERN_INFO "%s: len %d attrlen %d\n", __FUNCTION__,
	       nlmsg_len(nlh), nlmsg_attrlen(nlh, sizeof(*r)));

	if (nlmsg_len(nlh) < sizeof(*r))
                return -EINVAL;

        r = nlmsg_data(nlh);
        if (r->can_family != AF_CAN)
                return -EPFNOSUPPORT;

	gwj = kmem_cache_alloc(gw_cache, GFP_KERNEL);
	if (!gwj)
		return -ENOMEM;

	gwj->src_dev = dev_get_by_index(&init_net, r->src_ifindex);
	if (!gwj->src_dev) {
		err = -ENODEV;
		goto fail;
	}

	/* for now the source device needs to be a CAN device */
	if (gwj->src_dev->type != ARPHRD_CAN) {
		err = -ENODEV;
		goto put_src_fail;
	}

	gwj->dst_dev = dev_get_by_index(&init_net, r->dst_ifindex);
	if (!gwj->dst_dev) {
		err = -ENODEV;
		goto put_src_fail;
	}

	/* for now the destination device needs to be a CAN device */
	if (gwj->dst_dev->type != ARPHRD_CAN) {
		err = -ENODEV;
		goto put_src_dst_fail;
	}

	gwj->flags = 0;

	if (r->can_txflags & CAN_GW_TXFLAGS_LOOPBACK)
		gwj->flags |= CAN_TX_LOOPBACK;

	memset(&gwj->ccgw, 0, sizeof(gwj->ccgw)); 

	/* check for additional attributes / filters here */

	err = nlmsg_parse(nlh, sizeof(*r), tb, CGW_MAX, NULL);
	if (err < 0)
		goto put_src_dst_fail;

	/* check for can_filter in attributes */
	if (tb[CGW_FILTER] &&
	    nla_len(tb[CGW_FILTER]) == sizeof(struct can_filter))
		nla_memcpy(&gwj->ccgw.filter, tb[CGW_FILTER],
			   sizeof(struct can_filter));

	/* check for AND/OR/XOR/SET modifications */
	if (tb[CGW_MOD_AND] &&
	    nla_len(tb[CGW_MOD_AND]) == CGW_MODATTR_LEN) {
		nla_memcpy(&buf, tb[CGW_MOD_AND], CGW_MODATTR_LEN);

		memcpy(&gwj->ccgw.modframe.and, &buf[1],
		       sizeof(struct can_frame));

		if (buf[0] & CGW_MOD_ID)
			gwj->ccgw.modfunc[modidx++] = mod_and_id;

		if (buf[0] & CGW_MOD_DLC)
			gwj->ccgw.modfunc[modidx++] = mod_and_dlc;

		if (buf[0] & CGW_MOD_DATA)
			gwj->ccgw.modfunc[modidx++] = mod_and_data;
	}

	if (tb[CGW_MOD_OR] &&
	    nla_len(tb[CGW_MOD_OR]) == CGW_MODATTR_LEN) {
		nla_memcpy(&buf, tb[CGW_MOD_OR], CGW_MODATTR_LEN);

		memcpy(&gwj->ccgw.modframe.or, &buf[1],
		       sizeof(struct can_frame));

		if (buf[0] & CGW_MOD_ID)
			gwj->ccgw.modfunc[modidx++] = mod_or_id;

		if (buf[0] & CGW_MOD_DLC)
			gwj->ccgw.modfunc[modidx++] = mod_or_dlc;

		if (buf[0] & CGW_MOD_DATA)
			gwj->ccgw.modfunc[modidx++] = mod_or_data;
	}

	if (tb[CGW_MOD_XOR] &&
	    nla_len(tb[CGW_MOD_XOR]) == CGW_MODATTR_LEN) {
		nla_memcpy(&buf, tb[CGW_MOD_XOR], CGW_MODATTR_LEN);

		memcpy(&gwj->ccgw.modframe.xor, &buf[1],
		       sizeof(struct can_frame));

		if (buf[0] & CGW_MOD_ID)
			gwj->ccgw.modfunc[modidx++] = mod_xor_id;

		if (buf[0] & CGW_MOD_DLC)
			gwj->ccgw.modfunc[modidx++] = mod_xor_dlc;

		if (buf[0] & CGW_MOD_DATA)
			gwj->ccgw.modfunc[modidx++] = mod_xor_data;
	}

	if (tb[CGW_MOD_SET] &&
	    nla_len(tb[CGW_MOD_SET]) == CGW_MODATTR_LEN) {
		nla_memcpy(&buf, tb[CGW_MOD_SET], CGW_MODATTR_LEN);

		memcpy(&gwj->ccgw.modframe.set, &buf[1],
		       sizeof(struct can_frame));

		if (buf[0] & CGW_MOD_ID)
			gwj->ccgw.modfunc[modidx++] = mod_set_id;

		if (buf[0] & CGW_MOD_DLC)
			gwj->ccgw.modfunc[modidx++] = mod_set_dlc;

		if (buf[0] & CGW_MOD_DATA)
			gwj->ccgw.modfunc[modidx++] = mod_set_data;
	}

	spin_lock(&can_gw_list_lock);

	err = can_gw_register_filter(gwj);
	if (!err)
		hlist_add_head_rcu(&gwj->list, &can_gw_list);

	spin_unlock(&can_gw_list_lock);
	
	dev_put(gwj->src_dev);
	dev_put(gwj->dst_dev);

	if (err)
		goto fail;

	return 0;

put_src_dst_fail:
	dev_put(gwj->dst_dev);
put_src_fail:
	dev_put(gwj->src_dev);
fail:
	kmem_cache_free(gw_cache, gwj);
	return err;
}

static int gw_remove_job(struct sk_buff *skb,  struct nlmsghdr *nlh, void *arg)
{
	printk(KERN_INFO "%s (TODO)\n", __FUNCTION__);

	return 0;
}

static __init int gw_module_init(void)
{
	printk(banner);

	gw_cache = kmem_cache_create("can_gw", sizeof(struct gw_job),
				      0, 0, NULL);

	if (!gw_cache)
		return -ENOMEM;

	/* set notifier */
	notifier.notifier_call = gw_notifier;
	register_netdevice_notifier(&notifier);

	if (__rtnl_register(PF_CAN, RTM_GETROUTE, NULL, gw_dump_jobs)) {
		unregister_netdevice_notifier(&notifier);
		kmem_cache_destroy(gw_cache);
		return -ENOBUFS;
	}

	/* Only the first call to __rtnl_register can fail */
	__rtnl_register(PF_CAN, RTM_NEWROUTE, gw_create_job, NULL);
	__rtnl_register(PF_CAN, RTM_DELROUTE, gw_remove_job, NULL);

	return 0;
}

static __exit void gw_module_exit(void)
{
	struct gw_job *gwj = NULL;
	struct hlist_node *n, *nx;

	rtnl_unregister_all(PF_CAN);

	unregister_netdevice_notifier(&notifier);

	spin_lock(&can_gw_list_lock);

	hlist_for_each_entry_safe(gwj, n, nx, &can_gw_list, list) {
		hlist_del(&gwj->list);
		can_gw_unregister_filter(gwj);
		kfree(gwj);
	}

	spin_unlock(&can_gw_list_lock);

	rcu_barrier(); /* Wait for completion of call_rcu()'s */

	kmem_cache_destroy(gw_cache);
}

module_init(gw_module_init);
module_exit(gw_module_exit);
