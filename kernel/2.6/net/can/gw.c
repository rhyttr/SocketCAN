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
#include <linux/rculist.h>
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

#define CAN_GW_VERSION "20100222"
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
	struct {
		u8 and;
		u8 or;
		u8 xor;
		u8 set;
	} modtype;
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

/* content of u32 gw_job.flags */
#define CAN_TX_ECHO 0x00000001
#define CAN_TX_SRC_TSTAMP 0x00000002

/* modification functions that are invoked in the hot path in gw_rcv */
static void mod_and_id (struct can_frame *cf, struct can_can_gw *mod) {
	cf->can_id &= mod->modframe.and.can_id;
}
static void mod_and_dlc (struct can_frame *cf, struct can_can_gw *mod) {
	cf->can_dlc &= mod->modframe.and.can_dlc;
}
static void mod_and_data (struct can_frame *cf, struct can_can_gw *mod) {
	*(u64 *)cf->data &= *(u64 *)mod->modframe.and.data;
}
static void mod_or_id (struct can_frame *cf, struct can_can_gw *mod) {
	cf->can_id |= mod->modframe.or.can_id;
}
static void mod_or_dlc (struct can_frame *cf, struct can_can_gw *mod) {
	cf->can_dlc |= mod->modframe.or.can_dlc;
}
static void mod_or_data (struct can_frame *cf, struct can_can_gw *mod) {
	*(u64 *)cf->data |= *(u64 *)mod->modframe.or.data;
}
static void mod_xor_id (struct can_frame *cf, struct can_can_gw *mod) {
	cf->can_id ^= mod->modframe.xor.can_id;
}
static void mod_xor_dlc (struct can_frame *cf, struct can_can_gw *mod) {
	cf->can_dlc ^= mod->modframe.xor.can_dlc;
}
static void mod_xor_data (struct can_frame *cf, struct can_can_gw *mod) {
	*(u64 *)cf->data ^= *(u64 *)mod->modframe.xor.data;
}
static void mod_set_id (struct can_frame *cf, struct can_can_gw *mod) {
	cf->can_id = mod->modframe.set.can_id;
}
static void mod_set_dlc (struct can_frame *cf, struct can_can_gw *mod) {
	cf->can_dlc = mod->modframe.set.can_dlc;
}
static void mod_set_data (struct can_frame *cf, struct can_can_gw *mod) {
	*(u64 *)cf->data = *(u64 *)mod->modframe.set.data;
}

static inline void canframecpy(struct can_frame *dst, struct can_frame *src)
{
	/*
	 * Copy the struct members separately to ensure that no uninitialized
	 * data are copied in the 3 bytes hole of the struct. This is needed
	 * to make easy compares of the data in the struct can_can_gw.
	 */

	dst->can_id = src->can_id;
	dst->can_dlc = src->can_dlc;
	*(u64 *)dst->data = *(u64 *)src->data;
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

	if (!(gwj->dst_dev->flags & IFF_UP)) {
		gwj->dropped_frames++;
		return;
	}

	/*
	 * clone the given skb, which has not been done in can_rcv()
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

	/* clear the skb timestamp if not configured the other way */
	if (!(gwj->flags & CAN_TX_SRC_TSTAMP))
		nskb->tstamp.tv64 = 0;

	/* send to netdevice */
	if (can_send(nskb, gwj->flags & CAN_TX_ECHO))
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

static int gw_put_job(struct sk_buff *skb, struct gw_job *gwj)
{
	struct {
		struct can_frame cf;
		u8 modtype;
	} __attribute__((packed)) mb;

	struct rtcanmsg *rtcan;
	struct nlmsghdr *nlh = nlmsg_put(skb, 0, 0, 0, sizeof(*rtcan), 0);
	if (!nlh)
		return -EMSGSIZE;

	rtcan = nlmsg_data(nlh);
	rtcan->can_family = AF_CAN;
	rtcan->src_ifindex = gwj->src_dev->ifindex;
	rtcan->dst_ifindex = gwj->dst_dev->ifindex;
	rtcan->can_txflags = 0;

	if (gwj->flags & CAN_TX_ECHO)
		rtcan->can_txflags |= CAN_GW_TXFLAGS_ECHO;

	if (gwj->flags & CAN_TX_SRC_TSTAMP)
		rtcan->can_txflags |= CAN_GW_TXFLAGS_SRC_TSTAMP;

	/* check non default settings of attributes */
	if (gwj->handled_frames) {
		if (nla_put_u32(skb, CGW_HANDLED, gwj->handled_frames) < 0)
			goto cancel;
		else
			nlh->nlmsg_len += NLA_HDRLEN + NLA_ALIGN(sizeof(u32));
	}

	if (gwj->dropped_frames) {
		if (nla_put_u32(skb, CGW_DROPPED, gwj->dropped_frames) < 0)
			goto cancel;
		else
			nlh->nlmsg_len += NLA_HDRLEN + NLA_ALIGN(sizeof(u32));
	}

	if (gwj->ccgw.filter.can_id || gwj->ccgw.filter.can_mask) {
		if (nla_put(skb, CGW_FILTER, sizeof(struct can_filter),
			    &gwj->ccgw.filter) < 0)
			goto cancel;
		else
			nlh->nlmsg_len += NLA_HDRLEN +
				NLA_ALIGN(sizeof(struct can_filter));
	}

	if (gwj->ccgw.modtype.and) {
		memcpy(&mb.cf, &gwj->ccgw.modframe.and, sizeof(mb.cf));
		mb.modtype = gwj->ccgw.modtype.and;
		if (nla_put(skb, CGW_MOD_AND, sizeof(mb), &mb) < 0)
			goto cancel;
		else
			nlh->nlmsg_len += NLA_HDRLEN + NLA_ALIGN(sizeof(mb));
	}

	if (gwj->ccgw.modtype.or) {
		memcpy(&mb.cf, &gwj->ccgw.modframe.or, sizeof(mb.cf));
		mb.modtype = gwj->ccgw.modtype.or;
		if (nla_put(skb, CGW_MOD_OR, sizeof(mb), &mb) < 0)
			goto cancel;
		else
			nlh->nlmsg_len += NLA_HDRLEN + NLA_ALIGN(sizeof(mb));
	}

	if (gwj->ccgw.modtype.xor) {
		memcpy(&mb.cf, &gwj->ccgw.modframe.xor, sizeof(mb.cf));
		mb.modtype = gwj->ccgw.modtype.xor;
		if (nla_put(skb, CGW_MOD_XOR, sizeof(mb), &mb) < 0)
			goto cancel;
		else
			nlh->nlmsg_len += NLA_HDRLEN + NLA_ALIGN(sizeof(mb));
	}

	if (gwj->ccgw.modtype.set) {
		memcpy(&mb.cf, &gwj->ccgw.modframe.set, sizeof(mb.cf));
		mb.modtype = gwj->ccgw.modtype.set;
		if (nla_put(skb, CGW_MOD_SET, sizeof(mb), &mb) < 0)
			goto cancel;
		else
			nlh->nlmsg_len += NLA_HDRLEN + NLA_ALIGN(sizeof(mb));
	}

	return skb->len;

cancel:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

/* Dump information about all CAN gateway jobs, in response to RTM_GETROUTE */
static int gw_dump_jobs(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct gw_job *gwj = NULL;
	struct hlist_node *n;
	int idx = 0;
	int ret = 0;

	rcu_read_lock();
	hlist_for_each_entry_rcu(gwj, n, &can_gw_list, list) {
		if (idx >= cb->args[0]) {
			ret = gw_put_job(skb, gwj);
			if (ret > 0)
				cb->args[0]++;
			break;
		}
		idx++;
	}
	rcu_read_unlock();

	return ret;
}

/* check for attributes / filters for the CAN->CAN gateway */
static int can_can_parse_attr(struct nlmsghdr *nlh, struct can_can_gw *ccgw)
{
	struct nlattr *tb[CGW_MAX+1];
	int modidx = 0;
	int err = 0;

	struct {
		struct can_frame cf;
		u8 modtype;
	} __attribute__((packed)) mb;

	BUILD_BUG_ON(sizeof(mb) != CGW_MODATTR_LEN);

	memset(ccgw, 0, sizeof(*ccgw)); 

	err = nlmsg_parse(nlh, sizeof(struct rtcanmsg), tb, CGW_MAX, NULL);
	if (err < 0)
		return err;

	/* check for can_filter in attributes */
	if (tb[CGW_FILTER] &&
	    nla_len(tb[CGW_FILTER]) == sizeof(struct can_filter))
		nla_memcpy(&ccgw->filter, tb[CGW_FILTER],
			   sizeof(struct can_filter));

	/* check for AND/OR/XOR/SET modifications */
	if (tb[CGW_MOD_AND] &&
	    nla_len(tb[CGW_MOD_AND]) == CGW_MODATTR_LEN) {
		nla_memcpy(&mb, tb[CGW_MOD_AND], CGW_MODATTR_LEN);

		canframecpy(&ccgw->modframe.and, &mb.cf);
		ccgw->modtype.and = mb.modtype;

		if (mb.modtype & CGW_MOD_ID)
			ccgw->modfunc[modidx++] = mod_and_id;

		if (mb.modtype & CGW_MOD_DLC)
			ccgw->modfunc[modidx++] = mod_and_dlc;

		if (mb.modtype & CGW_MOD_DATA)
			ccgw->modfunc[modidx++] = mod_and_data;
	}

	if (tb[CGW_MOD_OR] &&
	    nla_len(tb[CGW_MOD_OR]) == CGW_MODATTR_LEN) {
		nla_memcpy(&mb, tb[CGW_MOD_OR], CGW_MODATTR_LEN);

		canframecpy(&ccgw->modframe.or, &mb.cf);
		ccgw->modtype.or = mb.modtype;

		if (mb.modtype & CGW_MOD_ID)
			ccgw->modfunc[modidx++] = mod_or_id;

		if (mb.modtype & CGW_MOD_DLC)
			ccgw->modfunc[modidx++] = mod_or_dlc;

		if (mb.modtype & CGW_MOD_DATA)
			ccgw->modfunc[modidx++] = mod_or_data;
	}

	if (tb[CGW_MOD_XOR] &&
	    nla_len(tb[CGW_MOD_XOR]) == CGW_MODATTR_LEN) {
		nla_memcpy(&mb, tb[CGW_MOD_XOR], CGW_MODATTR_LEN);

		canframecpy(&ccgw->modframe.xor, &mb.cf);
		ccgw->modtype.xor = mb.modtype;

		if (mb.modtype & CGW_MOD_ID)
			ccgw->modfunc[modidx++] = mod_xor_id;

		if (mb.modtype & CGW_MOD_DLC)
			ccgw->modfunc[modidx++] = mod_xor_dlc;

		if (mb.modtype & CGW_MOD_DATA)
			ccgw->modfunc[modidx++] = mod_xor_data;
	}

	if (tb[CGW_MOD_SET] &&
	    nla_len(tb[CGW_MOD_SET]) == CGW_MODATTR_LEN) {
		nla_memcpy(&mb, tb[CGW_MOD_SET], CGW_MODATTR_LEN);

		canframecpy(&ccgw->modframe.set, &mb.cf);
		ccgw->modtype.set = mb.modtype;

		if (mb.modtype & CGW_MOD_ID)
			ccgw->modfunc[modidx++] = mod_set_id;

		if (mb.modtype & CGW_MOD_DLC)
			ccgw->modfunc[modidx++] = mod_set_dlc;

		if (mb.modtype & CGW_MOD_DATA)
			ccgw->modfunc[modidx++] = mod_set_data;
	}

	return 0;
}

static int gw_create_job(struct sk_buff *skb,  struct nlmsghdr *nlh, void *arg)
{
	struct rtcanmsg *r;
	struct gw_job *gwj;
	int err = 0;

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

	gwj->handled_frames = 0;
	gwj->dropped_frames = 0;
	gwj->flags = 0;

	if (r->can_txflags & CAN_GW_TXFLAGS_ECHO)
		gwj->flags |= CAN_TX_ECHO;

	if (r->can_txflags & CAN_GW_TXFLAGS_SRC_TSTAMP)
		gwj->flags |= CAN_TX_SRC_TSTAMP;

	err = can_can_parse_attr(nlh, &gwj->ccgw);
	if (err < 0)
		goto put_src_dst_fail;

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

static void gw_remove_all_jobs(void)
{
	struct gw_job *gwj = NULL;
	struct hlist_node *n, *nx;

	spin_lock(&can_gw_list_lock);

	hlist_for_each_entry_safe(gwj, n, nx, &can_gw_list, list) {
		hlist_del(&gwj->list);
		can_gw_unregister_filter(gwj);
		kfree(gwj);
	}

	spin_unlock(&can_gw_list_lock);
}

static int gw_remove_job(struct sk_buff *skb,  struct nlmsghdr *nlh, void *arg)
{
	struct gw_job *gwj = NULL;
	struct hlist_node *n, *nx;
	struct rtcanmsg *r;
	struct can_can_gw ccgw;
	u32 flags = 0;
	int err = 0;

	if (nlmsg_len(nlh) < sizeof(*r))
                return -EINVAL;

        r = nlmsg_data(nlh);
        if (r->can_family != AF_CAN)
                return -EPFNOSUPPORT;

	/* if_index set to 0 => remove all entries */
	if (!r->src_ifindex && !r->dst_ifindex) {
		gw_remove_all_jobs();
		return 0;
	}

	if (r->can_txflags & CAN_GW_TXFLAGS_ECHO)
		flags |= CAN_TX_ECHO;

	if (r->can_txflags & CAN_GW_TXFLAGS_SRC_TSTAMP)
		flags |= CAN_TX_SRC_TSTAMP;

	err = can_can_parse_attr(nlh, &ccgw);
	if (err < 0)
		return err;

	err = -EINVAL;

	spin_lock(&can_gw_list_lock);

	/* remove only the first matching entry */
	hlist_for_each_entry_safe(gwj, n, nx, &can_gw_list, list) {

		if (gwj->dst_dev->ifindex != r->dst_ifindex)
			continue;

		if (gwj->src_dev->ifindex != r->src_ifindex)
			continue;

		if (gwj->flags != flags)
			continue;

		if (memcmp(&gwj->ccgw, &ccgw, sizeof(ccgw)))
			continue;

		hlist_del(&gwj->list);
		can_gw_unregister_filter(gwj);
		kfree(gwj);
		err = 0;
		break;
	}

	spin_unlock(&can_gw_list_lock);
	
	return err;
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
	rtnl_unregister_all(PF_CAN);

	unregister_netdevice_notifier(&notifier);

	gw_remove_all_jobs();

	rcu_barrier(); /* Wait for completion of call_rcu()'s */

	kmem_cache_destroy(gw_cache);
}

module_init(gw_module_init);
module_exit(gw_module_exit);
