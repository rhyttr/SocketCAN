/*
 * $Id$
 */

#ifndef CAN_COMPAT_H
#define CAN_COMPAT_H

#ifndef PF_CAN
#define PF_CAN 29
#endif

#ifndef AF_CAN
#define AF_CAN PF_CAN
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
static inline void *kzalloc(size_t size, unsigned int __nocast flags)
{
	void *ret = kmalloc(size, flags);
	if (ret)
		memset(ret, 0, size);
	return ret;
}

static inline void skb_get_timestamp(const struct sk_buff *skb,
				     struct timeval *stamp)
{
	stamp->tv_sec  = skb->stamp.tv_sec;
	stamp->tv_usec = skb->stamp.tv_usec;
}

static inline void skb_set_timestamp(struct sk_buff *skb,
				     const struct timeval *stamp)
{
	skb->stamp.tv_sec  = stamp->tv_sec;
	skb->stamp.tv_usec = stamp->tv_usec;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
#define round_jiffies(j) (j)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define   dev_get_by_index(ns, ifindex)   dev_get_by_index(ifindex)
#define __dev_get_by_index(ns, ifindex) __dev_get_by_index(ifindex)
#endif

#endif
