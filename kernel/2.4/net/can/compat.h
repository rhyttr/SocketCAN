/*
 * $Id$
 */

#ifndef CAN_COMPAT_H
#define CAN_COMPAT_H

static inline void *kzalloc(size_t size, unsigned int flags)
{
	void *ret = kmalloc(size, flags);
	if (ret)
		memset(ret, 0, size);
	return ret;
}

static inline void setup_timer(struct timer_list * timer,
			       void (*function)(unsigned long),
			       unsigned long data)
{
	timer->function = function;
	timer->data = data;
	init_timer(timer);
}

#define round_jiffies(j) (j)

#define __read_mostly
#define __user

#define   dev_get_by_index(ns, ifindex)   dev_get_by_index(ifindex)
#define __dev_get_by_index(ns, ifindex) __dev_get_by_index(ifindex)

#define sk_socket		socket
#define sk_err			err
#define sk_error_report		error_report
#define sk_receive_queue	receive_queue
#define sk_destruct		destruct

/* Force a compilation error if condition is true */
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))

#undef container_of
/*
 * container_of - cast a member of a structure out to the containing structure
 * @ptr: the pointer to the member.
 * @type: the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 */
#define container_of(ptr, type, member) ({ \
	const typeof( ((type *)0)->member ) *__mptr = (ptr); \
	(type *)( (char *)__mptr - offsetof(type,member) );})

/* ensure the needed list functions (introduced somewhere about 2.4.20) are available */

#undef list_for_each_entry
/**
 * list_for_each_entry	-	iterate over list of given type
 * @pos:	the type * to use as a loop counter.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
		     prefetch(pos->member.next);			\
	     &pos->member != (head); 					\
	     pos = list_entry(pos->member.next, typeof(*pos), member),	\
		     prefetch(pos->member.next))

#undef list_for_each_entry_safe
/**
 * list_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:	the type * to use as a loop counter.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
		n = list_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))

#endif
