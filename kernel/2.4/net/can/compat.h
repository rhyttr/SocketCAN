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

#endif
