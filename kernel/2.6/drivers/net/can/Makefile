#
#  $Id$
#


ifeq ($(KERNELRELEASE),)

KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)
TOPDIR    := $(PWD)/../../..

export CONFIG_CAN_VCAN=m
export CONFIG_CAN_DEV=m
export CONFIG_CAN_SJA1000_OLD=m
export CONFIG_CAN_I82527_OLD=m
export CONFIG_CAN_SJA1000=m

modules modules_install clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@ TOPDIR=$(TOPDIR)

else

-include $(TOPDIR)/Makefile.common

obj-$(CONFIG_CAN_VCAN)		+= vcan.o
obj-$(CONFIG_CAN_SLCAN)		+= slcan.o

obj-$(CONFIG_CAN_DEV)		+= can-dev.o
can-dev-y			:= dev.o sysfs.o

obj-$(CONFIG_CAN_SJA1000)	+= sja1000/
obj-$(CONFIG_CAN_MSCAN)		+= mscan/
obj-$(CONFIG_CAN_SJA1000_OLD)	+= old/sja1000/
obj-$(CONFIG_CAN_I82527_OLD)	+= old/i82527/
obj-$(CONFIG_CAN_MSCAN_OLD)	+= old/mscan/
obj-$(CONFIG_CAN_CCAN_OLD)	+= old/ccan/

endif
