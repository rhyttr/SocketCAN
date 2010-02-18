#
#  $Id$
#

ifeq ($(KERNELRELEASE),)

KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)
TOPDIR    := $(PWD)/../..

modules modules_install clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@ TOPDIR=$(TOPDIR)

export CONFIG_CAN=m
export CONFIG_CAN_RAW=m
export CONFIG_CAN_BCM=m
export CONFIG_CAN_ISOTP=m
export CONFIG_CAN_GW=m

else

-include $(TOPDIR)/Makefile.common

obj-$(CONFIG_CAN)	+= can.o
can-objs		:= af_can.o proc.o

obj-$(CONFIG_CAN_RAW)	+= can-raw.o
can-raw-objs		:= raw.o

obj-$(CONFIG_CAN_BCM)	+= can-bcm.o
can-bcm-objs		:= bcm.o

obj-$(CONFIG_CAN_ISOTP)	+= can-isotp.o
can-isotp-objs		:= isotp.o

obj-$(CONFIG_CAN_GW)	+= can-gw.o
can-gw-objs		:= gw.o

endif
