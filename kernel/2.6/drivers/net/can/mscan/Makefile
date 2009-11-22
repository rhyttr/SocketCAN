#
#  $Id$
#

ifeq ($(KERNELRELEASE),)

KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)
TOPDIR    := $(PWD)/../../../..

modules modules_install clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@ TOPDIR=$(TOPDIR)

else

-include $(TOPDIR)/Makefile.common

obj-$(CONFIG_CAN_MPC52XX)	+= mscan-mpc52xx.o
mscan-mpc52xx-objs		:= mscan.o mpc52xx_can.o

obj-$(CONFIG_CAN_MPC5XXX)	+= mscan-mpc5xxx.o
mscan-mpc5xxx-objs		:= mscan.o mpc5xxx_can.o

ifeq ($(CONFIG_CAN_DEBUG_DEVICES),y)
	EXTRA_CFLAGS += -DDEBUG
endif

endif
