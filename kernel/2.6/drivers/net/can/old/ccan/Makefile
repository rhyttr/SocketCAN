#
#  $Id: Makefile 438 2007-07-21 17:53:09Z hartkopp $
#

ifeq ($(KERNELRELEASE),)

KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)
TOPDIR    := $(PWD)/../../../..

modules modules_install clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@ TOPDIR=$(TOPDIR)

else

-include $(TOPDIR)/Makefile.common

obj-$(CONFIG_CAN_CCAN_OLD)		+= ccan.o
obj-$(CONFIG_CAN_H7202_OLD)		+= h7202_can.o

endif
