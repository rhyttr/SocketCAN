#
#  $Id: Makefile 443 2007-07-25 11:41:27Z hartkopp $
#

ifeq ($(KERNELRELEASE),)

KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)
TOPDIR    := $(PWD)/../../../..

modules modules_install clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@ TOPDIR=$(TOPDIR)

else

-include $(TOPDIR)/Makefile.common

obj-$(CONFIG_CAN_CC770) += cc770.o
obj-$(CONFIG_CAN_CC770_ISA) += cc770_isa.o
obj-$(CONFIG_CAN_CC770_OF_PLATFORM) += cc770_of_platform.o

ifeq ($(CONFIG_CAN_DEBUG_DEVICES),y)
	EXTRA_CFLAGS += -DDEBUG
endif

endif
