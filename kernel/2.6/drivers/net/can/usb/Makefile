#
#  Makefile for the Linux Controller Area Network USB drivers.
#

ifeq ($(KERNELRELEASE),)

KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)
TOPDIR    := $(PWD)/../../../..

modules modules_install clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@ TOPDIR=$(TOPDIR)

else

-include $(TOPDIR)/Makefile.common

obj-$(CONFIG_CAN_EMS_USB) += ems_usb.o
obj-$(CONFIG_CAN_ESD_USB2) += esd_usb2.o

ifeq ($(CONFIG_CAN_DEBUG_DEVICES),y)
	EXTRA_CFLAGS += -DDEBUG
endif

endif
