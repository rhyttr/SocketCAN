# Makefile for softing CAN driver

ifeq ($(KERNELRELEASE),)
# necessary when used outside kernel
KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)
TOPDIR    := $(PWD)/../../../..

modules modules_install clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@ TOPDIR=$(TOPDIR)

else

-include $(TOPDIR)/Makefile.common

softing-y := softing_main.o softing_fw.o softing_sysfs.o
obj-$(CONFIG_CAN_SOFTING)        += softing.o
obj-$(CONFIG_CAN_SOFTING_CS)     += softing_cs.o

endif
