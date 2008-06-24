#
#  $Id$
#

ifeq ($(KERNELRELEASE),)

KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)
TOPDIR    := $(PWD)/../../../../..

modules modules_install clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@ TOPDIR=$(TOPDIR)

else

-include $(TOPDIR)/Makefile.common
EXTRA_CFLAGS += -I$(TOPDIR)/drivers/net/can/old/hal

obj-m := i82527-pc7io.o i82527-iomem.o i82527-esdio.o

i82527-pc7io-objs := i82527.o proc.o ../hal/pc7io.o
i82527-iomem-objs := i82527.o proc.o ../hal/iomem.o
i82527-esdio-objs := i82527.o proc.o ../hal/esdio.o

endif
