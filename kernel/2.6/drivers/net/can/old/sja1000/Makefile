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

obj-m := sja1000-io.o sja1000-iomem.o sja1000-iomux.o sja1000-gw2.o sja1000-esdio.o sja1000-c200.o

sja1000-io-objs    := sja1000.o proc.o ../hal/io.o
sja1000-iomem-objs := sja1000.o proc.o ../hal/iomem.o
sja1000-iomux-objs := sja1000.o proc.o ../hal/iomux.o
sja1000-gw2-objs   := sja1000.o proc.o ../hal/gw2.o
sja1000-esdio-objs := sja1000.o proc.o ../hal/esdio.o
sja1000-c200-objs  := sja1000.o proc.o ../hal/c200.o

endif
