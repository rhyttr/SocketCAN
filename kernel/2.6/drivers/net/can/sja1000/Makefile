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
#EXTRA_CFLAGS += -I$(TOPDIR)/drivers/net/can/hal

obj-$(CONFIG_CAN_SJA1000) += sja1000.o
obj-$(CONFIG_CAN_SJA1000_PLATFORM) += sja1000_platform.o
obj-$(CONFIG_CAN_SJA1000_OF_PLATFORM) += sja1000_of_platform.o
obj-$(CONFIG_CAN_EMS_PCI) += ems_pci.o
obj-$(CONFIG_CAN_EMS_PCMCIA) += ems_pcmcia.o
obj-$(CONFIG_CAN_IXXAT_PCI) += ixxat_pci.o
obj-$(CONFIG_CAN_PEAK_PCI) += peak_pci.o
obj-$(CONFIG_CAN_PIPCAN) += pipcan.o
obj-$(CONFIG_CAN_KVASER_PCI) += kvaser_pci.o

ccflags-$(CONFIG_CAN_DEBUG_DEVICES) := -DDEBUG

endif
