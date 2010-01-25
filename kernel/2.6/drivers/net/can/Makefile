#
#  $Id$
#


ifeq ($(KERNELRELEASE),)

KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)
TOPDIR    := $(PWD)/../../..

export CONFIG_CAN_VCAN=m
export CONFIG_CAN_DEV=m
#export CONFIG_CAN_SJA1000_OLD=m
#export CONFIG_CAN_I82527_OLD=m
export CONFIG_CAN_CC770=m
export CONFIG_CAN_SJA1000=m
export CONFIG_CAN_SJA1000_PLATFORM=m
export CONFIG_CAN_PLX_PCI=m
export CONFIG_CAN_EMS_PCI=m
export CONFIG_CAN_EMS_PCMCIA=m
export CONFIG_CAN_ESD_PCI331=m
export CONFIG_CAN_ESD_USB2=m
export CONFIG_CAN_PIPCAN=m
export CONFIG_CAN_SOFTING=m
export CONFIG_CAN_SOFTING_CS=m
export CONFIG_CAN_MCP251X=m

modules modules_install clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@ TOPDIR=$(TOPDIR)

else

-include $(TOPDIR)/Makefile.common

obj-$(CONFIG_CAN_VCAN)		+= vcan.o
obj-$(CONFIG_CAN_SLCAN)		+= slcan.o

obj-$(CONFIG_CAN_DEV)		+= can-dev.o
can-dev-y			:= dev.o
can-dev-$(CONFIG_CAN_DEV_SYSFS) += sysfs.o

obj-$(CONFIG_CAN_CC770)		+= cc770/
obj-$(CONFIG_CAN_SJA1000)	+= sja1000/
obj-$(CONFIG_CAN_SOFTING)	+= softing/
obj-$(CONFIG_CAN_MSCAN)		+= mscan/
obj-$(CONFIG_USB)		+= usb/
obj-$(CONFIG_CAN_AT91)		+= at91_can.o
obj-$(CONFIG_CAN_ESD_PCI331)	+= esd_pci331.o
obj-$(CONFIG_CAN_SJA1000_OLD)	+= old/sja1000/
obj-$(CONFIG_CAN_I82527_OLD)	+= old/i82527/
obj-$(CONFIG_CAN_MSCAN_OLD)	+= old/mscan/
obj-$(CONFIG_CAN_CCAN_OLD)	+= old/ccan/
obj-$(CONFIG_CAN_MCP251X)	+= mcp251x.o

ifeq ($(CONFIG_CAN_DEBUG_DEVICES),y)
	EXTRA_CFLAGS += -DDEBUG
endif
ifeq ($(CONFIG_CAN_DEV_SYSFS),y)
	EXTRA_CFLAGS += -DCONFIG_CAN_DEV_SYSFS
endif
ifneq ($(CONFIG_CAN_CALC_BITTIMING),n)
	EXTRA_CFLAGS += -DCONFIG_CAN_CALC_BITTIMING
endif

endif
