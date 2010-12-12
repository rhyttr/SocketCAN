ifeq ($(KERNELRELEASE),)

KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)
TOPDIR    := $(PWD)

export CONFIG_CAN_VCAN=m
export CONFIG_CAN_SLCAN=m
export CONFIG_CAN_DEV=m
export CONFIG_CAN_CALC_BITTIMING=y
#export CONFIG_CAN_DEV_SYSFS=y
#export CONFIG_CAN_SJA1000_OLD=m
#export CONFIG_CAN_I82527_OLD=m
export CONFIG_CAN_CC770=m
export CONFIG_CAN_CC770_ISA=m
#export CONFIG_CAN_CC770_OF_PLATFORM=m
export CONFIG_CAN_SJA1000=m
export CONFIG_CAN_SJA1000_PLATFORM=m
#export CONFIG_CAN_SJA1000_OF_PLATFORM=m
export CONFIG_CAN_IXXAT_PCI=m
export CONFIG_CAN_PLX_PCI=m
export CONFIG_CAN_PEAK_PCI=m
export CONFIG_CAN_KVASER_PCI=m
export CONFIG_CAN_EMS_PCI=m
#export CONFIG_CAN_EMS_USB=m
#export CONFIG_CAN_EMS_PCMCIA=m
export CONFIG_CAN_EMS_104M=m
export CONFIG_CAN_ESD_PCI=m
export CONFIG_CAN_ESD_PCI331=m
#export CONFIG_CAN_ESD_USB2=m
export CONFIG_CAN_PIPCAN=m
#export CONFIG_CAN_SOFTING=m
#export CONFIG_CAN_SOFTING_CS=m
export CONFIG_CAN_MCP251X=m

export CONFIG_CAN=m
export CONFIG_CAN_RAW=m
export CONFIG_CAN_BCM=m
export CONFIG_CAN_ISOTP=m

modules modules_install clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@ TOPDIR=$(TOPDIR)

else

obj-m += drivers/net/can/
obj-m += net/can/

endif
