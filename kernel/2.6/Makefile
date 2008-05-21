ifeq ($(KERNELRELEASE),)

KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)
TOPDIR    := $(PWD)

export CONFIG_CAN_VCAN=m
export CONFIG_CAN_SJA1000=m
export CONFIG_CAN_SJA1000_OLD=m
export CONFIG_CAN_I82527_OLD=m
export CONFIG_CAN_EMS_PCI=m

export CONFIG_CAN=m
export CONFIG_CAN_RAW=m
export CONFIG_CAN_BCM=m

modules modules_install clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@ TOPDIR=$(TOPDIR)

else

obj-m += drivers/net/can/
obj-m += net/can/

endif
