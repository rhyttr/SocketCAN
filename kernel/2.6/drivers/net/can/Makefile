#
#  $Id$
#


ifeq ($(KERNELRELEASE),)

ifdef $(CONFIG_CAN_SLCAN)
SLCAN_MOD = slcan
else
SLCAN_MOD =
endif

KERNELDIR = /usr/src/linux
PWD       = $(shell pwd)

all: vcan $(SLCAN_MOD) sja1000 i82527 mscan

vcan:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) CONFIG_CAN_VCAN=m modules

slcan:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) CONFIG_CAN_SLCAN=$(CONFIG_CAN_SLCAN) modules

sja1000:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) CONFIG_CAN_SJA1000=m modules

i82527:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) CONFIG_CAN_I82527=m modules

mscan:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) CONFIG_CAN_MSCAN=m modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	rm -f Module.symvers

.PHONY: clean all vcan slcan sja1000 i82527 mscan

else

#CPPFLAGS	+= -Idrivers/net -Inet
#AFLAGS		+= -Idrivers/net -Inet
#CFLAGS		+= -Idrivers/net -Inet

ifneq ($(KBUILD_EXTMOD),)
EXTRA_CFLAGS += -I$(KBUILD_EXTMOD)/../../../include \
		-DETH_P_CAN=0x000C \
		-DARPHRD_CAN=280
endif

obj-$(CONFIG_CAN_VCAN)		+= vcan.o
obj-$(CONFIG_CAN_SLCAN)		+= slcan.o
obj-$(CONFIG_CAN_SJA1000)	+= sja1000/
obj-$(CONFIG_CAN_I82527)	+= i82527/
obj-$(CONFIG_CAN_MSCAN)		+= mscan/

endif
