#
#  $Id$
#


ifeq ($(KERNELRELEASE),)

KERNELDIR = /usr/src/linux
PWD       = $(shell pwd)

all: vcan sja1000 mscan

vcan:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) CONFIG_CAN_VCAN=m modules

sja1000:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) CONFIG_CAN_SJA1000=m modules

mscan:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) CONFIG_CAN_MSCAN=m modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

.PHONY: clean all vcan sja1000 mscan

else

CPPFLAGS	+= -Idrivers/net -Inet
AFLAGS		+= -Idrivers/net -Inet
CFLAGS		+= -Idrivers/net -Inet

ifneq ($(KBUILD_EXTMOD),)
EXTRA_CFLAGS += -I$(KBUILD_EXTMOD)/../../include
endif

obj-$(CONFIG_CAN_VCAN)		+= vcan.o
obj-$(CONFIG_CAN_SJA1000)	+= sja1000/
obj-$(CONFIG_CAN_MSCAN)		+= mscan/

endif
