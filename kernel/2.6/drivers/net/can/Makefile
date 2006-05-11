#
#  $Id$
#


ifeq ($(KERNELRELEASE),)

KERNELDIR = /usr/src/linux
PWD       = $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

else

ifneq ($(KBUILD_EXTMOD),)
EXTRA_CFLAGS += -I$(KBUILD_EXTMOD)/../../include
endif

obj-m := vcan.o

endif
