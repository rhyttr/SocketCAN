TOPDIR		= $(shell pwd)
KERNELVER	= $(shell uname -r)
KERNELDIR	= /lib/modules/$(KERNELVER)/build
MOD_DIR		= /lib/modules/$(KERNELVER)/kernel

SUBDIRS 	= \
	$(TOPDIR)/net/can \
	$(TOPDIR)/drivers/net/can

#
# targetinfo
#
# Print out the targetinfo line on the terminal
#
# $1: name of the target to be printed out
#
targetinfo = \
	echo; \
	TG=`echo "$(1)" | sed -e "s,$(TOPDIR)/,,g"`; \
	LINE=`echo target: $$TG |sed -e "s/./-/g"`; \
	echo $$LINE; \
	echo target: $$TG; \
	echo $$LINE; \
	echo

.PHONY: net drivers

all: net drivers

net:
	@$(call targetinfo, "running make in net/can")
	cd net/can && make KERNELDIR=$(KERNELDIR)

drivers:
	@$(call targetinfo, "running make in drivers/net/can")
	cd drivers/net/can && make KERNELDIR=$(KERNELDIR)

install: net drivers
	find -name \*.ko -exec install -v -D {} $(MOD_DIR)/{} \;
	depmod $(KERNELVER)

clean:
	@for dir in $(SUBDIRS); do \
		$(call targetinfo, "cleaning in $$dir"); \
		cd $$dir; \
		make clean KERNELDIR=$(KERNELDIR); \
	done

