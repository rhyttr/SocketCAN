#
#  $Id$
#

KERNELDIR     = /usr/src/linux

VERSION       = $(shell awk '/^VERSION/     {print $$3}' $(KERNELDIR)/Makefile)
PATCHLEVEL    = $(shell awk '/^PATCHLEVEL/  {print $$3}' $(KERNELDIR)/Makefile)
SUBLEVEL      = $(shell awk '/^SUBLEVEL/    {print $$3}' $(KERNELDIR)/Makefile)
EXTRAVERSION  = $(shell awk '/^EXTRAVERSION/{print $$3}' $(KERNELDIR)/Makefile)
KERNELRELEASE = $(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(EXTRAVERSION)

patch26:
	./mkpatch $(KERNELRELEASE) < FILES-2.6 | sed -e 's/socketcan\/can/linux\/can/' > patch-$(KERNELRELEASE)-socketcan

patch26all:
	./mkpatch $(KERNELRELEASE) < FILES-2.6-ALL | sed -e 's/socketcan\/can/linux\/can/' > patch-$(KERNELRELEASE)-socketcan-all
