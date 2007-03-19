#
#  $Id$
#

VERSION       = $(shell awk '/^VERSION/     {print $$3}' $(KERNELDIR)/Makefile)
PATCHLEVEL    = $(shell awk '/^PATCHLEVEL/  {print $$3}' $(KERNELDIR)/Makefile)
SUBLEVEL      = $(shell awk '/^SUBLEVEL/    {print $$3}' $(KERNELDIR)/Makefile)
EXTRAVERSION  = $(shell awk '/^EXTRAVERSION/{print $$3}' $(KERNELDIR)/Makefile)
KERNELRELEASE = $(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(EXTRAVERSION)

patch26:
	./mkpatch $(KERNELRELEASE) >patch-$(KERNELRELEASE)-socketcan < FILES-2.6
