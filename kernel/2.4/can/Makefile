#
#  $Id: Makefile,v 1.20 2006/03/07 07:47:42 ethuerm Exp $
#
#  Copyright (c) 2002-2005 Volkswagen Group Electronic Research
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions, the following disclaimer and
#     the referenced file 'COPYING'.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. Neither the name of Volkswagen nor the names of its contributors
#     may be used to endorse or promote products derived from this software
#     without specific prior written permission.
#
#  Alternatively, provided that this notice is retained in full, this
#  software may be distributed under the terms of the GNU General
#  Public License ("GPL") version 2 as distributed in the 'COPYING'
#  file from the main directory of the linux kernel source.
#
#  The provided data structures and external interfaces from this code
#  are not restricted to be used by modules with a GPL compatible license.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
#  DAMAGE.
#
#  Send feedback to <llcf@volkswagen.de>


CFLAGS    = -O2 -Wall -Wno-parentheses -D__KERNEL__ -DMODULE $(DEBUG) \
		-I$(KERNELDIR)/include -fno-strict-aliasing
KERNELDIR = /usr/src/linux

VERSION       = $(shell awk '/^VERSION/     {print $$3}' $(KERNELDIR)/Makefile)
PATCHLEVEL    = $(shell awk '/^PATCHLEVEL/  {print $$3}' $(KERNELDIR)/Makefile)
SUBLEVEL      = $(shell awk '/^SUBLEVEL/    {print $$3}' $(KERNELDIR)/Makefile)
EXTRAVERSION  = $(shell awk '/^EXTRAVERSION/{print $$3}' $(KERNELDIR)/Makefile)
KERNELRELEASE = $(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(EXTRAVERSION)

MODLIB := $(INSTALL_MOD_PATH)/lib/modules/$(KERNELRELEASE)/llcf

MOD_GPL = can.o vcan.o can-bcm.o can-raw.o
MOD_VW  = can-tpgen.o can-tp20.o can-tp16.o can-mcnet.o

default: all-gpl

all: all-gpl all-vw

all-gpl: $(MOD_GPL)

all-vw: $(MOD_VW)

ifeq "$(strip $(INSTALL_MOD_PATH))" ""
DEPMOD_BASE :=
else
DEPMOD_BASE := -r -b $(INSTALL_MOD_PATH)
endif

install: $(MOD_GPL)
	install -m 755 -d $(MODLIB)
	install -m 644 $^ $(MODLIB)
	depmod -ae -F $(KERNELDIR)/System.map $(DEPMOD_BASE) $(KERNELRELEASE)

install-vw: $(MOD_VW)
	install -m 755 -d $(MODLIB)
	install -m 644 $^ $(MODLIB)
	depmod -ae -F $(KERNELDIR)/System.map $(DEPMOD_BASE) $(KERNELRELEASE)

clean:
	rm -f *.o

can.o: af_can.o proc.o
	$(LD) -r -o $@ $^

can-bcm.o: bcm.o
	$(LD) -r -o $@ $^

can-raw.o: raw.o
	$(LD) -r -o $@ $^

can-tpgen.o: tp_gen.o
	$(LD) -r -o $@ $^

can-tp20.o: tp20.o
	$(LD) -r -o $@ $^

can-tp16.o: tp16.o
	$(LD) -r -o $@ $^

can-mcnet.o: mcnet.o
	$(LD) -r -o $@ $^

