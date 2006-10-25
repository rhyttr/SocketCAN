#
#  $Id$
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
#  Send feedback to <socketcan-users@lists.berlios.de>



ifeq ($(KERNELRELEASE),)

KERNELDIR = /usr/src/linux
PWD       = $(shell pwd)

all: can raw bcm

can:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) CONFIG_CAN=m modules

raw: can
	$(MAKE) -C $(KERNELDIR) M=$(PWD) CONFIG_CAN=m CONFIG_CAN_RAW=m modules

bcm: can
	$(MAKE) -C $(KERNELDIR) M=$(PWD) CONFIG_CAN=m CONFIG_CAN_BCM=m modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

.PHONY: clean all can raw bcm

else

ifneq ($(KBUILD_EXTMOD),)
EXTRA_CFLAGS += -I$(KBUILD_EXTMOD)/../../include
endif

obj-$(CONFIG_CAN)	+= can.o
can-objs		:= af_can.o proc.o

obj-$(CONFIG_CAN_RAW)	+= can-raw.o
can-raw-objs		:= raw.o

obj-$(CONFIG_CAN_BCM)	+= can-bcm.o
can-bcm-objs		:= bcm.o

obj-$(CONFIG_CAN)	+= candev.o
candev-objs		:= dev.o

endif
