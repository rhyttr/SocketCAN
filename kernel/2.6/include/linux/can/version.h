/*
 * linux/can/version.h
 *
 * Version information for the CAN network layer implementation

 * Author: Urs Thuermann   <urs.thuermann@volkswagen.de>
 * Copyright (c) 2002-2007 Volkswagen Group Electronic Research
 * All rights reserved.
 *
 * Send feedback to <socketcan-users@lists.berlios.de>
 *
 */

#ifndef CAN_VERSION_H
#define CAN_VERSION_H

#define RCSID(s) asm(".section .rodata.str1.1,\"aMS\",@progbits,1\n\t" \
		     ".string \"" s "\"\n\t.previous\n")

RCSID("$Id$");

#define MAJORVERSION 2
#define MINORVERSION 0
#define PATCHLEVEL   0
#define EXTRAVERSION "-pre5"

#define LLCF_VERSION_CODE (((MAJORVERSION) << 16) + ((MINORVERSION) << 8) \
				+ (PATCHLEVEL))

/* stringification:  these are the usual macros to stringify with macro
   expansion.   The str() macro does the expansion, the xstr() macro is
   for the actual stringification.
*/
#define str(arg) xstr(arg)
#define xstr(arg) #arg

#define VERSION str(MAJORVERSION) "." str(MINORVERSION) "." str(PATCHLEVEL) \
	EXTRAVERSION

#endif /* CAN_VERSION_H */
