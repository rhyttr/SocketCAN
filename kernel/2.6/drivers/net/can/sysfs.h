/*
 * $Id: dev.c 542 2007-11-07 13:57:16Z thuermann $
 *
 * Copyright (C) 2007 Wolfgang Grandegger <wg@grandegger.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the version 2 of the GNU General Public License
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef CAN_SYSFS_H
#define CAN_SYSFS_H

void can_create_sysfs(struct net_device *dev);
void can_remove_sysfs(struct net_device *dev);
int can_sample_point(struct can_bittiming *bt);

#endif /* CAN_SYSFS_H */
