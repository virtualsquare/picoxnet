/*********************************************************************
 * Pico-X BSD
 * Copyright (C) 2020  Renzo Davoli <renzo@cs.unibo.it>, Daniele Lacamera <root@danielinux.net>
 * VirtualSquare team.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Pico-X BSD is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) version 3.
 *
 * Pico-X BSD is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 *
 *
 *********************************************************************/
#ifndef PICOX_NL_OPS_H
#define PICOX_NL_OPS_H

struct pico_stack;

struct nlq_msg *picox_netlink_process(struct nlmsghdr *msg, struct pico_stack *stack);

#endif
