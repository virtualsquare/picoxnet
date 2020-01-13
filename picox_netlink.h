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
#ifndef PICOX_NETLINK_H
#define PICOX_NETLINK_H

#include <sys/types.h>
#include <sys/socket.h>
struct picoxnl;
struct pico_stack;

struct picoxnl *picoxnl_socket(struct pico_stack *stack, int domain, int type, int protocol);
void picoxnl_vpollfd(struct picoxnl *picoxnl, int vpollfd);
int picoxnl_close(struct picoxnl *picoxnl);

int picoxnl_bind(struct picoxnl *picoxnl, const struct sockaddr *addr, socklen_t addrlen);
int picoxnl_getpeername (struct picoxnl *picoxnl, struct sockaddr *addr, socklen_t *addrlen);
int picoxnl_getsockname (struct picoxnl *picoxnl, struct sockaddr *addr, socklen_t *addrlen);
int picoxnl_getsockopt (struct picoxnl *picoxnl, int level, int optname, void *optval, socklen_t *optlen);
int picoxnl_setsockopt (struct picoxnl *picoxnl, int level, int optname, const void *optval, socklen_t optlen);
int picoxnl_connect(struct picoxnl *picoxnl, const struct sockaddr *addr, socklen_t addrlen);
ssize_t picoxnl_recvfrom(struct picoxnl *picoxnl, void *buf, size_t len, int flags,
      struct sockaddr *from, socklen_t *fromlen);
ssize_t picoxnl_sendto(struct picoxnl *picoxnl, const void *buf, size_t len, int flags,
    const struct sockaddr *to, socklen_t tolen);
int picoxnl_ioctl(struct picoxnl *picoxnl, long cmd, void *argp);
int picoxnl_fcntl(struct picoxnl *picoxnl, int cmd, int val);

#endif 

