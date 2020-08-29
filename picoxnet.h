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
#ifndef PICOX_BSD_H
#define PICOX_BSD_H
#include <sys/socket.h>

struct picox;

int picox_msocket(struct picox *stack, int domain, int type, int protocol);
int picox_close(int fd);

int picox_bind(int fd, const struct sockaddr *addr, socklen_t addrlen);
int picox_connect(int fd, const struct sockaddr *addr, socklen_t addrlen);
int picox_listen(int fd, int backlog);
int picox_accept(int fd, struct sockaddr *addr, socklen_t *addrlen);
int picox_getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen);
int picox_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t picox_read(int fd, void *buf, size_t len);
ssize_t picox_readv(int fd, const struct iovec *iov, int iovcnt);
ssize_t picox_recv(int fd, void *buf, size_t len, int flags);
ssize_t picox_recvmsg(int fd, struct msghdr *msg, int flags);
ssize_t picox_recvfrom(int fd, void *buf, size_t len, int flags,
    struct sockaddr *from, socklen_t *fromlen);
ssize_t picox_write(int fd, const void *buf, size_t size);
ssize_t picox_writev(int fd, const struct iovec *iov, int iovcnt);
ssize_t picox_send(int fd, const void *buf, size_t size, int flags);
ssize_t picox_sendto(int fd, const void *buf, size_t size, int flags,
    const struct sockaddr *to, socklen_t tolen);
ssize_t picox_sendmsg(int fd, const struct msghdr *msg, int flags);
int picox_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen);
int picox_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen);
int picox_shutdown(int fd, int how);
int picox_ioctl(int fd, unsigned long cmd, void *argp);
int picox_fcntl(int fd, int cmd, long val);

struct picox *picox_newstack(char *vdeurl);
int picox_delstack(struct picox *stack);
#endif

