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

#include <stdio.h>
#include <errno.h>
#include <vunet.h>
#include <picox_bsd.h>

static int supported_domain (int domain) {
  switch (domain) {
    case AF_INET:
    case AF_INET6:
    case AF_NETLINK:
    //case AF_PACKET:
      return 1;
    default:
      return 0;
  }
}

static int supported_ioctl (unsigned long request) {
  return vunet_is_netdev_ioctl(request);
}

static int _picox_socket(int domain, int type, int protocol) {
  struct picox *stack = vunet_get_private_data();
  return picox_msocket(stack, domain, type, protocol);
}

static int vunetpicox_ioctl(int fd, unsigned long request, void *addr) {
	if (fd == -1) {
		if (addr == NULL) {
			int retval = vunet_ioctl_parms(request);
      if (retval == 0) {
        errno = ENOSYS; return -1;
      } else
        return retval;
    } else {
      int tmpfd = _picox_socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, 0);
      int retval;
      if (tmpfd < 0)
        return -1;
      else {
        retval = picox_ioctl(tmpfd, request, addr);
        picox_close(tmpfd);
        return retval;
      }
    }
  } else
    return ioctl(fd, request, addr);
}

static int vunetpicox_accept4(int fd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
  return picox_accept(fd, addr, addrlen);
}

int vunetpicox_init(const char *source, unsigned long flags, const char *args, void **private_data) {
  struct picox *vdestack = picox_newstack((char *) source);
  if (vdestack != NULL) {
    *private_data = vdestack;
    return 0;
  } else {
    errno = EINVAL;
    return -1;
  }
}

int vunetpicox_fini(void *private_data) {
  picox_delstack(private_data);
  return 0;
}

struct vunet_operations vunet_ops = {
  .socket = _picox_socket,
#if 1
  .bind = picox_bind,
  .connect = picox_connect,
  .listen = picox_listen,
  .accept4 = vunetpicox_accept4,
  .getsockname = picox_getsockname,
  .getpeername = picox_getpeername,
  .recvmsg = picox_recvmsg,
  .sendmsg = picox_sendmsg,
  .getsockopt = picox_getsockopt,
  .setsockopt = picox_setsockopt,
  .shutdown = picox_shutdown,
	.ioctl = vunetpicox_ioctl,
  .close = picox_close,

  .epoll_ctl = epoll_ctl,

  .supported_domain = supported_domain,
  .supported_ioctl = supported_ioctl,
#endif
  .init = vunetpicox_init,
  .fini = vunetpicox_fini,
};

