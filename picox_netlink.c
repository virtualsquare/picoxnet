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
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <linux/netlink.h>

#include <vpoll.h>
#include <libnlq.h>

#include <picox_netlink.h>
#include <picox_nl_ops.h>

struct picoxnl {
  struct pico_stack *stack;
  struct nlq_msg *msgq;
	pid_t pid;
  int vpollfd;
};

struct picoxnl *picoxnl_socket(struct pico_stack *stack, int domain, int type, int protocol) {
	struct picoxnl *picoxnl = malloc(sizeof(struct picoxnl));
	if (picoxnl == NULL)
		return errno = ENOMEM, NULL;
	picoxnl->stack = stack;
	picoxnl->msgq = NULL;
	picoxnl->pid = 0;
	picoxnl->vpollfd = -1;
	return picoxnl;
}

void picoxnl_vpollfd(struct picoxnl *picoxnl, int vpollfd) {
	if (picoxnl)
		picoxnl->vpollfd = vpollfd;
}

int picoxnl_close(struct picoxnl *picoxnl) {
	nlq_free(&picoxnl->msgq);
	free(picoxnl);
	return 0;
}

ssize_t picoxnl_recvfrom(struct picoxnl *picoxnl, void *buf, size_t len, int flags,
		struct sockaddr *from, socklen_t *fromlen) {
	ssize_t retval = 0;
	ssize_t copylen = 0;
	struct nlq_msg *headmsg = nlq_head(picoxnl->msgq);
	if (headmsg == NULL)
		return errno = ENODATA, -1;
	if (len < headmsg->nlq_size) {
		if (flags & MSG_TRUNC)
			retval = headmsg->nlq_size;
		else
			retval = len;
		copylen = len;
	} else
		retval = copylen = headmsg->nlq_size;
	if (buf != NULL && copylen > 0)
		memcpy(buf, headmsg->nlq_packet, copylen);
	if (!(flags & MSG_PEEK)) {
		nlq_dequeue(&picoxnl->msgq);
		nlq_freemsg(headmsg);
		if (nlq_length(picoxnl->msgq) == 0 && picoxnl->vpollfd)
			vpoll_ctl(picoxnl->vpollfd,VPOLL_CTL_DELEVENTS,EPOLLIN);
	}
	if (fromlen && *fromlen >= sizeof(struct sockaddr_nl)) {
		struct sockaddr_nl *rfrom = (struct sockaddr_nl *)from;
		struct sockaddr_nl sockname = {.nl_family = AF_NETLINK, .nl_pid = picoxnl->pid};
		*rfrom = sockname;
		*fromlen = sizeof(struct sockaddr_nl);
	}
	return retval;
}

ssize_t picoxnl_sendto(struct picoxnl *picoxnl, const void *buf, size_t len, int flags,
		const struct sockaddr *to, socklen_t tolen) {
	struct nlmsghdr *msg = (struct nlmsghdr *)buf;
	while (NLMSG_OK(msg, len)) {
		struct nlq_msg *msgq;
		msgq = picox_netlink_process(msg, picoxnl->stack);
		while (msgq != NULL) {
			struct nlq_msg *msg = nlq_dequeue(&msgq);
			nlq_enqueue(msg, &picoxnl->msgq);
		}
		msg = NLMSG_NEXT(msg, len);
	}

	if (nlq_length(picoxnl->msgq) > 0 && picoxnl->vpollfd >= 0)
		vpoll_ctl(picoxnl->vpollfd, VPOLL_CTL_ADDEVENTS, EPOLLIN);
	return len;
}

int picoxnl_bind(struct picoxnl *picoxnl, const struct sockaddr *addr, socklen_t addrlen) {
	struct sockaddr_nl *raddr = (struct sockaddr_nl *) addr;
	static pid_t fakepid = 0;
	if (addr == NULL)
		return errno = EFAULT, -1;
	if (addrlen < sizeof(*raddr) || raddr->nl_family != AF_NETLINK)
		return errno = EINVAL, -1;
	if (picoxnl == 0 && raddr->nl_pid == 0)
		raddr->nl_pid = ++fakepid;
	return 0;
}

int picoxnl_getsockname (struct picoxnl *picoxnl, struct sockaddr *addr, socklen_t *addrlen) {
	struct sockaddr_nl *raddr = (struct sockaddr_nl *) addr;
	struct sockaddr_nl sockname = {.nl_family = AF_NETLINK, .nl_pid = picoxnl->pid};
	if (addr == NULL || addrlen == NULL)
		return errno = EFAULT, -1;
	if (*addrlen < sizeof(sockname))
		return errno = EINVAL, -1;
	*raddr = sockname;
	*addrlen = sizeof(sockname);
	return 0;
}

int picoxnl_ioctl(struct picoxnl *picoxnl, long cmd, void *argp) {
	return picox_netlink_ioctl(picoxnl->stack, cmd, argp);
}

int picoxnl_getpeername (struct picoxnl *picoxnl, struct sockaddr *addr, socklen_t *addrlen) {
	errno = EOPNOTSUPP;
	return -1;
}

int picoxnl_getsockopt (struct picoxnl *picoxnl, int level, int optname, void *optval, socklen_t *optlen) {
	errno = EOPNOTSUPP;
	return -1;
}

int picoxnl_setsockopt (struct picoxnl *picoxnl, int level, int optname, const void *optval, socklen_t optlen) {
	switch (optname) {
		case SO_SNDBUF:
		case SO_RCVBUF:
			return 0;
	}
	errno = EOPNOTSUPP;
	return -1;
}

int picoxnl_connect(struct picoxnl *picoxnl, const struct sockaddr *addr, socklen_t addrlen) {
	errno = EOPNOTSUPP;
	return -1;
}

int picoxnl_fcntl(struct picoxnl *picoxnl, int cmd, int val) {
	errno = EOPNOTSUPP;
	return -1;
}
