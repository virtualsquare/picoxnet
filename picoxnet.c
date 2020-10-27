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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <vpoll.h>
#include <fduserdata.h>
#include <pico_bsd_sockets.h>

#include <picoxnet.h>
#include <picox_netlink.h>
#include <pico_dev_loop.h>
#include <pico_dev_vde.h>

#include <sys/random.h>

static FDUSERDATA *fd2picofd;

struct picox {
	struct pico_stack *pico_stack;
	pthread_t picotick;
};

struct fd_data {
	struct pico_stack *stack;
	int picofd;
	struct picoxnl *picoxnl;
	int fd;
};


static volatile int picotick_terminated = 0;
static void *picotick_thread (void *arg) {
	struct pico_stack *S = arg;
	while(1) {
		pico_bsd_stack_tick(S);
		if ((usleep(2000) > 0) || picotick_terminated) {
			//fprintf(stderr, "picotick_thread: Goodbye!\n");
			pthread_exit(NULL);
		}
	}
}

void event_cb(uint32_t events, int fd, void *arg) {
	//printf("%d->%x\n", fd, events);
	vpoll_ctl(fd, VPOLL_CTL_SETEVENTS, events);
}

static void picox_create_localhost (struct pico_stack *stack) {
	struct pico_device *dev;
	struct pico_ip4 ipaddr, netmask;
	struct pico_ip6 ipaddr6 = {{0}}, netmask6 = {{0}};
	uint32_t int_ipaddr, int_netmask;
	dev = pico_loop_create(stack);
	if (!dev) {
		perror("Creating loop");
		return;
	}
	pico_string_to_ipv4("127.0.0.1", &int_ipaddr);
	ipaddr.addr = int_ipaddr;
	pico_string_to_ipv4("255.0.0.0", &int_netmask);
	netmask.addr = int_netmask;
	//printf("Loopback created\n");
	pico_string_to_ipv6("::1", ipaddr6.addr);
	pico_string_to_ipv6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", netmask6.addr);
	pico_ipv6_link_add(dev, ipaddr6, netmask6);
}

struct picox *picox_newstack(char *vdeurl) {
	struct picox *stack = calloc(1, sizeof(struct picox));
	if (stack == NULL)
		return errno = ENOMEM, NULL;
	pico_stack_init(&stack->pico_stack);
	pico_bsd_init(stack->pico_stack, event_cb, NULL);
	picox_create_localhost(stack->pico_stack);
#ifdef DUMMYVDEEIF
	/*  code for debug only */
	{
		struct pico_device *pico_dev;
		struct pico_ip4 my_ip, netmask;
		uint32_t int_ipaddr, int_netmask;

		unsigned char macaddr[6]={0x0, 0x0, 0x0, 0xa, 0xb, 0xc};
		macaddr[4] ^= (uint8_t)(getpid() >> 8);
		macaddr[5] ^= (uint8_t) (getpid() & 0xFF);

		pico_string_to_ipv4("192.168.250.222", &int_ipaddr);
		my_ip.addr = int_ipaddr;
		pico_string_to_ipv4("255.255.255.0", &int_netmask);
		netmask.addr = int_netmask;

		pico_dev = (struct pico_device *) pico_vde_create(stack->pico_stack, "vde://", "vd0", macaddr);
		printf("%p\n",pico_dev);

		pico_ipv4_link_add(stack->pico_stack, pico_dev, my_ip, netmask);
	}
#else
	if (vdeurl != NULL && strcmp(vdeurl, "none") != 0) {
		struct pico_device *pico_dev;
		long int mrandmac = random();
		uint8_t macaddr[6] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00 };
		macaddr[5] = mrandmac;
		macaddr[4] = mrandmac >> 8;
		macaddr[3] = mrandmac >> 16;
		macaddr[2] = mrandmac >> 24;
		macaddr[1] = mrandmac >> 32;
		pico_dev = (struct pico_device *) pico_vde_create(stack->pico_stack, vdeurl, "vde0", macaddr);
	}
#endif
	pthread_create(&stack->picotick, NULL, picotick_thread, stack->pico_stack);
	return stack;
}

int picox_delstack(struct picox *stack) {
	picotick_terminated++;
	pico_bsd_deinit(stack->pico_stack);
	return 0;
}

static int picox_newsocket(struct pico_stack *stack, int picofd, struct picoxnl *picoxnl) {
	int fd;
	struct fd_data *fdd;
	int *fdp;
	/* TODO handle flags like SOCK_CLOEXEC */
	fd = vpoll_create(EPOLLOUT, 0); /* The socket is ready for packet sending */
	if (fd < 0)
		goto vpoll_create_err;
	fdd = fduserdata_new(fd2picofd, fd, struct fd_data);
	if (fdd == NULL)
		goto fduserdata_new_err;
	fdd->stack = stack;
	fdd->picofd = picofd;
	fdd->picoxnl = picoxnl;
	fduserdata_put(fdd);
	return fd;
fduserdata_new_err:
	close(fd);
vpoll_create_err:
	return -1;
}

int picox_msocket(struct picox *stack, int domain, int type, int protocol) {
	int fd;
	if (domain == AF_NETLINK) {
		struct picoxnl *picoxnl = picoxnl_socket(stack->pico_stack, domain, type, protocol);
		if (picoxnl == NULL)
			return -1;
		fd = picox_newsocket(stack->pico_stack, -1, picoxnl);
		if (fd < 0)
			picoxnl_close(picoxnl);
		else
			picoxnl_vpollfd(picoxnl, fd);
	} else {
		int picofd;
		picofd = pico_newsocket(stack->pico_stack, domain, type, protocol);
		if (picofd < 0)
			return -1;
		fd = picox_newsocket(stack->pico_stack, picofd, NULL);
		if (fd < 0)
			pico_close(picofd);
		else
			pico_bsd_set_posix_fd(picofd, fd);
	}
	return fd;
}

int picox_accept(int fd, struct sockaddr *addr, socklen_t *addrlen) {
	struct fd_data *fdd = fduserdata_get(fd2picofd, fd);
	if (fdd == NULL)
		return errno = ENOENT, -1;
	struct pico_stack *stack = fdd->stack;
	int newpicofd = 0;
	int newfd = 0;
	if (fdd->picoxnl == NULL) {
		int picofd = fdd->picofd;
		fduserdata_put(fdd);
		newpicofd = pico_accept(picofd, addr, addrlen);
	} else {
		errno = EOPNOTSUPP, newpicofd = -1;
		fduserdata_put(fdd);
	}
	if (newpicofd >= 0) {
		newfd = picox_newsocket(stack, newpicofd, NULL);
		if (newfd < 0)
			pico_close(newpicofd);
		else
			pico_bsd_set_posix_fd(newpicofd, newfd);
		return newfd;
	} else
		return -1;
}

int picox_close(int fd) {
	struct fd_data *fdd = fduserdata_get(fd2picofd, fd);
	if (fdd == NULL)
		return errno = ENOENT, -1;
	int ret = 0;
	if (fdd->picoxnl == NULL)
		ret = pico_close(fdd->picofd);
	else
		ret = picoxnl_close(fdd->picoxnl);
	vpoll_close(fd);
	fduserdata_del(fdd);
	return ret;
}

/* not suppported by netlink design */
//#define picoxnl_accept(...) (errno = EOPNOTSUPP, -1)
#define picoxnl_listen(...) (errno = EOPNOTSUPP, -1)
#define picoxnl_shutdown(...) (errno = EOPNOTSUPP, -1)

#define _PICOX(syscall, fd, ...) do { \
	struct fd_data *fdd = fduserdata_get(fd2picofd, fd); \
	ssize_t ret = 0; \
	if (fdd == NULL) \
	return errno = ENOENT, -1; \
	if (fdd->picoxnl == NULL) { \
		int picofd = fdd->picofd; \
		fduserdata_put(fdd); \
		ret = pico_##syscall(picofd, __VA_ARGS__); \
	} else { \
		ret = picoxnl_ ## syscall(fdd->picoxnl, __VA_ARGS__); \
		fduserdata_put(fdd); \
	} \
	return ret; \
} while (0)

int picox_bind(int fd, const struct sockaddr *addr, socklen_t addrlen) {
	_PICOX(bind, fd, (struct sockaddr *) addr, addrlen);
}

int picox_connect(int fd, const struct sockaddr *addr, socklen_t addrlen) {
	_PICOX(connect, fd, addr, addrlen);
}

int picox_listen(int fd, int backlog) {
	_PICOX(listen, fd, backlog);
}

int picox_getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen) {
	_PICOX(getsockname, fd, addr, addrlen);
}

int picox_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen) {
	_PICOX(getpeername, fd, addr, addrlen);
}

ssize_t picox_recvfrom(int fd, void *buf, size_t len, int flags,
		struct sockaddr *from, socklen_t *fromlen) {
	_PICOX(recvfrom, fd, buf, len, flags, from, fromlen);
}

ssize_t picox_sendto(int fd, const void *buf, size_t size, int flags,
		const struct sockaddr *to, socklen_t tolen) {
	_PICOX(sendto, fd, (void *) buf, size, flags, (struct sockaddr *) to, tolen);
}

ssize_t picox_recv(int fd, void *buf, size_t len, int flags) {
	return picox_recvfrom(fd, buf, len, flags, NULL, NULL);
}

ssize_t picox_send(int fd, const void *buf, size_t size, int flags) {
	return picox_sendto(fd, buf, size, flags, NULL, 0);
}

ssize_t picox_read(int fd, void *buf, size_t len) {
	return picox_recvfrom(fd, buf, len, 0, NULL, NULL);
}

ssize_t picox_write(int fd, const void *buf, size_t size) {
	return picox_sendto(fd, buf, size, 0, NULL, 0);
}

static size_t msg_totlen(struct iovec *msg_iov, size_t msg_iovlen) {
	size_t i, retval;
	for (i = retval = 0; i < msg_iovlen; i++)
		retval += msg_iov[i].iov_len;
	return retval;
}

static void msg_buf2iov(char *buf, size_t buflen, struct iovec *msg_iov, size_t msg_iovlen) {
	size_t chunklen;
	for (; msg_iovlen > 0 && buflen > 0;
			buf += chunklen, buflen -= chunklen, msg_iov++, msg_iovlen--) {
		chunklen = buflen < msg_iov->iov_len ? buflen : msg_iov->iov_len;
		memcpy(msg_iov->iov_base, buf, chunklen);
	}
}

static void msg_iov2buf(char *buf, size_t buflen, struct iovec *msg_iov, size_t msg_iovlen) {
	size_t chunklen;
	for (; msg_iovlen > 0 && buflen > 0;
			buf += chunklen, buflen -= chunklen, msg_iov++, msg_iovlen--) {
		chunklen = buflen < msg_iov->iov_len ? buflen : msg_iov->iov_len;
		memcpy(buf, msg_iov->iov_base, chunklen);
	}
}

ssize_t picox_recvmsg(int fd, struct msghdr *msg, int flags) {
	ssize_t retval;
	ssize_t msg_buflen;
	if (msg->msg_iovlen == 1) {
		msg_buflen = msg->msg_iov[0].iov_len;
		retval = picox_recvfrom(fd, msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len,
				flags, msg->msg_name, &msg->msg_namelen);
	} else {
		msg_buflen = msg_totlen(msg->msg_iov, msg->msg_iovlen);
		if (msg_buflen == 0)
			retval = picox_recvfrom(fd, NULL, 0, flags, msg->msg_name, &msg->msg_namelen);
		else {
			char msg_buf[msg_buflen];
			retval = picox_recvfrom(fd, msg_buf, msg_buflen,
					flags, msg->msg_name, &msg->msg_namelen);
			msg_buf2iov(msg_buf, retval, msg->msg_iov, msg->msg_iovlen);
		}
	}
	if (retval >= 0) {
		msg->msg_controllen = 0;
		if (retval > msg_buflen)
			msg->msg_flags |= MSG_TRUNC;
	}
	return retval;
}

ssize_t picox_sendmsg(int fd, const struct msghdr *msg, int flags) {
	ssize_t retval;
	if (msg->msg_iovlen == 1) {
		retval = picox_sendto(fd, msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len,
				flags, msg->msg_name, msg->msg_namelen);
	} else {
		size_t msg_buflen = msg_totlen(msg->msg_iov, msg->msg_iovlen);
		if (msg_buflen == 0)
			retval = picox_sendto(fd, NULL, 0, flags, msg->msg_name, msg->msg_namelen);
		else {
			char msg_buf[msg_buflen];
			msg_iov2buf(msg_buf, msg_buflen, msg->msg_iov, msg->msg_iovlen);
			retval = picox_sendto(fd, msg_buf, msg_buflen,
					flags, msg->msg_name, msg->msg_namelen);
		}
	}
	return retval;

}

ssize_t picox_readv(int fd, const struct iovec *iov, int iovcnt) {
	struct msghdr msg = {
		.msg_iov = (struct iovec *) iov,
		.msg_iovlen = iovcnt
	};
	return picox_recvmsg(fd, &msg, 0);
}

ssize_t picox_writev(int fd, const struct iovec *iov, int iovcnt) {
	struct msghdr msg = {
		.msg_iov = (struct iovec *) iov,
		.msg_iovlen = iovcnt
	};
	return picox_sendmsg(fd, &msg, 0);
}

int picox_setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen) {
	_PICOX(setsockopt, fd, level, optname, optval, optlen);
}

int picox_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen) {
	_PICOX(getsockopt, fd, level, optname, optval, optlen);
}

int picox_shutdown(int fd, int how) {
	_PICOX(shutdown, fd, how);
}

int picox_ioctl(int fd, unsigned long cmd, void *argp) {
	_PICOX(ioctl, fd, cmd, argp);
}

int picox_fcntl(int fd, int cmd, long val) {
	_PICOX(fcntl, fd, cmd, val);
}

/* Override default pico_rand() functions */
void pico_rand_feed(uint32_t feed)
{
}

uint32_t pico_rand(void)
{
    uint32_t rnd;
    int ret;
    ret = getrandom(&rnd, sizeof(rnd), 0);
    return rnd;
}

__attribute__((constructor))
	static void __init__(void) {
		srandom(time(NULL) + getpid());
		fd2picofd = fduserdata_create(0);
	}

__attribute__((destructor))
	static void __fini__(void) {
		fduserdata_destroy(fd2picofd); //callback?
	}
