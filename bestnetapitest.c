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
#include <strings.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <poll.h>
#include <picox_bsd.h>
#include <nlinline+.h>

#define SERV_PORT 3456
#define MAXCONN 4

NLINLINE_LIBMULTI(picox_)

	ssize_t str_echo(int i, int fd) {
		char buf[1025];
		ssize_t len;
		if ((len = picox_recv(fd, buf, 1024, 0)) > 0) {
			picox_send(fd, buf, len, 0);
			buf[len] = 0;
			printf("echo %d -> %s\n", i, buf);
		}
	}

void server(struct picox *stack) {
	struct sockaddr_in  cliaddr, servaddr;
	struct pollfd pfd[MAXCONN + 1] = {[0 ... MAXCONN] = {-1, POLLIN, 0}};
	int rv;

	pfd[0].fd = picox_msocket(stack, AF_INET, SOCK_STREAM, 0);
	printf("picox_socket %d\n", pfd[0].fd);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port        = htons(SERV_PORT);

	rv = picox_bind(pfd[0].fd, (struct sockaddr *) &servaddr, sizeof(servaddr));
	printf("picox_bind %d\n", rv);

	rv = picox_listen(pfd[0].fd, 5);
	printf("picox_listen %d\n", rv);

	for ( ; ; ) {
		int i;
		int events = poll(pfd, MAXCONN + 1, -1);
		if (events < 0) break;
		if (pfd[0].revents & POLLIN) {
			int         connfd;
			struct sockaddr_in  cliaddr;
			socklen_t     clilen = sizeof(cliaddr);

			connfd = picox_accept(pfd[0].fd, (struct sockaddr *) &cliaddr, &clilen);
			for (i = 1; i <= MAXCONN; i++) {
				if (pfd[i].fd < 0) {
					pfd[i].fd = connfd;
					break;
				}
			}
			if (i > MAXCONN) {
				picox_close(connfd);
				i = -1;
			}
			printf("picox_accept %d -> %d\n", connfd, i);
			events--;
		}
		for (i = 1; i <= MAXCONN && events > 0; i++) {
			if (pfd[i].revents & POLLIN) {
				if (str_echo(i, pfd[i].fd) <= 0) {
					picox_close(pfd[i].fd);
					pfd[i].fd = -1;
					printf("close %d\n", i);
				}
				events--;
			}
		}
	}
}

int main(int argc, char *argv[]) {
	int rv;
	uint8_t ipv4addr[] = {192,168,250,42};
	uint8_t ipv4gw[] = {192,168,250,1};
	uint8_t ipv6addr[16] = {0x20, 0x01, 0x07, 0x60, [15] = 0x02};
	uint8_t ipv6gw[16] = {0x20, 0x01, 0x07, 0x60, [15] = 0x01};

	struct picox *stack = picox_newstack(argv[1]);

	int ifindex;
	if ((ifindex = picox_iplink_add(stack, NULL, -1, "vde", "")) < 0)
		perror("link add");

#if 0
	int ifindex = picox_if_nametoindex(stack, "picox0");
	if (ifindex > 0)
		printf("%d\n", ifindex);
	else {
		perror("nametoindex");
		return 1;
	}
#endif

	if (picox_linksetupdown(stack, ifindex, 1) < 0)
		perror("link up");
	if (picox_ipaddr_add(stack, AF_INET, ipv4addr, 24, ifindex) < 0)
		perror("addr ipv4");
	if (picox_iproute_add(stack, AF_INET, NULL, 0, ipv4gw) < 0)
		perror("addr ipv6");
#if 0
	if (picox_ipaddr_add(stack, AF_INET6, ipv6addr, 64, ifindex) < 0)
		perror("route ipv4");
	if (picox_iproute_add(stack, AF_INET6, NULL, 0, ipv6gw) < 0)
		perror("route ipv6");
#endif

	/* use the stack */
	server(stack);

	picox_delstack(stack);
}
