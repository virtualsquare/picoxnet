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
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <picox_bsd.h>
#if USENETLINK
#include <nlinline+.h>
NLINLINE_LIBMULTI(picox_)
#endif

#define SERV_PORT 3456

void str_echo(int fd) {
	char buf[1025];
	ssize_t len;
	printf("strecho\n");
	while((len = picox_recv(fd, buf, 1024, 0)) > 0) {
		picox_send(fd, buf, len, 0);
		buf[len] = 0;
		printf("echo %s\n", buf);
	}
}

int main(int argc, char **argv)
{
	int					listenfd, connfd;
	socklen_t			clilen;
	struct sockaddr_in	cliaddr, servaddr;
	int rv;

#if USENETLINK
	struct picox *stack = picox_newstack(NULL);
	uint8_t ipv4addr[] = {192,168,250,42};
  uint8_t ipv4gw[] = {192,168,250,1};
	int ifindex;

	if ((ifindex = picox_iplink_add(stack, NULL, -1, "vde", "")) < 0)
		perror("link add");
	if (picox_linksetupdown(stack, ifindex, 1) < 0)
		perror("link up");
  if (picox_ipaddr_add(stack, AF_INET, ipv4addr, 24, ifindex) < 0)
    perror("addr ipv4");
  if (picox_iproute_add(stack, AF_INET, NULL, 0, ipv4gw) < 0)
    perror("route ipv4");
#else
	struct picox *stack = picox_newstack(argv[1]);
#endif
	printf("start\n");

	listenfd = picox_msocket(stack, AF_INET, SOCK_STREAM, 0);
	printf("pico_socket %d\n", listenfd);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port        = htons(SERV_PORT);

	rv = picox_bind(listenfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
	printf("pico_bind %d\n", rv);

	rv = picox_listen(listenfd, 5);
	printf("pico_listen %d\n", rv);

	for ( ; ; ) {
		clilen = sizeof(cliaddr);
		connfd = picox_accept(listenfd, (struct sockaddr *) &cliaddr, &clilen);
		printf("pico_accept %d\n", connfd);
		sleep(1);
		if (connfd >= 0) {
			str_echo(connfd);
		  picox_close(connfd);	
		} else
			perror("accept");
	}
}
