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
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <vumodule.h>
#include <errno.h>
#include <pthread.h>

#include <asm/types.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <libvumod.h>
#include <libnlq.h>
#include <pico_stack.h>
#include <pico_device.h>
#include <pico_queue.h>
#include <pico_ipv4.h>
#include <pico_ipv6.h>
#include <pico_dev_vde.h>

union pico_route {
	struct pico_ipv4_route ipv4;
	struct pico_ipv6_route ipv6;
};

static void nl_dump1link(struct nlq_msg *msg, struct pico_device *link) {
	uint32_t zero = 0;
	unsigned int flags = IFF_UP;
	uint8_t mac_zero[6] = {};
	uint8_t mac_bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	if (link->link_state) {
		if (link->link_state(link))
			flags |= IFF_RUNNING;
	} else
		flags |= IFF_RUNNING;

	nlq_addstruct(msg, ifinfomsg, .ifi_type= link->mode, .ifi_index=link->hash, .ifi_flags=flags);
	nlq_addattr(msg, IFLA_IFNAME, link->name, strlen(link->name) + 1);
	if (link->eth)
		nlq_addattr(msg, IFLA_ADDRESS, link->eth->mac.addr, 6);
	else
		nlq_addattr(msg, IFLA_ADDRESS, mac_zero, 6);
	nlq_addattr(msg, IFLA_BROADCAST, mac_bcast, 6);
	nlq_addattr(msg, IFLA_MTU, &link->mtu, 4);
	nlq_addattr(msg, IFLA_TXQLEN, &link->q_out->size, 4);
}

static void nl_dump1addr_v4(struct nlq_msg *msg, struct pico_ipv4_link *link)
{
	uint32_t prefix = nlq_mask2prefix(AF_INET, &link->netmask);
	nlq_addstruct(msg, ifaddrmsg,
			.ifa_family = AF_INET,
			.ifa_prefixlen = prefix,
			.ifa_scope=RT_SCOPE_UNIVERSE,
			.ifa_index=link->dev->hash);
	nlq_addattr(msg, IFA_LOCAL, &link->address.addr, sizeof(struct pico_ip4));
	nlq_addattr(msg, IFA_ADDRESS, &link->address.addr, sizeof(struct pico_ip4));
	if (link->dev != NULL)
		nlq_addattr(msg, IFA_LABEL, link->dev->name, strlen(link->dev->name) + 1);
}

static void nl_dump1addr_v6(struct nlq_msg *msg, struct pico_ipv6_link *link)
{
	uint32_t prefix = nlq_mask2prefix(AF_INET6, &link->netmask);
	unsigned char scope;
	if (pico_ipv6_is_localhost(link->address.addr)) {
		scope = RT_SCOPE_HOST;
	} else if (pico_ipv6_is_linklocal(link->address.addr)) {
		scope = RT_SCOPE_LINK;
	} else if (pico_ipv6_is_sitelocal(link->address.addr)) {
		scope = RT_SCOPE_SITE;
	} else {
		scope = RT_SCOPE_UNIVERSE;
	}
	nlq_addstruct(msg, ifaddrmsg,
			.ifa_family = AF_INET6,
			.ifa_prefixlen = prefix,
			.ifa_scope=scope,
			.ifa_index=link->dev->hash);
	nlq_addattr(msg, IFA_LOCAL, &link->address, sizeof(struct pico_ip6));
	nlq_addattr(msg, IFA_ADDRESS, &link->address, sizeof(struct pico_ip6));
	if (link->dev != NULL)
		nlq_addattr(msg, IFA_LABEL, link->dev->name, strlen(link->dev->name) + 1);
}

static void nl_dump1addr(struct nlq_msg *msg, struct pico_stack *stack, union pico_link *link) {
	struct pico_ipv4_link *l4;
	struct pico_ipv6_link *l6;
	struct pico_tree_node *scan_link;
	pico_tree_foreach(scan_link, &stack->Tree_dev_link) {
		l4 = scan_link->keyValue;
		if (l4 == (struct pico_ipv4_link *) link) {
			nl_dump1addr_v4(msg, l4);
			return;
		}
	}
	pico_tree_foreach(scan_link, &stack->IPV6Links) {
		l6 = scan_link->keyValue;
		if (l6 == (struct pico_ipv6_link *) link) {
			nl_dump1addr_v6(msg, l6);
			return;
		}
	}
}

static void nl_dump1route_v4(struct nlq_msg *msg, struct pico_ipv4_route *route) {
	uint32_t prefix = nlq_mask2prefix(AF_INET, &route->netmask);
	nlq_addstruct(msg, rtmsg,
			.rtm_family = AF_INET,
			.rtm_table = RT_TABLE_MAIN,
			.rtm_protocol=RTPROT_BOOT,
			.rtm_scope=RT_SCOPE_UNIVERSE,
			.rtm_type=RTN_UNICAST,
			.rtm_dst_len = prefix,
			.rtm_src_len = 0);
	nlq_addattr(msg, RTA_DST, &route->dest, sizeof(struct pico_ip4));
	nlq_addattr(msg, RTA_GATEWAY, &route->gateway, sizeof(struct pico_ip4));
	if (route->link && route->link->dev)
		nlq_addattr(msg, RTA_OIF, &route->link->dev->hash, sizeof(uint32_t));
}

static void nl_dump1route_v6(struct nlq_msg *msg, struct pico_ipv6_route *route) {
	uint32_t prefix = nlq_mask2prefix(AF_INET, &route->netmask);
	nlq_addstruct(msg, rtmsg,
			.rtm_family = AF_INET6,
			.rtm_table = RT_TABLE_MAIN,
			.rtm_protocol=RTPROT_BOOT,
			.rtm_scope=RT_SCOPE_UNIVERSE,
			.rtm_type=RTN_UNICAST,
			.rtm_dst_len = prefix,
			.rtm_src_len = 0);
	nlq_addattr(msg, RTA_DST, &route->dest, sizeof(struct pico_ip6));
	nlq_addattr(msg, RTA_GATEWAY, &route->gateway, sizeof(struct pico_ip6));
	if (route->link && route->link->dev)
		nlq_addattr(msg, RTA_OIF, &route->link->dev->hash, sizeof(uint32_t));
}

static void nl_dump1route(struct nlq_msg *msg, struct pico_stack *stack, union pico_route *route) {
	struct pico_ipv4_route *r4;
	struct pico_ipv6_route *r6;
	struct pico_tree_node *scan_route;
	pico_tree_foreach(scan_route, &stack->Routes) {
		r4 = scan_route->keyValue;
		if (r4 == (struct pico_ipv4_route *) route) {
			nl_dump1route_v4(msg, r4);
			return;
		}
	}
	pico_tree_foreach(scan_route, &stack->IPV6Routes) {
		r6 = scan_route->keyValue;
		if (r6 == (struct pico_ipv6_route *) route) {
			nl_dump1route_v6(msg, r6);
			return;
		}
	}
}

#if 0
#endif
static struct pico_device *dev_get_byindex(struct pico_stack *stack, uint32_t idx)
{
	struct pico_device *dev;
	struct pico_tree_node *index;
	pico_tree_foreach(index, &stack->Device_tree){
		dev = index->keyValue;
		if (idx == dev->hash)
			return dev;
	}
	return NULL;
}

static void *nl_search_link(struct nlmsghdr *msg, struct nlattr **attr, void *argenv) {
	struct ifinfomsg *ifi = (struct ifinfomsg *)(msg + 1);
	struct pico_stack *stack = argenv;
	if (attr[IFLA_IFNAME] != NULL)
		return pico_get_device(stack, (char *) (attr[IFLA_IFNAME] + 1));
	else
		return dev_get_byindex(stack, ifi->ifi_index);
}

static int nl_linkcreate(struct nlmsghdr *msg, struct nlattr **attr, void *argenv) {
	struct pico_stack *stack = argenv;
	struct nlattr *ifla_info[__IFLA_INFO_MAX];
	struct ifinfomsg *ifi = (struct ifinfomsg *)(msg + 1);
	struct pico_device *dev;
	char *vdeurl = "";
	long int mrandmac = random();
	uint8_t macaddr[6] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00 };
	macaddr[5] = mrandmac;
	macaddr[4] = mrandmac >> 8;
	macaddr[3] = mrandmac >> 16;
	macaddr[2] = mrandmac >> 24;
	macaddr[1] = mrandmac >> 32;

	if (attr[IFLA_LINKINFO] == NULL)
		return -EINVAL;
	nlq_parsexattr(attr[IFLA_LINKINFO],ifla_info,__IFLA_INFO_MAX);
	if (ifla_info[IFLA_INFO_KIND] == NULL)
		return -EINVAL;
	if (strcmp((char*)(ifla_info[IFLA_INFO_KIND]+1), "vde") != 0)
		return -EINVAL;
	if (ifla_info[IFLA_INFO_DATA] != NULL)
		vdeurl = (char *) (ifla_info[IFLA_INFO_DATA] + 1);

	if (attr[IFLA_IFNAME] != NULL) {
		char *name = (char *) (attr[IFLA_IFNAME]+1);
		dev = pico_vde_create(stack, vdeurl, name, macaddr);
	} else {
		static unsigned char counter = 0;
		char name[8];
		snprintf(name, 8, "vde%d\n", counter++);
		dev = pico_vde_create(stack, vdeurl, name, macaddr);
	}

	if (dev != NULL) {
		if (attr[IFLA_NEW_IFINDEX] != NULL)
			return dev->hash;
		else
			return 0;
	} else
		return -EINVAL;
}

static int nl_linkdel(void *item, struct nlmsghdr *msg, struct nlattr **attr, void *argenv) {
	struct pico_device *link = item;
	pico_ipv4_cleanup_links(link->stack, link);
	pico_device_destroy(link);
	return 0;
}

static int nl_linkset(void *entry, struct nlmsghdr *msg, struct nlattr **attr, void *argenv) {
	struct pico_device *link = entry;
	struct ifinfomsg *ifi = (struct ifinfomsg *)(msg + 1);
	if ((ifi->ifi_change & IFF_UP) == 0) {
		pico_ipv4_cleanup_links(link->stack, link);
	}
	if (attr[IFLA_MTU] != NULL)
		link->mtu = *(uint32_t *)(attr[IFLA_MTU] + 1);
	return 0;
}

static void *nl_search_addr(struct nlmsghdr *msg, struct nlattr **attr, void *argenv) {
	struct pico_stack *stack = argenv;
	struct ifaddrmsg *ifa = (struct ifaddrmsg *)(msg + 1);

	if (attr[IFA_ADDRESS] == NULL)
		return NULL;

	if (ifa->ifa_family == AF_INET)
		return pico_ipv4_link_get(stack, (struct pico_ip4 *) (attr[IFA_ADDRESS] + 1));
	if (ifa->ifa_family == AF_INET6)
		return pico_ipv6_link_get(stack, (struct pico_ip6 *) (attr[IFA_ADDRESS] + 1));
	return NULL;
}

static int nl_addrcreate(struct nlmsghdr *msg, struct nlattr **attr, void *argenv) {
	struct pico_stack *stack = argenv;
	struct ifaddrmsg *ifa = (struct ifaddrmsg *)(msg + 1);
	//union pico_address address, netmask;
	struct pico_device *dev;
	// check consistency;
	if (attr[IFA_ADDRESS] == NULL || attr[IFA_ADDRESS]->nla_len - sizeof(struct nlattr) != nlq_family2addrlen(ifa->ifa_family))
		return -EINVAL;

	dev = dev_get_byindex(stack, ifa->ifa_index);
	if (!dev)
		return -ENOENT;

	if (ifa->ifa_family == AF_INET) {
		struct pico_ip4 address, netmask;
		nlq_prefix2mask(AF_INET, &netmask, ifa->ifa_prefixlen);
		memcpy(&address, attr[IFA_ADDRESS] + 1, sizeof(struct pico_ip4));
        if (pico_ipv4_link_add(stack, dev, address, netmask) == 0)
            return 0;
        else
            return (0 - pico_err);
	}
	if (ifa->ifa_family == AF_INET6) {
		struct pico_ip6 address, netmask;
		nlq_prefix2mask(AF_INET6, &netmask, ifa->ifa_prefixlen);
		memcpy(&address, attr[IFA_ADDRESS] + 1, sizeof(struct pico_ip6));
        if (pico_ipv6_link_add(dev, address, netmask) != NULL)
            return 0;
        else
            return (0 - pico_err);
	}
}

static int nl_addrdel(void *item, struct nlmsghdr *msg, struct nlattr **attr, void *argenv) {
	union pico_link *link = item;
	struct pico_stack *stack = argenv;
	struct pico_device *dev;
	struct pico_ipv4_link *l4;
	struct pico_ipv6_link *l6;
	struct pico_tree_node *scan_link;
	struct pico_tree_node *_tmp = NULL;
	dev = link->ipv4.dev; /* In the same position in both structs */

	/* Try removing ipv4 link first */

	pico_tree_foreach_safe(scan_link, &stack->Tree_dev_link, _tmp) {
		l4 = scan_link->keyValue;
		if (l4 == (struct pico_ipv4_link *) link) {
			pico_ipv4_link_del(stack, dev, l4->address);
			return 0;
		}
	}
	pico_tree_foreach_safe(scan_link, &stack->IPV6Links, _tmp) {
		l6 = scan_link->keyValue;
		if (l6 == (struct pico_ipv6_link *) link) {
			pico_ipv6_link_del(stack, dev, l6->address);
			return 0;
		}
	}
	return -ENOENT;
}

static void *nl_search_route(struct nlmsghdr *msg, struct nlattr **attr, void *argenv)
{
	struct pico_stack *stack = argenv;
	struct pico_tree_node *scan;
	struct rtmsg *rtm = (struct rtmsg *) (msg + 1);
	struct pico_ipv4_route *r4;
	struct pico_ipv6_route *r6;

	if (rtm->rtm_family == AF_INET) {
		pico_tree_foreach(scan, &stack->Routes) {
			r4 = scan->keyValue;
			if ((rtm->rtm_dst_len == nlq_mask2prefix(AF_INET, &r4->netmask.addr)) &&
					((attr[RTA_DST] == NULL && (r4->dest.addr == 0)) ||
					 (attr[RTA_DST] != NULL && (r4->dest.addr != 0) &&
						memcmp(&r4->dest, attr[RTA_DST]+1, sizeof(struct pico_ip4))== 0)) &&
					attr[RTA_GATEWAY] != NULL &&
					memcmp(&r4->gateway, attr[RTA_GATEWAY]+1, sizeof(struct pico_ip4)) == 0 &&
					(attr[RTA_OIF] == NULL ||
					 r4->link->dev->hash == *((uint32_t *)(attr[RTA_OIF] + 1))) &&
					1)
				return r4;
		}
	}
	if (rtm->rtm_family == AF_INET6) {
		pico_tree_foreach(scan, &stack->IPV6Routes) {
			r6 = scan->keyValue;
			if ((rtm->rtm_dst_len == nlq_mask2prefix(AF_INET6, r6->netmask.addr)) &&
					((attr[RTA_DST] == NULL && pico_ipv6_is_null_address(&r6->dest)) ||
					 (attr[RTA_DST] != NULL && (!pico_ipv6_is_null_address(&r6->dest)) &&
						memcmp(&r6->dest, attr[RTA_DST]+1, sizeof(struct pico_ip6))== 0)) &&
					attr[RTA_GATEWAY] != NULL &&
					memcmp(&r6->gateway, attr[RTA_GATEWAY]+1, sizeof(struct pico_ip6)) == 0 &&
					(attr[RTA_OIF] == NULL ||
					 r6->link->dev->hash == *((uint32_t *)(attr[RTA_OIF] + 1))) &&
					1)
				return r6;
		}

	}
	return NULL;
}

static int nl_routecreate(struct nlmsghdr *msg, struct nlattr **attr, void *argenv) {
	struct pico_stack *stack = argenv;
	struct rtmsg *rtm = (struct rtmsg *)(msg + 1);
	int ret;
	if (attr[RTA_GATEWAY] == NULL || attr[RTA_GATEWAY]->nla_len - sizeof(struct nlattr) != nlq_family2addrlen(rtm->rtm_family))
		return -EINVAL;
	if (attr[RTA_DST] != NULL && attr[RTA_DST]->nla_len - sizeof(struct nlattr) != nlq_family2addrlen(rtm->rtm_family))
		return -EINVAL;
	if (rtm->rtm_family == AF_INET) {
		struct pico_ip4 dst, mask, gw;
		if (attr[RTA_DST] != NULL)
			memcpy(&dst, attr[RTA_DST]+1, sizeof(struct pico_ip4));
		else
			memset(&dst, 0, sizeof(struct pico_ip4));
		memcpy(&gw, attr[RTA_GATEWAY]+1, sizeof(struct pico_ip4));
		nlq_prefix2mask(AF_INET, &mask, rtm->rtm_dst_len);
		ret = pico_ipv4_route_add(stack, dst, mask, gw, 1, NULL);
		if (ret == 0)
			return 0;
		return (0 - pico_err);
	}
	if (rtm->rtm_family == AF_INET6) {
		struct pico_ip6 dst6, mask6, gw6;
		if (attr[RTA_DST] != NULL)
			memcpy(&dst6, attr[RTA_DST]+1, sizeof(struct pico_ip6));
		else
			memset(&dst6, 0, sizeof(struct pico_ip6));
		memcpy(&gw6, attr[RTA_GATEWAY]+1, sizeof(struct pico_ip6));
		nlq_prefix2mask(AF_INET6, &mask6, rtm->rtm_dst_len);
		pico_ipv6_route_add(stack, dst6, mask6, gw6, 1, NULL);
		if (ret == 0)
			return 0;
		return (0 - pico_err);
	}
	return -EINVAL;
}

static int nl_routedel(void *item, struct nlmsghdr *msg, struct nlattr **attr, void *argenv) {
	union pico_route *route = item;
	struct pico_stack *stack = argenv;
	//struct pico_device *dev;
	struct pico_ipv4_route *r4;
	struct pico_ipv6_route *r6;
	struct pico_tree_node *scan_route;
	struct pico_tree_node *_tmp = NULL;
	//dev = route->ipv4.dev; /* In the same position in both structs */

	/* Try removing ipv4 route first */

	pico_tree_foreach_safe(scan_route, &stack->Routes, _tmp) {
		r4 = scan_route->keyValue;
		if (r4 == (struct pico_ipv4_route *) route) {
			pico_ipv4_route_del(stack, r4->dest, r4->netmask, r4->metric);
			return 0;
		}
	}
	pico_tree_foreach_safe(scan_route, &stack->IPV6Routes, _tmp) {
		r6 = scan_route->keyValue;
		if (r6 == (struct pico_ipv6_route *) route) {
			pico_ipv6_route_del(stack, r6->dest, r6->netmask, r6->gateway, r6->metric, r6->link);
			return 0;
		}
	}
	return -ENOENT;
}

static int nl_linkget(void *entry, struct nlmsghdr *msg, struct nlattr **attr, struct nlq_msg **reply_msgq, void *argenv) {
	struct pico_stack *stack = argenv;
	struct pico_device *dev;
	struct pico_tree_node *scan;
	if (entry == NULL) { // DUMP
		pico_tree_foreach(scan, &stack->Device_tree) {
			struct nlq_msg *newmsg = nlq_createmsg(RTM_NEWLINK, NLM_F_MULTI, msg->nlmsg_seq, 0);
			dev = scan->keyValue;
			nl_dump1link(newmsg, dev);
			nlq_complete_enqueue(newmsg, reply_msgq);
		}
	} else {
		struct nlq_msg *newmsg = nlq_createmsg(RTM_NEWLINK, 0, msg->nlmsg_seq, 0);
		nl_dump1link(newmsg, entry);
		nlq_complete_enqueue(newmsg, reply_msgq);
	}
	return 0;
}

static int nl_addrget(void *entry, struct nlmsghdr *msg, struct nlattr **attr, struct nlq_msg **reply_msgq, void *argenv) {
	struct ifaddrmsg *ifa = (struct ifaddrmsg *)(msg + 1);

	struct pico_stack *stack = argenv;
	union  pico_link *link;
	struct pico_tree_node *scan;
	if (entry == NULL) { // DUMP
		if (ifa->ifa_family == AF_UNSPEC || ifa->ifa_family == AF_INET) {
			pico_tree_foreach(scan, &stack->Tree_dev_link) {
				struct nlq_msg *newmsg = nlq_createmsg(RTM_NEWADDR, NLM_F_MULTI, msg->nlmsg_seq, 0);
				link = scan->keyValue;
				nl_dump1addr_v4(newmsg, (struct pico_ipv4_link *) link);
				nlq_complete_enqueue(newmsg, reply_msgq);
			}
		}
		if (ifa->ifa_family == AF_UNSPEC || ifa->ifa_family == AF_INET6) {
			pico_tree_foreach(scan, &stack->IPV6Links) {
				struct nlq_msg *newmsg = nlq_createmsg(RTM_NEWADDR, NLM_F_MULTI, msg->nlmsg_seq, 0);
				link = scan->keyValue;
				nl_dump1addr_v6(newmsg, (struct pico_ipv6_link *) link);
				nlq_complete_enqueue(newmsg, reply_msgq);
			}
		}
	} else {
		struct nlq_msg *newmsg = nlq_createmsg(RTM_NEWADDR, 0, msg->nlmsg_seq, 0);
		nl_dump1addr(newmsg, stack, entry);
		nlq_complete_enqueue(newmsg, reply_msgq);
	}
	return 0;
}

static int nl_routeget(void *entry, struct nlmsghdr *msg, struct nlattr **attr, struct nlq_msg **reply_msgq, void *argenv)
{
	struct pico_stack *stack = argenv;
	union pico_route *route;
	struct pico_tree_node *scan;
	if (entry == NULL) { // DUMP
		pico_tree_foreach(scan, &stack->IPV6Routes) {
			struct nlq_msg *newmsg = nlq_createmsg(RTM_NEWROUTE, NLM_F_MULTI, msg->nlmsg_seq, 0);
			route = scan->keyValue;
			nl_dump1route_v6(newmsg, (struct pico_ipv6_route *) route);
			nlq_complete_enqueue(newmsg, reply_msgq);
		}
		pico_tree_foreach(scan, &stack->Routes) {
			struct nlq_msg *newmsg = nlq_createmsg(RTM_NEWROUTE, NLM_F_MULTI, msg->nlmsg_seq, 0);
			route = scan->keyValue;
			nl_dump1route_v4(newmsg, (struct pico_ipv4_route *) route);
			nlq_complete_enqueue(newmsg, reply_msgq);
		}
	} else {
		struct nlq_msg *newmsg = nlq_createmsg(RTM_NEWROUTE, 0, msg->nlmsg_seq, 0);
		nl_dump1route(newmsg, stack, entry);
		nlq_complete_enqueue(newmsg, reply_msgq);
	}
	return 0;
}

static nlq_request_handlers_table picostack_handlers_table = {
	[RTMF_LINK]={nl_search_link, nl_linkget, nl_linkcreate, nl_linkdel, nl_linkset},
	[RTMF_ADDR]={nl_search_addr, nl_addrget, nl_addrcreate, nl_addrdel},
	[RTMF_ROUTE]={nl_search_route, nl_routeget, nl_routecreate, nl_routedel}
};

struct nlq_msg *picox_netlink_process(struct nlmsghdr *msg, struct pico_stack *stack) {
	//printf("picox_netlink_process\n");
	return nlq_process_rtrequest(msg, picostack_handlers_table, stack);
}

int picox_netlink_ioctl(struct pico_stack *stack, unsigned long request, void *arg) {
	//printf("picox_netlink_ioctl\n");
	return nlq_server_ioctl(picostack_handlers_table, stack, request, arg);
}
