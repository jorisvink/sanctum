/*
 * Copyright (c) 2023 Joris Vink <joris@sanctorum.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>

#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sanctum.h"

static void	linux_configure_tundev(struct ifreq *);
static void	linux_rt_sin(struct nlmsghdr *, void *, u_int16_t,
		    struct sockaddr_in *);

/*
 * Linux tunnel device creation. The sanctum.clr device is created and a
 * file descriptor for it is returned to the caller.
 *
 * XXX - permissions on tunnel device.
 */
int
sanctum_platform_tundev_create(void)
{
	struct ifreq		ifr;
	int			len, fd, flags;

	memset(&ifr, 0, sizeof(ifr));

	if ((fd = open("/dev/net/tun", O_RDWR)) == -1)
		fatal("failed to open /dev/net/tun: %s", errno_s);

	len = snprintf(ifr.ifr_name, sizeof(ifr.ifr_name),
	    "%s.clr", sanctum->instance);
	if (len == -1 || (size_t)len >= sizeof(ifr.ifr_name))
		fatal("sanctum.clr interface name too large");

	ifr.ifr_flags = IFF_TUN | IFF_UP | IFF_NO_PI;

	if (ioctl(fd, TUNSETIFF, &ifr) == -1)
		fatal("ioctl: %s", errno_s);

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		fatal("fcntl: %s", errno_s);

	flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) == -1)
		fatal("fcntl: %s", errno_s);

	linux_configure_tundev(&ifr);

	return (fd);
}

/* Read a single packet from the tunnel device. */
ssize_t
sanctum_platform_tundev_read(int fd, struct sanctum_packet *pkt)
{
	u_int8_t	*data;

	PRECOND(fd >= 0);
	PRECOND(pkt != NULL);

	data = sanctum_packet_data(pkt);

	return (read(fd, data, SANCTUM_PACKET_DATA_LEN));
}

/* Write a single packet to the tunnel device. */
ssize_t
sanctum_platform_tundev_write(int fd, struct sanctum_packet *pkt)
{
	u_int8_t	*data;

	PRECOND(fd >= 0);
	PRECOND(pkt != NULL);

	data = sanctum_packet_data(pkt);

	return (write(fd, data, pkt->length));
}

/* Adds a new route via our tunnel device. */
void
sanctum_platform_tundev_route(struct sockaddr_in *net, struct sockaddr_in *mask)
{
	int			s;
	u_int32_t		m;
	ssize_t			ret;
	struct rtmsg		*rt;
	struct nlmsghdr		*hdr;
	struct nlmsgerr		*error;
	u_int8_t		buf[512];

	PRECOND(net != NULL);
	PRECOND(mask != NULL);

	memset(buf, 0, sizeof(buf));

	hdr = (struct nlmsghdr *)&buf;
	hdr->nlmsg_seq = 0;
	hdr->nlmsg_pid = getpid();
	hdr->nlmsg_type = RTM_NEWROUTE;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE |
	    NLM_F_EXCL | NLM_F_ACK;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(*rt));

	rt = (struct rtmsg *)&buf[NLMSG_HDRLEN];
	rt->rtm_family = AF_INET;
	rt->rtm_type = RTN_UNICAST;
	rt->rtm_table = RT_TABLE_MAIN;
	rt->rtm_protocol = RTPROT_STATIC;
	rt->rtm_scope = RT_SCOPE_UNIVERSE;

	rt->rtm_dst_len = 0;
	m = ntohl(mask->sin_addr.s_addr);

	while (m) {
		if (m & 1)
			rt->rtm_dst_len++;
		m = m >> 1;
	}

	linux_rt_sin(hdr, &buf[hdr->nlmsg_len], RTA_DST, net);
	linux_rt_sin(hdr, &buf[hdr->nlmsg_len], RTA_GATEWAY, &sanctum->tun_ip);

	if ((s = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) == -1)
		fatal("socket(AF_NETLINK): %s", errno_s);

	if ((ret = write(s, buf, hdr->nlmsg_len)) == -1)
		fatal("write: %s", errno_s);

	if ((size_t)ret != hdr->nlmsg_len)
		fatal("short write %zd/%u", ret, hdr->nlmsg_len);

	if ((ret = read(s, buf, sizeof(buf))) == -1)
		fatal("read: %s", errno_s);

	if (ret == 0)
		fatal("eof on netlink socket");

	if ((size_t)ret < (sizeof(*hdr) + sizeof(*error)))
		fatal("too short message from netlink (%zd)", ret);

	if (hdr->nlmsg_type != NLMSG_ERROR)
		fatal("unexpected type %u", hdr->nlmsg_type);

	error = (struct nlmsgerr *)&buf[NLMSG_HDRLEN];
	if (error->error != 0)
		fatal("failed to add route: %d", error->error);

	(void)close(s);
}

/* Helper to stuff a sockaddr_in into an rtattr for netlink. */
static void
linux_rt_sin(struct nlmsghdr *hdr, void *attr, u_int16_t type,
    struct sockaddr_in *sin)
{
	struct rtattr		*rta;

	PRECOND(hdr != NULL);
	PRECOND(attr != NULL);
	PRECOND(sin != NULL);

	rta = attr;

	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(sizeof(sin->sin_addr));

	memcpy(RTA_DATA(rta), &sin->sin_addr, sizeof(sin->sin_addr));
	hdr->nlmsg_len = NLMSG_ALIGN(hdr->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

/* Configure the tunnel device. */
static void
linux_configure_tundev(struct ifreq *ifr)
{
	int		fd;

	PRECOND(ifr != NULL);

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", errno_s);

	memcpy(&ifr->ifr_addr, &sanctum->tun_ip, sizeof(sanctum->tun_ip));
	if (ioctl(fd, SIOCSIFADDR, ifr) == -1)
		fatal("ioctl(SIOCSIFADDR): %s", errno_s);
	if (ioctl(fd, SIOCSIFDSTADDR, ifr) == -1)
		fatal("ioctl(SIOCSIFDSTADDR): %s", errno_s);

	memcpy(&ifr->ifr_addr, &sanctum->tun_mask, sizeof(sanctum->tun_mask));
	if (ioctl(fd, SIOCSIFNETMASK, ifr) == -1)
		fatal("ioctl(SIOCSIFNETMASK): %s", errno_s);

	ifr->ifr_flags = IFF_UP | IFF_RUNNING;
	if (ioctl(fd, SIOCSIFFLAGS, ifr) == -1)
		fatal("ioctl(SIOCSIFFLAGS): %s", errno_s);

	ifr->ifr_mtu = sanctum->tun_mtu;
	if (ioctl(fd, SIOCSIFMTU, ifr) == -1)
		fatal("ioctl(SIOCSIFMTU): %s", errno_s);

	(void)close(fd);
}
