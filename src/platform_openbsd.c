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
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>

#include <net/if.h>
#include <net/route.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sanctum.h"

struct rtmsg {
	struct rt_msghdr	rtm;
	u_int8_t		buf[512];
};

#define PATH_SKIP	(sizeof("/dev/") - 1)

static void	openbsd_route_add(const char *);
static void	openbsd_configure_tundev(const char *);

/*
 * OpenBSD tunnel device creation.
 * We attempt to open one of the defined tunnel interfaces under /dev.
 */
int
sanctum_platform_tundev_create(void)
{
	char		path[128];
	int		fd, idx, len, flags;

	for (idx = 0; idx < 256; idx++) {
		len = snprintf(path, sizeof(path), "/dev/tun%d", idx);
		if (len == -1 || (size_t)len >= sizeof(path))
			fatal("/dev/tun%d too long", idx);

		if ((fd = open(path, O_RDWR)) != -1)
			break;
	}

	if (idx == 256)
		fatal("unable to find free tunnel device");

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		fatal("fcntl: %s", errno_s);

	flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) == -1)
		fatal("fcntl: %s", errno_s);

	openbsd_configure_tundev(&path[PATH_SKIP]);
	openbsd_route_add(&path[PATH_SKIP]);

	sanctum_log(LOG_INFO, "using tun device '%s'", path);

	free(sanctum->tun_ip);
	free(sanctum->tun_mask);

	sanctum->tun_ip = NULL;
	sanctum->tun_mask = NULL;

	return (fd);
}

/* Read a single packet from the tunnel device. */
ssize_t
sanctum_platform_tundev_read(int fd, struct sanctum_packet *pkt)
{
	ssize_t			ret;
	u_int8_t		*data;
	struct iovec		iov[2];
	u_int32_t		protocol;

	PRECOND(fd >= 0);
	PRECOND(pkt != NULL);

	data = sanctum_packet_data(pkt);

	iov[0].iov_base = &protocol;
	iov[0].iov_len = sizeof(protocol);
	iov[1].iov_base = data;
	iov[1].iov_len = SANCTUM_PACKET_DATA_LEN;

	/*
	 * We have to adjust the total data read with the protocol
	 * information we read, otherwise the size makes no sense
	 * later for our other components.
	 */
	ret = readv(fd, iov, 2);
	if (ret != -1 && (size_t)ret >= sizeof(protocol))
		ret -= sizeof(protocol);

	return (ret);
}

/* Write a single packet to the tunnel device. */
ssize_t
sanctum_platform_tundev_write(int fd, struct sanctum_packet *pkt)
{
	u_int32_t		proto;
	u_int8_t		*data;
	struct iovec		iov[2];

	PRECOND(fd >= 0);
	PRECOND(pkt != NULL);

	data = sanctum_packet_data(pkt);
	proto = htonl(AF_INET);

	iov[0].iov_base = &proto;
	iov[0].iov_len = sizeof(proto);
	iov[1].iov_base = data;
	iov[1].iov_len = pkt->length;

	return (writev(fd, iov, 2));
}

/* Configure the tunnel device. */
static void
openbsd_configure_tundev(const char *dev)
{
	struct ifreq		ifr;
	struct ifaliasreq	ifra;
	int			fd, len;
	char			descr[128];

	PRECOND(dev != NULL);

	memset(&ifr, 0, sizeof(ifr));
	memset(&ifra, 0, sizeof(ifra));

	if (strlcpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name)) >=
	    sizeof(ifr.ifr_name))
		fatal("ifc '%s' too long", dev);

	if (strlcpy(ifra.ifra_name, dev, sizeof(ifra.ifra_name)) >=
	    sizeof(ifra.ifra_name))
		fatal("ifc '%s' too long", dev);

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", errno_s);

	sanctum_inet_addr(&ifra.ifra_addr, sanctum->tun_ip);
	sanctum_inet_addr(&ifra.ifra_mask, sanctum->tun_mask);
	sanctum_inet_addr(&ifra.ifra_broadaddr, sanctum->tun_ip);

	if (ioctl(fd, SIOCAIFADDR, &ifra) == -1)
		fatal("ioctl(SIOCAIFADDR): %s", errno_s);

	len = snprintf(descr, sizeof(descr), "sanctum instance %s",
	    sanctum->instance);
	if (len == -1 || (size_t)len >= sizeof(descr))
		fatal("the description name is too long");

	ifr.ifr_data = descr;
	if (ioctl(fd, SIOCSIFDESCR, &ifr) == -1)
		fatal("ioctl(SIOCSIFDESCR): %s", errno_s);

	ifr.ifr_flags = IFF_UP | IFF_RUNNING;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1)
		fatal("ioctl(SIOCSIFFLAGS): %s", errno_s);

	ifr.ifr_mtu = sanctum->tun_mtu;
	if (ioctl(fd, SIOCSIFMTU, &ifr) == -1)
		fatal("ioctl(SIOCSIFMTU): %s", errno_s);

	(void)close(fd);
}

/* Helper to add a route for our tunnel net. */
static void
openbsd_route_add(const char *dev)
{
	int			s;
	u_int8_t		*cp;
	struct rtmsg		msg;
	ssize_t			ret;
	struct sockaddr_in	mask, dst, gw;

	PRECOND(dev != NULL);

	memset(&msg, 0, sizeof(msg));

	msg.rtm.rtm_seq = 1;
	msg.rtm.rtm_type = RTM_ADD;
	msg.rtm.rtm_version = RTM_VERSION;
	msg.rtm.rtm_hdrlen = sizeof(msg.rtm);
	msg.rtm.rtm_flags = RTF_STATIC | RTF_UP | RTF_GATEWAY;
	msg.rtm.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;

	sanctum_inet_addr(&gw, sanctum->tun_ip);
	sanctum_inet_addr(&dst, sanctum->tun_ip);
	sanctum_inet_addr(&mask, sanctum->tun_mask);

	dst.sin_addr.s_addr &= mask.sin_addr.s_addr;

	cp = msg.buf;

	memcpy(cp, &dst, sizeof(dst));
	cp += sizeof(dst);

	memcpy(cp, &gw, sizeof(gw));
	cp += sizeof(gw);

	memcpy(cp, &mask, sizeof(mask));
	cp += sizeof(mask);

	msg.rtm.rtm_msglen = cp - (u_int8_t *)&msg;

	if ((s = socket(AF_ROUTE, SOCK_RAW, AF_INET)) == -1)
		fatal("socket: %s", errno_s);

	if ((ret = write(s, &msg, msg.rtm.rtm_msglen)) == -1)
		fatal("write: %s", errno_s);

	if ((size_t)ret != msg.rtm.rtm_msglen)
		fatal("failed to write entire message");

	(void)close(s);
}
