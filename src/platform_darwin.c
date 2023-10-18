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
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/uio.h>

#include <arpa/inet.h>

#include <net/if.h>
#include <net/if_utun.h>
#include <net/route.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sanctum.h"
#include "libnyfe.h"

struct rtmsg {
	struct rt_msghdr	rtm;
	u_int8_t		buf[512];
};

#define APPLE_UTUN_CONTROL	"com.apple.net.utun_control"

void	darwin_route_add(const char *);
void	darwin_configure_tundev(const char *);

/*
 * MacOS tunnel interface creation.
 * Attempts to create a tunnel device, anywhere from utun99 until utun104.
 */
int
sanctum_platform_tundev_create(void)
{
	struct sockaddr_ctl	sctl;
	struct ctl_info		info;
	char			ifname[IFNAMSIZ];
	int			len, idx, fd, flags;

	memset(&info, 0, sizeof(info));
	memset(&sctl, 0, sizeof(sctl));

	if ((fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)) == -1)
		fatal("socket: %s", errno_s);

	if (strlcpy(info.ctl_name, APPLE_UTUN_CONTROL,
	    sizeof(info.ctl_name)) >= sizeof(info.ctl_name))
		fatal("failed to copy %s", APPLE_UTUN_CONTROL);

	if (ioctl(fd, CTLIOCGINFO, &info) == -1)
		fatal("ioctl: %s", errno_s);

	for (idx = 100; idx < 105; idx++) {
		sctl.sc_unit = idx;
		sctl.sc_id = info.ctl_id;
		sctl.sc_family = AF_SYSTEM;
		sctl.ss_sysaddr = AF_SYS_CONTROL;

		if (connect(fd, (struct sockaddr *)&sctl, sizeof(sctl)) == -1) {
			if (errno == EBUSY)
				continue;
			fatal("connect: %s", errno_s);
		}

		break;
	}

	if (idx == 105)
		fatal("no free utun device found");

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		fatal("fcntl: %s", errno_s);

	flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) == -1)
		fatal("fcntl: %s", errno_s);

	len = snprintf(ifname, sizeof(ifname), "utun%u", idx - 1);
	if (len == -1 || (size_t)len >= sizeof(ifname))
		fatal("snprintf on utun%u failed", idx - 1);

	darwin_configure_tundev(ifname);
	darwin_route_add(ifname);

	free(sanctum->tun_ip);
	free(sanctum->tun_mask);

	sanctum->tun_ip = NULL;
	sanctum->tun_mask = NULL;

	return (fd);
}

/*
 * Read a packet from the tunnel device. On MacOS this is prefixed
 * with the protocol (4 bytes), so split up the read into two
 * parts: the protocol and the actual packet data.
 */
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

/*
 * Write a packet to the tunnel device. We must prefix it with the
 * correct protocol in network byte order.
 */
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
void
darwin_configure_tundev(const char *dev)
{
	int			fd;
	struct ifreq		ifr;
	struct ifaliasreq	ifra;

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

	ifr.ifr_flags = IFF_UP | IFF_RUNNING;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1)
		fatal("ioctl(SIOCSIFFLAGS): %s", errno_s);

	ifr.ifr_mtu = sanctum->tun_mtu;
	if (ioctl(fd, SIOCSIFMTU, &ifr) == -1)
		fatal("ioctl(SIOCSIFMTU): %s", errno_s);

	(void)close(fd);
}

/* Helper to add a route for our tunnel net. */
void
darwin_route_add(const char *dev)
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
