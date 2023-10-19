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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sanctum.h"

static void	linux_configure_tundev(struct ifreq *);

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

	free(sanctum->tun_ip);
	sanctum->tun_ip = NULL;

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

/* Configure the tunnel device. */
void
linux_configure_tundev(struct ifreq *ifr)
{
	int		fd;

	PRECOND(ifr != NULL);

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", errno_s);

	sanctum_inet_addr(&ifr->ifr_addr, sanctum->tun_ip);
	if (ioctl(fd, SIOCSIFADDR, ifr) == -1)
		fatal("ioctl(SIOCSIFADDR): %s", errno_s);
	if (ioctl(fd, SIOCSIFDSTADDR, ifr) == -1)
		fatal("ioctl(SIOCSIFDSTADDR): %s", errno_s);

	sanctum_inet_mask(&ifr->ifr_addr, sanctum->tun_mask);

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
