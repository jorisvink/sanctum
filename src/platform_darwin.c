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

#include <net/if_utun.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sanctum.h"

#define APPLE_UTUN_CONTROL	"com.apple.net.utun_control"

/*
 * MacOS tunnel interface creation.
 * Attempts to create a tunnel device, anywhere from utun99 until utun104.
 */
int
sanctum_platform_tundev_create(void)
{
	struct sockaddr_ctl	sctl;
	struct ctl_info		info;
	int			idx, fd, flags;

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

	/* XXX, take this from ESP next proto header later */
	proto = htonl(AF_INET);

	iov[0].iov_base = &proto;
	iov[0].iov_len = sizeof(proto);
	iov[1].iov_base = data;
	iov[1].iov_len = pkt->length;

	return (writev(fd, iov, 2));
}
