/*
 * Copyright (c) 2023-2026 Joris Vink <joris@sanctorum.se>
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
#include <sandbox.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sanctum.h"
#include "libnyfe.h"

/* A routing message when configuring stuff. */
struct rtmsg {
	struct rt_msghdr	rtm;
	u_int8_t		buf[512];
};

/* XXX Hard coded installation path. */
#define APPLE_SB_PATH		"/usr/local/share/sanctum/sb"

/* The apple defined name for a tun device. */
#define APPLE_UTUN_CONTROL	"com.apple.net.utun_control"

static void	darwin_configure_tundev(const char *);

/*
 * The ulock_wait and ulock_wakeup() interfaces are considered
 * private but screw it, we'll use them anyway since they do
 * not support futex(2) like other more sane operating systems.
 */
#define UL_COMPARE_AND_WAIT_SHARED	3
#define ULF_WAKE_ALL			0x00000100

int	__ulock_wait(uint32_t operation, void *addr, uint64_t value,
	    uint32_t timeout);
int	__ulock_wake(uint32_t operation, void *addr, uint64_t wake_value);

/* This sandbox API isn't declared publically either. */
int	sandbox_init_with_parameters(const char *profile,
	    uint64_t flags, const char *const parameters[], char **errorbuf);

/*
 * Setup the required platform bits and bobs.
 */
void
sanctum_platform_init(void)
{
	if (sanctum->flags & SANCTUM_FLAG_USE_TAP)
		fatal("macos does not support tap devices");
}

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

	if (sanctum->tun_ip.sin_addr.s_addr != 0 &&
	    sanctum->tun_mask.sin_addr.s_addr != 0xffffffff) {
		sanctum_platform_tundev_route(&sanctum->tun_ip,
		    &sanctum->tun_mask);
	}

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

/*
 * Enable or disable the setting of the DF bit in the IP header.
 */
void
sanctum_platform_ip_fragmentation(int fd, int on)
{
	PRECOND(fd > 0);
	PRECOND(on == 0 || on == 1);

	if (setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &on, sizeof(on)) == -1)
		fatal("%s: setsockopt: %s", __func__, errno_s);
}

/*
 * Adds a new route via our tunnel device.
 */
void
sanctum_platform_tundev_route(struct sockaddr_in *net, struct sockaddr_in *mask)
{
	int			s;
	u_int8_t		*cp;
	struct sockaddr_in	dst;
	struct rtmsg		msg;
	ssize_t			ret;

	PRECOND(net != NULL);
	PRECOND(mask != NULL);

	memset(&msg, 0, sizeof(msg));

	msg.rtm.rtm_seq = 1;
	msg.rtm.rtm_type = RTM_ADD;
	msg.rtm.rtm_version = RTM_VERSION;
	msg.rtm.rtm_flags = RTF_STATIC | RTF_UP | RTF_GATEWAY;
	msg.rtm.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;

	memcpy(&dst, net, sizeof(*net));
	dst.sin_addr.s_addr &= mask->sin_addr.s_addr;

	cp = msg.buf;

	memcpy(cp, &dst, sizeof(dst));
	cp += sizeof(dst);

	memcpy(cp, &sanctum->tun_ip, sizeof(sanctum->tun_ip));
	cp += sizeof(sanctum->tun_ip);

	memcpy(cp, mask, sizeof(*mask));
	cp += sizeof(*mask);

	msg.rtm.rtm_msglen = cp - (u_int8_t *)&msg;

	if ((s = socket(AF_ROUTE, SOCK_RAW, AF_INET)) == -1)
		fatal("socket: %s", errno_s);

	if ((ret = write(s, &msg, msg.rtm.rtm_msglen)) == -1)
		fatal("write: %s", errno_s);

	if ((size_t)ret != msg.rtm.rtm_msglen)
		fatal("failed to write entire message");

	(void)close(s);
}

/*
 * Load a sandbox profile from disk and apply it to our current process.
 * See all *.sb files inside of share/sb for the actual profiles.
 */
void
sanctum_platform_sandbox(struct sanctum_proc *proc)
{
	struct stat	st;
	size_t		flen;
	const char	*params[16];
	int		fd, len, idx;
	char		*profile, *errmsg, path[1024];

	PRECOND(proc != NULL);

	sanctum_proc_privsep(proc);

	switch (proc->type) {
	case SANCTUM_PROC_BLESS:
	case SANCTUM_PROC_CHAPEL:
	case SANCTUM_PROC_SHRINE:
	case SANCTUM_PROC_PILGRIM:
	case SANCTUM_PROC_CONFESS:
	case SANCTUM_PROC_CONTROL:
	case SANCTUM_PROC_CATHEDRAL:
	case SANCTUM_PROC_LITURGY:
	case SANCTUM_PROC_HEAVEN_TX:
	case SANCTUM_PROC_HEAVEN_RX:
	case SANCTUM_PROC_PURGATORY_TX:
	case SANCTUM_PROC_PURGATORY_RX:
		break;
	default:
		fatal("%s: unknown proc type %d", __func__, proc->type);
		break;
	}

	if (sanctum->secret != NULL) {
		len = snprintf(path, sizeof(path), "%s.new", sanctum->secret);
		if (len == -1 || (size_t)len >= sizeof(path))
			fatal("failed to construct new path");
	}

	/*
	 * Construct all parameters that the profiles can use.
	 * Note that it doesn't mean they will, for example only
	 * chapel will use KEY_PATH, KEK_PATH, CATHEDRAL_COSK or
	 * CATHEDRAL_SECRET.
	 */
	idx = 0;

	if (sanctum->secret != NULL) {
		params[idx++] = "KEY_PATH";
		params[idx++] = sanctum->secret;
		params[idx++] = "KEY_PATH_NEW";
		params[idx++] = path;
	}

	if (sanctum->cathedral_cosk != NULL) {
		params[idx++] = "CATHEDRAL_COSK";
		params[idx++] = sanctum->cathedral_cosk;
	}

	if (sanctum->cathedral_secret != NULL) {
		params[idx++] = "CATHEDRAL_SECRET";
		params[idx++] = sanctum->cathedral_secret;
	}

	if (sanctum->kek != NULL) {
		params[idx++] = "KEK_PATH";
		params[idx++] = sanctum->kek;
	}

	params[idx] = NULL;

	/* Open the profile from disk. */
	len = snprintf(path, sizeof(path), "%s/%s.sb",
	    APPLE_SB_PATH, proc->name);
	if (len == -1 || (size_t)len >= sizeof(path))
		fatal("failed to create path to sandbox profile");

	if ((fd = sanctum_file_open(path, &st)) == -1)
		fatal("failed to open sandbox profile '%s'", path);

	if (st.st_size < 0 || st.st_size > 1024 * 1024)
		fatal("sandbox profile filesize for '%s' is weird", proc->name);

	flen = (size_t)st.st_size;

	if ((profile = calloc(1, flen + 1)) == NULL)
		fatal("calloc failed");

	if (nyfe_file_read(fd, profile, flen) != flen)
		fatal("failed to read profile");

	profile[flen] = '\0';

	/* And finally, apply it. */
	if (sandbox_init_with_parameters(profile, 0, params, &errmsg) == -1)
		fatal("sandbox init: %s", errmsg);

	free(profile);
	(void)close(fd);
}

/*
 * Suspend the calling process using the synchronization addr.
 * If we were already told to be awake, we simply return and do not block.
 */
void
sanctum_platform_suspend(u_int32_t *addr, int64_t sleep)
{
	u_int32_t	timeo;

	PRECOND(addr != NULL);

	if (sanctum_atomic_cas_simple(addr, 1, 0))
		return;

	if (sleep < 0)
		timeo = 0;
	else
		timeo = sleep * 1e6;

	if (__ulock_wait(UL_COMPARE_AND_WAIT_SHARED, addr, 0, timeo) == -1) {
		if (errno != ETIMEDOUT && errno != EINTR)
			sanctum_log(LOG_NOTICE, "ulock wait: %s", errno_s);
	}
}

/*
 * Wakeup whoever is suspended on the synchronization address in addr,
 * unless they are already awake.
 */
void
sanctum_platform_wakeup(u_int32_t *addr)
{
	int		ret;

	PRECOND(addr != NULL);

	if (sanctum_atomic_cas_simple(addr, 0, 1)) {
		ret = __ulock_wake(UL_COMPARE_AND_WAIT_SHARED, addr, 0);
		if (ret == -1)
			sanctum_log(LOG_INFO, "ulock wake: %s", errno_s);
	}
}

/* Configure the tunnel device. */
static void
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

	memcpy(&ifra.ifra_addr, &sanctum->tun_ip, sizeof(sanctum->tun_ip));
	memcpy(&ifra.ifra_mask, &sanctum->tun_mask, sizeof(sanctum->tun_mask));
	memcpy(&ifra.ifra_broadaddr, &sanctum->tun_ip, sizeof(sanctum->tun_ip));

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
