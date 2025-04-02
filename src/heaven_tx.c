/*
 * Copyright (c) 2023-2025 Joris Vink <joris@sanctorum.se>
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

#include <netinet/in.h>
#include <netinet/ip.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "sanctum.h"

static void	heaven_tx_drop_access(void);
static void	heaven_tx_send_packet(int, struct sanctum_packet *);

static void	heaven_tx_l2_log(struct sanctum_ether *);
static int	heaven_tx_l2_sinner(struct sanctum_packet *);

static void	heaven_tx_l3_log(struct ip *);
static int	heaven_tx_l3_sinner(struct sanctum_packet *);

/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/*
 * The process responsible for submitting decrypted packets into heaven.
 */
void
sanctum_heaven_tx(struct sanctum_proc *proc)
{
	struct sanctum_packet	*pkt;
	int			sig, running;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);
	PRECOND(sanctum->mode != SANCTUM_MODE_PILGRIM);

	io = proc->arg;
	heaven_tx_drop_access();

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	sanctum_proc_privsep(proc);
	sanctum_platform_sandbox(proc);

	running = 1;

	while (running) {
		if ((sig = sanctum_last_signal()) != -1) {
			sanctum_log(LOG_NOTICE, "received signal %d", sig);
			switch (sig) {
			case SIGQUIT:
				running = 0;
				continue;
			}
		}

		if (sanctum_ring_pending(io->heaven) == 0)
			sanctum_proc_suspend(-1);

		while ((pkt = sanctum_ring_dequeue(io->heaven)))
			heaven_tx_send_packet(io->clear, pkt);
	}

	sanctum_log(LOG_NOTICE, "exiting");

	exit(0);
}

/*
 * Drop access to the queues and fds it does not need.
 */
static void
heaven_tx_drop_access(void)
{
	(void)close(io->nat);
	(void)close(io->crypto);

	sanctum_shm_detach(io->tx);
	sanctum_shm_detach(io->rx);
	sanctum_shm_detach(io->offer);
	sanctum_shm_detach(io->chapel);
	sanctum_shm_detach(io->confess);
	sanctum_shm_detach(io->purgatory);

	io->tx = NULL;
	io->rx = NULL;
	io->offer = NULL;
	io->chapel = NULL;
	io->confess = NULL;
	io->purgatory = NULL;
}

/*
 * Send the given packet onto the heaven interface.
 * This function will return the packet to the packet pool.
 */
static void
heaven_tx_send_packet(int fd, struct sanctum_packet *pkt)
{
	PRECOND(fd >= 0);
	PRECOND(pkt != NULL);
	PRECOND(pkt->target == SANCTUM_PROC_HEAVEN_TX);
	PRECOND(sanctum->mode != SANCTUM_MODE_PILGRIM);

	if (sanctum->flags & SANCTUM_FLAG_USE_TAP) {
		if (heaven_tx_l2_sinner(pkt) == -1) {
			sanctum_packet_release(pkt);
			return;
		}
	} else {
		if (heaven_tx_l3_sinner(pkt) == -1) {
			sanctum_packet_release(pkt);
			return;
		}
	}

	for (;;) {
		if (sanctum_platform_tundev_write(fd, pkt) == -1) {
			if (errno == EINTR)
				continue;
			if (errno == EIO || errno == ENOMEM)
				break;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			fatal("%s: write(): %s", __func__, errno_s);
		}

		sanctum_atomic_add(&sanctum->rx.pkt, 1);
		sanctum_atomic_add(&sanctum->rx.bytes, pkt->length);
		sanctum_atomic_write(&sanctum->rx.last, sanctum->uptime);
		break;
	}

	sanctum_packet_release(pkt);
}

/*
 * Check if the L2 packet we are about to send on the heaven interface
 * actually is traffic we expect and allow.
 */
static int
heaven_tx_l2_sinner(struct sanctum_packet *pkt)
{
	u_int16_t		proto;
	struct sanctum_ether	*ether;

	PRECOND(pkt != NULL);
	PRECOND(pkt->target == SANCTUM_PROC_HEAVEN_TX);
	PRECOND(sanctum->flags & SANCTUM_FLAG_USE_TAP);

	if (pkt->length < sizeof(*ether))
		return (-1);

	ether = sanctum_packet_data(pkt);
	proto = be16toh(ether->proto);

	switch (proto) {
	case SANCTUM_ETHER_TYPE_ARP:
	case SANCTUM_ETHER_TYPE_VLAN:
	case SANCTUM_ETHER_TYPE_IPV4:
	case SANCTUM_ETHER_TYPE_IPV6:
		break;
	default:
		heaven_tx_l2_log(ether);
		return (-1);
	}

	return (0);
}

/*
 * Check if the L3 packet we are about to send on the heaven interface
 * actually is traffic we expect and allow.
 */
static int
heaven_tx_l3_sinner(struct sanctum_packet *pkt)
{
	struct ip	*ip;
	in_addr_t	net, mask;

	PRECOND(pkt != NULL);
	PRECOND(pkt->target == SANCTUM_PROC_HEAVEN_TX);

	if (pkt->length < sizeof(*ip))
		return (-1);

	ip = sanctum_packet_data(pkt);

	if (ip->ip_v != IPVERSION)
		return (-1);

	switch (ip->ip_p) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ICMP:
		break;
	default:
		heaven_tx_l3_log(ip);
		return (-1);
	}

	mask = sanctum->tun_mask.sin_addr.s_addr;
	net = sanctum->tun_ip.sin_addr.s_addr & mask;

	if ((ip->ip_src.s_addr & mask) != net) {
		if (sanctum_config_routable(ip->ip_src.s_addr) == -1) {
			heaven_tx_l3_log(ip);
			return (-1);
		}
	}

	if ((ip->ip_dst.s_addr & mask) != net) {
		if (sanctum_config_routable(ip->ip_dst.s_addr) == -1) {
			heaven_tx_l3_log(ip);
			return (-1);
		}
	}

	return (0);
}

/*
 * Log an L2 packet that was blocked by heaven_tx_l2_sinner().
 */
static void
heaven_tx_l2_log(struct sanctum_ether *ether)
{
	PRECOND(ether != NULL);

	sanctum_log(LOG_INFO, "blocked 0x%04x "
	    "%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x",
	    ether->proto, ether->src[0], ether->src[1], ether->src[2],
	    ether->src[3], ether->src[4], ether->src[5], ether->dst[0],
	    ether->dst[1], ether->dst[2], ether->dst[3], ether->dst[4],
	    ether->dst[5]);
}

/*
 * Log an L3 packet that was blocked by heaven_tx_l3_sinner().
 */
static void
heaven_tx_l3_log(struct ip *ip)
{
	const char	*proto;
	char		buf[16];

	PRECOND(ip != NULL);

	switch (ip->ip_p) {
	case IPPROTO_TCP:
		proto = "tcp";
		break;
	case IPPROTO_UDP:
		proto = "udp";
		break;
	case IPPROTO_ICMP:
		proto = "icmp";
		break;
	default:
		(void)snprintf(buf, sizeof(buf), "%02x", ip->ip_p);
		proto = buf;
		break;
	}

	sanctum_log(LOG_INFO,
	    "blocked %s %u.%u.%u.%u -> %u.%u.%u.%u", proto,
	    ip->ip_src.s_addr & 0xff, (ip->ip_src.s_addr >> 8) & 0xff,
	    (ip->ip_src.s_addr >> 16) & 0xff, (ip->ip_src.s_addr >> 24) & 0xff,
	    ip->ip_dst.s_addr & 0xff, (ip->ip_dst.s_addr >> 8) & 0xff,
	    (ip->ip_dst.s_addr >> 16) & 0xff, (ip->ip_dst.s_addr >> 24) & 0xff);
}
