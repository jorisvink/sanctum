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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "sanctum.h"

/* The amount of times we send out standard MTU sized probes first. */
#define MTU_DISCOVERY_FIRST_PROBES	2

/* The amount of time before we retry MTU discovery. */
#define MTU_DISCOVERY_INTERVAL		600

/*
 * Time bookkeeping data structure for different grace types.
 */
struct grace_time {
	u_int64_t		next;
	u_int64_t		reset;
	u_int64_t		interval;
};

static void	heaven_rx_holepunch(void);
static void	heaven_rx_grace_heartbeat(void);

static void	heaven_rx_grace_mtu(void);
static void	heaven_rx_grace_mtu_reset(void);
static void	heaven_rx_grace_mtu_ack(u_int16_t);
static void	heaven_rx_grace_mtu_probe(u_int16_t);

static void	heaven_rx_drop_access(void);
static void	heaven_rx_recv_packets(int);

/* Temporary packet for when the packet pool is empty. */
static struct sanctum_packet	tpkt;

/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/* The current time, read from guardian once every event tick. */
static u_int64_t		now = 0;

/* Local timekeeping for sending heartbeat graces. */
static struct grace_time	heartbeats;

/* Local timekeeping for sending mtu probe graces. */
static struct grace_time	mtu_probes;

/* If we should wakeup SANCTUM_PROC_BLESS. */
static int			bless_wakeup = 0;

/* Is this our first mtu probe? If so we send a full size. */
static int			mtu_first = MTU_DISCOVERY_FIRST_PROBES;

/*
 * Some standard MTU sizes we send probes for when we start the
 * MTU discovery process in the hopes to speed it up.
 */
static const u_int16_t mtu_sizes[] = {
	1500,
	1422,
	1280,
	0,
};

/*
 * The process responsible for receiving packets on the heaven side
 * and enqueuing them for encryption via bless.
 *
 * The process will also generate grace traffic as its the only process
 * with access to the bless packet queue to submit packets for encryption.
 */
void
sanctum_heaven_rx(struct sanctum_proc *proc)
{
	struct pollfd		pfd;
	int			sig, running;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);
	PRECOND(sanctum->mode != SANCTUM_MODE_SHRINE);

	io = proc->arg;
	heaven_rx_drop_access();

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	sanctum_config_routes();
	sanctum_platform_sandbox(proc);
	sanctum_proc_started(proc);

	pfd.revents = 0;
	pfd.fd = io->clear;
	pfd.events = POLLIN;

	running = 1;
	now = sanctum_atomic_read(&sanctum->uptime);

	memset(&heartbeats, 0, sizeof(heartbeats));
	heartbeats.interval = 1;
	heartbeats.next = now + heartbeats.interval;

	memset(&mtu_probes, 0, sizeof(mtu_probes));
	mtu_probes.interval = 5;
	mtu_probes.next = now + mtu_probes.interval;

	while (running) {
		if ((sig = sanctum_last_signal()) != -1) {
			sanctum_log(LOG_NOTICE, "received signal %d", sig);
			switch (sig) {
			case SIGQUIT:
				running = 0;
				continue;
			}
		}

		if (poll(&pfd, 1, 1000) == -1) {
			if (errno == EINTR)
				continue;
			fatal("poll: %s", errno_s);
		}

		now = sanctum_atomic_read(&sanctum->uptime);

		heaven_rx_holepunch();
		heaven_rx_grace_mtu();
		heaven_rx_grace_heartbeat();

		heaven_rx_recv_packets(io->clear);

		if (bless_wakeup) {
			bless_wakeup = 0;
			sanctum_proc_wakeup(SANCTUM_PROC_BLESS);
		}
	}

	sanctum_config_release();
	sanctum_log(LOG_NOTICE, "exiting");

	nyfe_zeroize_warn();
	nyfe_zeroize_all();

	exit(0);
}

/*
 * Drop access to the queues and fds it does not need.
 */
static void
heaven_rx_drop_access(void)
{
	(void)close(io->nat);
	(void)close(io->crypto);

	sanctum_shm_detach(io->tx);
	sanctum_shm_detach(io->rx);
	sanctum_shm_detach(io->stx);
	sanctum_shm_detach(io->srx);
	sanctum_shm_detach(io->offer);
	sanctum_shm_detach(io->chapel);
	sanctum_shm_detach(io->confess);
	sanctum_shm_detach(io->purgatory);

	io->tx = NULL;
	io->rx = NULL;
	io->stx = NULL;
	io->srx = NULL;
	io->offer = NULL;
	io->chapel = NULL;
	io->confess = NULL;
	io->purgatory = NULL;
}

/*
 * Read packets from the clear interface and queue them up for encryption
 * via the bless process. Once the read() returns an error we break.
 */
static void
heaven_rx_recv_packets(int fd)
{
	ssize_t				ret;
	struct sanctum_packet		*pkt;

	PRECOND(fd >= 0);
	PRECOND(sanctum->mode != SANCTUM_MODE_SHRINE);

	for (;;) {
		if ((pkt = sanctum_packet_get()) == NULL)
			pkt = &tpkt;

		if ((ret = sanctum_platform_tundev_read(fd, pkt)) == -1) {
			if (pkt != &tpkt)
				sanctum_packet_release(pkt);
			if (errno == EINTR)
				break;
			if (errno == EIO)
				break;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			fatal("%s: read(): %s", __func__, errno_s);
		}

		if (ret == 0)
			fatal("eof on tunnel interface");

		if (ret <= SANCTUM_PACKET_MIN_LEN) {
			if (pkt != &tpkt)
				sanctum_packet_release(pkt);
			continue;
		}

		if (pkt == &tpkt)
			continue;

		pkt->length = ret;
		pkt->type = SANCTUM_PACKET_IP;
		pkt->target = SANCTUM_PROC_BLESS;

		if (sanctum_ring_queue(io->bless, pkt) == -1)
			sanctum_packet_release(pkt);
		else
			bless_wakeup = 1;
	}
}

/*
 * Reset the MTU discovery state.
 */
static void
heaven_rx_grace_mtu_reset(void)
{
	mtu_first = MTU_DISCOVERY_FIRST_PROBES;
	mtu_probes.next = now + MTU_DISCOVERY_INTERVAL;

	sanctum_atomic_write(&sanctum->mtu_value, 0);
	sanctum_atomic_write(&sanctum->mtu_attempts, 0);
}

/*
 * Check if we need to do anything with the holepunching.
 */
static void
heaven_rx_holepunch(void)
{
	if (sanctum_atomic_cas_simple(&sanctum->holepunch, 1, 0)) {
		heartbeats.next = now;
		heartbeats.interval = 1;
		heartbeats.reset = now + SANCTUM_GRACE_HEARTBEAT_INTERVAL;
	} else if (heartbeats.reset != 0 && now >= heartbeats.reset) {
		heartbeats.reset = 0;
		heartbeats.interval = SANCTUM_GRACE_HEARTBEAT_INTERVAL;
	}
}

/*
 * Check if we should generate a grace heartbeat and send it to our peer.
 */
static void
heaven_rx_grace_heartbeat(void)
{
	struct sanctum_packet		*pkt;
	struct sanctum_grace		*grace;

	if (sanctum_atomic_read(&sanctum->tx.spi) == 0)
		return;

	if (heartbeats.next == 0 || now < heartbeats.next)
		return;

	if ((pkt = sanctum_packet_get()) == NULL)
		return;

	grace = sanctum_packet_data(pkt);
	grace->type = SANCTUM_GRACE_TYPE_HEARTBEAT;

	pkt->length = sizeof(*grace);
	pkt->next = SANCTUM_PACKET_GRACE;
	pkt->target = SANCTUM_PROC_BLESS;

	if (sanctum_ring_queue(io->bless, pkt) == -1)
		sanctum_packet_release(pkt);
	else
		bless_wakeup = 1;

	heartbeats.next = now + heartbeats.interval;
}

/*
 * Check if we should generate a grace MTU probe to send to our peer
 * and if we should generate an MTU ack for an incoming probe.
 */
static void
heaven_rx_grace_mtu(void)
{
	int		i;
	size_t		overhead;
	u_int16_t	mtu, preset;

	if (sanctum->mode != SANCTUM_MODE_TUNNEL)
		return;

	if (sanctum_atomic_read(&sanctum->tx.spi) == 0)
		return;

	if ((sanctum->flags & SANCTUM_FLAG_MTU_DISCOVERY) &&
	    mtu_probes.next != 0 && now >= mtu_probes.next) {
		mtu = sanctum_atomic_read(&sanctum->mtu_value);

		if (mtu == sanctum->tun_mtu) {
			heaven_rx_grace_mtu_reset();
			return;
		}

		if (mtu_first > 0) {
			mtu_first--;
			heaven_rx_grace_mtu_probe(sanctum->tun_mtu);

			overhead = sizeof(struct ip) + sizeof(struct udphdr) +
			    sizeof(struct sanctum_proto_hdr) +
			    sizeof(struct sanctum_proto_tail) +
			    SANCTUM_TAG_LENGTH;

			if (sanctum->flags & SANCTUM_FLAG_SHROUD) {
				overhead += sizeof(struct sanctum_shroud_hdr);
				overhead += SANCTUM_SHROUD_TRAIL_LEN;
			}

			for (i = 0; mtu_sizes[i] != 0; i++) {
				preset = mtu_sizes[i] - overhead;
				if (preset > mtu && preset != sanctum->tun_mtu)
					heaven_rx_grace_mtu_probe(preset);
			}

			return;
		}

		if (mtu == 0) {
			mtu = SANCTUM_MTU_SIZE_MIN;
		} else {
			VERIFY(mtu < sanctum->tun_mtu);
			mtu += MIN(sanctum->tun_mtu - mtu, 32);
		}

		if (sanctum_atomic_read(&sanctum->mtu_attempts) < 3) {
			sanctum_atomic_add(&sanctum->mtu_attempts, 1);
		} else {
			heaven_rx_grace_mtu_reset();
			return;
		}

		heaven_rx_grace_mtu_probe(mtu);
	}

	if ((mtu = sanctum_atomic_read(&sanctum->mtu_probe_ack)) == 0)
		return;

	if (!sanctum_atomic_cas_simple(&sanctum->mtu_probe_ack, mtu, 0))
		fatal("mtu_probe_ack changed unexpected");

	if (mtu < SANCTUM_MTU_SIZE_MIN || mtu > sanctum->tun_mtu) {
		sanctum_log(LOG_NOTICE, "peer sent bad MTU size of %u", mtu);
		return;
	}

	heaven_rx_grace_mtu_ack(mtu);
}

/*
 * Generate a grace MTU ack packet and queue it for encryption.
 */
static void
heaven_rx_grace_mtu_ack(u_int16_t mtu)
{
	struct sanctum_packet		*pkt;
	struct sanctum_grace_mtu	*resp;

	PRECOND(mtu >= SANCTUM_MTU_SIZE_MIN && mtu <= sanctum->tun_mtu);

	if ((pkt = sanctum_packet_get()) == NULL)
		return;

	resp = sanctum_packet_data(pkt);

	resp->grace.type = SANCTUM_GRACE_TYPE_MTU_ACK;
	resp->size = mtu;

	pkt->length = sizeof(*resp);
	pkt->next = SANCTUM_PACKET_GRACE;
	pkt->target = SANCTUM_PROC_BLESS;

	if (sanctum_ring_queue(io->bless, pkt) == -1)
		sanctum_packet_release(pkt);
	else
		bless_wakeup = 1;
}

/*
 * Generate a grace MTU probe packet and queue it for encryption.
 */
static void
heaven_rx_grace_mtu_probe(u_int16_t mtu)
{
	struct sanctum_packet		*pkt;
	struct sanctum_grace_mtu	*probe;

	PRECOND(mtu >= SANCTUM_MTU_SIZE_MIN && mtu <= sanctum->tun_mtu);

	if ((pkt = sanctum_packet_get()) == NULL)
		return;

	probe = sanctum_packet_data(pkt);

	probe->size = mtu;
	probe->grace.type = SANCTUM_GRACE_TYPE_MTU_PROBE;

	pkt->length = mtu;
	pkt->next = SANCTUM_PACKET_GRACE;
	pkt->target = SANCTUM_PROC_BLESS;

	if (sanctum_ring_queue(io->bless, pkt) == -1)
		sanctum_packet_release(pkt);
	else
		bless_wakeup = 1;

	mtu_probes.next = now + mtu_probes.interval;
}
