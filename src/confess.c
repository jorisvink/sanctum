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

/* XXX */
#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ip.h>

#include <poll.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "sanctum.h"

static void	confess_clear_state(void);
static void	confess_drop_access(void);
static void	confess_key_management(void);
static void	confess_packet_process(struct sanctum_packet *);
static void	confess_packet_heartbeat(struct sanctum_packet *);
static int	confess_with_slot(struct sanctum_sa *, struct sanctum_packet *);

static int	confess_arwin_check(struct sanctum_sa *,
		    struct sanctum_packet *, struct sanctum_ipsec_hdr *);
static void	confess_arwin_update(struct sanctum_sa *,
		    struct sanctum_packet *, struct sanctum_ipsec_hdr *);

/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/* The local state for RX. */
static struct {
	struct sanctum_sa	active;
	struct sanctum_sa	pending;
} state;

/* If we should wakeup SANCTUM_PROC_HEAVEN_TX. */
static int			tx_wakeup = 0;

/*
 * Confess - The process responsible for the confession of packets coming
 * from the purgatory side.
 *
 * Note that Chapel is responsible for handling ages of RX SAs.
 */
void
sanctum_confess(struct sanctum_proc *proc)
{
	struct sanctum_packet	*pkt;
	int			sig, running;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);

	io = proc->arg;
	confess_drop_access();

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	memset(&state, 0, sizeof(state));

	nyfe_zeroize_register(&state, sizeof(state));
	nyfe_zeroize_register(io->rx, sizeof(*io->rx));

	running = 1;

	sanctum_proc_privsep(proc);
	sanctum_platform_sandbox(proc);

	while (running) {
		if ((sig = sanctum_last_signal()) != -1) {
			sanctum_log(LOG_NOTICE, "received signal %d", sig);
			switch (sig) {
			case SIGQUIT:
				running = 0;
				continue;
			}
		}

		if (sanctum_ring_pending(io->confess) == 0)
			sanctum_proc_suspend(-1);

		confess_key_management();

		while ((pkt = sanctum_ring_dequeue(io->confess)))
			confess_packet_process(pkt);

		if (tx_wakeup) {
			tx_wakeup = 0;
			sanctum_proc_wakeup(SANCTUM_PROC_HEAVEN_TX);
		}
	}

	confess_clear_state();
	sanctum_log(LOG_NOTICE, "exiting");

	exit(0);
}

/*
 * Drop access to queues the confess process does not need.
 */
static void
confess_drop_access(void)
{
	(void)close(io->clear);
	(void)close(io->crypto);

	sanctum_shm_detach(io->tx);
	sanctum_shm_detach(io->bless);
	sanctum_shm_detach(io->offer);
	sanctum_shm_detach(io->chapel);
	sanctum_shm_detach(io->purgatory);

	io->tx = NULL;
	io->bless = NULL;
	io->offer = NULL;
	io->chapel = NULL;
	io->purgatory = NULL;
}

/*
 * Clear entire RX state.
 */
static void
confess_clear_state(void)
{
	sanctum_sa_clear(&state.active);
	sanctum_sa_clear(&state.pending);
	sanctum_stat_clear(&sanctum->rx);
	sanctum_atomic_write(&sanctum->rx_pending, 0);

	sanctum_mem_zero(&state, sizeof(state));
}

/*
 * Erase any keys that need to be erased, if we're told too do so.
 * Attempt to install any pending keys into the correct slot.
 *
 * Once we have a primary RX key in active, all keys that are
 * pending will be installed under the pending slot first.
 */
static void
confess_key_management(void)
{
	if (sanctum_key_erase("RX", io->rx, &state.active) != -1)
		sanctum_stat_clear(&sanctum->rx);

	(void)sanctum_key_erase("RX", io->rx, &state.pending);

	if (state.active.cipher == NULL) {
		if (sanctum_key_install(io->rx, &state.active) != -1) {
			sanctum_atomic_write(&sanctum->rx.spi,
			    state.active.spi);
			sanctum_atomic_write(&sanctum->rx.age,
			    state.active.age);
		}
	} else {
		if (sanctum_key_install(io->rx, &state.pending) != -1) {
			sanctum_atomic_write(&sanctum->rx_pending,
			    state.pending.spi);
		}
	}
}

/*
 * Handle a received heartbeat packet.
 *
 * It may contain information about the our peer its public ip:port
 * in the cases we are using a cathedral.
 */
static void
confess_packet_heartbeat(struct sanctum_packet *pkt)
{
	struct sanctum_heartbeat	*hb;

	PRECOND(pkt != NULL);

	if (sanctum->flags & SANCTUM_FLAG_CATHEDRAL_ACTIVE) {
		hb = sanctum_packet_data(pkt);
		if (hb->ip != 0 && hb->port != 0)
			sanctum_peer_update(hb->ip, hb->port);
	}

	sanctum_packet_release(pkt);
	sanctum_atomic_add(&sanctum->rx.pkt, 1);
	sanctum_atomic_write(&sanctum->rx.last, sanctum->uptime);
}

/*
 * Decrypt and verify a single packet under the current RX key, or if
 * that fails and there is a pending key, under the pending RX key.
 *
 * If successfull the packet is sent onto the clear interface.
 * If the pending RX key was used, it becomes the active one.
 */
static void
confess_packet_process(struct sanctum_packet *pkt)
{
	struct sanctum_ipsec_hdr	*hdr;

	PRECOND(pkt != NULL);
	PRECOND(pkt->target == SANCTUM_PROC_CONFESS);

	confess_key_management();

	if (sanctum_packet_crypto_checklen(pkt) == -1) {
		sanctum_packet_release(pkt);
		return;
	}

	hdr = sanctum_packet_head(pkt);
	hdr->esp.spi = be32toh(hdr->esp.spi);
	hdr->esp.seq = be32toh(hdr->esp.seq);
	hdr->pn = be64toh(hdr->pn);

	if (confess_with_slot(&state.active, pkt) != -1)
		return;

	if (confess_with_slot(&state.pending, pkt) == -1) {
		sanctum_packet_release(pkt);
		return;
	}

	/* Swap to RX SA in pending. */
	state.active.seqnr = 0;
	state.active.bitmap = 0;
	sanctum_atomic_write(&sanctum->last_pn, 0);
	sanctum_atomic_write(&sanctum->rx_pending, 0);

	sanctum_cipher_cleanup(state.active.cipher);

	state.active.spi = state.pending.spi;
	state.active.salt = state.pending.salt;
	state.active.seqnr = state.pending.seqnr;
	state.active.cipher = state.pending.cipher;

	sanctum_mem_zero(&state.pending, sizeof(state.pending));
}

/*
 * Attempt to verify and confess a packet using the given SA.
 */
static int
confess_with_slot(struct sanctum_sa *sa, struct sanctum_packet *pkt)
{
	u_int64_t			now;
	struct ip			*ip;
	struct sanctum_ipsec_hdr	*hdr;
	struct sanctum_ipsec_tail	*tail;
	u_int8_t			nonce[12], aad[12];

	PRECOND(sa != NULL);
	PRECOND(pkt != NULL);

	if (sa->cipher == NULL)
		return (-1);

	hdr = sanctum_packet_head(pkt);
	if (hdr->esp.spi != sa->spi)
		return (-1);

	if (confess_arwin_check(sa, pkt, hdr) == -1)
		return (-1);

	memcpy(nonce, &sa->salt, sizeof(sa->salt));
	memcpy(&nonce[sizeof(sa->salt)], &hdr->pn, sizeof(hdr->pn));

	memcpy(aad, &sa->spi, sizeof(sa->spi));
	memcpy(&aad[sizeof(sa->spi)], &hdr->pn, sizeof(hdr->pn));

	if (sanctum_cipher_decrypt(sa->cipher, nonce, sizeof(nonce),
	    aad, sizeof(aad), pkt) == -1)
		return (-1);

	if (sa->pending) {
		sa->pending = 0;
		sanctum_atomic_write(&sanctum->rx.pkt, 0);
		sanctum_atomic_write(&sanctum->rx.bytes, 0);
		sanctum_atomic_write(&sanctum->rx.age, sa->age);
		sanctum_atomic_write(&sanctum->rx.spi, sa->spi);
		sanctum_log(LOG_NOTICE, "RX SA active (spi=0x%08x)", sa->spi);
	}

	confess_arwin_update(sa, pkt, hdr);
	sanctum_peer_update(pkt->addr.sin_addr.s_addr, pkt->addr.sin_port);

	/* The length was checked earlier by the caller. */
	pkt->length -= sizeof(struct sanctum_ipsec_hdr);
	pkt->length -= sizeof(struct sanctum_ipsec_tail);
	pkt->length -= sanctum_cipher_overhead();

	tail = sanctum_packet_tail(pkt);
	if (tail->pad != 0)
		return (-1);

	now = sanctum_atomic_read(&sanctum->uptime);
	sanctum_atomic_write(&sanctum->heartbeat, now);

	if (tail->next == SANCTUM_PACKET_HEARTBEAT) {
		confess_packet_heartbeat(pkt);
		return (0);
	}

	if (tail->next != IPPROTO_IP)
		return (-1);

	/* Remove the TFC padding if enabled. */
	if (sanctum->flags & SANCTUM_FLAG_TFC_ENABLED) {
		ip = sanctum_packet_data(pkt);
		pkt->length = be16toh(ip->ip_len);
	}

	/* The packet checks out, it is bound for heaven. */
	pkt->target = SANCTUM_PROC_HEAVEN_TX;

	if (sanctum_ring_queue(io->heaven, pkt) == -1)
		sanctum_packet_release(pkt);
	else
		tx_wakeup = 1;

	return (0);
}

/*
 * Check if the given packet was too old, or already seen.
 */
static int
confess_arwin_check(struct sanctum_sa *sa, struct sanctum_packet *pkt,
    struct sanctum_ipsec_hdr *hdr)
{
	u_int64_t	bit;

	PRECOND(sa != NULL);
	PRECOND(pkt != NULL);
	PRECOND(hdr != NULL);

	if ((hdr->pn & 0xffffffff) != hdr->esp.seq)
		return (-1);

	if (hdr->pn > sa->seqnr)
		return (0);

	if (hdr->pn > 0 && SANCTUM_ARWIN_SIZE > sa->seqnr - hdr->pn) {
		bit = (SANCTUM_ARWIN_SIZE - 1) - (sa->seqnr - hdr->pn);
		if (sa->bitmap & ((u_int64_t)1 << bit)) {
			sanctum_log(LOG_INFO,
			    "packet seq=0x%" PRIx64 " already seen", hdr->pn);
			return (-1);
		}
		return (0);
	}

	sanctum_log(LOG_INFO,
	    "packet seq=0x%" PRIx64 " too old", hdr->pn);

	return (-1);
}

/*
 * Update the anti-replay window.
 */
static void
confess_arwin_update(struct sanctum_sa *sa, struct sanctum_packet *pkt,
    struct sanctum_ipsec_hdr *hdr)
{
	u_int64_t	bit;

	PRECOND(sa != NULL);
	PRECOND(pkt != NULL);
	PRECOND(hdr != NULL);

	if (hdr->pn > sa->seqnr) {
		if (hdr->pn - sa->seqnr >= SANCTUM_ARWIN_SIZE) {
			sa->bitmap = ((u_int64_t)1 << 63);
		} else {
			sa->bitmap >>= (hdr->pn - sa->seqnr);
			sa->bitmap |= ((u_int64_t)1 << 63);
		}

		sa->seqnr = hdr->pn;
		sanctum_atomic_write(&sanctum->last_pn, sa->seqnr);
		return;
	}

	if (sa->seqnr < hdr->pn)
		fatal("%s: window corrupt", __func__);

	bit = (SANCTUM_ARWIN_SIZE - 1) - (sa->seqnr - hdr->pn);
	sa->bitmap |= ((u_int64_t)1 << bit);
}
