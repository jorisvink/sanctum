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
#include <sys/socket.h>

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
static int	confess_with_slot(struct sanctum_sa *, struct sanctum_packet *);

static void	confess_packet_process(struct sanctum_packet *);
static void	confess_packet_transfer(struct sanctum_packet *);
static int	confess_packet_adjust_length(struct sanctum_packet *);
static int	confess_packet_matches(struct sanctum_sa *,
		    struct sanctum_packet *);
static int	confess_packet_decrypt(struct sanctum_sa *,
		    struct sanctum_packet *);
static int	confess_packet_replay_check(struct sanctum_sa *,
		    struct sanctum_packet *);
static void	confess_packet_replay_update(struct sanctum_sa *,
		    struct sanctum_packet *);

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

	sanctum_platform_sandbox(proc);
	sanctum_proc_started(proc);

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

		if (sanctum_ring_pending(io->confess) == 0)
			sanctum_proc_suspend(-1);

		confess_key_management();

		while ((pkt = sanctum_packet_dequeue(io->confess)))
			confess_packet_process(pkt);

		if (tx_wakeup) {
			tx_wakeup = 0;
			sanctum_proc_wakeup(SANCTUM_PROC_HEAVEN_TX);
		}
	}

	confess_clear_state();

	nyfe_zeroize(&state, sizeof(state));
	nyfe_zeroize(io->rx, sizeof(*io->rx));

	sanctum_config_release();
	sanctum_log(LOG_NOTICE, "exiting");

	nyfe_zeroize_warn();
	nyfe_zeroize_all();

	exit(0);
}

/*
 * Drop access to queues the confess process does not need.
 */
static void
confess_drop_access(void)
{
	(void)close(io->nat);
	(void)close(io->clear);
	(void)close(io->crypto);

	sanctum_shm_detach(io->tx);
	sanctum_shm_detach(io->stx);
	sanctum_shm_detach(io->srx);
	sanctum_shm_detach(io->bless);
	sanctum_shm_detach(io->offer);
	sanctum_shm_detach(io->chapel);
	sanctum_shm_detach(io->purgatory);

	io->tx = NULL;
	io->stx = NULL;
	io->srx = NULL;
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
	sanctum_stat_clear(&shared->rx);
	sanctum_atomic_write(&shared->last_pn, 0);
	sanctum_atomic_write(&shared->rx_pending, 0);

	nyfe_mem_zero(&state, sizeof(state));
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
	if (sanctum_key_erase("RX", io->rx,
	    &state.active, &state.pending) != -1) {
		sanctum_stat_clear(&shared->rx);
		sanctum_atomic_write(&shared->last_pn, 0);
		sanctum_atomic_write(&shared->rx_pending, 0);
		nyfe_mem_zero(&state, sizeof(state));
	}

	if (state.active.cipher == NULL) {
		if (sanctum_key_install(io->rx, &state.active) != -1) {
			sanctum_atomic_write(&shared->rx.spi,
			    state.active.spi);
			sanctum_atomic_write(&shared->rx.age,
			    state.active.age);
		}
	} else {
		if (sanctum_key_install(io->rx, &state.pending) != -1) {
			sanctum_atomic_write(&shared->rx_pending,
			    state.pending.spi);
		}
	}
}

/*
 * Decrypt and verify a single packet under the current RX key, or if
 * that fails and there is a pending key, under the pending RX key.
 *
 * If successfull the packet is sent onto the clear interface.
 * If the pending RX key was used, it becomes the active one.
 */
static void
confess_packet_process(struct sanctum_packet *in)
{
	struct sanctum_packet		*pkt;
	struct sanctum_proto_hdr	*hdr;
	u_int64_t			flock_src, flock_dst;

	PRECOND(in != NULL);

	confess_key_management();

	if ((pkt = sanctum_packet_transfer(in,
	    SANCTUM_PROC_HEAVEN_TX)) == NULL) {
		sanctum_packet_release(in);
		return;
	}

	if (sanctum_packet_crypto_checklen(pkt) == -1) {
		sanctum_packet_release(pkt);
		return;
	}

	hdr = sanctum_packet_head(pkt);
	hdr->esp.spi = be32toh(hdr->esp.spi);
	hdr->esp.seq = be32toh(hdr->esp.seq);

	flock_src = be64toh(hdr->flock.src);
	flock_dst = be64toh(hdr->flock.dst);

	if (flock_src != sanctum->cathedral_flock_dst ||
	    flock_dst != sanctum->cathedral_flock) {
		sanctum_packet_release(pkt);
		return;
	}

	if (confess_with_slot(&state.active, pkt) != -1)
		return;

	if (confess_with_slot(&state.pending, pkt) == -1) {
		sanctum_packet_release(pkt);
		return;
	}

	sanctum_atomic_write(&shared->last_pn, 0);
	sanctum_atomic_write(&shared->rx_pending, 0);

	sanctum_cipher_cleanup(state.active.cipher);

	state.active.spi = state.pending.spi;
	state.active.salt = state.pending.salt;
	state.active.seqnr = state.pending.seqnr;
	state.active.cipher = state.pending.cipher;
	state.active.bitmap = state.pending.bitmap;
	state.active.pending = state.pending.pending;

	nyfe_mem_zero(&state.pending, sizeof(state.pending));
}

/*
 * Attempt to verify and confess a packet using the given SA.
 */
static int
confess_with_slot(struct sanctum_sa *sa, struct sanctum_packet *pkt)
{
	size_t			min;
	u_int64_t		now;

	PRECOND(sa != NULL);
	PRECOND(pkt != NULL);

	if (sa->cipher == NULL)
		return (-1);

	min = sizeof(struct sanctum_proto_hdr) +
	    sizeof(struct sanctum_proto_tail) + SANCTUM_TAG_LENGTH;

	if (pkt->length < min || pkt->length > SANCTUM_MTU_SIZE_MAX)
		return (-1);

	if (confess_packet_matches(sa, pkt) == -1)
		return (-1);

	if (confess_packet_replay_check(sa, pkt) == -1)
		return (-1);

	if (confess_packet_decrypt(sa, pkt) == -1)
		return (-1);

	if (sa->pending) {
		sa->pending = 0;
		sanctum_atomic_write(&shared->rx.pkt, 1);
		sanctum_atomic_write(&shared->rx.bytes, 0);
		sanctum_atomic_write(&shared->rx.age, sa->age);
		sanctum_atomic_write(&shared->rx.spi, sa->spi);
		sanctum_log(LOG_NOTICE, "RX SA active (spi=%08x)", sa->spi);
	}

	confess_packet_replay_update(sa, pkt);

	if (confess_packet_adjust_length(pkt) == -1)
		return (-1);

	now = sanctum_atomic_read(&shared->uptime);
	sanctum_atomic_write(&shared->heartbeat, now);
	sanctum_peer_update(pkt->addr.sin_addr.s_addr, pkt->addr.sin_port);

	confess_packet_transfer(pkt);

	return (0);
}

/*
 * Check if the given packet its SPI matches our SA SPI.
 */
static int
confess_packet_matches(struct sanctum_sa *sa, struct sanctum_packet *pkt)
{
	struct sanctum_proto_hdr	*hdr;

	PRECOND(sa != NULL);
	PRECOND(pkt != NULL);

	hdr = sanctum_packet_head(pkt);

	if (hdr->esp.spi != sa->spi)
		return (-1);

	return (0);
}

/*
 * Check if the given packet was too old, or already seen.
 */
static int
confess_packet_replay_check(struct sanctum_sa *sa, struct sanctum_packet *pkt)
{
	struct sanctum_proto_hdr	*hdr;
	u_int64_t			bit, pn;

	PRECOND(sa != NULL);
	PRECOND(pkt != NULL);

	hdr = sanctum_packet_head(pkt);
	pn = be64toh(hdr->pn);

	if ((pn & 0xffffffff) != hdr->esp.seq)
		return (-1);

	if (pn > sa->seqnr)
		return (0);

	if (pn > 0 && SANCTUM_ARWIN_SIZE > sa->seqnr - pn) {
		bit = (SANCTUM_ARWIN_SIZE - 1) - (sa->seqnr - pn);
		if (sa->bitmap & ((u_int64_t)1 << bit)) {
			sanctum_log(LOG_INFO,
			    "packet seq=%" PRIx64 " already seen", pn);
			return (-1);
		}
		return (0);
	}

	sanctum_log(LOG_INFO, "packet seq=%" PRIx64 " too old", pn);

	return (-1);
}

/*
 * Prepare the nonce and AAD and decrypt the packet its contents and
 * verify its integrity.
 */
static int
confess_packet_decrypt(struct sanctum_sa *sa, struct sanctum_packet *pkt)
{
	size_t				ctlen;
	struct sanctum_cipher		cipher;
	struct sanctum_proto_hdr	*hdr, aad;
	u_int8_t			*data, nonce[SANCTUM_NONCE_LENGTH];

	PRECOND(sa != NULL);
	PRECOND(pkt != NULL);

	hdr = sanctum_packet_head(pkt);
	ctlen = pkt->length - sizeof(*hdr) - SANCTUM_TAG_LENGTH;

	memset(nonce, 0, sizeof(nonce));
	memcpy(nonce, &sa->salt, sizeof(sa->salt));
	memcpy(&nonce[sizeof(sa->salt)], &hdr->pn, sizeof(hdr->pn));

	memcpy(&aad, hdr, sizeof(*hdr));
	aad.esp.spi = htobe32(hdr->esp.spi);
	aad.esp.seq = htobe32(hdr->esp.seq);

	cipher.aad = &aad;
	cipher.aad_len = sizeof(aad);

	cipher.nonce = nonce;
	cipher.nonce_len = sizeof(nonce);

	cipher.ctx = sa->cipher;
	cipher.data_len = ctlen;

	data = sanctum_packet_data(pkt);

	cipher.ct = data;
	cipher.pt = data;
	cipher.tag = data + ctlen;

	if (sanctum_cipher_decrypt(&cipher) == -1)
		return (-1);

	return (0);
}

/*
 * Update the anti-replay window with the given packet.
 */
static void
confess_packet_replay_update(struct sanctum_sa *sa, struct sanctum_packet *pkt)
{
	u_int64_t			bit;
	struct sanctum_proto_hdr	*hdr;

	PRECOND(sa != NULL);
	PRECOND(pkt != NULL);

	hdr = sanctum_packet_head(pkt);
	hdr->pn = be64toh(hdr->pn);

	if (hdr->pn > sa->seqnr) {
		if (hdr->pn - sa->seqnr >= SANCTUM_ARWIN_SIZE) {
			sa->bitmap = ((u_int64_t)1 << 63);
		} else {
			sa->bitmap >>= (hdr->pn - sa->seqnr);
			sa->bitmap |= ((u_int64_t)1 << 63);
		}

		sa->seqnr = hdr->pn;
		sanctum_atomic_write(&shared->last_pn, sa->seqnr);
		return;
	}

	if (sa->seqnr < hdr->pn)
		fatal("%s: window corrupt", __func__);

	bit = (SANCTUM_ARWIN_SIZE - 1) - (sa->seqnr - hdr->pn);
	sa->bitmap |= ((u_int64_t)1 << bit);
}

/*
 * Adjust the length for the decrypted packet by removing the
 * overhead bytes. Once we've done that check the protocol tail
 * and adjust for TFC if required.
 */
static int
confess_packet_adjust_length(struct sanctum_packet *pkt)
{
	u_int16_t			len;
	struct ip			*ip;
	struct sanctum_proto_tail	*tail;

	PRECOND(pkt != NULL);

	/* The length was checked earlier by the caller. */
	pkt->length -= sizeof(struct sanctum_proto_hdr);
	pkt->length -= sizeof(struct sanctum_proto_tail);
	pkt->length -= SANCTUM_TAG_LENGTH;

	tail = sanctum_packet_tail(pkt);
	if (tail->reserved != 0)
		return (-1);

	switch (tail->next) {
	case SANCTUM_PACKET_IP:
		if (sanctum->flags & SANCTUM_FLAG_TFC_ENABLED) {
			if (pkt->length < sizeof(*ip))
				return (-1);

			ip = sanctum_packet_data(pkt);
			len = be16toh(ip->ip_len);
			if (len > pkt->length || len > sanctum->tun_mtu)
				return (-1);

			pkt->length = len;
		}
		break;
	case SANCTUM_PACKET_GRACE:
		break;
	default:
		return (-1);
	}

	pkt->type = tail->next;

	return (0);
}

/*
 * Transfer the decrypted packet to the heaven-tx process.
 */
static void
confess_packet_transfer(struct sanctum_packet *pkt)
{
	pkt->target = SANCTUM_PROC_HEAVEN_TX;

	if (sanctum_packet_queue(io->heaven, pkt) == -1)
		sanctum_packet_release(pkt);
	else
		tx_wakeup = 1;
}
