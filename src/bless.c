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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "sanctum.h"

/* After installing a new TX key, we pulse heartbeats for this duration. */
#define BLESS_KEY_HEARTBEAT_INTERVAL	1
#define BLESS_KEY_HEARTBEAT_DURATION	5

static void	bless_drop_access(void);
static void	bless_packet_heartbeat(void);
static void	bless_packet_process(struct sanctum_packet *);

/* The shared queues. */
static struct sanctum_proc_io	*io = NULL;

/* The local state for TX. */
static struct sanctum_sa	state;

/* Local timekeeping for heartbeats. */
static u_int64_t	now = 0;
static u_int64_t	heartbeat_next = 0;
static u_int64_t	heartbeat_reset = 0;
static u_int64_t	heartbeat_interval = SANCTUM_HEARTBEAT_INTERVAL;

/* If we should wakeup SANCTUM_PROC_PURGATORY_TX. */
static int		tx_wakeup = 0;

/*
 * Bless - The process responsible for the blessing of packets coming
 * from the heaven side.
 */
void
sanctum_bless(struct sanctum_proc *proc)
{
	struct sanctum_packet	*pkt;
	int			sig, running;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);

	io = proc->arg;
	bless_drop_access();

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	memset(&state, 0, sizeof(state));

	nyfe_zeroize_register(&state, sizeof(state));
	nyfe_zeroize_register(io->tx, sizeof(*io->tx));

	sanctum_platform_sandbox(proc);
	sanctum_proc_started(proc);

	running = 1;
	now = sanctum_atomic_read(&sanctum->uptime);
	heartbeat_next = now + heartbeat_interval;

	while (running) {
		if ((sig = sanctum_last_signal()) != -1) {
			sanctum_log(LOG_NOTICE, "received signal %d", sig);
			switch (sig) {
			case SIGQUIT:
				running = 0;
				continue;
			}
		}

		now = sanctum_atomic_read(&sanctum->uptime);

		if (sanctum_ring_pending(io->bless) == 0)
			sanctum_proc_suspend(heartbeat_next - now);

		now = sanctum_atomic_read(&sanctum->uptime);

		if (sanctum_atomic_cas_simple(&sanctum->holepunch, 1, 0)) {
			heartbeat_next = now;
			heartbeat_interval = 1;
			heartbeat_reset = now + SANCTUM_HEARTBEAT_INTERVAL;
		} else if (heartbeat_reset != 0 && now >= heartbeat_reset) {
			heartbeat_reset = 0;
			heartbeat_interval = SANCTUM_HEARTBEAT_INTERVAL;
		}

		if (sanctum_key_erase("TX", io->tx, &state, NULL) != -1)
			sanctum_stat_clear(&sanctum->tx);

		if (sanctum_key_install(io->tx, &state) != -1) {
			heartbeat_interval = BLESS_KEY_HEARTBEAT_INTERVAL;
			heartbeat_next = now + BLESS_KEY_HEARTBEAT_INTERVAL;
			heartbeat_reset = now + BLESS_KEY_HEARTBEAT_DURATION;
			sanctum_atomic_write(&sanctum->tx.pkt, 0);
			sanctum_atomic_write(&sanctum->tx.bytes, 0);
			sanctum_atomic_write(&sanctum->tx.age, now);
			sanctum_atomic_write(&sanctum->tx.spi, state.spi);
		}

		while ((pkt = sanctum_ring_dequeue(io->bless)))
			bless_packet_process(pkt);

		if (heartbeat_next != 0 && now >= heartbeat_next)
			bless_packet_heartbeat();

		if (tx_wakeup) {
			tx_wakeup = 0;
			sanctum_proc_wakeup(SANCTUM_PROC_PURGATORY_TX);
		}
	}

	sanctum_sa_clear(&state);

	nyfe_zeroize(&state, sizeof(state));
	nyfe_zeroize(io->tx, sizeof(*io->tx));

	sanctum_log(LOG_NOTICE, "exiting");

	exit(0);
}

/*
 * Drop access to queues the bless process does not need.
 */
static void
bless_drop_access(void)
{
	(void)close(io->nat);
	(void)close(io->clear);
	(void)close(io->crypto);

	sanctum_shm_detach(io->rx);
	sanctum_shm_detach(io->offer);
	sanctum_shm_detach(io->heaven);
	sanctum_shm_detach(io->chapel);
	sanctum_shm_detach(io->confess);

	io->rx = NULL;
	io->offer = NULL;
	io->heaven = NULL;
	io->chapel = NULL;
	io->confess = NULL;
}

/*
 * Generate a heartbeat packet.
 */
static void
bless_packet_heartbeat(void)
{
	struct sanctum_packet		*pkt;

	if (state.cipher == NULL)
		return;

	if ((pkt = sanctum_packet_get()) == NULL)
		return;

	pkt->length = 0;
	pkt->target = SANCTUM_PROC_BLESS;
	pkt->next = SANCTUM_PACKET_HEARTBEAT;

	bless_packet_process(pkt);
	heartbeat_next = now + heartbeat_interval;
}

/*
 * Encrypt a single packet under the current TX key.
 */
static void
bless_packet_process(struct sanctum_packet *pkt)
{
	struct sanctum_proto_tail	*tail;
	struct sanctum_cipher		cipher;
	struct sanctum_proto_hdr	*hdr, aad;
	size_t				overhead, offset;
	u_int8_t			nonce[SANCTUM_NONCE_LENGTH], *data;

	PRECOND(pkt != NULL);
	PRECOND(pkt->target == SANCTUM_PROC_BLESS);

	if (sanctum_key_erase("TX", io->tx, &state, NULL) != -1)
		sanctum_stat_clear(&sanctum->tx);

	if (sanctum_key_install(io->tx, &state) != -1) {
		heartbeat_interval = BLESS_KEY_HEARTBEAT_INTERVAL;
		heartbeat_next = now + BLESS_KEY_HEARTBEAT_INTERVAL;
		heartbeat_reset = now + BLESS_KEY_HEARTBEAT_DURATION;
		sanctum_atomic_write(&sanctum->tx.pkt, 0);
		sanctum_atomic_write(&sanctum->tx.bytes, 0);
		sanctum_atomic_write(&sanctum->tx.age, now);
		sanctum_atomic_write(&sanctum->tx.spi, state.spi);
	}

	if (state.cipher == NULL) {
		sanctum_packet_release(pkt);
		return;
	}

	if (state.seqnr >= SANCTUM_SA_PACKET_HARD || (now > state.age &&
	    (now - state.age) >= SANCTUM_SA_LIFETIME_HARD)) {
		sanctum_log(LOG_NOTICE,
		    "expired TX SA (seqnr=%" PRIu64 ", age=%" PRIu64 ")",
		    state.seqnr, (now - state.age));
		sanctum_cipher_cleanup(state.cipher);
		state.cipher = NULL;
		sanctum_packet_release(pkt);
		sanctum_stat_clear(&sanctum->tx);
		return;
	}

	if (state.pending) {
		state.pending = 0;
		sanctum_log(LOG_NOTICE, "TX SA active (spi=%08x)", state.spi);
	}

	overhead = sizeof(*hdr) + sizeof(*tail) + SANCTUM_TAG_LENGTH;
	if ((pkt->length + overhead < pkt->length) ||
	    (pkt->length + overhead > sizeof(pkt->buf))) {
		sanctum_packet_release(pkt);
		return;
	}

	if ((sanctum->flags & SANCTUM_FLAG_TFC_ENABLED) &&
	    pkt->length < sanctum->tun_mtu) {
		offset = pkt->length;
		pkt->length = sanctum->tun_mtu;
		data = sanctum_packet_data(pkt);
		nyfe_mem_zero(&data[offset], pkt->length - offset);
	}

	hdr = sanctum_packet_head(pkt);
	tail = sanctum_packet_tail(pkt);

	hdr->pn = state.seqnr++;
	hdr->esp.spi = htobe32(state.spi);
	hdr->esp.seq = htobe32(hdr->pn & 0xffffffff);
	hdr->pn = htobe64(hdr->pn);

	hdr->flock.src = htobe64(sanctum->cathedral_flock);
	hdr->flock.dst = htobe64(sanctum->cathedral_flock_dst);

	tail->pad = 0;
	tail->next = pkt->next;
	pkt->length += sizeof(*tail);

	memcpy(&aad, hdr, sizeof(*hdr));

	memset(nonce, 0, sizeof(nonce));
	memcpy(nonce, &state.salt, sizeof(state.salt));
	memcpy(&nonce[sizeof(state.salt)], &hdr->pn, sizeof(hdr->pn));

	cipher.aad = &aad;
	cipher.aad_len = sizeof(aad);

	cipher.nonce = nonce;
	cipher.nonce_len = sizeof(nonce);

	cipher.ctx = state.cipher;
	cipher.data_len = pkt->length;

	cipher.pt = sanctum_packet_data(pkt);
	cipher.ct = sanctum_packet_data(pkt);
	cipher.tag = sanctum_packet_tail(pkt);

	sanctum_cipher_encrypt(&cipher);

	VERIFY(pkt->length + SANCTUM_TAG_LENGTH < sizeof(pkt->buf));
	pkt->length += SANCTUM_TAG_LENGTH;

	VERIFY(pkt->length + sizeof(*hdr) < sizeof(pkt->buf));
	pkt->length += sizeof(*hdr);

	pkt->target = SANCTUM_PROC_PURGATORY_TX;

	if (sanctum_ring_queue(io->purgatory, pkt) == -1) {
		sanctum_packet_release(pkt);
	} else {
		tx_wakeup = 1;
		sanctum_atomic_add(&sanctum->tx.pkt, 1);
		sanctum_atomic_add(&sanctum->tx.bytes, pkt->length);
		sanctum_atomic_write(&sanctum->tx.last, sanctum->uptime);
	}
}
