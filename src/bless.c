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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "sanctum.h"

static void	bless_drop_access(void);
static void	bless_packet_heartbeat(void);
static void	bless_packet_process(struct sanctum_packet *);

/* The shared queues. */
static struct sanctum_proc_io	*io = NULL;

/* The local state for TX. */
static struct sanctum_sa	state;

/* Local timekeeping for heartbeats. */
static u_int64_t		now = 0;
static u_int64_t		next_heartbeat = 0;

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

	running = 1;
	sanctum_proc_privsep(proc);

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

		if (sanctum_key_erase("TX", io->tx, &state) != -1)
			sanctum_stat_clear(&sanctum->tx);

		if (sanctum_key_install(io->tx, &state) != -1) {
			state.seqnr = 1;
			next_heartbeat = now;
			sanctum_atomic_write(&sanctum->tx.age, now);
			sanctum_atomic_write(&sanctum->tx.spi, state.spi);
		}

		while ((pkt = sanctum_ring_dequeue(io->bless)))
			bless_packet_process(pkt);

		if (next_heartbeat != 0 && now >= next_heartbeat)
			bless_packet_heartbeat();

#if !defined(SANCTUM_HIGH_PERFORMANCE)
		usleep(500);
#endif
	}

	sanctum_sa_clear(&state);

	sanctum_log(LOG_NOTICE, "exiting");

	exit(0);
}

/*
 * Drop access to queues the bless process does not need.
 */
static void
bless_drop_access(void)
{
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
	next_heartbeat = now + SANCTUM_HEARTBEAT_INTERVAL;
}

/*
 * Encrypt a single packet under the current TX key.
 */
static void
bless_packet_process(struct sanctum_packet *pkt)
{
	struct sanctum_ipsec_hdr	*hdr;
	struct sanctum_ipsec_tail	*tail;
	size_t				overhead;
	u_int8_t			nonce[12], aad[12];

	PRECOND(pkt != NULL);
	PRECOND(pkt->target == SANCTUM_PROC_BLESS);

	/* Erase key if requested. */
	sanctum_key_erase("TX", io->tx, &state);

	/* Install any pending TX key first. */
	if (sanctum_key_install(io->tx, &state) != -1) {
		sanctum_atomic_write(&sanctum->tx.age, now);
		sanctum_atomic_write(&sanctum->tx.spi, state.spi);
	}

	/* If we don't have a cipher state, we shall not submit. */
	if (state.cipher == NULL) {
		sanctum_packet_release(pkt);
		return;
	}

	/*
	 * If we reached max number of packets that can be transmitted,
	 * or the SA is too old, we do not submit.
	 */
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
		sanctum_log(LOG_NOTICE, "TX SA active (spi=0x%08x)", state.spi);
	}

	/* Belts and suspenders. */
	overhead = sizeof(*hdr) + sizeof(*tail) + sanctum_cipher_overhead();

	if ((pkt->length + overhead < pkt->length) ||
	    (pkt->length + overhead > sizeof(pkt->buf))) {
		sanctum_packet_release(pkt);
		return;
	}

	/* Fill in ESP header and t(r)ail. */
	hdr = sanctum_packet_head(pkt);
	tail = sanctum_packet_tail(pkt);

	hdr->pn = state.seqnr++;
	hdr->esp.spi = htobe32(state.spi);
	hdr->esp.seq = htobe32(hdr->pn & 0xffffffff);

	/* We don't pad, RFC says its a SHOULD not a MUST. */
	tail->pad = 0;
	tail->next = pkt->next;

	/* Tail is included in the plaintext. */
	pkt->length += sizeof(*tail);

	/* Prepare the nonce and aad. */
	memcpy(nonce, &state.salt, sizeof(state.salt));
	memcpy(&nonce[sizeof(state.salt)], &hdr->pn, sizeof(hdr->pn));

	memcpy(aad, &state.spi, sizeof(state.spi));
	memcpy(&aad[sizeof(state.spi)], &hdr->pn, sizeof(hdr->pn));

	hdr->pn = htobe64(hdr->pn);

	/* Do the cipher dance. */
	sanctum_cipher_encrypt(state.cipher, nonce, sizeof(nonce),
	    aad, sizeof(aad), pkt);

	/* Account for the header. */
	VERIFY(pkt->length + sizeof(*hdr) < sizeof(pkt->buf));

	pkt->length += sizeof(*hdr);
	pkt->target = SANCTUM_PROC_PURGATORY;

	/* Send it into purgatory. */
	if (sanctum_ring_queue(io->purgatory, pkt) == -1) {
		sanctum_packet_release(pkt);
	} else {
		sanctum_atomic_add(&sanctum->tx.pkt, 1);
		sanctum_atomic_add(&sanctum->tx.bytes, pkt->length);
		sanctum_atomic_write(&sanctum->tx.last, sanctum->uptime);
	}
}
