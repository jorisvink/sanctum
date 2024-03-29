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

#include <arpa/inet.h>
#include <netinet/in.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include "sanctum.h"
#include "libnyfe.h"

/* The PILGRIM KDF label. */
#define SHRINE_DERIVE_LABEL	"SANCTUM.PILGRIMAGE.KDF"

/* The half-time window in which offers are valid. */
#define SHRINE_OFFER_VALID		(SANCTUM_SA_LIFETIME_SOFT / 2)

static void	shrine_offer_decrypt(struct sanctum_packet *, u_int64_t);

static void	shrine_drop_access(void);
static void	shrine_install(struct sanctum_key *,
		    u_int32_t, u_int32_t, void *, size_t);

/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/* Last received verified offer its SPI. */
static u_int32_t		last_spi = 0;

/*
 * Shrine - A keying process that only receives offers from a pilgrim.
 * This process is used when the sanctum mode is set to "shrine".
 *
 * In this mode, sanctum is only capable of receiving data and will
 * thus only attempt to verify and decrypt key offers and install
 * them as its RX keys.
 */
void
sanctum_shrine(struct sanctum_proc *proc)
{
	u_int64_t		now;
	struct sanctum_packet	*pkt;
	int			sig, running;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);

	nyfe_random_init();

	io = proc->arg;
	shrine_drop_access();

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

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

		sanctum_proc_suspend(-1);
		now = sanctum_atomic_read(&sanctum->uptime);

		while ((pkt = sanctum_ring_dequeue(io->chapel)) != NULL) {
			shrine_offer_decrypt(pkt, now);
			sanctum_packet_release(pkt);
		}
	}

	sanctum_log(LOG_NOTICE, "exiting");

	exit(0);
}

/*
 * Drop access to queues that chapel does not need.
 */
static void
shrine_drop_access(void)
{
	(void)close(io->clear);
	(void)close(io->crypto);

	sanctum_shm_detach(io->bless);
	sanctum_shm_detach(io->heaven);
	sanctum_shm_detach(io->confess);
	sanctum_shm_detach(io->purgatory);

	io->bless = NULL;
	io->heaven = NULL;
	io->confess = NULL;
	io->purgatory = NULL;
}

/*
 * Attempt to verify the given offer in pkt.
 *
 * If we can verify that it was sent by the peer and it is not
 * too old then we will install it as the RX key for it.
 */
static void
shrine_offer_decrypt(struct sanctum_packet *pkt, u_int64_t now)
{
	struct timespec			ts;
	struct sanctum_offer		*op;
	struct nyfe_agelas		cipher;
	u_int8_t			tag[32];

	PRECOND(pkt != NULL);
	PRECOND(io != NULL);

	if (pkt->length != sizeof(*op))
		return;

	op = sanctum_packet_head(pkt);

	/* Derive the key we will use. */
	nyfe_zeroize_register(&cipher, sizeof(cipher));
	if (sanctum_cipher_kdf(sanctum->secret, SHRINE_DERIVE_LABEL,
	    &cipher, op->hdr.seed, sizeof(op->hdr.seed)) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		return;
	}

	/* Decrypt and verify the integrity of the offer first. */
	nyfe_agelas_aad(&cipher, &op->hdr, sizeof(op->hdr));
	nyfe_agelas_decrypt(&cipher, &op->data, &op->data, sizeof(op->data));
	nyfe_agelas_authenticate(&cipher, tag, sizeof(tag));
	nyfe_zeroize(&cipher, sizeof(cipher));

	if (memcmp(op->tag, tag, sizeof(op->tag)))
		return;

	/* Make sure the offer isn't too old. */
	(void)clock_gettime(CLOCK_REALTIME, &ts);
	op->data.timestamp = be64toh(op->data.timestamp);

	if (op->data.timestamp < ((u_int64_t)ts.tv_sec - SHRINE_OFFER_VALID) ||
	    op->data.timestamp > ((u_int64_t)ts.tv_sec + SHRINE_OFFER_VALID))
		return;

	/* If we have seen this offer recently, ignore it. */
	op->hdr.spi = be32toh(op->hdr.spi);
	if (op->hdr.spi == last_spi)
		return;

	/* Everything checks out, update the peer address if needed. */
	sanctum_peer_update(pkt);

	/* Install received key as the RX key. */
	shrine_install(io->rx, op->hdr.spi,
	    op->data.salt, op->data.key, sizeof(op->data.key));

	last_spi = op->hdr.spi;

	/* Wakeup confess so it can setup the RX SA. */
	sanctum_proc_wakeup(SANCTUM_PROC_CONFESS);
}

/*
 * Install the given key into shared memory so that RX/TX can pick these up.
 */
static void
shrine_install(struct sanctum_key *state, u_int32_t spi, u_int32_t salt,
    void *key, size_t len)
{
	PRECOND(state != NULL);
	PRECOND(spi > 0);
	PRECOND(key != NULL);
	PRECOND(len == SANCTUM_KEY_LENGTH);

	while (sanctum_atomic_read(&state->state) != SANCTUM_KEY_EMPTY)
		sanctum_cpu_pause();

	if (!sanctum_atomic_cas_simple(&state->state,
	    SANCTUM_KEY_EMPTY, SANCTUM_KEY_GENERATING))
		fatal("failed to swap key state to generating");

	nyfe_memcpy(state->key, key, len);
	sanctum_atomic_write(&state->spi, spi);
	sanctum_atomic_write(&state->salt, salt);

	if (!sanctum_atomic_cas_simple(&state->state,
	    SANCTUM_KEY_GENERATING, SANCTUM_KEY_PENDING))
		fatal("failed to swap key state to pending");
}
