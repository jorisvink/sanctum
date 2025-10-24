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

/*
 * A key offer sent to our peer, this is wrapped with a key derived
 * from a shared secret.
 */
struct key_offer {
	u_int16_t		ttl;
	u_int32_t		spi;
	u_int32_t		salt;
	u_int64_t		pulse;
	u_int8_t		key[SANCTUM_KEY_LENGTH];
};

static void	pilgrim_drop_access(void);

static void	pilgrim_offer_clear(void);
static void	pilgrim_offer_check(u_int64_t);
static void	pilgrim_offer_encrypt(u_int64_t);

/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/* The current offer for our peer. */
static struct key_offer		*offer = NULL;

/* The next time we can offer at the earliest. */
static u_int64_t		offer_next = 0;

/*
 * We pulse out the current offer every 30 seconds with a max ttl
 * of 115, resulting in a total offer time of 3450 seconds, 50 seconds
 * less than SANCTUM_SA_LIFETIME_SOFT.
 */
static u_int64_t		offer_ttl = 115;
static u_int64_t		offer_next_send = 30;

/* Randomly generated local ID. */
static u_int64_t		local_id = 0;

/*
 * Pilgrim - A keying process that submits wrapped keys to our peer.
 * This process is used when the sanctum mode is set to "pilgrim".
 *
 * In this mode, sanctum is only able to submit encrypted data to the peer,
 * and thus the keying happens differently then normal. We simply pulse
 * out the wrapped TX key to the peer.
 */
void
sanctum_pilgrim(struct sanctum_proc *proc)
{
	u_int64_t		now;
	int			sig, running;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);

	sanctum_random_init();
	sanctum_random_bytes(&local_id, sizeof(local_id));

	io = proc->arg;
	pilgrim_drop_access();

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

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

		sanctum_proc_suspend(1);
		now = sanctum_atomic_read(&sanctum->uptime);

		if (offer != NULL) {
			if (now >= offer->pulse)
				pilgrim_offer_encrypt(now);
		} else {
			pilgrim_offer_check(now);
		}
	}

	sanctum_log(LOG_NOTICE, "exiting");

	exit(0);
}

/*
 * Drop access to queues that chapel does not need.
 */
static void
pilgrim_drop_access(void)
{
	(void)close(io->nat);
	(void)close(io->clear);
	(void)close(io->crypto);

	sanctum_shm_detach(io->bless);
	sanctum_shm_detach(io->chapel);
	sanctum_shm_detach(io->heaven);
	sanctum_shm_detach(io->confess);
	sanctum_shm_detach(io->purgatory);

	io->bless = NULL;
	io->chapel = NULL;
	io->heaven = NULL;
	io->confess = NULL;
	io->purgatory = NULL;
}

/*
 * Check if a new offer needs to be sent and do it when required.
 */
static void
pilgrim_offer_check(u_int64_t now)
{
	u_int64_t		age;
	const char		*reason;
	int			offer_now;

	PRECOND(offer == NULL);

	if (now < offer_next)
		return;

	offer_now = 0;
	reason = NULL;

	if (sanctum_atomic_read(&sanctum->tx.spi) != 0) {
		age = sanctum_atomic_read(&sanctum->tx.age);
		if (now - age >= SANCTUM_SA_LIFETIME_SOFT) {
			offer_now = 1;
			reason = "SA age limit";
		}
	} else {
		offer_now = 1;
		reason = "no keys";
		sanctum_atomic_write(&sanctum->heartbeat, now);
	}

	if (offer_now == 0)
		return;

	if ((offer = calloc(1, sizeof(*offer))) == NULL)
		fatal("calloc");

	offer->pulse = now;
	offer->ttl = offer_ttl;

	sanctum_random_bytes(offer->key, sizeof(offer->key));
	sanctum_random_bytes(&offer->spi, sizeof(offer->spi));
	sanctum_random_bytes(&offer->salt, sizeof(offer->salt));

	sanctum_install_key_material(io->tx, offer->spi,
	    offer->salt, offer->key, sizeof(offer->key));

	sanctum_log(LOG_INFO, "sending fresh key (%s) "
	    "(spi=0x%08x, ttl=%" PRIu64 ", next=%" PRIu64 ")",
	    reason, offer->spi, offer_ttl, offer_next_send);

	offer_next = now + SANCTUM_SA_LIFETIME_SOFT;
	sanctum_proc_wakeup(SANCTUM_PROC_BLESS);
}

/*
 * Generate a new encrypted packet containing our current offer for
 * our peer and submit it via the crypto process.
 */
static void
pilgrim_offer_encrypt(u_int64_t now)
{
	struct sanctum_offer		*op;
	struct sanctum_packet		*pkt;
	struct sanctum_key_offer	*key;
	struct sanctum_key		cipher;

	PRECOND(offer != NULL);

	offer->ttl--;
	offer->pulse = now + offer_next_send;

	if ((pkt = sanctum_packet_get()) == NULL)
		goto cleanup;

	op = sanctum_offer_init(pkt, offer->spi,
	    SANCTUM_KEY_OFFER_MAGIC, SANCTUM_OFFER_TYPE_KEY);

	nyfe_zeroize_register(&cipher, sizeof(cipher));
	if (sanctum_offer_kdf(sanctum->secret,
	    SANCTUM_SHRINE_PILGRIM_DERIVE_LABEL,
	    &cipher, op->hdr.seed, sizeof(op->hdr.seed), 0, 0) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		sanctum_packet_release(pkt);
		goto cleanup;
	}

	key = &op->data.offer.key;
	key->salt = offer->salt;
	key->id = htobe64(local_id);
	nyfe_memcpy(key->key, offer->key, sizeof(offer->key));

	sanctum_offer_encrypt(&cipher, op);
	nyfe_zeroize(&cipher, sizeof(cipher));

	pkt->length = sizeof(*op);
	pkt->target = SANCTUM_PROC_PURGATORY_TX;

	if (sanctum_ring_queue(io->offer, pkt) == -1)
		sanctum_packet_release(pkt);
	else
		sanctum_proc_wakeup(SANCTUM_PROC_PURGATORY_TX);

cleanup:
	if (offer->ttl == 0)
		pilgrim_offer_clear();
}

/*
 * Clear the current offer.
 */
static void
pilgrim_offer_clear(void)
{
	PRECOND(offer != NULL);

	sanctum_mem_zero(offer, sizeof(*offer));
	free(offer);
	offer = NULL;
}
