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

/* The SACRISTY KDF label. */
#define PILGRIM_DERIVE_LABEL	"SANCTUM.PILGRIMAGE.KDF"

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

static void	pilgrim_offer_clear(void);
static void	pilgrim_offer_check(u_int64_t);
static void	pilgrim_offer_encrypt(u_int64_t);
static void	pilgrim_offer_kdf(struct nyfe_agelas *, void *, size_t);

static void	pilgrim_drop_access(void);
static void	pilgrim_install(struct sanctum_key *,
		    u_int32_t, u_int32_t, void *, size_t);

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

	nyfe_random_init();
	nyfe_random_bytes(&local_id, sizeof(local_id));

	io = proc->arg;
	pilgrim_drop_access();

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

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

		if (offer != NULL) {
			if (now >= offer->pulse)
				pilgrim_offer_encrypt(now);
		} else {
			pilgrim_offer_check(now);
		}

		usleep(10000);
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
	u_int32_t		spi;
	u_int64_t		age;
	const char		*reason;
	int			offer_now;

	PRECOND(offer == NULL);

	if (now < offer_next)
		return;

	offer_now = 0;
	reason = NULL;

	if ((spi = sanctum_atomic_read(&sanctum->tx.spi)) != 0) {
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

	nyfe_random_bytes(offer->key, sizeof(offer->key));
	nyfe_random_bytes(&offer->spi, sizeof(offer->spi));
	nyfe_random_bytes(&offer->salt, sizeof(offer->salt));

	pilgrim_install(io->tx, offer->spi,
	    offer->salt, offer->key, sizeof(offer->key));

	sanctum_log(LOG_INFO, "sending fresh key (%s) "
	    "(spi=0x%08x, ttl=%" PRIu64 ", next=%" PRIu64 ")",
	    reason, offer->spi, offer_ttl, offer_next_send);

	offer_next = now + SANCTUM_SA_LIFETIME_SOFT;
}

/*
 * Generate a new encrypted packet containing our current offer for
 * our peer and submit it via the crypto process.
 */
static void
pilgrim_offer_encrypt(u_int64_t now)
{
	struct timespec			ts;
	struct sanctum_offer		*op;
	struct sanctum_packet		*pkt;
	struct nyfe_agelas		cipher;

	PRECOND(offer != NULL);

	offer->ttl--;
	offer->pulse = now + offer_next_send;

	if ((pkt = sanctum_packet_get()) == NULL)
		goto cleanup;

	op = sanctum_packet_head(pkt);

	/* Construct the header and data. */
	op->hdr.spi = htobe32(offer->spi);
	op->hdr.magic = htobe64(SANCTUM_KEY_OFFER_MAGIC);
	nyfe_random_bytes(op->hdr.seed, sizeof(op->hdr.seed));

	(void)clock_gettime(CLOCK_REALTIME, &ts);
	op->data.timestamp = htobe64((u_int64_t)ts.tv_sec);

	op->data.salt = offer->salt;
	op->data.id = htobe64(local_id);
	nyfe_memcpy(op->data.key, offer->key, sizeof(offer->key));

	/* Encrypt the offer packet. */
	pilgrim_offer_kdf(&cipher, op->hdr.seed, sizeof(op->hdr.seed));
	nyfe_agelas_aad(&cipher, &op->hdr, sizeof(op->hdr));
	nyfe_agelas_encrypt(&cipher, &op->data, &op->data, sizeof(op->data));
	nyfe_agelas_authenticate(&cipher, op->tag, sizeof(op->tag));
	sanctum_mem_zero(&cipher, sizeof(cipher));

	/* Submit it into purgatory. */
	pkt->length = sizeof(*op);
	pkt->target = SANCTUM_PROC_PURGATORY;

	if (sanctum_ring_queue(io->offer, pkt) == -1)
		sanctum_packet_release(pkt);

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

/*
 * Install the given key into shared memory so that RX/TX can pick these up.
 */
static void
pilgrim_install(struct sanctum_key *state, u_int32_t spi, u_int32_t salt,
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

/*
 * Derive a symmetrical key from our secret and the given seed and
 * setup the given agelas cipher context.
 */
static void
pilgrim_offer_kdf(struct nyfe_agelas *cipher, void *seed, size_t seed_len)
{
	int				fd;
	struct nyfe_kmac256		kdf;
	u_int8_t			len;
	u_int8_t			okm[64], secret[SANCTUM_KEY_LENGTH];

	PRECOND(cipher != NULL);
	PRECOND(seed != NULL);
	PRECOND(seed_len == 64);

	fd = nyfe_file_open(sanctum->secret, NYFE_FILE_READ);
	if (nyfe_file_read(fd, secret, sizeof(secret)) != sizeof(secret))
		fatal("failed to read secret");
	(void)close(fd);

	len = 64;

	nyfe_kmac256_init(&kdf, secret, sizeof(secret),
	    PILGRIM_DERIVE_LABEL, sizeof(PILGRIM_DERIVE_LABEL) - 1);
	sanctum_mem_zero(secret, sizeof(secret));

	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, seed, seed_len);
	nyfe_kmac256_final(&kdf, okm, sizeof(okm));
	sanctum_mem_zero(&kdf, sizeof(kdf));

	nyfe_agelas_init(cipher, okm, sizeof(okm));
	sanctum_mem_zero(&okm, sizeof(okm));
}
