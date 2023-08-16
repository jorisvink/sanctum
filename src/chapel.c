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
#define CHAPEL_DERIVE_LABEL	"SANCTUM.SACRISTY.KDF"

/* The half-time window in which offers are valid. */
#define CHAPEL_OFFER_VALID		5

/*
 * An RX offer we send to our peer (meaning the peer can use this key as
 * a TX key and we will be able to decrypt traffic with it).
 */
struct rx_offer {
	u_int16_t		ttl;
	u_int32_t		spi;
	u_int32_t		salt;
	u_int64_t		pulse;
	u_int8_t		key[SANCTUM_KEY_LENGTH];
};

static void	chapel_offer_clear(void);
static void	chapel_offer_check(u_int64_t);
static void	chapel_offer_encrypt(u_int64_t);
static void	chapel_offer_create(u_int64_t, const char *);
static void	chapel_offer_kdf(struct nyfe_agelas *, void *, size_t);
static void	chapel_offer_decrypt(struct sanctum_packet *, u_int64_t);

static void	chapel_drop_access(void);
static void	chapel_install(struct sanctum_key *,
		    u_int32_t, u_int32_t, void *, size_t);


/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/* The current offer for our peer. */
static struct rx_offer		*offer = NULL;

/* Last received verified offer its SPI. */
static u_int32_t		last_spi = 0;

/* Current offer TTL and next send intervals. */
static u_int64_t		offer_ttl = 5;
static u_int64_t		offer_next_send = 1;

/*
 * Chapel - The keying process.
 *
 * This process is responsible sending key offers to our peer, if
 * it is known, as long as we have not seen any RX traffic from it.
 */
void
sanctum_chapel(struct sanctum_proc *proc)
{
	u_int64_t		now;
	u_int32_t		spi;
	struct sanctum_packet	*pkt;
	int			sig, running;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);

	nyfe_random_init();

	io = proc->arg;
	chapel_drop_access();

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	running = 1;
	sanctum_proc_privsep(proc);

	while (running) {
		if ((sig = sanctum_last_signal()) != -1) {
			syslog(LOG_NOTICE, "received signal %d", sig);
			switch (sig) {
			case SIGQUIT:
				running = 0;
				continue;
			}
		}

		now = sanctum_atomic_read(&sanctum->uptime);

		while ((pkt = sanctum_ring_dequeue(io->chapel)) != NULL) {
			chapel_offer_decrypt(pkt, now);
			sanctum_packet_release(pkt);
		}

		if (offer != NULL) {
			spi = sanctum_atomic_read(&sanctum->rx.spi);
			if (spi == offer->spi &&
			    sanctum_atomic_read(&sanctum->rx.pkt) > 0) {
				chapel_offer_clear();
			} else {
				if (now >= offer->pulse)
					chapel_offer_encrypt(now);
			}
		} else {
			chapel_offer_check(now);
		}

		sleep(1);
	}

	syslog(LOG_NOTICE, "exiting");

	exit(0);
}

/*
 * Drop access to queues that chapel does not need.
 */
static void
chapel_drop_access(void)
{
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
 * Check if an offer must be sent to our peer.
 *
 * 1) We must have the peer address.
 * 2) If we have a previous RX SA, the peer must have timed out,
 *    reached the SA packet limit or SA lifetime limit.
 * 3) If we do not have a previous RX SA, we always send an offer.
 */
static void
chapel_offer_check(u_int64_t now)
{
	const char	*reason;
	int		offer_now;
	u_int64_t	pkt, age, hbeat;

	PRECOND(offer == NULL);

	if (sanctum_atomic_read(&sanctum->peer_ip) == 0)
		return;

	offer_now = 0;
	reason = NULL;

	if (sanctum_atomic_read(&sanctum->rx.spi) != 0) {
		offer_ttl = 30;
		offer_next_send = 10;

		age = sanctum_atomic_read(&sanctum->rx.age);
		pkt = sanctum_atomic_read(&sanctum->rx.pkt);
		hbeat = sanctum_atomic_read(&sanctum->heartbeat);

		if ((now - hbeat) >= SANCTUM_HEARTBEAT_INTERVAL * 2) {
			offer_now = 1;
			reason = "heartbeat timeout";
		} else if (pkt >= SANCTUM_SA_PACKET_SOFT) {
			offer_now = 1;
			reason = "SA packet limit";
		} else  if (now - age >= SANCTUM_SA_LIFETIME_SOFT) {
			offer_now = 1;
			reason = "SA age limit";
		}
	} else {
		offer_now = 1;
		reason = "no keys";
	}

	if (offer_now == 0)
		return;

	chapel_offer_create(now, reason);
}

/*
 * Generate a new offer that can be sent to the peer.
 */
static void
chapel_offer_create(u_int64_t now, const char *reason)
{
	PRECOND(offer == NULL);
	PRECOND(reason != NULL);

	if (sanctum_atomic_read(&sanctum->peer_ip) == 0)
		return;

	if ((offer = calloc(1, sizeof(*offer))) == NULL)
		fatal("calloc");

	offer->pulse = now;
	offer->ttl = offer_ttl;

	nyfe_random_bytes(offer->key, sizeof(offer->key));
	nyfe_random_bytes(&offer->spi, sizeof(offer->spi));
	nyfe_random_bytes(&offer->salt, sizeof(offer->salt));

	chapel_install(io->rx, offer->spi,
	    offer->salt, offer->key, sizeof(offer->key));

	syslog(LOG_INFO, "offering fresh key (%s) (spi=0x%08x)",
	    reason, offer->spi);
}

/*
 * Generate a new encrypted packet containing our current offer for
 * our peer and submit it via the crypto process.
 */
static void
chapel_offer_encrypt(u_int64_t now)
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
	memcpy(op->data.key, offer->key, sizeof(offer->key));

	/* Encrypt the offer packet. */
	chapel_offer_kdf(&cipher, op->hdr.seed, sizeof(op->hdr.seed));
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
		chapel_offer_clear();
}

/*
 * Clear the current offer.
 */
static void
chapel_offer_clear(void)
{
	PRECOND(offer != NULL);

	sanctum_mem_zero(offer, sizeof(*offer));
	free(offer);
	offer = NULL;
}

/*
 * Attempt to verify the given offer in pkt.
 *
 * If we can verify that it was sent by the peer and it is not
 * too old then we will install it as the TX key for it.
 */
static void
chapel_offer_decrypt(struct sanctum_packet *pkt, u_int64_t now)
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

	/* Decrypt and verify the integrity of the offer first. */
	chapel_offer_kdf(&cipher, op->hdr.seed, sizeof(op->hdr.seed));
	nyfe_agelas_aad(&cipher, &op->hdr, sizeof(op->hdr));
	nyfe_agelas_decrypt(&cipher, &op->data, &op->data, sizeof(op->data));
	nyfe_agelas_authenticate(&cipher, tag, sizeof(tag));
	sanctum_mem_zero(&cipher, sizeof(cipher));

	if (memcmp(op->tag, tag, sizeof(op->tag)))
		return;

	/* Make sure the offer isn't too old. */
	(void)clock_gettime(CLOCK_REALTIME, &ts);
	op->data.timestamp = be64toh(op->data.timestamp);

	if (op->data.timestamp < ((u_int64_t)ts.tv_sec - CHAPEL_OFFER_VALID) ||
	    op->data.timestamp > ((u_int64_t)ts.tv_sec + CHAPEL_OFFER_VALID))
		return;

	/* If we have seen this offer recently, ignore it. */
	op->hdr.spi = be32toh(op->hdr.spi);
	if (op->hdr.spi == last_spi)
		return;

	/* Make sure a someone didn't reflect our current offer back to us. */
	if (offer != NULL) {
		if (op->hdr.spi == offer->spi && op->data.salt == offer->salt &&
		    !memcmp(op->data.key, offer->key, sizeof(offer->key))) {
			return;
		}
	}

	/* Everything checks out, update the peer address if needed. */
	sanctum_peer_update(pkt);

	/* Install received key as the TX key. */
	chapel_install(io->tx, op->hdr.spi,
	    op->data.salt, op->data.key, sizeof(op->data.key));

	last_spi = op->hdr.spi;

	/* Reduce initial TTL and next send back to base values. */
	offer_ttl = 5;
	offer_next_send = 1;
}

/*
 * Install the given key into shared memory so that RX/TX can pick these up.
 */
static void
chapel_install(struct sanctum_key *state, u_int32_t spi, u_int32_t salt,
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

	memcpy(state->key, key, len);
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
chapel_offer_kdf(struct nyfe_agelas *cipher, void *seed, size_t seed_len)
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
	    CHAPEL_DERIVE_LABEL, sizeof(CHAPEL_DERIVE_LABEL) - 1);
	sanctum_mem_zero(secret, sizeof(secret));

	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, seed, seed_len);
	nyfe_kmac256_final(&kdf, okm, sizeof(okm));
	sanctum_mem_zero(&kdf, sizeof(kdf));

	nyfe_agelas_init(cipher, okm, sizeof(okm));
	sanctum_mem_zero(&okm, sizeof(okm));
}
