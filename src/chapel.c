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

/* The SACRAMENT KDF label. */
#define CHAPEL_DERIVE_LABEL	"SANCTUM.SACRAMENT.KDF"

/* The half-time window in which offers are valid. */
#define CHAPEL_OFFER_VALID		5

/* The clock jump in seconds we always offer keys at. */
#define CHAPEL_CLOCK_JUMP_MAX		60

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

static void	chapel_peer_check(u_int64_t);
static void	chapel_cathedral_notify(u_int64_t);

static void	chapel_offer_clear(void);
static void	chapel_offer_check(u_int64_t);
static void	chapel_offer_encrypt(u_int64_t);
static void	chapel_offer_create(u_int64_t, const char *);
static void	chapel_offer_decrypt(struct sanctum_packet *, u_int64_t);

static void	chapel_drop_access(void);
static void	chapel_erase(struct sanctum_key *, u_int32_t);

static void	chapel_install(struct sanctum_key *,
		    u_int32_t, u_int32_t, void *, size_t);

/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/* The current offer for our peer. */
static struct rx_offer		*offer = NULL;

/* Last received verified offer its SPI. */
static u_int32_t		last_spi = 0;

/* The next time we can offer at the earliest. */
static u_int64_t		offer_next = 0;

/* The next time we update the cathedral. */
static u_int64_t		cathedral_next = 0;

/* Current offer TTL and next send intervals. */
static u_int64_t		offer_ttl = 5;
static u_int64_t		offer_next_send = 1;

/* Randomly generated local ID. */
static u_int64_t		local_id = 0;

/* The randomly generated peer ID. */
static u_int64_t		peer_id = 0;

/*
 * Chapel - The keying process.
 *
 * This process is responsible sending key offers to our peer, if
 * it is known, as long as we have not seen any RX traffic from it.
 *
 * It will track heartbeat timeouts for the peer and submit registration
 * offers to a configured cathedral.
 */
void
sanctum_chapel(struct sanctum_proc *proc)
{
	struct timespec		ts;
	u_int64_t		now;
	u_int32_t		spi;
	struct sanctum_packet	*pkt;
	time_t			last_rtime;
	int			sig, running, delay_check;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);

	nyfe_random_init();
	nyfe_random_bytes(&local_id, sizeof(local_id));

	io = proc->arg;
	chapel_drop_access();

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	running = 1;
	last_rtime = 0;
	delay_check = 0;

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

		sanctum_proc_suspend(1);

		(void)clock_gettime(CLOCK_REALTIME, &ts);
		now = sanctum_atomic_read(&sanctum->uptime);

		/*
		 * If the clock jumped a lot, generate a new local_id
		 * to signal a soft "restart" to the other side.
		 *
		 * Note that we delay the peer check for 10 seconds in the
		 * case we just created our offer and it decided the peer
		 * is unresponsive and clears it.
		 */
		if (last_rtime != 0 &&
		    (ts.tv_sec - last_rtime) >= CHAPEL_CLOCK_JUMP_MAX) {
			delay_check = 10;
			if (offer != NULL)
				chapel_offer_clear();
			nyfe_random_bytes(&local_id, sizeof(local_id));
			chapel_offer_create(now, "clock jump");
		}

		last_rtime = ts.tv_sec;

		if (sanctum->flags & SANCTUM_FLAG_CATHEDRAL_ACTIVE)
			chapel_cathedral_notify(now);

		while ((pkt = sanctum_ring_dequeue(io->chapel)) != NULL) {
			chapel_offer_decrypt(pkt, now);
			sanctum_packet_release(pkt);
		}

		if (sanctum_atomic_read(&sanctum->communion) == 1 &&
		    offer != NULL) {
			offer_next = 0;
			chapel_erase(io->rx, offer->spi);
			sanctum_proc_wakeup(SANCTUM_PROC_CONFESS);
			chapel_offer_clear();
		}

		if (delay_check == 0)
			chapel_peer_check(now);
		else
			delay_check--;

		if (offer != NULL) {
			/*
			 * If we saw traffic on our current offer we
			 * clear it as we know the other side got it.
			 */
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
	}

	sanctum_log(LOG_NOTICE, "exiting");

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
 * Do some form of dead peer detection and wipe keys if we find
 * the peer to be deadsies.
 */
static void
chapel_peer_check(u_int64_t now)
{
	u_int64_t	spi, hbeat;

	if ((spi = sanctum_atomic_read(&sanctum->rx.spi)) == 0)
		return;

	if ((hbeat = sanctum_atomic_read(&sanctum->heartbeat)) == 0)
		return;

	if ((now - hbeat) < SANCTUM_HEARTBEAT_INTERVAL * 4)
		return;

	sanctum_log(LOG_NOTICE, "our peer is unresponsive, resetting");

	if (sanctum->flags & SANCTUM_FLAG_PEER_AUTO) {
		offer_next = 0;
		sanctum_atomic_write(&sanctum->peer_ip, 0);
		sanctum_atomic_write(&sanctum->peer_port, 0);
	} else {
		offer_next = now;
	}

	offer_ttl = 5;
	offer_next_send = 1;

	chapel_erase(io->rx, spi);
	sanctum_proc_wakeup(SANCTUM_PROC_CONFESS);

	if (offer != NULL) {
		if (offer->spi != spi) {
			chapel_erase(io->rx, offer->spi);
			sanctum_proc_wakeup(SANCTUM_PROC_CONFESS);
		}
		chapel_offer_clear();
	}

	if ((spi = sanctum_atomic_read(&sanctum->tx.spi)) != 0) {
		chapel_erase(io->tx, spi);
		sanctum_proc_wakeup(SANCTUM_PROC_BLESS);
	}

	sanctum_atomic_write(&sanctum->heartbeat, 0);
}

/*
 * Check if it is time we notify our cathedral about the tunnel we
 * are configured to carry.
 */
static void
chapel_cathedral_notify(u_int64_t now)
{
	struct timespec			ts;
	struct sanctum_offer		*op;
	struct sanctum_packet		*pkt;
	struct nyfe_agelas		cipher;

	PRECOND(sanctum->flags & SANCTUM_FLAG_CATHEDRAL_ACTIVE);
	PRECOND(sanctum->cathedral_secret != NULL);

	if (now < cathedral_next)
		return;

	if ((pkt = sanctum_packet_get()) == NULL)
		return;

	op = sanctum_packet_head(pkt);

	/* Construct the header and data. */
	op->hdr.spi = htobe32(sanctum->cathedral_id);
	op->hdr.magic = htobe64(SANCTUM_CATHEDRAL_MAGIC);
	nyfe_random_bytes(op->hdr.seed, sizeof(op->hdr.seed));

	(void)clock_gettime(CLOCK_REALTIME, &ts);

	op->data.id = htobe64(sanctum->tun_spi);
	op->data.timestamp = htobe64((u_int64_t)ts.tv_sec);

	/* Fill in the rest with random garbage. */
	nyfe_random_bytes(op->data.key, sizeof(op->data.key));
	nyfe_random_bytes(&op->data.salt, sizeof(op->data.salt));

	/* Derive the key we should use. */
	nyfe_zeroize_register(&cipher, sizeof(cipher));
	if (sanctum_cipher_kdf(sanctum->cathedral_secret,
	    SANCTUM_CATHEDRAL_KDF_LABEL, &cipher,
	    op->hdr.seed, sizeof(op->hdr.seed)) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		sanctum_packet_release(pkt);
		return;
	}

	/* Encrypt the offer packet. */
	nyfe_agelas_aad(&cipher, &op->hdr, sizeof(op->hdr));
	nyfe_agelas_encrypt(&cipher, &op->data, &op->data, sizeof(op->data));
	nyfe_agelas_authenticate(&cipher, op->tag, sizeof(op->tag));
	nyfe_zeroize(&cipher, sizeof(cipher));

	/* Submit it into purgatory. */
	pkt->length = sizeof(*op);
	pkt->target = SANCTUM_PROC_PURGATORY_TX;

	if (sanctum_ring_queue(io->offer, pkt) == -1)
		sanctum_packet_release(pkt);
	else
		sanctum_proc_wakeup(SANCTUM_PROC_PURGATORY_TX);

	cathedral_next = now + 5;
}

/*
 * Check if a new offer needs to be sent.
 *
 * In order to send a new offer, we must have the peer address and the peer
 * its heartbeats must have stopped, or we reached some form of limit.
 *
 * If we have no keys at all, we always send an offer.
 */
static void
chapel_offer_check(u_int64_t now)
{
	u_int32_t	spi;
	const char	*reason;
	int		offer_now;
	u_int64_t	pkt, age, hbeat;

	PRECOND(offer == NULL);

	if (sanctum_atomic_read(&sanctum->peer_ip) == 0)
		return;

	if (now < offer_next)
		return;

	offer_now = 0;
	reason = NULL;

	if ((spi = sanctum_atomic_read(&sanctum->rx.spi)) != 0) {
		/* Default is now to offer for 60 seconds. */
		offer_ttl = 6;
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
		sanctum_atomic_write(&sanctum->heartbeat, now);
	}

	if (sanctum_atomic_cas_simple(&sanctum->communion, 1, 0)) {
		reason = "communion";
		offer_now = 1;
		offer_ttl = 5;
		offer_next_send = 1;
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

	if (sanctum->tun_spi != 0) {
		offer->spi = (offer->spi & 0x0000ffff) |
		    ((u_int32_t)sanctum->tun_spi << 16);
	}

	chapel_install(io->rx, offer->spi,
	    offer->salt, offer->key, sizeof(offer->key));

	sanctum_log(LOG_INFO, "offering fresh key (%s) "
	    "(spi=0x%08x, ttl=%" PRIu64 ", next=%" PRIu64 ")",
	    reason, offer->spi, offer_ttl, offer_next_send);

	/* Wakeup confess so it can setup the RX SA. */
	sanctum_proc_wakeup(SANCTUM_PROC_CONFESS);
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
	op->data.id = htobe64(local_id);
	nyfe_memcpy(op->data.key, offer->key, sizeof(offer->key));

	/* Derive the key we should use. */
	nyfe_zeroize_register(&cipher, sizeof(cipher));
	if (sanctum_cipher_kdf(sanctum->secret, CHAPEL_DERIVE_LABEL,
	    &cipher, op->hdr.seed, sizeof(op->hdr.seed)) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		sanctum_packet_release(pkt);
		return;
	}

	/* Encrypt the offer packet. */
	nyfe_agelas_aad(&cipher, &op->hdr, sizeof(op->hdr));
	nyfe_agelas_encrypt(&cipher, &op->data, &op->data, sizeof(op->data));
	nyfe_agelas_authenticate(&cipher, op->tag, sizeof(op->tag));
	nyfe_zeroize(&cipher, sizeof(cipher));

	/* Submit it into purgatory. */
	pkt->length = sizeof(*op);
	pkt->target = SANCTUM_PROC_PURGATORY_TX;

	if (sanctum_ring_queue(io->offer, pkt) == -1)
		sanctum_packet_release(pkt);
	else
		sanctum_proc_wakeup(SANCTUM_PROC_PURGATORY_TX);

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

	/* Derive the key we should use. */
	nyfe_zeroize_register(&cipher, sizeof(cipher));
	if (sanctum_cipher_kdf(sanctum->secret, CHAPEL_DERIVE_LABEL,
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

	if (op->data.timestamp < ((u_int64_t)ts.tv_sec - CHAPEL_OFFER_VALID) ||
	    op->data.timestamp > ((u_int64_t)ts.tv_sec + CHAPEL_OFFER_VALID))
		return;

	/* If we have seen this offer recently, ignore it. */
	op->hdr.spi = be32toh(op->hdr.spi);
	if (op->hdr.spi == last_spi)
		return;

	/* Make sure a someone didn't reflect our current offer back to us. */
	op->data.id = be64toh(op->data.id);
	if (op->data.id == local_id) {
		sanctum_log(LOG_NOTICE, "someone replayed our own key offer");
		return;
	}

	/* Everything checks out, update the peer address if needed. */
	sanctum_peer_update(pkt);

	/* Install received key as the TX key. */
	chapel_install(io->tx, op->hdr.spi,
	    op->data.salt, op->data.key, sizeof(op->data.key));

	/* Wakeup the bless process so it can install the TX SA. */
	sanctum_proc_wakeup(SANCTUM_PROC_BLESS);

	/* Reduce offer settings back to base values. */
	offer_ttl = 5;
	offer_next = 0;
	offer_next_send = 1;

	/*
	 * If the peer ID differs, the remote restarted and we should
	 * offer keys immediately in response to this.
	 */
	if (peer_id != 0 && op->data.id != peer_id) {
		if (offer == NULL)
			chapel_offer_create(now, "peer restart");
	}

	peer_id = op->data.id;
	last_spi = op->hdr.spi;
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

	nyfe_memcpy(state->key, key, len);
	sanctum_atomic_write(&state->spi, spi);
	sanctum_atomic_write(&state->salt, salt);

	if (!sanctum_atomic_cas_simple(&state->state,
	    SANCTUM_KEY_GENERATING, SANCTUM_KEY_PENDING))
		fatal("failed to swap key state to pending");
}

/*
 * Mark the given sanctum key as needing to be erased by the owner process.
 */
static void
chapel_erase(struct sanctum_key *state, u_int32_t spi)
{
	PRECOND(state != NULL);

	while (sanctum_atomic_read(&state->state) != SANCTUM_KEY_EMPTY)
		sanctum_cpu_pause();

	if (!sanctum_atomic_cas_simple(&state->state,
	    SANCTUM_KEY_EMPTY, SANCTUM_KEY_GENERATING))
		fatal("failed to swap key state to generating");

	sanctum_atomic_write(&state->salt, 0);
	sanctum_atomic_write(&state->spi, spi);
	sanctum_mem_zero(state->key, sizeof(state->key));

	if (!sanctum_atomic_cas_simple(&state->state,
	    SANCTUM_KEY_GENERATING, SANCTUM_KEY_ERASE))
		fatal("failed to swap key state to erase");
}
