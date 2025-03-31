/*
 * Copyright (c) 2023-2024 Joris Vink <joris@sanctorum.se>
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
static void	chapel_cathedral_send_info(u_int64_t);

static void	chapel_cathedral_p2p(struct sanctum_offer *, u_int64_t);
static void	chapel_cathedral_ambry(struct sanctum_offer *, u_int64_t);
static void	chapel_cathedral_packet(struct sanctum_packet *, u_int64_t);

static void	chapel_ambry_write(struct sanctum_ambry_offer *, u_int64_t);
static void	chapel_ambry_unwrap(struct sanctum_ambry_offer *, u_int64_t);

static void	chapel_packet_handle(struct sanctum_packet *, u_int64_t);

static void	chapel_offer_clear(void);
static void	chapel_offer_check(u_int64_t);
static void	chapel_offer_encrypt(u_int64_t);
static void	chapel_offer_create(u_int64_t, const char *);
static void	chapel_offer_decrypt(struct sanctum_packet *, u_int64_t);

static void	chapel_drop_access(void);
static void	chapel_erase(struct sanctum_key *, u_int32_t);

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

/* The ambry generation, initially 0. */
static u_int32_t		ambry_generation = 0;

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

	sanctum_proc_privsep(proc);
	sanctum_platform_sandbox(proc);

	running = 1;
	last_rtime = 0;
	delay_check = 0;

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
			chapel_packet_handle(pkt, now);
			sanctum_packet_release(pkt);
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
	(void)close(io->nat);
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

	if ((now - hbeat) < SANCTUM_HEARTBEAT_INTERVAL * 8)
		return;

	sanctum_log(LOG_NOTICE, "our peer is unresponsive, resetting");

	if (sanctum->flags & SANCTUM_FLAG_PEER_AUTO) {
		offer_next = 0;
		sanctum_atomic_write(&sanctum->peer_ip, 0);
		sanctum_atomic_write(&sanctum->peer_port, 0);
	} else {
		if ((sanctum->flags & SANCTUM_FLAG_CATHEDRAL_ACTIVE) &&
		    !(sanctum->flags & SANCTUM_FLAG_PEER_CONFIGURED)) {
			sanctum_atomic_write(&sanctum->peer_ip,
			    sanctum->cathedral.sin_addr.s_addr);
			sanctum_atomic_write(&sanctum->peer_port,
			    sanctum->cathedral.sin_port);
		}
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
 * Handle an incoming packet and decide who gets to handle it.
 *
 * We accept key exchange packets and cathedral packets.
 */
static void
chapel_packet_handle(struct sanctum_packet *pkt, u_int64_t now)
{
	struct sanctum_ipsec_hdr	*hdr;
	u_int32_t			spi, seq;

	PRECOND(pkt != NULL);

	if (pkt->length < sizeof(struct sanctum_offer))
		return;

	hdr = sanctum_packet_head(pkt);
	seq = be32toh(hdr->esp.seq);
	spi = be32toh(hdr->esp.spi);

	if ((spi == (SANCTUM_KEY_OFFER_MAGIC >> 32)) &&
	    (seq == (SANCTUM_KEY_OFFER_MAGIC & 0xffffffff))) {
		chapel_offer_decrypt(pkt, now);
	} else if ((spi == (SANCTUM_CATHEDRAL_MAGIC >> 32)) &&
	    (seq == (SANCTUM_CATHEDRAL_MAGIC & 0xffffffff))) {
		chapel_cathedral_packet(pkt, now);
	} else {
		fatal("invalid chapel packet (spi=%08x, seq=0x%x)", spi, seq);
	}
}

/*
 * Check if it is time we notify our cathedral about the tunnel we
 * are configured to carry.
 */
static void
chapel_cathedral_notify(u_int64_t now)
{
	PRECOND(sanctum->flags & SANCTUM_FLAG_CATHEDRAL_ACTIVE);
	PRECOND(sanctum->cathedral_secret != NULL);

	if (now < cathedral_next)
		return;

	chapel_cathedral_send_info(SANCTUM_CATHEDRAL_MAGIC);

	if (sanctum->cathedral_nat_port != 0)
		chapel_cathedral_send_info(SANCTUM_CATHEDRAL_NAT_MAGIC);

	cathedral_next = now + 5;
}

/*
 * Send an info message to the cathedral, this is either a normal cathedral
 * notification message or a NAT detection message.
 */
static void
chapel_cathedral_send_info(u_int64_t magic)
{
	struct sanctum_offer		*op;
	struct sanctum_packet		*pkt;
	struct sanctum_info_offer	*info;
	struct sanctum_key		cipher;

	PRECOND(magic == SANCTUM_CATHEDRAL_MAGIC ||
	    (magic == SANCTUM_CATHEDRAL_NAT_MAGIC &&
	    sanctum->cathedral_nat_port != 0));

	if ((pkt = sanctum_packet_get()) == NULL)
		return;

	op = sanctum_offer_init(pkt,
	    sanctum->cathedral_id, magic, SANCTUM_OFFER_TYPE_INFO);
	op->hdr.flock = htobe64(sanctum->cathedral_flock);

	info = &op->data.offer.info;
	info->instance = htobe64(local_id);
	info->tunnel = htobe16(sanctum->tun_spi);
	info->ambry_generation = htobe32(ambry_generation);
	info->rx_active = sanctum_atomic_read(&sanctum->rx.spi);
	info->rx_pending = sanctum_atomic_read(&sanctum->rx_pending);

	nyfe_zeroize_register(&cipher, sizeof(cipher));
	if (sanctum_cipher_kdf(sanctum->cathedral_secret,
	    SANCTUM_CATHEDRAL_KDF_LABEL, &cipher,
	    op->hdr.seed, sizeof(op->hdr.seed)) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		sanctum_packet_release(pkt);
		return;
	}

	sanctum_offer_encrypt(&cipher, op);
	nyfe_zeroize(&cipher, sizeof(cipher));

	pkt->length = sizeof(*op);
	pkt->target = SANCTUM_PROC_PURGATORY_TX;

	sanctum_offer_tfc(pkt);

	pkt->addr.sin_family = AF_INET;
	pkt->addr.sin_addr.s_addr = sanctum->cathedral.sin_addr.s_addr;

	if (magic == SANCTUM_CATHEDRAL_MAGIC)
		pkt->addr.sin_port = sanctum->cathedral.sin_port;
	else
		pkt->addr.sin_port = htobe16(sanctum->cathedral_nat_port);

	if (sanctum_ring_queue(io->offer, pkt) == -1)
		sanctum_packet_release(pkt);
	else
		sanctum_proc_wakeup(SANCTUM_PROC_PURGATORY_TX);
}

/*
 * Handle a cathedral packet by attempting to verifying and decrypting it.
 * If successful, check the inner offer type and handle accordingly.
 */
static void
chapel_cathedral_packet(struct sanctum_packet *pkt, u_int64_t now)
{
	struct sanctum_offer		*op;
	struct sanctum_key		cipher;

	PRECOND(pkt != NULL);
	PRECOND(pkt->length >= sizeof(*op));
	PRECOND(sanctum->mode == SANCTUM_MODE_TUNNEL);
	PRECOND(sanctum->flags & SANCTUM_FLAG_CATHEDRAL_ACTIVE);

	op = sanctum_packet_head(pkt);

	nyfe_zeroize_register(&cipher, sizeof(cipher));
	if (sanctum_cipher_kdf(sanctum->cathedral_secret,
	    SANCTUM_CATHEDRAL_KDF_LABEL, &cipher,
	    op->hdr.seed, sizeof(op->hdr.seed)) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		sanctum_packet_release(pkt);
		return;
	}

	if (sanctum_offer_decrypt(&cipher, op, SANCTUM_OFFER_VALID) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		return;
	}

	nyfe_zeroize(&cipher, sizeof(cipher));

	switch (op->data.type) {
	case SANCTUM_OFFER_TYPE_AMBRY:
		chapel_cathedral_ambry(op, now);
		break;
	case SANCTUM_OFFER_TYPE_INFO:
		chapel_cathedral_p2p(op, now);
		break;
	default:
		sanctum_log(LOG_NOTICE, "bad offer type from cathedral (%u)",
		    op->data.type);
		break;
	}
}

/*
 * We received a p2p information packet from the cathedral. This contains
 * connection information about ourselves and our peer.
 *
 * On the first swap to the peer its public ip:port we will ask bless
 * to start heartbeating faster so the hole punching will have effect.
 */
static void
chapel_cathedral_p2p(struct sanctum_offer *op, u_int64_t now)
{
	struct sanctum_info_offer	*info;
	u_int32_t			old_ip;
	u_int16_t			old_port;

	PRECOND(op != NULL);
	PRECOND(op->data.type == SANCTUM_OFFER_TYPE_INFO);

	info = &op->data.offer.info;
	old_ip = sanctum_atomic_read(&sanctum->peer_ip);
	old_port = sanctum_atomic_read(&sanctum->peer_port);

	sanctum_atomic_write(&sanctum->local_ip, info->local_ip);
	sanctum_atomic_write(&sanctum->local_port, info->local_port);

	/* We do not update the peer if it was configured by user. */
	if (!(sanctum->flags & SANCTUM_FLAG_PEER_CONFIGURED) &&
	    info->peer_ip != 0 && info->peer_port != 0) {
		sanctum_peer_update(info->peer_ip, info->peer_port);

		if (info->peer_ip != info->local_ip &&
		    (old_ip != info->peer_ip || old_port != info->peer_port) &&
		    info->peer_ip != sanctum->cathedral.sin_addr.s_addr) {
			sanctum_atomic_write(&sanctum->holepunch, 1);
			sanctum_proc_wakeup(SANCTUM_PROC_BLESS);
		}
	}
}

/*
 * An ambry message was received from the cathedral, sanity check it
 * and then unwrap it and install it if possible.
 */
static void
chapel_cathedral_ambry(struct sanctum_offer *op, u_int64_t now)
{
	struct sanctum_offer_data	*data;
	u_int16_t			tunnel;

	PRECOND(op != NULL);
	PRECOND(op->data.type == SANCTUM_OFFER_TYPE_AMBRY);

	if (sanctum->kek == NULL) {
		sanctum_log(LOG_NOTICE,
		    "Ambry received from cathedral but no KEK configured");
		return;
	}

	data = &op->data;
	tunnel = be16toh(data->offer.ambry.tunnel);

	op->hdr.spi = be32toh(op->hdr.spi);

	if (op->hdr.spi != sanctum->cathedral_id ||
	    tunnel != sanctum->tun_spi) {
		sanctum_log(LOG_NOTICE,
		    "got an ambry not ment for us (%04x)", tunnel);
		return;
	}

	chapel_ambry_unwrap(&data->offer.ambry, now);
}

/*
 * Unwrap the ambry using our configured kek.
 */
static void
chapel_ambry_unwrap(struct sanctum_ambry_offer *ambry, u_int64_t now)
{
	int				fd;
	u_int8_t			len;
	struct nyfe_kmac256		kdf;
	struct sanctum_key		key;
	struct sanctum_ambry_aad	aad;
	struct sanctum_cipher		cipher;
	u_int8_t			kek[SANCTUM_AMBRY_KEK_LEN];
	u_int8_t			nonce[SANCTUM_NONCE_LENGTH];

	PRECOND(ambry != NULL);
	PRECOND(sanctum->kek != NULL);

	if ((fd = sanctum_file_open(sanctum->kek, NULL)) == -1)
		return;

	nyfe_zeroize_register(kek, sizeof(kek));
	nyfe_zeroize_register(&key, sizeof(key));
	nyfe_zeroize_register(&kdf, sizeof(kdf));
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	if (nyfe_file_read(fd, kek, sizeof(kek)) != sizeof(kek))
		fatal("failed to read kek");
	(void)close(fd);

	nyfe_kmac256_init(&kdf, kek, sizeof(kek),
	    SANCTUM_AMBRY_KDF, strlen(SANCTUM_AMBRY_KDF));
	nyfe_zeroize(kek, sizeof(kek));

	len = sizeof(key.key);
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, ambry->seed, sizeof(ambry->seed));
	nyfe_kmac256_final(&kdf, key.key, sizeof(key.key));
	nyfe_zeroize(&kdf, sizeof(kdf));

	cipher.ctx = sanctum_cipher_setup(&key);
	nyfe_zeroize(&key, sizeof(key));

	aad.tunnel = ambry->tunnel;
	aad.generation = ambry->generation;
	nyfe_memcpy(aad.seed, ambry->seed, sizeof(ambry->seed));

	cipher.aad = &aad;
	cipher.aad_len = sizeof(aad);

	sanctum_offer_nonce(nonce, sizeof(nonce));
	cipher.nonce_len = sizeof(nonce);
	cipher.nonce = nonce;

	cipher.pt = ambry->key;
	cipher.ct = ambry->key;
	cipher.tag = &ambry->tag[0];
	cipher.data_len = sizeof(ambry->key);

	if (sanctum_cipher_decrypt(&cipher) == -1) {
		sanctum_cipher_cleanup(cipher.ctx);
		sanctum_log(LOG_NOTICE, "ambry integrity check failed");
		return;
	}

	sanctum_cipher_cleanup(cipher.ctx);
	nyfe_zeroize(&cipher, sizeof(cipher));

	chapel_ambry_write(ambry, now);
}

/*
 * Write the ambry key under op->data.key to the sanctum configured
 * secret file so it can be used by chapel.
 */
static void
chapel_ambry_write(struct sanctum_ambry_offer *ambry, u_int64_t now)
{
	int		fd, len;
	char		path[1024];

	PRECOND(ambry != NULL);

	len = snprintf(path, sizeof(path), "%s.new", sanctum->secret);
	if (len == -1 || (size_t)len >= sizeof(path))
		fatal("failed to create tmp secret path");

	if (unlink(path) == -1 && errno != ENOENT) {
		sanctum_log(LOG_NOTICE,
		    "failed to remove tmp file (%s)", errno_s);
		return;
	}

	fd = nyfe_file_open(path, NYFE_FILE_CREATE);
	nyfe_file_write(fd, ambry->key, sizeof(ambry->key));
	nyfe_file_close(fd);

	if (rename(path, sanctum->secret) == -1) {
		sanctum_log(LOG_NOTICE,
		    "failed to rename secret into place (%s)", errno_s);

		if (unlink(path) == -1) {
			sanctum_log(LOG_NOTICE,
			    "failed to remove tmp file (%s)", errno_s);
		}
	} else {
		ambry_generation = be32toh(ambry->generation);
		sanctum_log(LOG_INFO, "ambry generation %08x active",
		    ambry_generation);

		if (offer != NULL)
			chapel_offer_clear();
		chapel_offer_create(now, "ambry generation switch");
	}
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

	if (sanctum_atomic_read(&sanctum->rx.spi) != 0) {
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

	if (sanctum->kek != NULL && ambry_generation == 0)
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

	sanctum_install_key_material(io->rx, offer->spi,
	    offer->salt, offer->key, sizeof(offer->key));

	sanctum_log(LOG_INFO, "offering fresh key (%s) "
	    "(spi=%08x, ttl=%" PRIu64 ", next=%" PRIu64 ")",
	    reason, offer->spi, offer_ttl, offer_next_send);

	sanctum_proc_wakeup(SANCTUM_PROC_CONFESS);
}

/*
 * Generate a new encrypted packet containing our current key offer
 * for our peer and submit it via the purgatory process.
 */
static void
chapel_offer_encrypt(u_int64_t now)
{
	struct sanctum_offer		*op;
	struct sanctum_key_offer	*key;
	struct sanctum_packet		*pkt;
	struct sanctum_key		cipher;

	PRECOND(offer != NULL);

	offer->ttl--;
	offer->pulse = now + offer_next_send;

	if ((pkt = sanctum_packet_get()) == NULL)
		goto cleanup;

	op = sanctum_offer_init(pkt, offer->spi,
	    SANCTUM_KEY_OFFER_MAGIC, SANCTUM_OFFER_TYPE_KEY);

	if (sanctum->cathedral_flock != 0)
		op->hdr.flock = htobe64(sanctum->cathedral_flock);

	nyfe_zeroize_register(&cipher, sizeof(cipher));
	if (sanctum_cipher_kdf(sanctum->secret, CHAPEL_DERIVE_LABEL,
	    &cipher, op->hdr.seed, sizeof(op->hdr.seed)) == -1) {
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

	sanctum_offer_tfc(pkt);

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
 * Attempt to verify the given key offer that should be in pkt.
 *
 * If we can verify that it was sent by the peer and it is not
 * too old then we will install it as the TX key for it.
 */
static void
chapel_offer_decrypt(struct sanctum_packet *pkt, u_int64_t now)
{
	struct sanctum_offer		*op;
	struct sanctum_key_offer	*key;
	struct sanctum_key		cipher;

	PRECOND(pkt != NULL);
	PRECOND(io != NULL);
	PRECOND(pkt->length >= sizeof(*op));

	op = sanctum_packet_head(pkt);

	nyfe_zeroize_register(&cipher, sizeof(cipher));
	if (sanctum_cipher_kdf(sanctum->secret, CHAPEL_DERIVE_LABEL,
	    &cipher, op->hdr.seed, sizeof(op->hdr.seed)) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		return;
	}

	if (sanctum_offer_decrypt(&cipher, op, SANCTUM_OFFER_VALID) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		return;
	}

	nyfe_zeroize(&cipher, sizeof(cipher));
	if (op->data.type != SANCTUM_OFFER_TYPE_KEY)
		return;

	op->hdr.spi = be32toh(op->hdr.spi);
	if (op->hdr.spi == last_spi)
		return;

	key = &op->data.offer.key;
	key->id = be64toh(key->id);
	if (key->id == local_id) {
		sanctum_log(LOG_NOTICE, "someone replayed our own key offer");
		return;
	}

	sanctum_peer_update(pkt->addr.sin_addr.s_addr, pkt->addr.sin_port);

	sanctum_offer_install(io->tx, op);
	sanctum_proc_wakeup(SANCTUM_PROC_BLESS);

	offer_ttl = 5;
	offer_next = 0;
	offer_next_send = 1;

	/*
	 * If the peer ID differs, the remote restarted and we should
	 * offer keys immediately in response to this.
	 */
	if (key->id != peer_id) {
		if (offer == NULL)
			chapel_offer_create(now, "peer restart");
	}

	peer_id = key->id;
	last_spi = op->hdr.spi;
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
