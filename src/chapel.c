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

#include <arpa/inet.h>
#include <netinet/in.h>

#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include "sanctum.h"
#include "libnyfe.h"

/* The SACRAMENT KDF label. */
#define CHAPEL_DERIVE_LABEL		"SANCTUM.SACRAMENT.KDF"

/* The clock jump in seconds we always offer keys at. */
#define CHAPEL_CLOCK_JUMP_MAX		60

/* Should we generate an offer that includes the ML-KEM-1024 public key. */
#define OFFER_INCLUDE_KEM_PK		(1 << 0)

/* Should we generate an offer include the ML-KEM-1024 ciphertext. */
#define OFFER_INCLUDE_KEM_CT		(1 << 1)

/*
 * Exchange data for a specific direction.
 */
struct exchange_info {
	struct sanctum_mlkem1024	kem;
	u_int32_t			spi;
	u_int32_t			salt;
	u_int8_t			public[SANCTUM_X25519_SCALAR_BYTES];
	u_int8_t			private[SANCTUM_X25519_SCALAR_BYTES];
};

/*
 * An active key offering. This keeps track of the state of the key offering
 * and what needs to be sent and used for the actual derivation of session
 * keys.
 */
struct exchange_offer {
	struct exchange_info		local;
	struct exchange_info		remote;

	u_int16_t			ttl;
	u_int64_t			pulse;
	u_int32_t			flags;

	u_int8_t			pk_frag;
	u_int8_t			ct_frag;
};

static void	chapel_peer_check(u_int64_t);
static void	chapel_derive_session_key(struct sanctum_offer *, u_int8_t);

static void	chapel_cathedral_notify(u_int64_t);
static void	chapel_cathedral_send_info(u_int64_t);
static void	chapel_cathedral_p2p(struct sanctum_offer *, u_int64_t);
static void	chapel_cathedral_ambry(struct sanctum_offer *, u_int64_t);
static void	chapel_cathedral_packet(struct sanctum_packet *, u_int64_t);

static void	chapel_ambry_write(struct sanctum_ambry_offer *, u_int64_t);
static void	chapel_ambry_unwrap(struct sanctum_ambry_offer *, u_int64_t);

static void	chapel_packet_handle(struct sanctum_packet *, u_int64_t);
static void	chapel_session_key_exchange(struct sanctum_offer *, u_int64_t);

static void	chapel_offer_clear(void);
static void	chapel_offer_send(u_int64_t);
static void	chapel_offer_check(u_int64_t);
static void	chapel_offer_create(u_int64_t, const char *);
static void	chapel_offer_encrypt(u_int64_t, int, u_int8_t);
static void	chapel_offer_decrypt(struct sanctum_packet *, u_int64_t);

static void	chapel_drop_access(void);
static void	chapel_erase(struct sanctum_key *, u_int32_t);

/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/* The current offer for our peer. */
static struct exchange_offer	*offer = NULL;

/* The next time we can offer at the earliest. */
static u_int64_t		offer_next = 0;

/* The last remote spi we negotiated keys for. */
static u_int32_t		last_spi = 0;

/* The next time we update the cathedral. */
static u_int64_t		cathedral_next = 0;

/* Current offer TTL and next send intervals. */
static u_int64_t		offer_ttl = 15;
static u_int64_t		offer_next_send = 1;

/* Randomly generated local ID. */
static u_int64_t		local_id = 0;

/* The last peer ID received during an exchange. */
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

	sanctum->cathedral_last = sanctum_atomic_read(&sanctum->uptime);

	if ((sanctum->flags & SANCTUM_FLAG_CATHEDRAL_ACTIVE) &&
	    sanctum->cathedral_remembrance != NULL)
		sanctum_cathedrals_remembrance();

	while (running) {
		if ((sig = sanctum_last_signal()) != -1) {
			sanctum_log(LOG_NOTICE, "received signal %d", sig);
			switch (sig) {
			case SIGQUIT:
				running = 0;
				continue;
			}
		}

		if (sanctum_ring_pending(io->chapel) == 0)
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

		if (sanctum->flags & SANCTUM_FLAG_CATHEDRAL_ACTIVE) {
			sanctum_cathedral_timeout(now);
			chapel_cathedral_notify(now);
		}

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
			if (spi == offer->local.spi &&
			    sanctum_atomic_read(&sanctum->rx.pkt) > 0) {
				offer->flags &= ~OFFER_INCLUDE_KEM_CT;
				if (offer->flags == 0)
					chapel_offer_clear();
			} else {
				if (now >= offer->pulse)
					chapel_offer_send(now);
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

	offer_ttl = 15;
	offer_next_send = 1;

	sanctum_proc_wakeup(SANCTUM_PROC_CONFESS);
	chapel_erase(io->rx, spi);
	sanctum_proc_wakeup(SANCTUM_PROC_CONFESS);

	if ((spi = sanctum_atomic_read(&sanctum->tx.spi)) != 0) {
		sanctum_proc_wakeup(SANCTUM_PROC_BLESS);
		chapel_erase(io->tx, spi);
		sanctum_proc_wakeup(SANCTUM_PROC_BLESS);
	}

	if (offer != NULL)
		chapel_offer_clear();

	sanctum_atomic_write(&sanctum->heartbeat, 0);
}

/*
 * Handle an incoming packet and decide who gets to handle it.
 * We accept key exchange offers and cathedral packets.
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

	if (sanctum->cathedral_remembrance != NULL)
		info->flags = SANCTUM_INFO_FLAG_REMEMBRANCE;

	nyfe_zeroize_register(&cipher, sizeof(cipher));
	if (sanctum_offer_kdf(sanctum->cathedral_secret,
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

	sanctum->cathedral_last = now;
	op = sanctum_packet_head(pkt);

	nyfe_zeroize_register(&cipher, sizeof(cipher));
	if (sanctum_offer_kdf(sanctum->cathedral_secret,
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
	case SANCTUM_OFFER_TYPE_REMEMBRANCE:
		sanctum_offer_remembrance(op, now);
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

	nyfe_zeroize_register(offer, sizeof(*offer));

	offer->pulse = now;
	offer->ttl = offer_ttl;
	offer->flags = OFFER_INCLUDE_KEM_PK;

	nyfe_random_bytes(&offer->local.spi, sizeof(offer->local.spi));
	nyfe_random_bytes(&offer->local.salt, sizeof(offer->local.salt));

	if (sanctum->tun_spi != 0) {
		offer->local.spi = (offer->local.spi & 0x0000ffff) |
		    ((u_int32_t)sanctum->tun_spi << 16);
	}

	sanctum_mlkem1024_keypair(&offer->local.kem);

	sanctum_asymmetry_keygen(offer->local.private,
	    sizeof(offer->local.private), offer->local.public,
	    sizeof(offer->local.public));

	sanctum_asymmetry_keygen(offer->remote.private,
	    sizeof(offer->remote.private), offer->remote.public,
	    sizeof(offer->remote.public));

	sanctum_log(LOG_INFO, "starting new key offering (%s) "
	    "(spi=%08x, ttl=%" PRIu64 ", next=%" PRIu64 ")",
	    reason, offer->local.spi, offer_ttl, offer_next_send);
}

/*
 * Generate new offer packets depending on our current offer state.
 * The KEM offers are split into several fragments for the receiver side
 * and are conditional depending on offer->flags.
 */
static void
chapel_offer_send(u_int64_t now)
{
	u_int8_t	frag;

	PRECOND(offer != NULL);

	offer->ttl--;
	offer->pulse = now + offer_next_send;

	if (offer->flags & OFFER_INCLUDE_KEM_PK) {
		for (frag = 0; frag < SANCTUM_OFFER_KEM_FRAGMENTS; frag++)
			chapel_offer_encrypt(now, OFFER_INCLUDE_KEM_PK, frag);
	}

	if (offer->flags & OFFER_INCLUDE_KEM_CT) {
		for (frag = 0; frag < SANCTUM_OFFER_KEM_FRAGMENTS; frag++)
			chapel_offer_encrypt(now, OFFER_INCLUDE_KEM_CT, frag);
	}

	if (offer->ttl == 0)
		chapel_offer_clear();
}

/*
 * Encrypt and send a single offer packet to our peer. What it includes
 * is based on the which parameter.
 */
static void
chapel_offer_encrypt(u_int64_t now, int which, u_int8_t frag)
{
	struct sanctum_offer		*op;
	struct sanctum_packet		*pkt;
	struct exchange_info		*info;
	struct sanctum_key		cipher;
	size_t				offset;
	struct sanctum_exchange_offer	*exchange;

	PRECOND(offer != NULL);
	PRECOND(which == OFFER_INCLUDE_KEM_PK || which == OFFER_INCLUDE_KEM_CT);
	PRECOND(frag < SANCTUM_OFFER_KEM_FRAGMENTS);

	if ((pkt = sanctum_packet_get()) == NULL)
		return;

	if (which == OFFER_INCLUDE_KEM_CT)
		info = &offer->remote;
	else
		info = &offer->local;

	op = sanctum_offer_init(pkt, offer->local.spi,
	    SANCTUM_KEY_OFFER_MAGIC, SANCTUM_OFFER_TYPE_EXCHANGE);

	if (sanctum->cathedral_flock != 0)
		op->hdr.flock = htobe64(sanctum->cathedral_flock);

	nyfe_zeroize_register(&cipher, sizeof(cipher));
	if (sanctum_offer_kdf(sanctum->secret, CHAPEL_DERIVE_LABEL,
	    &cipher, op->hdr.seed, sizeof(op->hdr.seed)) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		sanctum_packet_release(pkt);
		return;
	}

	exchange = &op->data.offer.exchange;

	exchange->fragment = frag;
	exchange->salt = info->salt;
	exchange->id = htobe64(local_id);
	exchange->spi = htobe32(info->spi);

	nyfe_memcpy(exchange->ecdh, info->public, sizeof(info->public));
	offset = frag * SANCTUM_OFFER_KEM_FRAGMENT_SIZE;

	if (which == OFFER_INCLUDE_KEM_CT) {
		exchange->state = SANCTUM_OFFER_STATE_KEM_CT_FRAGMENT;
		nyfe_memcpy(exchange->kem, &offer->remote.kem.ct[offset],
		    SANCTUM_OFFER_KEM_FRAGMENT_SIZE);
	} else {
		exchange->state = SANCTUM_OFFER_STATE_KEM_PK_FRAGMENT;
		nyfe_memcpy(exchange->kem, &offer->local.kem.pk[offset],
		    SANCTUM_OFFER_KEM_FRAGMENT_SIZE);
	}

	sanctum_offer_encrypt(&cipher, op);
	nyfe_zeroize(&cipher, sizeof(cipher));

	pkt->length = sizeof(*op);
	pkt->target = SANCTUM_PROC_PURGATORY_TX;

	sanctum_offer_tfc(pkt);

	if (sanctum_ring_queue(io->offer, pkt) == -1) {
		sanctum_packet_release(pkt);
		sanctum_log(LOG_NOTICE, "failed to queue %d:%u", which, frag);
	} else {
		sanctum_proc_wakeup(SANCTUM_PROC_PURGATORY_TX);
	}
}

/*
 * Clear the current offer.
 */
static void
chapel_offer_clear(void)
{
	PRECOND(offer != NULL);

	sanctum_log(LOG_INFO, "key offer cleared (spi=%08x)", offer->local.spi);

	offer_ttl = 15;
	offer_next = 0;
	offer_next_send = 1;

	nyfe_zeroize(offer, sizeof(*offer));
	free(offer);
	offer = NULL;
}

/*
 * Attempt to verify the given key offer that should be in pkt.
 *
 * If we can verify that it was sent by the peer, and it is not
 * too old we will finalize our asymmetrical exchange based on
 * the current offer we are sending (or we create one) and derive
 * fresh session keys for both RX/TX directions.
 */
static void
chapel_offer_decrypt(struct sanctum_packet *pkt, u_int64_t now)
{
	struct sanctum_offer		*op;
	struct sanctum_key		cipher;
	struct sanctum_exchange_offer	*exchange;

	PRECOND(pkt != NULL);
	PRECOND(io != NULL);
	PRECOND(pkt->length >= sizeof(*op));

	op = sanctum_packet_head(pkt);

	nyfe_zeroize_register(&cipher, sizeof(cipher));
	if (sanctum_offer_kdf(sanctum->secret, CHAPEL_DERIVE_LABEL,
	    &cipher, op->hdr.seed, sizeof(op->hdr.seed)) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		return;
	}

	if (sanctum_offer_decrypt(&cipher, op, SANCTUM_OFFER_VALID) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		return;
	}

	nyfe_zeroize(&cipher, sizeof(cipher));
	if (op->data.type != SANCTUM_OFFER_TYPE_EXCHANGE)
		return;

	exchange = &op->data.offer.exchange;
	exchange->id = be64toh(exchange->id);

	if (exchange->id == local_id) {
		sanctum_log(LOG_NOTICE, "someone replayed our own key offer");
		return;
	}

	op->hdr.spi = be32toh(op->hdr.spi);

	chapel_session_key_exchange(op, now);
	sanctum_peer_update(pkt->addr.sin_addr.s_addr, pkt->addr.sin_port);
}

/*
 * Performing a key exchange boils down to the following:
 *
 *	Both sides start by sending out offerings that contain an ML-KEM-1024
 *	public key and an x25519 public key.
 *
 *	Both sides upon receiving these offerings will perform ML-KEM-1024
 *	encapsulation and send back the ciphertext and their own x25519
 *	public key which differs from the one sent in the initial offering.
 *
 *	When a side performs encapsulation it will derive a fresh
 *	RX session key using all of that key material and install the
 *	key as a pending RX key.
 *
 *	When a side performs decapsulation it will derive a fresh
 *	TX session key using all of that key material and install the
 *	key as the active TX key.
 *
 * In both cases this results in unique shared secrets for x25519
 * and ML-KEM-1024 in each direction, while allowing us to gracefully
 * install pending RX keys so that we do not miss a beat.
 */
static void
chapel_session_key_exchange(struct sanctum_offer *op, u_int64_t now)
{
	size_t				offset;
	struct sanctum_exchange_offer	*exchange;

	PRECOND(op != NULL);

	exchange = &op->data.offer.exchange;
	exchange->spi = be32toh(exchange->spi);

	switch (exchange->state) {
	case SANCTUM_OFFER_STATE_KEM_PK_FRAGMENT:
		if (exchange->spi == last_spi)
			break;

		if (offer == NULL) {
			chapel_offer_create(now, "peer renegotiate");
			if (offer == NULL)
				break;
		}

		if (offer->pk_frag == SANCTUM_OFFER_KEM_FRAGMENTS_DONE) {
			if (exchange->id != peer_id && offer != NULL) {
				chapel_offer_clear();
				chapel_offer_create(now, "peer restarted");
				if (offer == NULL)
					break;
			}
			break;
		}

		if (exchange->fragment >= SANCTUM_OFFER_KEM_FRAGMENTS) {
			sanctum_log(LOG_NOTICE,
			    "peer sent invalid pk fragment %u",
			    exchange->fragment);
			break;
		}

		if (offer->pk_frag & (1 << exchange->fragment)) {
			sanctum_log(LOG_INFO,
			    "pk fragment %u already seen", exchange->fragment);
			break;
		}

		offset = exchange->fragment * SANCTUM_OFFER_KEM_FRAGMENT_SIZE;
		nyfe_memcpy(&offer->remote.kem.pk[offset],
		    exchange->kem, sizeof(exchange->kem));

		offer->pk_frag |= (1 << exchange->fragment);
		if (offer->pk_frag != SANCTUM_OFFER_KEM_FRAGMENTS_DONE)
			break;

		offer->ttl = offer_ttl;
		offer->remote.spi = exchange->spi;
		offer->remote.salt = exchange->salt;
		offer->flags |= OFFER_INCLUDE_KEM_CT;

		last_spi = exchange->spi;
		sanctum_mlkem1024_encapsulate(&offer->remote.kem);
		chapel_derive_session_key(op, SANCTUM_KEY_DIRECTION_RX);
		break;
	case SANCTUM_OFFER_STATE_KEM_CT_FRAGMENT:
		if (offer == NULL)
			break;

		if (exchange->spi != offer->local.spi) {
			sanctum_log(LOG_INFO,
			    "ct fragment, wrong spi (got:%08x - expected:%08x)",
			    exchange->spi, offer->local.spi);
			break;
		}

		if (!(offer->flags & OFFER_INCLUDE_KEM_PK))
			break;

		if (offer->ct_frag & (1 << exchange->fragment)) {
			sanctum_log(LOG_INFO,
			    "ct fragment %u already seen", exchange->fragment);
			break;
		}

		if (exchange->fragment >= SANCTUM_OFFER_KEM_FRAGMENTS) {
			sanctum_log(LOG_NOTICE,
			    "peer sent invalid ct fragment %u",
			    exchange->fragment);
			break;
		}

		offset = exchange->fragment * SANCTUM_OFFER_KEM_FRAGMENT_SIZE;
		nyfe_memcpy(&offer->local.kem.ct[offset],
		    exchange->kem, sizeof(exchange->kem));

		offer->ct_frag |= (1 << exchange->fragment);
		if (offer->ct_frag != SANCTUM_OFFER_KEM_FRAGMENTS_DONE)
			break;

		offer->flags &= ~OFFER_INCLUDE_KEM_PK;
		sanctum_mlkem1024_decapsulate(&offer->local.kem);
		chapel_derive_session_key(op, SANCTUM_KEY_DIRECTION_TX);
		break;
	default:
		sanctum_log(LOG_NOTICE, "ignoring unknown offer packet");
		break;
	}

	peer_id = exchange->id;
}

/*
 * Derive a new session key for the given direction based upon the
 * shared secrets we negotiated, in combination with a derivative
 * of our shared symmetrical secret.
 */
static void
chapel_derive_session_key(struct sanctum_offer *op, u_int8_t dir)
{
	struct sanctum_kex		kex;
	struct exchange_info		*info;
	struct sanctum_exchange_offer	*exchange;
	u_int8_t			okm[SANCTUM_KEY_LENGTH];

	PRECOND(op != NULL);
	PRECOND(offer != NULL);
	PRECOND(dir == SANCTUM_KEY_DIRECTION_RX ||
	    dir == SANCTUM_KEY_DIRECTION_TX);

	exchange = &op->data.offer.exchange;

	nyfe_zeroize_register(okm, sizeof(okm));
	nyfe_zeroize_register(&kex, sizeof(kex));

	nyfe_memcpy(kex.remote, exchange->ecdh, sizeof(exchange->ecdh));

	if (dir == SANCTUM_KEY_DIRECTION_RX) {
		info = &offer->remote;
		nyfe_memcpy(kex.kem, offer->remote.kem.ss, sizeof(kex.kem));
	} else {
		info = &offer->local;
		nyfe_memcpy(kex.kem, offer->local.kem.ss, sizeof(kex.kem));
	}

	nyfe_memcpy(kex.private, info->private, sizeof(info->private));

	if (exchange->id < local_id) {
		nyfe_memcpy(kex.pub1, info->public, sizeof(info->public));
		nyfe_memcpy(kex.pub2, exchange->ecdh, sizeof(exchange->ecdh));
	} else {
		nyfe_memcpy(kex.pub1, exchange->ecdh, sizeof(exchange->ecdh));
		nyfe_memcpy(kex.pub2, info->public, sizeof(info->public));
	}

	if (sanctum_traffic_kdf(&kex, okm, sizeof(okm)) == -1) {
		nyfe_zeroize(okm, sizeof(okm));
		nyfe_zeroize(&kex, sizeof(kex));
		return;
	}

	if (dir == SANCTUM_KEY_DIRECTION_RX) {
		sanctum_proc_wakeup(SANCTUM_PROC_CONFESS);
		sanctum_install_key_material(io->rx,
		    offer->local.spi, offer->local.salt, okm, sizeof(okm));
		sanctum_proc_wakeup(SANCTUM_PROC_CONFESS);
	} else {
		sanctum_proc_wakeup(SANCTUM_PROC_BLESS);
		sanctum_install_key_material(io->tx,
		    offer->remote.spi, offer->remote.salt, okm, sizeof(okm));
		sanctum_proc_wakeup(SANCTUM_PROC_BLESS);
	}

	nyfe_zeroize(okm, sizeof(okm));
	nyfe_zeroize(&kex, sizeof(kex));
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
