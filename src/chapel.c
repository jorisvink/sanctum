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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "sanctum.h"
#include "libnyfe.h"

#define CHAPEL_DERIVE_LABEL	"SANCTUM.SACRISTY.KDF"

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

static void	chapel_offer_create(u_int64_t);
static void	chapel_offer_encrypt(u_int64_t);
static void	chapel_offer_kdf(struct nyfe_agelas *, void *, size_t);
static void	chapel_offer_decrypt(struct sanctum_packet *, u_int64_t);

static void	chapel_drop_access(void);
static void	chapel_install(struct sanctum_key *, u_int32_t, void *, size_t);


/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/* The current offer for our peer. */
static struct rx_offer		*offer = NULL;

/*
 * Chapel - The keying process.
 *
 * This process is responsible sending key offers to our peer, if
 * it is known, as long as we have not seen any RX traffic from it.
 */
void
sanctum_chapel(struct sanctum_proc *proc)
{
	struct sanctum_packet	*pkt;
	int			sig, running;
	u_int64_t		now, next_chapel;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);

	nyfe_random_init();

	io = proc->arg;
	chapel_drop_access();

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	running = 1;
	next_chapel = 0;
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

		if ((pkt = sanctum_ring_dequeue(io->chapel)) != NULL)
			chapel_offer_decrypt(pkt, now);

		if (offer != NULL && now >= offer->pulse)
			chapel_offer_encrypt(now);

		/* XXX - if no active RX, do it as well. */
		if (now >= next_chapel) {
			next_chapel = now + 120;
			chapel_offer_create(now);
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
	sanctum_shm_detach(io->arwin);
	sanctum_shm_detach(io->bless);
	sanctum_shm_detach(io->heaven);
	sanctum_shm_detach(io->confess);
	sanctum_shm_detach(io->purgatory);

	io->arwin = NULL;
	io->bless = NULL;
	io->heaven = NULL;
	io->confess = NULL;
	io->purgatory = NULL;
}

/*
 * Create a new RX key and start offering it to the other side.
 *
 * The offer shall continue until the other side sends us a packet
 * encrypted with said key.
 */
static void
chapel_offer_create(u_int64_t now)
{
	PRECOND(offer == NULL);

	if (sanctum_atomic_read(&sanctum->peer_ip) == 0)
		return;

	if ((offer = calloc(1, sizeof(*offer))) == NULL)
		fatal("calloc");

	offer->ttl = 1;
	offer->pulse = now + 5;

	nyfe_random_bytes(offer->key, sizeof(offer->key));
	nyfe_random_bytes(&offer->spi, sizeof(offer->spi));
	nyfe_random_bytes(&offer->salt, sizeof(offer->salt));

	printf("creating new RX offer for peer\n");

	printf("key offer = ");
	for (size_t idx = 0; idx < sizeof(offer->key); idx++)
		printf("%02x", offer->key[idx]);
	printf("\n");

	chapel_install(io->rx, offer->spi, offer->key, sizeof(offer->key));
}

static void
dump(const char *label, void *ptr, size_t len)
{
	u_int8_t	*p = ptr;
	size_t		idx, col;

	printf("%s (%zu) =\n", label, len);

	col = 0;

	for (idx = 0; idx < len; idx++) {
		printf("%02x", p[idx]);

		if (col++ == 15) {
			printf("\n");
			col = 0;
		}
	}

	if (col == 15)
		printf("\n");
}

/*
 * Generate a new encrypted packet containing our current offer for
 * our peer and submit it via the crypto process.
 */
static void
chapel_offer_encrypt(u_int64_t now)
{
	struct sanctum_offer		*op;
	struct sanctum_packet		*pkt;
	struct nyfe_agelas		cipher;

	PRECOND(offer != NULL);

	if (offer->ttl == 0) {
		printf("clearing offer, expired\n");
		sanctum_mem_zero(offer, sizeof(*offer));
		free(offer);
		offer = NULL;
		return;
	}

	offer->ttl--;
	offer->pulse = now + 5;
	printf("pulse (%u)\n", offer->ttl);

	if ((pkt = sanctum_packet_get()) == NULL)
		return;

	op = sanctum_packet_head(pkt);

	op->hdr.spi = htobe32(offer->spi);
	op->hdr.magic = htobe64(SANCTUM_KEY_OFFER_MAGIC);
	nyfe_random_bytes(op->hdr.seed, sizeof(op->hdr.seed));

	op->data.salt = offer->salt;
	memcpy(op->data.key, offer->key, sizeof(offer->key));

	chapel_offer_kdf(&cipher, op->hdr.seed, sizeof(op->hdr.seed));
	nyfe_agelas_aad(&cipher, &op->hdr, sizeof(op->hdr));
	nyfe_agelas_encrypt(&cipher, &op->data, &op->data, sizeof(op->data));
	nyfe_agelas_authenticate(&cipher, op->tag, sizeof(op->tag));
	sanctum_mem_zero(&cipher, sizeof(cipher));

	pkt->length = sizeof(*op);
	pkt->target = SANCTUM_PROC_PURGATORY;

	dump("packet", sanctum_packet_head(pkt), pkt->length);

	if (sanctum_ring_queue(io->offer, pkt) == -1)
		sanctum_packet_release(pkt);
}

/*
 * Check if there are any offers on the queue that must be processed.
 */
static void
chapel_offer_decrypt(struct sanctum_packet *pkt, u_int64_t now)
{
	struct sanctum_offer		*op;
	struct nyfe_agelas		cipher;
	u_int8_t			tag[32];

	PRECOND(pkt != NULL);
	PRECOND(io != NULL);

	if (pkt->length != sizeof(*op)) {
		sanctum_packet_release(pkt);
		return;
	}

	printf("got offer\n");

	op = sanctum_packet_head(pkt);

	chapel_offer_kdf(&cipher, op->hdr.seed, sizeof(op->hdr.seed));
	nyfe_agelas_aad(&cipher, &op->hdr, sizeof(op->hdr));
	nyfe_agelas_decrypt(&cipher, &op->data, &op->data, sizeof(op->data));
	nyfe_agelas_authenticate(&cipher, tag, sizeof(tag));
	sanctum_mem_zero(&cipher, sizeof(cipher));

	if (memcmp(op->tag, tag, sizeof(op->tag))) {
		printf("tag mismatch\n");
		sanctum_packet_release(pkt);
		return;
	}

	sanctum_peer_update(pkt);

	op->hdr.spi = be32toh(op->hdr.spi);
	chapel_install(io->tx, op->hdr.spi, op->data.key, sizeof(op->data.key));

	sanctum_packet_release(pkt);
}

/*
 * Install the given key into shared memory so that RX/TX can pick these up.
 */
static void
chapel_install(struct sanctum_key *state, u_int32_t spi, void *key, size_t len)
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
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, seed, seed_len);
	nyfe_kmac256_final(&kdf, okm, sizeof(okm));
	sanctum_mem_zero(&kdf, sizeof(kdf));

	nyfe_agelas_init(cipher, okm, sizeof(okm));
	dump("okm", okm, sizeof(okm));
	sanctum_mem_zero(&okm, sizeof(okm));
}
