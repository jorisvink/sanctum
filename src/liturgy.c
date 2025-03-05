/*
 * Copyright (c) 2025 Joris Vink <joris@sanctorum.se>
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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include "sanctum.h"
#include "libnyfe.h"

static void	liturgy_bishop_inform(u_int8_t, int);

static void	liturgy_offer_send(void);
static void	liturgy_offer_recv(struct sanctum_packet *, u_int64_t);

/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/* Our own id for tunnel mapping. */
static u_int16_t		local_id;

/*
 * Liturgy - Automatic tunnel discovery via cathedrals.
 *
 * This process will periodically send out liturgy offers to its configured
 * cathedral and receive peer discover/timeout events in response.
 *
 * Based on the liturgy, the bishop process will instantiate new
 * sanctum instances for the tunnels that need to be online.
 */
void
sanctum_liturgy(struct sanctum_proc *proc)
{
	struct sanctum_packet	*pkt;
	int			sig, running;
	u_int64_t		now, next_liturgy;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);
	PRECOND(sanctum->mode == SANCTUM_MODE_LITURGY);

	nyfe_random_init();
	io = proc->arg;

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	sanctum_proc_privsep(proc);
	sanctum_platform_sandbox(proc);

	running = 1;
	next_liturgy = 0;
	local_id = sanctum->tun_spi & 0xff;

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

		if (now >= next_liturgy) {
			next_liturgy = now + 5;
			liturgy_offer_send();
		}

		while ((pkt = sanctum_ring_dequeue(io->chapel))) {
			liturgy_offer_recv(pkt, now);
			sanctum_packet_release(pkt);
		}
	}

	sanctum_log(LOG_NOTICE, "exiting");

	exit(0);
}

/*
 * Send a liturgy request to the cathedral. This will automatically put
 * us on the list of liturgies for our flock and in response we will get
 * a liturgy message back containing a list of all current peers.
 */
static void
liturgy_offer_send(void)
{
	struct sanctum_offer		*op;
	struct sanctum_packet		*pkt;
	struct sanctum_liturgy_offer	*lit;
	struct nyfe_agelas		cipher;

	if ((pkt = sanctum_packet_get()) == NULL)
		return;

	op = sanctum_offer_init(pkt, sanctum->cathedral_id,
	    SANCTUM_CATHEDRAL_LITURGY_MAGIC, SANCTUM_OFFER_TYPE_LITURGY);
	op->hdr.flock = htobe64(sanctum->cathedral_flock);

	lit = &op->data.offer.liturgy;
	lit->id = local_id;

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
	pkt->addr.sin_port = sanctum->cathedral.sin_port;
	pkt->addr.sin_addr.s_addr = sanctum->cathedral.sin_addr.s_addr;

	if (sanctum_ring_queue(io->purgatory, pkt) == -1)
		sanctum_packet_release(pkt);
	else
		sanctum_proc_wakeup(SANCTUM_PROC_PURGATORY_TX);
}

/*
 * Handle the cathedral its response to our liturgy request.
 */
static void
liturgy_offer_recv(struct sanctum_packet *pkt, u_int64_t now)
{
	u_int8_t			id;
	struct sanctum_offer		*op;
	struct sanctum_liturgy_offer	*lit;
	struct nyfe_agelas		cipher;

	if (pkt->length < sizeof(*op))
		return;

	op = sanctum_packet_head(pkt);
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	if (sanctum_cipher_kdf(sanctum->cathedral_secret,
	    SANCTUM_CATHEDRAL_KDF_LABEL, &cipher,
	    op->hdr.seed, sizeof(op->hdr.seed)) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		return;
	}

	if (sanctum_offer_decrypt(&cipher, op, SANCTUM_OFFER_VALID) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		return;
	}

	nyfe_zeroize(&cipher, sizeof(cipher));

	op->hdr.spi = be32toh(op->hdr.spi);
	if (op->hdr.spi != sanctum->cathedral_id)
		return;

	if (op->data.type != SANCTUM_OFFER_TYPE_LITURGY)
		return;

	lit = &op->data.offer.liturgy;
	for (id = 0; id < SANCTUM_PEERS_PER_FLOCK; id++) {
		if (id == local_id)
			continue;

		if (lit->peers[id] != 0 && lit->peers[id] != 1) {
			sanctum_log(LOG_INFO, "cathedral sent bad data");
			continue;
		}

		liturgy_bishop_inform(id, lit->peers[id]);
	}

	sanctum_proc_wakeup(SANCTUM_PROC_BISHOP);
}

/*
 * Inform the bishop about a tunnel instance that should be put into the
 * given state. The bishop will, as the privileged process, do the thing.
 */
static void
liturgy_bishop_inform(u_int8_t id, int present)
{
	struct sanctum_packet	*pkt;
	struct sanctum_liturgy	*info;

	PRECOND(id != local_id);
	PRECOND(present == 0 || present == 1);

	if ((pkt = sanctum_packet_get()) == NULL)
		return;

	info = sanctum_packet_head(pkt);

	info->present = present;
	info->instance = (local_id << 8) | id;

	pkt->length = sizeof(*info);
	pkt->target = SANCTUM_PROC_BISHOP;

	if (sanctum_ring_queue(io->bishop, pkt) == -1)
		sanctum_packet_release(pkt);
}
