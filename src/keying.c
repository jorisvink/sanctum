/*
 * Copyright (c) 2023 Joris Vink <joris@coders.se>
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

static void	keying_offer_check(void);
static void	keying_offer_pulse(u_int64_t);
static void	keying_offer_create(u_int64_t);

static void	keying_drop_access(void);
static void	keying_install(struct sanctum_key *, u_int32_t, void *, size_t);


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
sanctum_keying_entry(struct sanctum_proc *proc)
{
	int			sig, running;
	u_int64_t		now, next_keying;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);

	io = proc->arg;
	keying_drop_access();

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	running = 1;
	next_keying = 0;
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

		keying_offer_check();
		now = sanctum_atomic_read(&sanctum->uptime);

		if (offer != NULL && now >= offer->pulse)
			keying_offer_pulse(now);

		if (now >= next_keying) {
			next_keying = now + 120;
			keying_offer_create(now);
		}

		usleep(250000);
	}

	syslog(LOG_NOTICE, "exiting");

	exit(0);
}

/*
 * Drop access to queues that keying does not need.
 */
static void
keying_drop_access(void)
{
	sanctum_shm_detach(io->arwin);
	sanctum_shm_detach(io->clear);
	sanctum_shm_detach(io->crypto);
	sanctum_shm_detach(io->encrypt);
	sanctum_shm_detach(io->decrypt);

	io->clear = NULL;
	io->arwin = NULL;
	io->crypto = NULL;
	io->encrypt = NULL;
	io->decrypt = NULL;
}

/*
 * Create a new RX key and start offering it to the other side.
 *
 * The offer shall continue until the other side sends us a packet
 * encrypted with said key.
 */
static void
keying_offer_create(u_int64_t now)
{
	PRECOND(offer == NULL);

	if (sanctum_atomic_read(&sanctum->peer_ip) == 0)
		return;

	if ((offer = calloc(1, sizeof(*offer))) == NULL)
		fatal("calloc");

	offer->ttl = 2;
	offer->pulse = now + 5;
	offer->spi = 0xdeadbeef;

	printf("creating new RX offer for peer\n");
}

/*
 * Resubmit the current offer to our peer.
 */
static void
keying_offer_pulse(u_int64_t now)
{
	PRECOND(offer != NULL);

	if (offer->ttl == 0) {
		printf("clearing offer, expired\n");
		sanctum_mem_zero(offer, sizeof(*offer));
		free(offer);
		offer = NULL;
		return;
	}

	printf("pulse (%u)\n", offer->ttl);

	offer->ttl--;
	offer->pulse = now + 5;
}

/*
 * Check if there are any offers on the queue that must be processed.
 */
static void
keying_offer_check(void)
{
	struct sanctum_packet	*pkt;
	u_int8_t		key[32];

	PRECOND(io != NULL);

	if ((pkt = sanctum_ring_dequeue(io->key)) == NULL)
		return;

	printf("got offer\n");

	sanctum_packet_release(pkt);

	keying_install(io->rx, 0xdeadbeef, key, sizeof(key));
}

/*
 * Install the given key into shared memory so that RX/TX can pick these up.
 */
static void
keying_install(struct sanctum_key *state, u_int32_t spi, void *key, size_t len)
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
