/*
 * Copyright (c) 2023-2026 Joris Vink <joris@sanctorum.se>
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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "sanctum.h"

static int	bless_sa_check(void);
static void	bless_drop_access(void);
static int	bless_key_management(void);

static void	bless_packet_tfc(struct sanctum_packet *);
static void	bless_packet_encrypt(struct sanctum_packet *);
static void	bless_packet_process(struct sanctum_packet *);
static void	bless_packet_transfer(struct sanctum_packet *);
static void	bless_packet_protocol(struct sanctum_packet *);
static void	bless_packet_commixtion(struct sanctum_packet *);

/* The local state for TX. */
static struct sanctum_sa	state;

/* The current time. */
static u_int64_t		now = 0;

/* The shared queues. */
static struct sanctum_proc_io	*io = NULL;

/* If we should wakeup SANCTUM_PROC_PURGATORY_TX. */
static int			tx_wakeup = 0;

/*
 * Bless - The process responsible for the blessing of packets coming
 * from the heaven side.
 */
void
sanctum_bless(struct sanctum_proc *proc)
{
	struct sanctum_packet	*pkt;
	int			sig, running;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);

	io = proc->arg;
	bless_drop_access();

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	memset(&state, 0, sizeof(state));

	nyfe_zeroize_register(&state, sizeof(state));
	nyfe_zeroize_register(io->tx, sizeof(*io->tx));

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

		if (sanctum_ring_pending(io->bless) == 0)
			sanctum_proc_suspend(-1);

		now = sanctum_atomic_read(&shared->uptime);

		if (sanctum_key_erase("TX", io->tx, &state, NULL) != -1)
			sanctum_stat_clear(&shared->tx);

		if (sanctum_key_install(io->tx, &state) != -1) {
			sanctum_atomic_write(&shared->holepunch, 1);
			sanctum_atomic_write(&shared->tx.pkt, 0);
			sanctum_atomic_write(&shared->tx.bytes, 0);
			sanctum_atomic_write(&shared->tx.age, now);
			sanctum_atomic_write(&shared->tx.spi, state.spi);
		}

		while ((pkt = sanctum_packet_dequeue(io->bless)))
			bless_packet_process(pkt);

		if (tx_wakeup) {
			tx_wakeup = 0;
			sanctum_proc_wakeup(SANCTUM_PROC_PURGATORY_TX);
		}
	}

	sanctum_sa_clear(&state);

	nyfe_zeroize(&state, sizeof(state));
	nyfe_zeroize(io->tx, sizeof(*io->tx));

	sanctum_config_release();
	sanctum_log(LOG_NOTICE, "exiting");

	nyfe_zeroize_warn();
	nyfe_zeroize_all();

	exit(0);
}

/*
 * Drop access to queues the bless process does not need.
 */
static void
bless_drop_access(void)
{
	(void)close(io->nat);
	(void)close(io->clear);
	(void)close(io->crypto);

	sanctum_shm_detach(io->rx);
	sanctum_shm_detach(io->stx);
	sanctum_shm_detach(io->srx);
	sanctum_shm_detach(io->offer);
	sanctum_shm_detach(io->heaven);
	sanctum_shm_detach(io->chapel);
	sanctum_shm_detach(io->confess);

	io->rx = NULL;
	io->srx = NULL;
	io->stx = NULL;
	io->offer = NULL;
	io->heaven = NULL;
	io->chapel = NULL;
	io->confess = NULL;
}

/*
 * Encrypt a single packet under the current TX key.
 */
static void
bless_packet_process(struct sanctum_packet *pkt)
{
	size_t		overhead;

	PRECOND(pkt != NULL);
	PRECOND(pkt->target == SANCTUM_PROC_BLESS);

	if (bless_key_management() == -1) {
		sanctum_packet_release(pkt);
		return;
	}

	if (bless_sa_check() == -1) {
		sanctum_packet_release(pkt);
		return;
	}

	overhead = sizeof(struct sanctum_proto_hdr) +
	    sizeof(struct sanctum_proto_tail) + SANCTUM_TAG_LENGTH;

	if ((pkt->length + overhead < pkt->length) ||
	    (pkt->length + overhead > SANCTUM_MTU_SIZE_MAX)) {
		sanctum_packet_release(pkt);
		return;
	}

	bless_packet_tfc(pkt);
	bless_packet_protocol(pkt);
	bless_packet_encrypt(pkt);
	bless_packet_commixtion(pkt);
	bless_packet_transfer(pkt);
}

/*
 * Perform any required key management before we use a TX key.
 */
static int
bless_key_management(void)
{
	if (sanctum_key_erase("TX", io->tx, &state, NULL) != -1)
		sanctum_stat_clear(&shared->tx);

	if (sanctum_key_install(io->tx, &state) != -1) {
		sanctum_atomic_write(&shared->holepunch, 1);
		sanctum_atomic_write(&shared->tx.pkt, 0);
		sanctum_atomic_write(&shared->tx.bytes, 0);
		sanctum_atomic_write(&shared->tx.age, now);
		sanctum_atomic_write(&shared->tx.spi, state.spi);
	}

	if (state.cipher == NULL)
		return (-1);

	return (0);
}

/*
 * Check our current SA if its expired or if we have sent too many
 * packets under the same key.
 */
static int
bless_sa_check(void)
{
	if (state.seqnr >= SANCTUM_SA_PACKET_HARD || (now > state.age &&
	    (now - state.age) >= SANCTUM_SA_LIFETIME_HARD)) {
		sanctum_log(LOG_NOTICE,
		    "expired TX SA (seqnr=%" PRIu64 ", age=%" PRIu64 ")",
		    state.seqnr, (now - state.age));
		sanctum_cipher_cleanup(state.cipher);
		state.cipher = NULL;
		sanctum_stat_clear(&shared->tx);
		return (-1);
	}

	if (state.pending) {
		state.pending = 0;
		sanctum_log(LOG_NOTICE, "TX SA active (spi=%08x)", state.spi);
	}

	return (0);
}

/*
 * Apply TFC padding to the packet if required.
 */
static void
bless_packet_tfc(struct sanctum_packet *pkt)
{
	u_int8_t		*data;
	size_t			offset;

	PRECOND(pkt != NULL);

	if (!(sanctum->flags & SANCTUM_FLAG_TFC_ENABLED))
		return;

	if (pkt->length < sanctum->tun_mtu) {
		offset = pkt->length;
		pkt->length = sanctum->tun_mtu;
		data = sanctum_packet_data(pkt);
		nyfe_mem_zero(&data[offset], pkt->length - offset);
	}
}

/*
 * Build the protocol header and trailer for the packet that will be encrypted.
 */
static void
bless_packet_protocol(struct sanctum_packet *pkt)
{
	struct sanctum_proto_hdr	*hdr;
	struct sanctum_proto_tail	*tail;

	PRECOND(pkt != NULL);

	hdr = sanctum_packet_head(pkt);
	tail = sanctum_packet_tail(pkt);

	hdr->pn = state.seqnr++;
	hdr->esp.spi = htobe32(state.spi);
	hdr->esp.seq = htobe32(hdr->pn & 0xffffffff);
	hdr->pn = htobe64(hdr->pn);

	hdr->flock.src = htobe64(sanctum->cathedral_flock);
	hdr->flock.dst = htobe64(sanctum->cathedral_flock_dst);

	tail->reserved = 0;
	tail->next = pkt->type;
	pkt->length += sizeof(*tail);
}

/*
 * Prepare the nonce and AAD and encrypt the packet its contents.
 */
static void
bless_packet_encrypt(struct sanctum_packet *pkt)
{
	struct sanctum_cipher		cipher;
	struct sanctum_proto_hdr	*hdr, aad;
	u_int8_t			nonce[SANCTUM_NONCE_LENGTH];

	PRECOND(pkt != NULL);

	hdr = sanctum_packet_head(pkt);
	memcpy(&aad, hdr, sizeof(*hdr));

	memset(nonce, 0, sizeof(nonce));
	memcpy(nonce, &state.salt, sizeof(state.salt));
	memcpy(&nonce[sizeof(state.salt)], &hdr->pn, sizeof(hdr->pn));

	cipher.aad = &aad;
	cipher.aad_len = sizeof(aad);

	cipher.nonce = nonce;
	cipher.nonce_len = sizeof(nonce);

	cipher.ctx = state.cipher;
	cipher.data_len = pkt->length;

	cipher.pt = sanctum_packet_data(pkt);
	cipher.ct = sanctum_packet_data(pkt);
	cipher.tag = sanctum_packet_tail(pkt);

	sanctum_cipher_encrypt(&cipher);

	VERIFY(pkt->length + SANCTUM_TAG_LENGTH < SANCTUM_MTU_SIZE_MAX);
	pkt->length += SANCTUM_TAG_LENGTH;

	VERIFY(pkt->length + sizeof(*hdr) < SANCTUM_MTU_SIZE_MAX);
	pkt->length += sizeof(*hdr);
}

/*
 * If commixtion is enabled, set the number of hops we will be doing
 * encoded in the packet sequence number.
 */
static void
bless_packet_commixtion(struct sanctum_packet *pkt)
{
	struct sanctum_proto_hdr	*hdr;

	PRECOND(pkt != NULL);

	if (!(sanctum->flags & SANCTUM_FLAG_COMMIXTION))
		return;

	hdr = sanctum_packet_head(pkt);

	hdr->pn = be64toh(hdr->pn);
	hdr->pn |= (u_int64_t)SANCTUM_CATHEDRAL_HOPS << 56;
	hdr->pn = htobe64(hdr->pn);
}

/*
 * Transfer the encrypted packet to purgatory-tx.
 */
static void
bless_packet_transfer(struct sanctum_packet *pkt)
{
	size_t			len;
	struct sanctum_packet	*out;

	PRECOND(pkt != NULL);

	len = pkt->length;

	if ((out = sanctum_packet_transfer(pkt,
	    SANCTUM_PROC_PURGATORY_TX)) == NULL) {
		sanctum_packet_release(pkt);
		return;
	}

	if (sanctum_packet_queue(io->purgatory, out) == -1) {
		sanctum_packet_release(out);
	} else {
		tx_wakeup = 1;
		sanctum_atomic_add(&shared->tx.pkt, 1);
		sanctum_atomic_add(&shared->tx.bytes, len);
		sanctum_atomic_write(&shared->tx.last, shared->uptime);
	}
}
