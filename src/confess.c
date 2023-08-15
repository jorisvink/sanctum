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
#include <sys/socket.h>

#include <netinet/in.h>

#include <poll.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "sanctum.h"

static void	confess_drop_access(void);
static void	confess_keys_install(void);
static void	confess_packet_process(struct sanctum_packet *);
static int	confess_with_slot(struct sanctum_sa *, struct sanctum_packet *);

static int	confess_arwin_check(struct sanctum_sa *,
		    struct sanctum_packet *, struct sanctum_ipsec_hdr *);
static void	confess_arwin_update(struct sanctum_sa *,
		    struct sanctum_packet *, struct sanctum_ipsec_hdr *);

/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/* The local state for RX. */
static struct {
	struct sanctum_sa	slot_1;
	struct sanctum_sa	slot_2;
} state;

/*
 * Confess - The process responsible for the confession of packets coming
 * from the purgatory side.
 */
void
sanctum_confess(struct sanctum_proc *proc)
{
	struct sanctum_packet		*pkt;
	int				sig, running;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);

	io = proc->arg;
	confess_drop_access();

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	memset(&state, 0, sizeof(state));

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

		confess_keys_install();

		while ((pkt = sanctum_ring_dequeue(io->confess)))
			confess_packet_process(pkt);

#if !defined(SANCTUM_HIGH_PERFORMANCE)
		usleep(500);
#endif
	}

	syslog(LOG_NOTICE, "exiting");

	exit(0);
}

/*
 * Drop access to queues the confess process does not need.
 */
static void
confess_drop_access(void)
{
	sanctum_shm_detach(io->tx);
	sanctum_shm_detach(io->bless);
	sanctum_shm_detach(io->offer);
	sanctum_shm_detach(io->chapel);
	sanctum_shm_detach(io->purgatory);

	io->tx = NULL;
	io->bless = NULL;
	io->offer = NULL;
	io->chapel = NULL;
	io->purgatory = NULL;
}

/*
 * Attempt to install any pending keys into the correct slot.
 *
 * Once we have a primary RX key in slot_1, all keys that are
 * pending will be installed under slot_2 first.
 */
static void
confess_keys_install(void)
{
	if (state.slot_1.cipher == NULL) {
		if (sanctum_key_install(io->rx, &state.slot_1) != -1) {
			sanctum_atomic_write(&sanctum->rx.spi,
			    state.slot_1.spi);
			syslog(LOG_NOTICE, "new RX SA (spi=0x%08x)",
			    state.slot_1.spi);
		}
	} else {
		if (sanctum_key_install(io->rx, &state.slot_2) != -1) {
			sanctum_atomic_write(&sanctum->rx_pending,
			    state.slot_2.spi);
			syslog(LOG_NOTICE, "pending RX SA (spi=0x%08x)",
			    state.slot_2.spi);
		}
	}
}

/*
 * Decrypt and verify a single packet under the current RX key, or if
 * that fails and there is a pending key, under the pending RX key.
 *
 * If successfull the packet is sent onto the clear interface.
 * If the pending RX key was used, it becomes the active one.
 */
static void
confess_packet_process(struct sanctum_packet *pkt)
{
	struct sanctum_ipsec_hdr	*hdr;

	PRECOND(pkt != NULL);
	PRECOND(pkt->target == SANCTUM_PROC_CONFESS);

	confess_keys_install();

	if (sanctum_packet_crypto_checklen(pkt) == -1) {
		sanctum_packet_release(pkt);
		return;
	}

	hdr = sanctum_packet_head(pkt);
	hdr->esp.spi = be32toh(hdr->esp.spi);
	hdr->esp.seq = be32toh(hdr->esp.seq);
	hdr->pn = be64toh(hdr->pn);

	if (confess_with_slot(&state.slot_1, pkt) != -1)
		return;

	if (confess_with_slot(&state.slot_2, pkt) == -1) {
		sanctum_packet_release(pkt);
		return;
	}

	sanctum_atomic_write(&sanctum->rx.spi, state.slot_2.spi);
	sanctum_atomic_write(&sanctum->rx_pending, 0);

	syslog(LOG_NOTICE, "swapping RX SA (spi=0x%08x)", state.slot_2.spi);

	state.slot_1.seqnr = 0;
	state.slot_1.bitmap = 0;
	sanctum_atomic_write(&sanctum->last_pn, 0);

	sanctum_cipher_cleanup(state.slot_1.cipher);

	state.slot_1.spi = state.slot_2.spi;
	state.slot_1.salt = state.slot_2.salt;
	state.slot_1.seqnr = state.slot_2.seqnr;
	state.slot_1.cipher = state.slot_2.cipher;

	sanctum_mem_zero(&state.slot_2, sizeof(state.slot_2));
}

/*
 * Attempt to verify and confess a packet using the given SA.
 */
static int
confess_with_slot(struct sanctum_sa *sa, struct sanctum_packet *pkt)
{
	struct sanctum_ipsec_hdr	*hdr;
	struct sanctum_ipsec_tail	*tail;
	u_int8_t			nonce[12], aad[12];

	PRECOND(sa != NULL);
	PRECOND(pkt != NULL);

	if (sa->cipher == NULL)
		return (-1);

	hdr = sanctum_packet_head(pkt);
	if (hdr->esp.spi != sa->spi)
		return (-1);

	if (confess_arwin_check(sa, pkt, hdr) == -1)
		return (-1);

	memcpy(nonce, &sa->salt, sizeof(sa->salt));
	memcpy(&nonce[sizeof(sa->salt)], &hdr->pn, sizeof(hdr->pn));

	memcpy(aad, &sa->spi, sizeof(sa->spi));
	memcpy(&aad[sizeof(sa->spi)], &hdr->pn, sizeof(hdr->pn));

	if (sanctum_cipher_decrypt(sa->cipher, nonce, sizeof(nonce),
	    aad, sizeof(aad), pkt) == -1)
		return (-1);

	confess_arwin_update(sa, pkt, hdr);
	sanctum_peer_update(pkt);

	pkt->length -= sizeof(struct sanctum_ipsec_hdr);
	pkt->length -= sizeof(struct sanctum_ipsec_tail);
	pkt->length -= sanctum_cipher_overhead();

	tail = sanctum_packet_tail(pkt);
	if (tail->pad != 0)
		return (-1);

	if (tail->next == SANCTUM_PKT_HEARTBEAT) {
		sanctum_packet_release(pkt);
		return (0);
	}

	if (tail->next != IPPROTO_IP)
		return (-1);

	/* The packet checks out, it is bound for heaven. */
	pkt->target = SANCTUM_PROC_HEAVEN;
	if (sanctum_ring_queue(io->heaven, pkt) == -1)
		sanctum_packet_release(pkt);

	return (0);
}

/*
 * Check if the given packet was too old, or already seen.
 */
static int
confess_arwin_check(struct sanctum_sa *sa, struct sanctum_packet *pkt,
    struct sanctum_ipsec_hdr *hdr)
{
	u_int64_t	bit;

	PRECOND(sa != NULL);
	PRECOND(pkt != NULL);
	PRECOND(hdr != NULL);

	if ((hdr->pn & 0xffffffff) != hdr->esp.seq)
		return (-1);

	if (hdr->pn > sa->seqnr)
		return (0);

	if (hdr->pn > 0 && SANCTUM_ARWIN_SIZE > sa->seqnr - hdr->pn) {
		bit = (SANCTUM_ARWIN_SIZE - 1) - (sa->seqnr - hdr->pn);
		if (sa->bitmap & ((u_int64_t)1 << bit)) {
			syslog(LOG_INFO,
			    "packet seq=0x%" PRIx64 " already seen", hdr->pn);
			return (-1);
		}
		return (0);
	}

	syslog(LOG_INFO,
	    "packet seq=0x%" PRIx64 " too old", hdr->pn);

	return (-1);
}

/*
 * Update the anti-replay window.
 */
static void
confess_arwin_update(struct sanctum_sa *sa, struct sanctum_packet *pkt,
    struct sanctum_ipsec_hdr *hdr)
{
	u_int64_t	bit;

	PRECOND(sa != NULL);
	PRECOND(pkt != NULL);
	PRECOND(hdr != NULL);

	if (hdr->pn > sa->seqnr) {
		if (hdr->pn - sa->seqnr >= SANCTUM_ARWIN_SIZE) {
			sa->bitmap = ((u_int64_t)1 << 63);
		} else {
			sa->bitmap >>= (hdr->pn - sa->seqnr);
			sa->bitmap |= ((u_int64_t)1 << 63);
		}

		sa->seqnr = hdr->pn;
		sanctum_atomic_write(&sanctum->last_pn, sa->seqnr);
		return;
	}

	if (sa->seqnr < hdr->pn)
		fatal("%s: window corrupt", __func__);

	bit = (SANCTUM_ARWIN_SIZE - 1) - (sa->seqnr - hdr->pn);
	sa->bitmap |= ((u_int64_t)1 << bit);
}
