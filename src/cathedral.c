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

/* The half-time window in which offers are valid. */
#define CATHEDRAL_REG_VALID		5

/* The maximum age in seconds for a cached tunnel entry. */
#define CATHEDRAL_TUNNEL_MAX_AGE	30

/*
 * A known tunnel and its endpoint.
 */
struct tunnel {
	u_int32_t		id;
	u_int32_t		ip;
	u_int64_t		age;
	u_int16_t		port;
	LIST_ENTRY(tunnel)	list;
};

static void	cathedral_federation_reload(void);
static void	cathedral_packet_handle(struct sanctum_packet *, u_int64_t);

static void	cathedral_tunnel_expire(u_int64_t);
static int	cathedral_tunnel_forward(struct sanctum_packet *, u_int32_t);
static void	cathedral_tunnel_register(struct sanctum_packet *, u_int64_t);

/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/* The list of tunnels we know. */
static LIST_HEAD(, tunnel)	tunnels;

/* The list of federation cathedrals we can forward too. */
static LIST_HEAD(, tunnel)	federations;

/*
 * Cathedral - The place packets all meet and get exchanged.
 *
 * When running as a cathedral, we receive packets immediately
 * from the purgatory side. We check if we know the tunnel encoded inside
 * of the esp header and forward the packet to the correct endpoint.
 */
void
sanctum_cathedral(struct sanctum_proc *proc)
{
	struct sanctum_packet	*pkt;
	u_int64_t		now, next_expire;
	int			sig, running, suspend;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);
	PRECOND(sanctum->mode == SANCTUM_MODE_CATHEDRAL);

	nyfe_random_init();
	io = proc->arg;

	sanctum_signal_trap(SIGHUP);
	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	LIST_INIT(&tunnels);
	LIST_INIT(&federations);

	sanctum_proc_privsep(proc);
	sanctum_platform_sandbox(proc);
	cathedral_federation_reload();

	running = 1;
	suspend = 0;
	next_expire = 0;

	while (running) {
		if ((sig = sanctum_last_signal()) != -1) {
			sanctum_log(LOG_NOTICE, "received signal %d", sig);
			switch (sig) {
			case SIGQUIT:
				running = 0;
				continue;
			case SIGHUP:
				cathedral_federation_reload();
				break;
			}
		}

		now = sanctum_atomic_read(&sanctum->uptime);

		if (now >= next_expire) {
			next_expire = now + 10;
			cathedral_tunnel_expire(now);
		}

		if (sanctum_ring_pending(io->chapel)) {
			suspend = 0;
			while ((pkt = sanctum_ring_dequeue(io->chapel)))
				cathedral_packet_handle(pkt, now);
		} else {
			if (suspend < 500)
				suspend++;
		}

		if (sanctum_ring_pending(io->chapel) == 0)
			usleep(suspend * 10);
	}

	sanctum_log(LOG_NOTICE, "exiting");

	exit(0);
}

/*
 * Handle an incoming packet, it may be either a tunnel registration
 * or a packet we have to forward somewhere.
 */
static void
cathedral_packet_handle(struct sanctum_packet *pkt, u_int64_t now)
{
	struct sanctum_ipsec_hdr	*hdr;
	struct sanctum_offer_hdr	*offer;
	u_int32_t			seq, spi;

	PRECOND(pkt != NULL);

	hdr = sanctum_packet_head(pkt);
	seq = be32toh(hdr->esp.seq);
	spi = be32toh(hdr->esp.spi);

	if ((spi == (SANCTUM_CATHEDRAL_MAGIC >> 32)) &&
	    (seq == (SANCTUM_CATHEDRAL_MAGIC & 0xffffffff))) {
		cathedral_tunnel_register(pkt, now);
		sanctum_packet_release(pkt);
	} else {
		if ((spi == (SANCTUM_KEY_OFFER_MAGIC >> 32)) &&
		    (seq == (SANCTUM_KEY_OFFER_MAGIC & 0xffffffff))) {
			if (pkt->length < sizeof(struct sanctum_offer_hdr)) {
				sanctum_packet_release(pkt);
				return;
			}

			offer = sanctum_packet_head(pkt);
			spi = be32toh(offer->spi);

			/* Swap src and dst in the spi. */
			spi = (u_int32_t)(be16toh(spi >> 16)) << 16 |
			    (spi & 0x0000ffff);
		}

		if (cathedral_tunnel_forward(pkt, spi) == -1)
			sanctum_packet_release(pkt);
	}
}

/*
 * Attempt to decrypt a tunnel registration, if successfull either
 * create a new tunnel entry or update an existing one.
 */
static void
cathedral_tunnel_register(struct sanctum_packet *pkt, u_int64_t now)
{
	struct timespec			ts;
	int				len;
	u_int32_t			spi;
	struct sanctum_offer		*op;
	struct nyfe_agelas		cipher;
	struct tunnel			*tunnel;
	u_int8_t			tag[32];
	char				secret[1024];

	PRECOND(pkt != NULL);

	if (pkt->length != sizeof(*op))
		return;

	op = sanctum_packet_head(pkt);
	spi = be32toh(op->hdr.spi);

	/* Get path to the key for the sender. */
	len = snprintf(secret, sizeof(secret), "%s/0x%02x.key",
	    sanctum->secretdir, spi >> 8);
	if (len == -1 || (size_t)len >= sizeof(secret))
		fatal("failed to construct path to secret");

	/* Derive the key we should use. */
	if (sanctum_cipher_kdf(secret, SANCTUM_CATHEDRAL_KDF_LABEL,
	    &cipher, op->hdr.seed, sizeof(op->hdr.seed)) == -1)
		return;

	/* Decrypt and verify the integrity of the offer first. */
	nyfe_agelas_aad(&cipher, &op->hdr, sizeof(op->hdr));
	nyfe_agelas_decrypt(&cipher, &op->data, &op->data, sizeof(op->data));
	nyfe_agelas_authenticate(&cipher, tag, sizeof(tag));
	sanctum_mem_zero(&cipher, sizeof(cipher));

	if (memcmp(op->tag, tag, sizeof(op->tag)))
		return;

	/* Make sure the offer isn't too old. */
	(void)clock_gettime(CLOCK_REALTIME, &ts);
	op->data.timestamp = be64toh(op->data.timestamp);

	if (op->data.timestamp < ((u_int64_t)ts.tv_sec - CATHEDRAL_REG_VALID) ||
	    op->data.timestamp > ((u_int64_t)ts.tv_sec + CATHEDRAL_REG_VALID))
		return;

	/* The spi is specified in both the header and payload. */
	op->data.id = be64toh(op->data.id);
	if (spi != op->data.id)
		return;

	/*
	 * We do not accept registrations for anything that is
	 * supposed to be federated.
	 */
	LIST_FOREACH(tunnel, &federations, list) {
		if (tunnel->id == (spi >> 8))
			return;
	}

	/*
	 * Check if the tunnel exists, if it does we update the endpoint.
	 */
	LIST_FOREACH(tunnel, &tunnels, list) {
		if (tunnel->id == spi) {
			tunnel->age = now;
			tunnel->port = pkt->addr.sin_port;
			tunnel->ip = pkt->addr.sin_addr.s_addr;
			return;
		}
	}

	/* Nope, we add a new entry instead. */
	if ((tunnel = calloc(1, sizeof(*tunnel))) == NULL)
		fatal("calloc failed");

	tunnel->id = spi;
	tunnel->age = now;
	tunnel->port = pkt->addr.sin_port;
	tunnel->ip = pkt->addr.sin_addr.s_addr;

	LIST_INSERT_HEAD(&tunnels, tunnel, list);
}

/*
 * Forward the given packet to the correct tunnel endpoint.
 */
static int
cathedral_tunnel_forward(struct sanctum_packet *pkt, u_int32_t spi)
{
	u_int16_t		id;
	struct tunnel		*tunnel;

	PRECOND(pkt != NULL);

	id = spi >> 16;

	/*
	 * Check the federations first, we unconditionally forward
	 * packets matching the recipient to these.
	 *
	 * We only match on the recipient.
	 */
	LIST_FOREACH(tunnel, &federations, list) {
		if (tunnel->id == (id >> 8)) {
			pkt->target = SANCTUM_PROC_PURGATORY;

			pkt->addr.sin_family = AF_INET;
			pkt->addr.sin_port = tunnel->port;
			pkt->addr.sin_addr.s_addr = tunnel->ip;

			return (sanctum_ring_queue(io->purgatory, pkt));
		}
	}

	/*
	 * Now check the registered tunnels, we match on the entire id.
	 */
	LIST_FOREACH(tunnel, &tunnels, list) {
		if (tunnel->id == id) {
			pkt->target = SANCTUM_PROC_PURGATORY;

			pkt->addr.sin_family = AF_INET;
			pkt->addr.sin_port = tunnel->port;
			pkt->addr.sin_addr.s_addr = tunnel->ip;

			return (sanctum_ring_queue(io->purgatory, pkt));
		}
	}

	return (-1);
}

/*
 * Expire tunnels that are too old and remove them from the known list.
 */
static void
cathedral_tunnel_expire(u_int64_t now)
{
	struct tunnel	*tunnel, *next;

	for (tunnel = LIST_FIRST(&tunnels); tunnel != NULL; tunnel = next) {
		next = LIST_NEXT(tunnel, list);

		if ((now - tunnel->age) >= CATHEDRAL_TUNNEL_MAX_AGE) {
			LIST_REMOVE(tunnel, list);
			free(tunnel);
		}
	}
}

/*
 * Reload the federation rules from disk, if they exist.
 */
static void
cathedral_federation_reload(void)
{
	u_int8_t		id;
	struct sockaddr_in	sin;
	FILE			*fp;
	u_int16_t		port;
	struct tunnel		*tunnel;
	char			buf[256], *option;
	char			ip[INET_ADDRSTRLEN];

	if (sanctum->federation == NULL)
		return;

	if ((fp = fopen(sanctum->federation, "r")) == NULL) {
		sanctum_log(LOG_NOTICE, "failed to open '%s': %s",
		    sanctum->federation, errno_s);
		return;
	}

	while ((tunnel = LIST_FIRST(&federations)) != NULL) {
		LIST_REMOVE(tunnel, list);
		free(tunnel);
	}

	LIST_INIT(&federations);

	while ((option = sanctum_config_read(fp, buf, sizeof(buf))) != NULL) {
		if (strlen(option) == 0)
			continue;

		if (sscanf(option, "0x%02hhx %15s %hu", &id, ip, &port) != 3) {
			sanctum_log(LOG_NOTICE,
			    "format error '%s' in federation config", option);
			continue;
		}

		if (inet_pton(AF_INET, ip, &sin.sin_addr) == -1) {
			sanctum_log(LOG_NOTICE,
			    "invalid ip address '%s' in federation config", ip);
			continue;
		}

		if ((tunnel = calloc(1, sizeof(*tunnel))) == NULL)
			fatal("calloc: failed to allocate federation");

		tunnel->id = id;
		tunnel->port = htobe16(port);
		tunnel->ip = sin.sin_addr.s_addr;

		LIST_INSERT_HEAD(&federations, tunnel, list);

		sanctum_log(LOG_INFO,
		    "federation: 0x%02x -> %s:%u", id, ip, port);
	}

	sanctum_log(LOG_INFO, "federation reload");

	(void)fclose(fp);
}
