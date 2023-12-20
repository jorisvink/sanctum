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
#include <limits.h>
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

/* The CATACOMB message magic. */
#define CATHEDRAL_CATACOMB_MAGIC	0x43415441434F4D42

/* The KDF label for the tunnel sync. */
#define CATHEDRAL_CATACOMB_LABEL	"SANCTUM.CATHEDRAL.CATACOMB"

/*
 * A known tunnel and its endpoint, or a federated cathedral.
 */
struct tunnel {
	u_int32_t		id;
	u_int32_t		ip;
	u_int64_t		age;
	u_int16_t		port;
	u_int64_t		pkts;
	LIST_ENTRY(tunnel)	list;
};

static void	cathedral_federation_reload(void);
static void	cathedral_packet_handle(struct sanctum_packet *, u_int64_t);

static void	cathedral_tunnel_expire(u_int64_t);
static void	cathedral_tunnel_federate(struct sanctum_packet *);
static int	cathedral_tunnel_forward(struct sanctum_packet *, u_int32_t);
static void	cathedral_tunnel_update(struct sanctum_packet *,
		    u_int64_t, int);

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
 * Handle an incoming packet. It is one of the following:
 *
 * 1) A tunnel update from a sanctum instance.
 * 2) A CATACOMB message from another cathedral.
 * 3) A normal packet that must be forwarded.
 */
static void
cathedral_packet_handle(struct sanctum_packet *pkt, u_int64_t now)
{
	struct tunnel			*srv;
	struct sanctum_ipsec_hdr	*hdr;
	struct sanctum_offer_hdr	*offer;
	u_int32_t			seq, spi;

	PRECOND(pkt != NULL);

	hdr = sanctum_packet_head(pkt);
	seq = be32toh(hdr->esp.seq);
	spi = be32toh(hdr->esp.spi);

	/* It's a tunnel update message. */
	if ((spi == (SANCTUM_CATHEDRAL_MAGIC >> 32)) &&
	    (seq == (SANCTUM_CATHEDRAL_MAGIC & 0xffffffff))) {
		cathedral_tunnel_update(pkt, now, 0);
		sanctum_packet_release(pkt);
	} else if ((spi == (CATHEDRAL_CATACOMB_MAGIC >> 32)) &&
	    (seq == (CATHEDRAL_CATACOMB_MAGIC & 0xffffffff))) {
		/* It is a catacomb message. */
		LIST_FOREACH(srv, &federations, list) {
			if (srv->ip == pkt->addr.sin_addr.s_addr &&
			    srv->port == pkt->addr.sin_port)
				break;
		}

		if (srv == NULL) {
			sanctum_log(LOG_INFO,
			    "CATACOMB update from unknown cathedral %s:%u",
			    inet_ntoa(pkt->addr.sin_addr),
			    be16toh(pkt->addr.sin_port));
			sanctum_packet_release(pkt);
			return;
		}

		cathedral_tunnel_update(pkt, now, 1);
		sanctum_packet_release(pkt);
	} else {
		/* It is a normal traffic packet. */
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
cathedral_tunnel_update(struct sanctum_packet *pkt, u_int64_t now, int catacomb)
{
	struct timespec			ts;
	int				len;
	u_int32_t			spi;
	struct sanctum_offer		*op;
	struct nyfe_agelas		cipher;
	const char			*label;
	struct tunnel			*tunnel;
	u_int8_t			tag[32];
	char				*secret, path[1024];

	PRECOND(pkt != NULL);

	if (pkt->length != sizeof(*op))
		return;

	op = sanctum_packet_head(pkt);
	spi = be32toh(op->hdr.spi);

	/*
	 * If this is a CATACOMB message, use our own secret, otherwise
	 * we load the secret for the indicated client.
	 */
	if (catacomb) {
		secret = sanctum->secret;
		label = CATHEDRAL_CATACOMB_LABEL;
	} else {
		/* Get path to the key for the sender. */
		len = snprintf(path, sizeof(path), "%s/0x%x.key",
		    sanctum->secretdir, spi);
		if (len == -1 || (size_t)len >= sizeof(path))
			fatal("failed to construct path to secret");
		secret = path;
		label = SANCTUM_CATHEDRAL_KDF_LABEL;
	}

	/* Derive the key we should use. */
	if (sanctum_cipher_kdf(secret, label, &cipher,
	    op->hdr.seed, sizeof(op->hdr.seed)) == -1)
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

	/* The tunnel is is carried in the encrypted payload. */
	op->data.id = be64toh(op->data.id);

	/*
	 * Check if the tunnel exists, if it does we update the endpoint.
	 */
	LIST_FOREACH(tunnel, &tunnels, list) {
		if (tunnel->id == op->data.id) {
			tunnel->age = now;
			tunnel->port = pkt->addr.sin_port;
			tunnel->ip = pkt->addr.sin_addr.s_addr;
			if (catacomb == 0)
				cathedral_tunnel_federate(pkt);
			return;
		}
	}

	/* Nope, we add a new entry instead. */
	if ((tunnel = calloc(1, sizeof(*tunnel))) == NULL)
		fatal("calloc failed");

	tunnel->age = now;
	tunnel->id = op->data.id;
	tunnel->port = pkt->addr.sin_port;
	tunnel->ip = pkt->addr.sin_addr.s_addr;

	LIST_INSERT_HEAD(&tunnels, tunnel, list);

	if (catacomb == 0)
		cathedral_tunnel_federate(pkt);
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
	 * Now check the registered tunnels, we match on the entire id.
	 */
	LIST_FOREACH(tunnel, &tunnels, list) {
		if (tunnel->id == id) {
			tunnel->pkts++;

			pkt->addr.sin_family = AF_INET;
			pkt->addr.sin_port = tunnel->port;
			pkt->addr.sin_addr.s_addr = tunnel->ip;

			pkt->target = SANCTUM_PROC_PURGATORY;
			return (sanctum_ring_queue(io->purgatory, pkt));
		}
	}

	return (-1);
}

/*
 * Send out the given tunnel update and to all federated cathedrals.
 */
static void
cathedral_tunnel_federate(struct sanctum_packet *update)
{
	struct timespec			ts;
	struct sanctum_offer		*op;
	struct sanctum_packet		*pkt;
	u_int8_t			*ptr;
	struct nyfe_agelas		cipher;
	struct tunnel			*tunnel;

	PRECOND(update != NULL);

	if (update->length != sizeof(*op))
		fatal("%s: pkt length invalid (%zu)", __func__, update->length);

	op = sanctum_packet_head(update);

	/* Set header to our own. */
	op->hdr.magic = htobe64(CATHEDRAL_CATACOMB_MAGIC);
	nyfe_random_bytes(op->hdr.seed, sizeof(op->hdr.seed));

	/* Derive the key we should use. */
	if (sanctum_cipher_kdf(sanctum->secret, CATHEDRAL_CATACOMB_LABEL,
	    &cipher, op->hdr.seed, sizeof(op->hdr.seed)) == -1)
		return;

	/* Update in the current timestamp. */
	(void)clock_gettime(CLOCK_REALTIME, &ts);
	op->data.timestamp = htobe64((u_int64_t)ts.tv_sec);

	/* Make sure we revert the data.id back. */
	op->data.id = htobe64(op->data.id);

	/* Encrypt and authenticate entire message. */
	nyfe_agelas_aad(&cipher, &op->hdr, sizeof(op->hdr));
	nyfe_agelas_encrypt(&cipher, &op->data, &op->data, sizeof(op->data));
	nyfe_agelas_authenticate(&cipher, op->tag, sizeof(op->tag));
	sanctum_mem_zero(&cipher, sizeof(cipher));

	/* Submit it to each federated cathedral. */
	LIST_FOREACH(tunnel, &federations, list) {
		if ((pkt = sanctum_packet_get()) == NULL) {
			sanctum_log(LOG_NOTICE,
			    "no CATACOMB update possible, out of packets");
			return;
		}

		ptr = sanctum_packet_head(pkt);
		memcpy(ptr, op, sizeof(*op));

		pkt->length = sizeof(*op);
		pkt->target = SANCTUM_PROC_PURGATORY;

		pkt->addr.sin_family = AF_INET;
		pkt->addr.sin_port = tunnel->port;
		pkt->addr.sin_addr.s_addr = tunnel->ip;

		if (sanctum_ring_queue(io->purgatory, pkt) == -1) {
			sanctum_log(LOG_NOTICE,
			    "no CATACOMB update possible, failed to queue");
			sanctum_packet_release(pkt);
		}
	}
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

		if (sscanf(option, "%15s %hu", ip, &port) != 2) {
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

		tunnel->port = htobe16(port);
		tunnel->ip = sin.sin_addr.s_addr;

		LIST_INSERT_HEAD(&federations, tunnel, list);

		sanctum_log(LOG_INFO, "federation: %s:%u", ip, port);
	}

	sanctum_log(LOG_INFO, "federation reload");

	(void)fclose(fp);
}
