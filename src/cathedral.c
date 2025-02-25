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

/* The half-time window in which offers are valid. */
#define CATHEDRAL_REG_VALID		5

/* The maximum age in seconds for a cached tunnel entry. */
#define CATHEDRAL_TUNNEL_MAX_AGE	(30 * 1000)

/* The interval at which we check for expired tunnel entries. */
#define CATHEDRAL_TUNNEL_EXPIRE_NEXT	(10 * 1000)

/* The interval at which we check if settings changed. */
#define CATHEDRAL_SETTINGS_RELOAD_NEXT	(10 * 1000)

/* The CATACOMB message magic. */
#define CATHEDRAL_CATACOMB_MAGIC	0x43415441434F4D42

/* The KDF label for the tunnel sync. */
#define CATHEDRAL_CATACOMB_LABEL	"SANCTUM.CATHEDRAL.CATACOMB"

/* The length of an ambry bundle. */
#define CATHEDRAL_AMBRY_BUNDLE_LEN	8486416

/*
 * A known tunnel and its endpoint, or a federated cathedral.
 */
struct tunnel {
	/* tunnel information. */
	u_int32_t		id;
	u_int32_t		ip;
	u_int64_t		age;
	u_int16_t		port;
	int			natseen;
	int			peerinfo;
	int			federated;

	/* leaky bucket for bw handling. */
	u_int32_t		limit;
	u_int32_t		current;
	u_int64_t		last_drain;
	u_int32_t		drain_per_ms;

	LIST_ENTRY(tunnel)	list;
};

/*
 * A mapping of a secret key id that is used by an endpoint to send us
 * updates and the spis they are allowed to send updates for.
 */
struct allow {
	u_int32_t		id;
	u_int32_t		bw;
	u_int8_t		spi;
	LIST_ENTRY(allow)	list;
};

/*
 * An ambry that can be given to a client.
 */
struct ambry {
	struct sanctum_ambry_entry	entry;
	LIST_ENTRY(ambry)		list;
};

/*
 * A flock is a group of clients that can talk to each other via the
 * cathedral.
 */
struct flockent {
	u_int64_t		id;
	int			retain;
	time_t			ambry_mtime;
	u_int32_t		ambry_generation;
	LIST_HEAD(, allow)	allows;
	LIST_HEAD(, tunnel)	tunnels;
	LIST_HEAD(, ambry)	ambries;
	LIST_ENTRY(flockent)	list;
};

static u_int64_t	cathedral_ms(void);
static struct flockent	*cathedral_flock_lookup(u_int64_t);
static struct tunnel	*cathedral_tunnel_lookup(struct flockent *, u_int16_t);

static void	cathedral_flock_allows_clear(struct flockent *);
static void	cathedral_flock_tunnels_clear(struct flockent *);
static void	cathedral_flock_ambries_clear(struct flockent *);
static void	cathedral_packet_handle(struct sanctum_packet *, u_int64_t);

static void	cathedral_secret_path(char *, size_t, u_int64_t, u_int32_t);
static int	cathedral_offer_send(const char *, struct sanctum_packet *,
		    struct sockaddr_in *);

static void	cathedral_settings_reload(void);
static void	cathedral_settings_federate(const char *);
static void	cathedral_settings_allow(const char *, struct flockent *);
static void	cathedral_settings_ambry(const char *, struct flockent *);
static void	cathedral_settings_flock(const char *, struct flockent **);

static void	cathedral_ambry_send(struct flockent *,
		    struct sanctum_info_offer *, struct sockaddr_in *,
		    u_int32_t);
static void	cathedral_info_send(struct flockent *,
		    struct sanctum_info_offer *, struct sockaddr_in *,
		    u_int32_t, int);

static void	cathedral_tunnel_expire(u_int64_t);
static void	cathedral_tunnel_prune(struct flockent *);
static void	cathedral_tunnel_federate(struct flockent *,
		    struct sanctum_packet *);

static int	cathedral_tunnel_forward(struct sanctum_packet *,
		    int, u_int32_t, u_int64_t);
static void	cathedral_tunnel_update(struct sanctum_packet *,
		    u_int64_t, int, int);
static int	cathedral_tunnel_update_valid(struct flockent *,
		    struct sanctum_offer *, u_int32_t, int);
static int	cathedral_tunnel_update_allowed(struct flockent *,
		    struct sanctum_info_offer *, u_int32_t, u_int32_t *);

/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/* The list of federation cathedrals we can forward too. */
static LIST_HEAD(, tunnel)	federations;

/* The list of configured flocks (congregations). */
static LIST_HEAD(, flockent)	flocks;

/* The last modified time of the settings file. */
static time_t			settings_last_mtime = -1;

/*
 * Cathedral - The place packets all meet and get exchanged.
 *
 * When running as a cathedral, we receive packets immediately
 * from the purgatory side. We check if we know the tunnel encoded inside
 * of the esp header and forward the packet to the correct endpoint.
 *
 * The cathedral can also send the endpoint its ambry for the tunnel.
 *
 * Note that the cathedral will use 2 listening sockets, io->crypto and
 * the io->cathedral one. This is done for NAT-type detection.
 */
void
sanctum_cathedral(struct sanctum_proc *proc)
{
	struct sanctum_packet	*pkt;
	int			sig, running;
	u_int64_t		now, next_expire, next_settings;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);
	PRECOND(sanctum->mode == SANCTUM_MODE_CATHEDRAL);

	nyfe_random_init();
	io = proc->arg;

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	LIST_INIT(&flocks);
	LIST_INIT(&federations);

	sanctum_proc_privsep(proc);
	sanctum_platform_sandbox(proc);
	cathedral_settings_reload();

	running = 1;
	next_expire = 0;
	next_settings = 0;

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
		now = cathedral_ms();

		if (now >= next_settings) {
			next_settings = now + CATHEDRAL_SETTINGS_RELOAD_NEXT;
			cathedral_settings_reload();
		}

		if (now >= next_expire) {
			next_expire = now + CATHEDRAL_TUNNEL_EXPIRE_NEXT;
			cathedral_tunnel_expire(now);
		}

		while ((pkt = sanctum_ring_dequeue(io->chapel)))
			cathedral_packet_handle(pkt, now);
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
	int				exchange;
	u_int32_t			seq, spi;

	PRECOND(pkt != NULL);

	hdr = sanctum_packet_head(pkt);
	seq = be32toh(hdr->esp.seq);
	spi = be32toh(hdr->esp.spi);

	if ((spi == (SANCTUM_CATHEDRAL_MAGIC >> 32)) &&
	    (seq == (SANCTUM_CATHEDRAL_MAGIC & 0xffffffff))) {
		cathedral_tunnel_update(pkt, now, 0, 0);
		sanctum_packet_release(pkt);
	} else if ((spi == (SANCTUM_CATHEDRAL_NAT_MAGIC >> 32)) &&
	    (seq == (SANCTUM_CATHEDRAL_NAT_MAGIC & 0xffffffff))) {
		cathedral_tunnel_update(pkt, now, 1, 0);
		sanctum_packet_release(pkt);
	} else if ((spi == (CATHEDRAL_CATACOMB_MAGIC >> 32)) &&
	    (seq == (CATHEDRAL_CATACOMB_MAGIC & 0xffffffff))) {
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

		cathedral_tunnel_update(pkt, now, 0, 1);
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

			/*
			 * We have to swap src and dst in the spi for
			 * the forward to work here.
			 */
			spi = (u_int32_t)(be16toh(spi >> 16)) << 16 |
			    (spi & 0x0000ffff);

			/*
			 * Indicate this is an exchange so it does not
			 * get thrown away by the bandwidth limiter.
			 */
			exchange = 1;
		} else {
			exchange = 0;
		}

		if (cathedral_tunnel_forward(pkt, exchange, spi, now) == -1)
			sanctum_packet_release(pkt);
	}
}

/*
 * Attempt to decrypt a tunnel registration, if successfull either
 * create a new tunnel entry or update an existing one.
 */
static void
cathedral_tunnel_update(struct sanctum_packet *pkt, u_int64_t now,
    int nat, int catacomb)
{
	u_int64_t			fid;
	struct sanctum_offer		*op;
	struct tunnel			*tun;
	struct sanctum_info_offer	*info;
	struct flockent			*flock;
	u_int32_t			id, bw;

	PRECOND(pkt != NULL);

	if (pkt->length < sizeof(*op))
		return;

	op = sanctum_packet_head(pkt);
	id = be32toh(op->hdr.spi);
	fid = be64toh(op->hdr.flock);

	if ((flock = cathedral_flock_lookup(fid)) == NULL)
		return;

	if (cathedral_tunnel_update_valid(flock, op, id, catacomb) == -1)
		return;

	info = &op->data.offer.info;
	info->tunnel = be16toh(info->tunnel);
	info->ambry_generation = be32toh(info->ambry_generation);

	if (cathedral_tunnel_update_allowed(flock, info, id, &bw) == -1)
		return;

	if ((tun = cathedral_tunnel_lookup(flock, info->tunnel)) == NULL) {
		if ((tun = calloc(1, sizeof(*tun))) == NULL)
			fatal("calloc failed");

		tun->limit = (bw / 8) * 1024 * 1024;
		tun->drain_per_ms = tun->limit / 1000;

		LIST_INSERT_HEAD(&flock->tunnels, tun, list);
		sanctum_log(LOG_INFO, "tunnel 0x%04x discovered (%u mbit/sec)",
		    info->tunnel, bw);
	 }

	if (catacomb == 0 && nat == 0) {
		cathedral_ambry_send(flock, info, &pkt->addr, id);
		cathedral_info_send(flock, info, &pkt->addr, id, tun->peerinfo);
	}

	if (tun->natseen) {
		if ((tun->ip == pkt->addr.sin_addr.s_addr &&
		    tun->port != pkt->addr.sin_port) ||
		    tun->ip != pkt->addr.sin_addr.s_addr) {
			tun->peerinfo = 0;
		} else {
			tun->peerinfo = 1;
		}
	}

	if (nat) {
		tun->natseen = 1;
	} else {
		tun->age = now;
		tun->id = info->tunnel;
		tun->port = pkt->addr.sin_port;
		tun->ip = pkt->addr.sin_addr.s_addr;

		if (catacomb == 0)
			cathedral_tunnel_federate(flock, pkt);
		else
			tun->federated = 1;
	}
}

/*
 * Verify and decrypt an info offer we received from a potential client
 * or from another cathedral we federate with.
 */
static int
cathedral_tunnel_update_valid(struct flockent *flock, struct sanctum_offer *op,
    u_int32_t id, int cb)
{
	struct nyfe_agelas	cipher;
	const char		*label;
	char			*secret, path[1024];

	PRECOND(flock != NULL);
	PRECOND(op != NULL);

	if (cb) {
		secret = sanctum->secret;
		label = CATHEDRAL_CATACOMB_LABEL;
	} else {
		cathedral_secret_path(path, sizeof(path), flock->id, id);
		secret = path;
		label = SANCTUM_CATHEDRAL_KDF_LABEL;
	}

	nyfe_zeroize_register(&cipher, sizeof(cipher));

	if (sanctum_cipher_kdf(secret, label, &cipher,
	    op->hdr.seed, sizeof(op->hdr.seed)) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		return (-1);
	}

	if (sanctum_offer_decrypt(&cipher, op, SANCTUM_OFFER_VALID) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		return (-1);
	}

	nyfe_zeroize(&cipher, sizeof(cipher));

	if (op->data.type != SANCTUM_OFFER_TYPE_INFO)
		return (-1);

	return (0);
}

/*
 * Check if a given combination of key id and spi are allowed to
 * update the connection information for the given tunnel.
 */
static int
cathedral_tunnel_update_allowed(struct flockent *flock,
    struct sanctum_info_offer *info, u_int32_t id, u_int32_t *bw)
{
	struct allow		*allow;

	PRECOND(flock != NULL);
	PRECOND(info != NULL);
	PRECOND(bw != NULL);

	LIST_FOREACH(allow, &flock->allows, list) {
		if (allow->id == id && (allow->spi == info->tunnel >> 8)) {
			*bw = allow->bw;
			return (0);
		}
	}

	return (-1);
}

/*
 * Forward the given packet to the correct tunnel endpoint if possible.
 * We do not check the bandwidth limiter if the packet contained in pkt
 * is an actual key offer for an exchange.
 */
static int
cathedral_tunnel_forward(struct sanctum_packet *pkt, int exchange,
    u_int32_t spi, u_int64_t now)
{
	u_int16_t		id;
	u_int32_t		drain;
	u_int64_t		delta;
	struct flockent		*flock;
	struct tunnel		*tunnel;

	PRECOND(pkt != NULL);
	PRECOND(exchange == 0 || exchange == 1);

	id = spi >> 16;

	/* XXX - very much not optimal. */
	LIST_FOREACH(flock, &flocks, list) {
		LIST_FOREACH(tunnel, &flock->tunnels, list) {
			if (tunnel->ip == pkt->addr.sin_addr.s_addr &&
			    tunnel->port == pkt->addr.sin_port)
				break;
		}

		if (tunnel != NULL)
			break;
	}

	if (flock == NULL)
		return (-1);

	LIST_FOREACH(tunnel, &flock->tunnels, list) {
		if (tunnel->id != id)
			continue;
		break;
	}

	if (tunnel == NULL)
		return (-1);

	if (tunnel->limit != 0) {
		delta = now - tunnel->last_drain;
		if (delta >= 1) {
			tunnel->last_drain = now;
			drain = tunnel->drain_per_ms * delta;
			if (drain <= tunnel->current) {
				tunnel->current -= drain;
			} else {
				tunnel->current = 0;
			}
		}

		if (exchange == 0 && tunnel->current >= tunnel->limit)
			return (-1);

		tunnel->current += pkt->length;
	}

	pkt->addr.sin_family = AF_INET;
	pkt->addr.sin_port = tunnel->port;
	pkt->addr.sin_addr.s_addr = tunnel->ip;

	pkt->target = SANCTUM_PROC_PURGATORY_TX;

	if (sanctum_ring_queue(io->purgatory, pkt) == -1)
		return (-1);

	sanctum_proc_wakeup(SANCTUM_PROC_PURGATORY_TX);
	return (0);
}

/*
 * Send out the given tunnel update to all federated cathedrals.
 */
static void
cathedral_tunnel_federate(struct flockent *flock, struct sanctum_packet *update)
{
	struct sanctum_offer		*op;
	struct sanctum_packet		*pkt;
	u_int8_t			*ptr;
	struct sanctum_info_offer	*info;
	struct nyfe_agelas		cipher;
	struct tunnel			*tunnel;

	PRECOND(flock != NULL);
	PRECOND(update != NULL);

	if (update->length < sizeof(*op))
		fatal("%s: pkt length invalid (%zu)", __func__, update->length);

	/*
	 * We update the information in place with a new magic field,
	 * a new seed and a new timestamp.
	 *
	 * This is then re-encrypted with our synchronization key and
	 * sent to all cathedrals that are configured.
	 */
	op = sanctum_packet_head(update);
	op = sanctum_offer_init(update, be32toh(op->hdr.spi),
	    CATHEDRAL_CATACOMB_MAGIC, op->data.type);

	op->hdr.flock = htobe64(flock->id);

	info = &op->data.offer.info;
	info->tunnel = htobe16(info->tunnel);

	nyfe_zeroize_register(&cipher, sizeof(cipher));
	if (sanctum_cipher_kdf(sanctum->secret, CATHEDRAL_CATACOMB_LABEL,
	    &cipher, op->hdr.seed, sizeof(op->hdr.seed)) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		return;
	}

	sanctum_offer_encrypt(&cipher, op);
	nyfe_zeroize(&cipher, sizeof(cipher));

	LIST_FOREACH(tunnel, &federations, list) {
		if ((pkt = sanctum_packet_get()) == NULL) {
			sanctum_log(LOG_NOTICE,
			    "no CATACOMB update possible, out of packets");
			return;
		}

		ptr = sanctum_packet_head(pkt);
		memcpy(ptr, op, sizeof(*op));

		pkt->length = sizeof(*op);
		pkt->target = SANCTUM_PROC_PURGATORY_TX;

		sanctum_offer_tfc(pkt);

		pkt->addr.sin_family = AF_INET;
		pkt->addr.sin_port = tunnel->port;
		pkt->addr.sin_addr.s_addr = tunnel->ip;

		if (sanctum_ring_queue(io->purgatory, pkt) == -1) {
			sanctum_log(LOG_NOTICE,
			    "no CATACOMB update possible, failed to queue");
			sanctum_packet_release(pkt);
		} else {
			sanctum_proc_wakeup(SANCTUM_PROC_PURGATORY_TX);
		}
	}
}

/*
 * See if we have peer information for the other end of the tunnel given.
 */
static struct tunnel *
cathedral_tunnel_lookup(struct flockent *flock, u_int16_t spi)
{
	struct tunnel		*tunnel;

	PRECOND(flock != NULL);

	LIST_FOREACH(tunnel, &flock->tunnels, list) {
		if (tunnel->id == spi)
			break;
	}

	return (tunnel);
}

/*
 * Remove tunnels from the flock that are no longer configured.
 */
static void
cathedral_tunnel_prune(struct flockent *flock)
{
	struct allow		*allow;
	struct tunnel		*tun, *next;

	PRECOND(flock != NULL);

	for (tun = LIST_FIRST(&flock->tunnels); tun != NULL; tun = next) {
		next = LIST_NEXT(tun, list);

		LIST_FOREACH(allow, &flock->allows, list) {
			if (allow->spi == tun->id >> 8)
				break;
		}

		if (allow == NULL) {
			sanctum_log(LOG_INFO, "peer 0x%02x must be deleted",
			    tun->id >> 8);
			LIST_REMOVE(tun, list);
			free(tun);
		} else {
			sanctum_log(LOG_INFO, "peer 0x%02x retained",
			    tun->id >> 8);
		}
	}
}

/*
 * Send the information required for both peers to establish a
 * connection towards each other, skipping the cathedral for traffic.
 */
static void
cathedral_info_send(struct flockent *flock, struct sanctum_info_offer *info,
    struct sockaddr_in *sin, u_int32_t id, int peerinfo)
{
	struct sanctum_offer		*op;
	struct sanctum_packet		*pkt;
	struct tunnel			*peer;
	u_int16_t			tunnel;
	char				secret[1024];

	PRECOND(flock != NULL);
	PRECOND(info != NULL);
	PRECOND(sin != NULL);

	tunnel = htobe16(info->tunnel);

	if ((peer = cathedral_tunnel_lookup(flock, tunnel)) == NULL)
		return;

	if (peer->federated == 1)
		return;

	if ((pkt = sanctum_packet_get()) == NULL)
		return;

	op = sanctum_offer_init(pkt, id,
	    SANCTUM_CATHEDRAL_MAGIC, SANCTUM_OFFER_TYPE_INFO);

	info = &op->data.offer.info;
	info->local_port = sin->sin_port;
	info->local_ip = sin->sin_addr.s_addr;

	if (peerinfo && peer->peerinfo) {
		info->peer_ip = peer->ip;
		info->peer_port = peer->port;
	} else {
		info->peer_port = sanctum->local.sin_port;
		info->peer_ip = sanctum->local.sin_addr.s_addr;
	}

	cathedral_secret_path(secret, sizeof(secret), flock->id, id);

	if (cathedral_offer_send(secret, pkt, sin) == -1)
		sanctum_packet_release(pkt);
}

/*
 * Check if we should send an ambry to the peer by checking if its
 * ambry generation mismatches from the one we have loaded.
 *
 * If it needs to be updated, we send the fresh wrapped ambry.
 */
static void
cathedral_ambry_send(struct flockent *flock, struct sanctum_info_offer *info,
    struct sockaddr_in *s, u_int32_t id)
{
	struct sanctum_offer		*op;
	struct sanctum_packet		*pkt;
	struct sanctum_ambry_offer	*offer;
	struct ambry			*ambry;
	char				secret[1024];

	PRECOND(flock != NULL);
	PRECOND(info != NULL);
	PRECOND(s != NULL);

	if (info->ambry_generation == flock->ambry_generation)
		return;

	LIST_FOREACH(ambry, &flock->ambries, list) {
		if (info->tunnel == ambry->entry.tunnel)
			break;
	}

	if (ambry == NULL)
		return;

	if ((pkt = sanctum_packet_get()) == NULL)
		return;

	op = sanctum_offer_init(pkt, id,
	    SANCTUM_CATHEDRAL_MAGIC, SANCTUM_OFFER_TYPE_AMBRY);

	offer = &op->data.offer.ambry;
	offer->tunnel = htobe16(ambry->entry.tunnel);
	offer->generation = htobe32(flock->ambry_generation);

	nyfe_memcpy(offer->key, ambry->entry.key, sizeof(offer->key));
	nyfe_memcpy(offer->tag, ambry->entry.tag, sizeof(offer->tag));
	nyfe_memcpy(offer->seed, ambry->entry.seed, sizeof(offer->seed));

	cathedral_secret_path(secret, sizeof(secret), flock->id, id);

	if (cathedral_offer_send(secret, pkt, s) == -1)
		sanctum_packet_release(pkt);
}

/*
 * Encrypt and send a sanctum offer back to the client.
 */
static int
cathedral_offer_send(const char *secret, struct sanctum_packet *pkt,
    struct sockaddr_in *sin)
{
	struct sanctum_offer		*op;
	struct nyfe_agelas		cipher;

	PRECOND(secret != NULL);
	PRECOND(pkt != NULL);
	PRECOND(sin != NULL);

	op = sanctum_packet_head(pkt);

	nyfe_zeroize_register(&cipher, sizeof(cipher));
	if (sanctum_cipher_kdf(secret, SANCTUM_CATHEDRAL_KDF_LABEL,
	    &cipher, op->hdr.seed, sizeof(op->hdr.seed)) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		return (-1);
	}

	sanctum_offer_encrypt(&cipher, op);
	nyfe_zeroize(&cipher, sizeof(cipher));

	pkt->length = sizeof(*op);
	pkt->target = SANCTUM_PROC_PURGATORY_TX;

	sanctum_offer_tfc(pkt);

	pkt->addr.sin_family = AF_INET;
	pkt->addr.sin_port = sin->sin_port;
	pkt->addr.sin_addr.s_addr = sin->sin_addr.s_addr;

	if (sanctum_ring_queue(io->purgatory, pkt) == -1)
		return (-1);

	sanctum_proc_wakeup(SANCTUM_PROC_PURGATORY_TX);

	return (0);
}

/*
 * Expire tunnels that are too old and remove them from the known list.
 */
static void
cathedral_tunnel_expire(u_int64_t now)
{
	struct flockent		*flock;
	struct tunnel		*tunnel, *next;

	LIST_FOREACH(flock, &flocks, list) {
		for (tunnel = LIST_FIRST(&flock->tunnels);
		    tunnel != NULL; tunnel = next) {
			next = LIST_NEXT(tunnel, list);

			if ((now - tunnel->age) >= CATHEDRAL_TUNNEL_MAX_AGE) {
				LIST_REMOVE(tunnel, list);
				free(tunnel);
			}
		}
	}
}

/*
 * Lookup the flock for the given id.
 */
static struct flockent *
cathedral_flock_lookup(u_int64_t id)
{
	struct flockent		*flock;

	LIST_FOREACH(flock, &flocks, list) {
		if (flock->id == id)
			return (flock);
	}

	return (NULL);
}

/*
 * Clear all allows for a flock.
 */
static void
cathedral_flock_allows_clear(struct flockent *flock)
{
	struct allow	*entry;

	PRECOND(flock != NULL);

	while ((entry = LIST_FIRST(&flock->allows)) != NULL) {
		LIST_REMOVE(entry, list);
		free(entry);
	}

	LIST_INIT(&flock->allows);
}

/*
 * Clear all tunnels from a flock.
 */
static void
cathedral_flock_tunnels_clear(struct flockent *flock)
{
	struct tunnel	*entry;

	PRECOND(flock != NULL);

	while ((entry = LIST_FIRST(&flock->tunnels)) != NULL) {
		LIST_REMOVE(entry, list);
		free(entry);
	}

	LIST_INIT(&flock->tunnels);
}

/*
 * Clear all ambries from a flock.
 */
static void
cathedral_flock_ambries_clear(struct flockent *flock)
{
	struct ambry	*entry;

	PRECOND(flock != NULL);

	while ((entry = LIST_FIRST(&flock->ambries)) != NULL) {
		LIST_REMOVE(entry, list);
		nyfe_mem_zero(&entry->entry, sizeof(entry->entry));
		free(entry);
	}

	LIST_INIT(&flock->ambries);
}

/*
 * Create the path to a cathedral secret for the given flock and id.
 */
static void
cathedral_secret_path(char *buf, size_t buflen, u_int64_t flock, u_int32_t id)
{
	int		len;

	PRECOND(buf != NULL);
	PRECOND(buflen > 0);

	len = snprintf(buf, buflen, "%s/flock-%" PRIx64 "/%08x.key",
	    sanctum->secretdir, flock, id);
	if (len == -1 || (size_t)len >= buflen)
		fatal("failed to construct path to secret");
}

/*
 * Reload the settings from disk and apply them to the cathedral if
 * they changed since last time we looked at them.
 */
static void
cathedral_settings_reload(void)
{
	int			fd;
	struct stat		st;
	FILE			*fp;
	struct tunnel		*entry;
	struct flockent		*flock, *next;
	char			buf[256], *kw, *option;

	if (sanctum->settings == NULL)
		return;

	if ((fd = sanctum_file_open(sanctum->settings, &st)) == -1)
		return;

	if (st.st_mtime == settings_last_mtime) {
		(void)close(fd);
		return;
	}

	sanctum_log(LOG_INFO, "settings changed, reloading");

	if ((fp = fdopen(fd, "r")) == NULL) {
		sanctum_log(LOG_NOTICE, "failed to fdopen '%s': %s",
		    sanctum->settings, errno_s);
		(void)close(fd);
		return;
	}

	LIST_FOREACH(flock, &flocks, list)
		flock->retain = 0;

	while ((entry = LIST_FIRST(&federations)) != NULL) {
		LIST_REMOVE(entry, list);
		free(entry);
	}

	flock = NULL;
	LIST_INIT(&federations);

	while ((kw = sanctum_config_read(fp, buf, sizeof(buf))) != NULL) {
		if (strlen(kw ) == 0)
			continue;

		if (!strcmp(kw, "}")) {
			if (flock == NULL) {
				sanctum_log(LOG_NOTICE,
				    "trying to close unopened flock block");
			}

			flock = NULL;
			continue;
		}

		if ((option = strchr(kw, ' ')) == NULL) {
			sanctum_log(LOG_NOTICE,
			    "format error '%s' in settings", kw);
			continue;
		}

		*(option)++ = '\0';

		if (!strcmp(kw, "flock")) {
			cathedral_settings_flock(option, &flock);
		} else if (!strcmp(kw, "federate")) {
			cathedral_settings_federate(option);
		} else if (!strcmp(kw, "allow")) {
			cathedral_settings_allow(option, flock);
		} else if (!strcmp(kw, "ambry")) {
			cathedral_settings_ambry(option, flock);
		} else {
			sanctum_log(LOG_NOTICE,
			    "unknown keyword '%s' in settings", kw);
		}
	}

	for (flock = LIST_FIRST(&flocks); flock != NULL; flock = next) {
		next = LIST_NEXT(flock, list);

		if (flock->retain) {
			sanctum_log(LOG_INFO, "flock %" PRIx64 " retained",
			    flock->id);
			cathedral_tunnel_prune(flock);
			continue;
		}

		sanctum_log(LOG_INFO, "flock %" PRIx64 " is gone", flock->id);

		LIST_REMOVE(flock, list);

		cathedral_flock_allows_clear(flock);
		cathedral_flock_ambries_clear(flock);
		cathedral_flock_tunnels_clear(flock);

		free(flock);
	}

	sanctum_log(LOG_INFO, "settings reloaded");

	settings_last_mtime = st.st_mtime;
	(void)fclose(fp);
}

/*
 * Adds a new federation to the cathedral.
 */
static void
cathedral_settings_federate(const char *option)
{
	struct sockaddr_in	sin;
	u_int16_t		port;
	struct tunnel		*tunnel;
	char			ip[INET_ADDRSTRLEN];

	PRECOND(option != NULL);

	if (sscanf(option, "%15s %hu", ip, &port) != 2) {
		sanctum_log(LOG_NOTICE,
		    "format error '%s' in federate-to", option);
		return;
	}

	if (inet_pton(AF_INET, ip, &sin.sin_addr) != 1) {
		sanctum_log(LOG_NOTICE,
		    "invalid ip address '%s' in federate-to", ip);
		return;
	}

	if (sin.sin_addr.s_addr == sanctum->local.sin_addr.s_addr &&
	    htobe16(port) == sanctum->local.sin_port) {
		sanctum_log(LOG_INFO, "skipping federation to own cathedral");
		return;
	}

	if ((tunnel = calloc(1, sizeof(*tunnel))) == NULL)
		fatal("calloc: failed to allocate federation");

	tunnel->port = htobe16(port);
	tunnel->ip = sin.sin_addr.s_addr;

	sanctum_log(LOG_INFO, "federating to %s:%u", ip, port);
	LIST_INSERT_HEAD(&federations, tunnel, list);
}

/*
 * Create a new flock under which we can attach tunnels and ambries.
 */
static void
cathedral_settings_flock(const char *option, struct flockent **out)
{
	u_int64_t		id;
	struct flockent		*flock;

	PRECOND(option != NULL);
	PRECOND(out != NULL);

	if (*out != NULL) {
		sanctum_log(LOG_NOTICE, "previous flock not closed");
		return;
	}

	if (sscanf(option, "%" PRIx64 " {", &id) != 1) {
		sanctum_log(LOG_NOTICE,
		    "format error '%s' in flock", option);
		return;
	}

	if ((flock = cathedral_flock_lookup(id)) != NULL) {
		flock->retain = 1;
		cathedral_flock_allows_clear(flock);
	} else {
		if ((flock = calloc(1, sizeof(*flock))) == NULL)
			fatal("calloc: failed");

		flock->id = id;
		flock->retain = 1;

		LIST_INIT(&flock->allows);
		LIST_INIT(&flock->ambries);
		LIST_INIT(&flock->tunnels);
		LIST_INSERT_HEAD(&flocks, flock, list);
	}

	*out = flock;
}

/*
 * Adds a new allow for a key ID and tunnel SPI.
 */
static void
cathedral_settings_allow(const char *option, struct flockent *flock)
{
	u_int8_t	spi;
	u_int32_t	id, bw;
	struct allow	*allow;

	PRECOND(option != NULL);

	if (flock == NULL) {
		sanctum_log(LOG_NOTICE, "allow not inside of a flock config");
		return;
	}

	if (sscanf(option, "%x spi %hhx %u", &id, &spi, &bw) != 3) {
		sanctum_log(LOG_NOTICE,
		    "format error '%s' in allow", option);
		return;
	}

	if ((allow = calloc(1, sizeof(*allow))) == NULL)
		fatal("calloc: failed to allocate allow entry");

	allow->bw = bw;
	allow->id = id;
	allow->spi = spi;

	LIST_INSERT_HEAD(&flock->allows, allow, list);
}

/*
 * Load the ambry file containing wrapped secrets for clients.
 *
 * We check if the ambry has been modified since last time and do not
 * reload it if it should still be the same.
 */
static void
cathedral_settings_ambry(const char *option, struct flockent *flock)
{
	int				fd;
	struct stat			st;
	struct sanctum_ambry_head	hdr;
	size_t				ret;
	struct sanctum_ambry_entry	entry;
	struct ambry			*ambry;

	PRECOND(option != NULL);

	if (flock == NULL) {
		sanctum_log(LOG_NOTICE, "ambry not inside of a flock config");
		return;
	}

	if ((fd = sanctum_file_open(option, &st)) == -1)
		return;

	if (st.st_size != CATHEDRAL_AMBRY_BUNDLE_LEN) {
		sanctum_log(LOG_NOTICE,
		    "ambry file '%s' has an abnormal size", option);
		goto out;
	}

	if (st.st_mtime == flock->ambry_mtime)
		goto out;

	if (nyfe_file_read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
		sanctum_log(LOG_NOTICE,
		    "ambry file '%s' failed to read header", option);
		goto out;
	}

	hdr.generation = be32toh(hdr.generation);
	if (hdr.generation == flock->ambry_generation)
		goto out;

	sanctum_log(LOG_INFO,
	    "reloading ambry file for flock %" PRIx64, flock->id);

	cathedral_flock_ambries_clear(flock);

	for (;;) {
		if ((ambry = calloc(1, sizeof(*ambry))) == NULL)
			fatal("calloc: failed to allocate ambry entry");

		ret = nyfe_file_read(fd, &ambry->entry, sizeof(ambry->entry));
		if (ret == 0) {
			free(ambry);
			break;
		}

		LIST_INSERT_HEAD(&flock->ambries, ambry, list);

		if (ret != sizeof(entry)) {
			sanctum_log(LOG_NOTICE,
			    "ambry file '%s' had partial entries, ignoring",
			    option);
			cathedral_flock_ambries_clear(flock);
			break;
		}

		ambry->entry.tunnel = be16toh(ambry->entry.tunnel);
	}

	flock->ambry_mtime = st.st_mtime;
	flock->ambry_generation = hdr.generation;

out:
	(void)close(fd);
}

/*
 * Returns the current monotonic timestamp as milliseconds.
 */
static u_int64_t
cathedral_ms(void)
{
	struct timespec		ts;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);

	return ((u_int64_t)(ts.tv_sec * 1000 + (ts.tv_nsec / 1000000)));
}
