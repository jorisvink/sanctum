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

/* The maximum age in seconds for a cached tunnel or liturgy entries. */
#define CATHEDRAL_TUNNEL_MAX_AGE	(30 * 1000)

/* The interval at which we check for expired tunnel and liturgy entries. */
#define CATHEDRAL_TUNNEL_EXPIRE_NEXT	(10 * 1000)

/* The interval at which we check if settings changed. */
#define CATHEDRAL_SETTINGS_RELOAD_NEXT	(10 * 1000)

/* The CATACOMB message magic. */
#define CATHEDRAL_CATACOMB_MAGIC	0x43415441434F4D42

/* The KDF label for the tunnel sync. */
#define CATHEDRAL_CATACOMB_LABEL	"SANCTUM.CATHEDRAL.CATACOMB"

/* The length of an ambry bundle. */
#define CATHEDRAL_AMBRY_BUNDLE_LEN	7441936

/*
 * A known tunnel and its endpoint, or a federated cathedral.
 */
struct tunnel {
	/* tunnel information. */
	u_int32_t		id;
	u_int32_t		ip;
	u_int64_t		age;
	u_int16_t		port;
	u_int64_t		instance;
	int			peerinfo;
	int			federated;
	u_int32_t		rx_active;
	u_int32_t		rx_pending;

	/* p2p sync */
	u_int32_t		p2p_ip;
	u_int16_t		p2p_port;

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
 * A client that will receive a liturgy update for the attached flock.
 */
struct liturgy {
	u_int32_t		ip;
	u_int64_t		age;
	u_int16_t		id;
	u_int16_t		port;
	u_int16_t		group;
	LIST_ENTRY(liturgy)	list;
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
	LIST_HEAD(, liturgy)	liturgies;
	LIST_ENTRY(flockent)	list;
};

static u_int64_t	cathedral_ms(void);
static struct flockent	*cathedral_flock_lookup(u_int64_t);
static struct tunnel	*cathedral_tunnel_lookup(struct flockent *, u_int16_t);

static void	cathedral_flock_allows_clear(struct flockent *);
static void	cathedral_flock_tunnels_clear(struct flockent *);
static void	cathedral_flock_ambries_clear(struct flockent *);
static void	cathedral_flock_liturgies_clear(struct flockent *);
static void	cathedral_packet_handle(struct sanctum_packet *, u_int64_t);

static void	cathedral_secret_path(char *, size_t, u_int64_t, u_int32_t);

static void	cathedral_offer_federate(struct flockent *,
		    struct sanctum_packet *);
static void	cathedral_offer_handle(struct sanctum_packet *,
		    u_int64_t, int, int);
static int	cathedral_offer_send(const char *,
		    struct sanctum_packet *, struct sockaddr_in *);
static int	cathedral_offer_validate(struct flockent *,
		    struct sanctum_offer *, u_int32_t, int);
static void	cathedral_offer_info(struct sanctum_packet *,
		    struct flockent *, u_int64_t, int, int);
static void	cathedral_offer_liturgy(struct sanctum_packet *,
		    struct flockent *, u_int64_t, int);

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
		    u_int32_t);
static void	cathedral_liturgy_send(struct flockent *,
		    struct liturgy *, struct sockaddr_in *, u_int32_t);

static void	cathedral_tunnel_expire(u_int64_t);
static void	cathedral_tunnel_prune(struct flockent *);
static int	cathedral_tunnel_update_allowed(struct flockent *,
		    u_int8_t, u_int32_t, u_int32_t *);

static int	cathedral_forward_data(struct sanctum_packet *,
		    u_int32_t, u_int64_t);
static int	cathedral_forward_offer(struct sanctum_packet *,
		    struct flockent *, u_int32_t);

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
 * 3) A liturgy message from a sanctum instance.
 * 4) A normal packet that must be forwarded.
 */
static void
cathedral_packet_handle(struct sanctum_packet *pkt, u_int64_t now)
{
	u_int64_t			fid;
	struct tunnel			*srv;
	struct sanctum_ipsec_hdr	*hdr;
	struct sanctum_offer_hdr	*offer;
	struct flockent			*flock;
	u_int32_t			seq, spi;

	PRECOND(pkt != NULL);

	hdr = sanctum_packet_head(pkt);
	seq = be32toh(hdr->esp.seq);
	spi = be32toh(hdr->esp.spi);

	if ((spi == (SANCTUM_CATHEDRAL_MAGIC >> 32)) &&
	    (seq == (SANCTUM_CATHEDRAL_MAGIC & 0xffffffff))) {
		cathedral_offer_handle(pkt, now, 0, 0);
		sanctum_packet_release(pkt);
	} else if ((spi == (SANCTUM_CATHEDRAL_NAT_MAGIC >> 32)) &&
	    (seq == (SANCTUM_CATHEDRAL_NAT_MAGIC & 0xffffffff))) {
		cathedral_offer_handle(pkt, now, 1, 0);
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

		cathedral_offer_handle(pkt, now, 0, 1);
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
			fid = be64toh(offer->flock);

			if ((flock = cathedral_flock_lookup(fid)) == NULL) {
				sanctum_packet_release(pkt);
				return;
			}

			if (cathedral_forward_offer(pkt, flock, spi) == -1)
				sanctum_packet_release(pkt);
		} else {
			if (cathedral_forward_data(pkt, spi, now) == -1)
				sanctum_packet_release(pkt);
		}
	}
}

/*
 * Attempt to verify and decrypt an incoming offer message from a client.
 * We accept both INFO and LITURGY messages.
 */
static void
cathedral_offer_handle(struct sanctum_packet *pkt, u_int64_t now,
    int nat, int catacomb)
{
	u_int32_t			id;
	u_int64_t			fid;
	struct sanctum_offer		*op;
	struct flockent			*flock;

	PRECOND(pkt != NULL);

	if (pkt->length < sizeof(*op))
		return;

	op = sanctum_packet_head(pkt);
	id = be32toh(op->hdr.spi);
	fid = be64toh(op->hdr.flock);

	if ((flock = cathedral_flock_lookup(fid)) == NULL)
		return;

	if (cathedral_offer_validate(flock, op, id, catacomb) == -1)
		return;

	switch (op->data.type) {
	case SANCTUM_OFFER_TYPE_INFO:
		cathedral_offer_info(pkt, flock, now, nat, catacomb);
		break;
	case SANCTUM_OFFER_TYPE_LITURGY:
		cathedral_offer_liturgy(pkt, flock, now, catacomb);
		break;
	default:
		break;
	}
}

/*
 * Encrypt and send a sanctum offer back to the client.
 */
static int
cathedral_offer_send(const char *secret, struct sanctum_packet *pkt,
    struct sockaddr_in *sin)
{
	struct sanctum_offer		*op;
	struct sanctum_key		cipher;

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
 * Verify and decrypt an offer we received from a potential client
 * or from another cathedral we federate with.
 */
static int
cathedral_offer_validate(struct flockent *flock, struct sanctum_offer *op,
    u_int32_t id, int catacomb)
{
	struct sanctum_key	cipher;
	const char		*label;
	char			*secret, path[1024];

	PRECOND(flock != NULL);
	PRECOND(op != NULL);

	if (catacomb) {
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

	return (0);
}

/*
 * We received a tunnel registration update, so we create a new tunnel
 * entry or update an existing one.
 */
static void
cathedral_offer_info(struct sanctum_packet *pkt, struct flockent *flock,
    u_int64_t now, int nat, int catacomb)
{
	u_int8_t			tid;
	struct sanctum_offer		*op;
	struct tunnel			*tun;
	struct sanctum_info_offer	*info;
	u_int32_t			id, bw;

	PRECOND(pkt != NULL);
	PRECOND(flock != NULL);
	PRECOND(pkt->length >= sizeof(*op));

	op = sanctum_packet_head(pkt);
	VERIFY(op->data.type == SANCTUM_OFFER_TYPE_INFO);

	id = be32toh(op->hdr.spi);

	info = &op->data.offer.info;
	info->tunnel = be16toh(info->tunnel);
	info->instance = be64toh(info->instance);
	info->ambry_generation = be32toh(info->ambry_generation);

	tid = info->tunnel >> 8;
	if (cathedral_tunnel_update_allowed(flock, tid, id, &bw) == -1) {
		sanctum_log(LOG_NOTICE, "%" PRIx64 ":%02x is not tied to %08x",
		    flock->id, tid, id);
		return;
	}

	if ((tun = cathedral_tunnel_lookup(flock, info->tunnel)) == NULL) {
		if (nat) {
			sanctum_log(LOG_INFO,
			    "%" PRIx64 ":%04x NAT but no tunnel",
			    flock->id, info->tunnel);
			return;
		}

		if ((tun = calloc(1, sizeof(*tun))) == NULL)
			fatal("calloc failed");

		tun->id = info->tunnel;
		tun->instance = info->instance;
		tun->limit = (bw / 8) * 1024 * 1024;
		tun->drain_per_ms = tun->limit / 1000;

		LIST_INSERT_HEAD(&flock->tunnels, tun, list);
		sanctum_log(LOG_INFO,
		    "%" PRIx64 ":%04x discovered (%u mbit/sec) (%d)",
		    flock->id, info->tunnel, bw, catacomb);
	 }

	if (info->instance != tun->instance) {
		tun->peerinfo = 0;
		sanctum_log(LOG_INFO, "%" PRIx64 ":%04x peer restart detected",
		    flock->id, info->tunnel);
	} else if (catacomb == 0 && nat == 0) {
		cathedral_ambry_send(flock, info, &pkt->addr, id);
		if (tun->peerinfo)
			cathedral_info_send(flock, info, &pkt->addr, id);
	}

	if (nat) {
		if (tun->federated) {
			sanctum_log(LOG_INFO,
			    "%" PRIx64 ":%04x NAT for federated tunnel",
			    flock->id, info->tunnel);
			return;
		}

		if ((tun->ip == pkt->addr.sin_addr.s_addr &&
		    tun->port != pkt->addr.sin_port) ||
		    tun->ip != pkt->addr.sin_addr.s_addr) {
			tun->p2p_ip = 0;
			tun->p2p_port = 0;
			tun->peerinfo = 0;
		} else {
			tun->peerinfo = 1;
			tun->p2p_port = pkt->addr.sin_port;
			tun->p2p_ip = pkt->addr.sin_addr.s_addr;
		}

		return;
	}

	tun->age = now;
	tun->rx_active = info->rx_active;
	tun->rx_pending = info->rx_pending;

	tun->instance = info->instance;
	tun->port = pkt->addr.sin_port;
	tun->ip = pkt->addr.sin_addr.s_addr;

	if (catacomb) {
		tun->federated = 1;
		tun->peerinfo = info->flags;
		tun->p2p_ip = info->peer_ip;
		tun->p2p_port = info->peer_port;
	} else {
		tun->federated = 0;

		if (sanctum->flags & SANCTUM_FLAG_CATHEDRAL_P2P_SYNC) {
			info->peer_ip = tun->ip;
			info->peer_port = tun->port;
			info->flags = tun->peerinfo;
		} else {
			info->flags = 0;
			info->peer_ip = 0;
			info->peer_port = 0;
		}

		info->tunnel = htobe16(info->tunnel);
		info->instance = htobe64(info->instance);
		info->ambry_generation = htobe32(info->ambry_generation);

		cathedral_offer_federate(flock, pkt);
	}
}

/*
 * A liturgy message from a sanctum instance arrived. We verify and
 * decrypt it and respond to the client with our own liturgy message
 * carrying the relevant information.
 */
static void
cathedral_offer_liturgy(struct sanctum_packet *pkt, struct flockent *flock,
    u_int64_t now, int catacomb)
{
	u_int32_t			id;
	struct sanctum_offer		*op;
	struct sanctum_liturgy_offer	*lit;
	u_int16_t			group;
	struct liturgy			*entry;

	PRECOND(pkt != NULL);
	PRECOND(flock != NULL);
	PRECOND(pkt->length >= sizeof(*op));

	op = sanctum_packet_head(pkt);
	VERIFY(op->data.type == SANCTUM_OFFER_TYPE_LITURGY);

	id = be32toh(op->hdr.spi);
	lit = &op->data.offer.liturgy;
	group = be16toh(lit->group);

	if (cathedral_tunnel_update_allowed(flock, lit->id, id, NULL) == -1) {
		sanctum_log(LOG_NOTICE, "%" PRIx64 ":%02x is not tied to %08x",
		    flock->id, lit->id, id);
		return;
	}

	LIST_FOREACH(entry, &flock->liturgies, list) {
		if (entry->id == lit->id)
			break;
	}

	if (entry == NULL) {
		if ((entry = calloc(1, sizeof(*entry))) == NULL)
			fatal("calloc: failed to allocate liturgy");

		entry->id = lit->id;
		LIST_INSERT_HEAD(&flock->liturgies, entry, list);
	}

	if (entry->age == 0 || entry->group != group) {
		sanctum_log(LOG_INFO,
		    "liturgy for %" PRIx64 ":%02x (%04x) (%d)",
		    flock->id, lit->id, group, catacomb);
	}

	entry->age = now;
	entry->group = group;

	entry->port = pkt->addr.sin_port;
	entry->ip = pkt->addr.sin_addr.s_addr;

	if (catacomb == 0) {
		cathedral_offer_federate(flock, pkt);
		cathedral_liturgy_send(flock, entry, &pkt->addr, id);
	}
}

/*
 * Send out the offer inside of the given packet to all other cathedrals.
 */
static void
cathedral_offer_federate(struct flockent *flock, struct sanctum_packet *update)
{
	struct sanctum_offer		*op;
	struct sanctum_packet		*pkt;
	u_int8_t			*ptr;
	struct sanctum_key		cipher;
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
 * Check if the given tunnel id (tid) in the provided flock should be
 * allowed to send us data by checking the key id that was used to
 * verify the packet.
 */
static int
cathedral_tunnel_update_allowed(struct flockent *flock, u_int8_t tid,
    u_int32_t id, u_int32_t *bw)
{
	struct allow		*allow;

	PRECOND(flock != NULL);
	/* bw is optional */

	LIST_FOREACH(allow, &flock->allows, list) {
		if (allow->id == id && (allow->spi == tid)) {
			if (bw != NULL)
				*bw = allow->bw;
			return (0);
		}
	}

	return (-1);
}

/*
 * Forward a key offer packet towards the correct peer.
 */
static int
cathedral_forward_offer(struct sanctum_packet *pkt, struct flockent *flock,
    u_int32_t spi)
{
	u_int16_t		id;
	struct tunnel		*tunnel;
	u_int8_t		src, dst;

	PRECOND(pkt != NULL);
	PRECOND(flock != NULL);

	id = spi >> 16;

	src = id >> 8;
	dst = id & 0xff;

	id = ((u_int16_t)dst << 8) | src;

	LIST_FOREACH(tunnel, &flock->tunnels, list) {
		if (tunnel->id == id)
			break;
	}

	if (tunnel == NULL) {
		sanctum_log(LOG_INFO,
		    "%" PRIx64 ":%04x not found for offer", flock->id, id);
		return (-1);
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
 * Forward the data packet towards the correct peer after applying
 * a bandwidth limitation on it.
 */
static int
cathedral_forward_data(struct sanctum_packet *pkt, u_int32_t spi, u_int64_t now)
{
	u_int32_t		drain;
	u_int64_t		delta;
	struct flockent		*flock;
	struct tunnel		*tunnel;

	PRECOND(pkt != NULL);

	/*
	 * XXX - for now this exhaustive search works unless we start
	 * talking large volumes of traffic. If it becomes clear we
	 * are bottlenecking we should rewrite this. But until then,
	 * this very much will do.
	 */
	LIST_FOREACH(flock, &flocks, list) {
		LIST_FOREACH(tunnel, &flock->tunnels, list) {
			if ((tunnel->rx_active != 0 &&
			    tunnel->rx_active == spi) ||
			    (tunnel->rx_pending != 0 &&
			    tunnel->rx_pending == spi))
				break;
		}

		if (tunnel != NULL)
			break;
	}

	if (flock == NULL) {
		sanctum_log(LOG_INFO, "tunnel for spi 0x%08x not found", spi);
		return (-1);
	}

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

		if (tunnel->current >= tunnel->limit)
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
 * Expire tunnel and liturgy entries that are too old and remove them
 * from the known list.
 */
static void
cathedral_tunnel_expire(u_int64_t now)
{
	struct flockent		*flock;
	struct tunnel		*tunnel, *tunnel_next;
	struct liturgy		*liturgy, *liturgy_next;

	LIST_FOREACH(flock, &flocks, list) {
		for (liturgy = LIST_FIRST(&flock->liturgies);
		    liturgy != NULL; liturgy = liturgy_next) {
			liturgy_next = LIST_NEXT(liturgy, list);

			if ((now - liturgy->age) >= CATHEDRAL_TUNNEL_MAX_AGE) {
				sanctum_log(LOG_INFO,
				    "liturgy %" PRIx64 ":%02x (%04x) removed",
				    flock->id, liturgy->group, liturgy->id);
				LIST_REMOVE(liturgy, list);
				free(liturgy);
			}
		}

		for (tunnel = LIST_FIRST(&flock->tunnels);
		    tunnel != NULL; tunnel = tunnel_next) {
			tunnel_next = LIST_NEXT(tunnel, list);

			if ((now - tunnel->age) >= CATHEDRAL_TUNNEL_MAX_AGE) {
				sanctum_log(LOG_INFO,
				    "tunnel %" PRIx64 ":%04x removed",
				    flock->id, tunnel->id);
				LIST_REMOVE(tunnel, list);
				free(tunnel);
			}
		}
	}
}

/*
 * Send the information required for both peers to establish a
 * connection towards each other, skipping the cathedral for traffic.
 */
static void
cathedral_info_send(struct flockent *flock, struct sanctum_info_offer *info,
    struct sockaddr_in *sin, u_int32_t id)
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

	if (peer->federated &&
	    !(sanctum->flags & SANCTUM_FLAG_CATHEDRAL_P2P_SYNC))
		return;

	if ((pkt = sanctum_packet_get()) == NULL)
		return;

	op = sanctum_offer_init(pkt, id,
	    SANCTUM_CATHEDRAL_MAGIC, SANCTUM_OFFER_TYPE_INFO);

	info = &op->data.offer.info;
	info->local_port = sin->sin_port;
	info->local_ip = sin->sin_addr.s_addr;

	/*
	 * Sanctum does not share any internal ip addresses with the cathedral
	 * and thus the cathedral cannot determine if they would be able to
	 * use those internal ones to communicate when coming from the same
	 * external ip.
	 *
	 * This means that two peers sharing the same external ip need to
	 * relay their traffic, otherwise their fw/gw will be unhappy when
	 * they start sending traffic to its external ip from an internal
	 * interface, which is usually going to be the case.
	 */
	if (peer->peerinfo && peer->p2p_ip != sin->sin_addr.s_addr) {
		info->peer_ip = peer->p2p_ip;
		info->peer_port = peer->p2p_port;
	} else {
		info->peer_port = sanctum->local.sin_port;
		info->peer_ip = sanctum->local.sin_addr.s_addr;
	}

	cathedral_secret_path(secret, sizeof(secret), flock->id, id);

	if (cathedral_offer_send(secret, pkt, sin) == -1)
		sanctum_packet_release(pkt);
}

/*
 * Send a liturgy offering to a client. In this message we will include
 * all peers in the same flock that are part of the liturgy.
 */
static void
cathedral_liturgy_send(struct flockent *flock, struct liturgy *src,
    struct sockaddr_in *sin, u_int32_t id)
{
	struct sanctum_offer		*op;
	struct sanctum_packet		*pkt;
	struct sanctum_liturgy_offer	*lit;
	struct liturgy			*entry;
	char				secret[1024];

	PRECOND(flock != NULL);
	PRECOND(src != NULL);
	PRECOND(sin != NULL);

	if ((pkt = sanctum_packet_get()) == NULL)
		return;

	op = sanctum_offer_init(pkt, id,
	    SANCTUM_CATHEDRAL_MAGIC, SANCTUM_OFFER_TYPE_LITURGY);

	lit = &op->data.offer.liturgy;
	lit->group = htobe16(src->group);

	LIST_FOREACH(entry, &flock->liturgies, list) {
		if (entry != src && entry->group == src->group)
			lit->peers[entry->id] = 1;
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
 * Clear all liturgies from a flock.
 */
static void
cathedral_flock_liturgies_clear(struct flockent *flock)
{
	struct liturgy	*entry;

	PRECOND(flock != NULL);

	while ((entry = LIST_FIRST(&flock->liturgies)) != NULL) {
		LIST_REMOVE(entry, list);
		free(entry);
	}

	LIST_INIT(&flock->liturgies);
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
		cathedral_flock_liturgies_clear(flock);

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
		LIST_INIT(&flock->liturgies);
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
