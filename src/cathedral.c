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

/* The number of domains per flock. */
#define CATHEDRAL_FLOCK_DOMAIN_BITS	8
#define CATHEDRAL_FLOCK_DOMAINS		(1 << CATHEDRAL_FLOCK_DOMAIN_BITS)
#define CATHEDRAL_FLOCK_DOMAIN_MASK	(CATHEDRAL_FLOCK_DOMAINS - 1)

/* The number of seconds in between allowed federation for offers. */
#define CATHEDRAL_FEDERATE_NEXT		(1 * 1000)

/* The maximum age in seconds for a cached tunnel or liturgy entries. */
#define CATHEDRAL_TUNNEL_MAX_AGE	(30 * 1000)

/* The interval at which we check for expired tunnel and liturgy entries. */
#define CATHEDRAL_TUNNEL_EXPIRE_NEXT	(10 * 1000)

/* The interval at which we check if settings changed. */
#define CATHEDRAL_SETTINGS_RELOAD_NEXT	(10 * 1000)

/* The interval at which we send out status log. */
#define CATHEDRAL_STATUS_NEXT		(5 * 1000)

/* The interval at which we send remembrances to peers. */
#define CATHEDRAL_REMEMBRANCE_NEXT	(15 * 1000)

/* Cooldown period from peer restart to when we send peerinfo again. */
#define CATHEDRAL_P2P_COOLDOWN		(10 * 1000)

/* The CATACOMB message magic. */
#define CATHEDRAL_CATACOMB_MAGIC	0x43415441434F4D42

/* The length of an ambry bundle. */
#if SANCTUM_TAG_LENGTH == 32
#define CATHEDRAL_AMBRY_BUNDLE_LEN	4793050
#define CATHEDRAL_AMBRY_INTERFLOCK_LEN	9623770
#elif SANCTUM_TAG_LENGTH == 16
#define CATHEDRAL_AMBRY_BUNDLE_LEN	3756730
#define CATHEDRAL_AMBRY_INTERFLOCK_LEN	7542970
#else
#error "Unknown SANCTUM_TAG_LENGTH"
#endif

/*
 * Used to track statistics on packets.
 */
struct ifstats {
	u_int64_t		pkts_in;
	u_int64_t		pkts_out;
	u_int64_t		bytes;
};

/*
 * Used to track statistics on things like tunnels or liturgies.
 */
struct peerstat {
	u_int32_t		local;
	u_int32_t		federated;
};

/*
 * A known tunnel and its endpoint, or a federated cathedral.
 * These live under the flockent's tunnel list. 
 */
struct tunnel {
	/* tunnel information. */
	u_int16_t		id;
	u_int32_t		ip;
	u_int16_t		port;
	u_int64_t		age;
	u_int64_t		update;
	u_int64_t		instance;
	int			peerinfo;
	int			federated;
	u_int32_t		rx_active;
	u_int32_t		rx_pending;

	/* flock information */
	u_int64_t		src;
	u_int64_t		dst;

	/* p2p sync */
	u_int32_t		p2p_ip;
	u_int16_t		p2p_port;
	int			p2p_pending;
	u_int64_t		p2p_cooldown;

	/* Next federation timestamp. */
	u_int64_t		at;

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
 * A client that will receive a liturgy update inside of a flock.
 */
struct liturgy {
	u_int32_t		ip;
	u_int64_t		at;
	u_int64_t		age;
	u_int16_t		id;
	u_int16_t		port;
	u_int32_t		flags;
	u_int16_t		group;
	u_int8_t		hidden;
	u_int64_t		update;
	int			federated;
	u_int8_t		peers[SANCTUM_PEERS_PER_FLOCK];
	LIST_ENTRY(liturgy)	list;
};

/*
 * An ambry entry that can be given to a client.
 */
struct ambry {
	struct sanctum_ambry_entry	entry;
	LIST_ENTRY(ambry)		list;
};

/*
 * A "cached" ambry file that is attached to a flock or xflock.
 */
struct ambries {
	time_t			mtime;
	int			retain;
	u_int64_t		flock_a;
	u_int64_t		flock_b;
	u_int16_t		expires;
	u_int32_t		generation;
	u_int8_t		seed[SANCTUM_AMBRY_SEED_LEN];
	LIST_HEAD(, ambry)	entries;
	LIST_ENTRY(ambry_cache)	list;
};

/*
 * A flock domain that is allocated and contains tunnels and liturgies.
 */
struct flockdom {
	u_int8_t		id;
	LIST_HEAD(, tunnel)	tunnels;
	LIST_HEAD(, liturgy)	liturgies;
	LIST_ENTRY(flockdom)	list;
};

/*
 * A flock is a group of clients that can talk to each other via the
 * cathedral. A flock is 64-bit where 56-bit are the flock id and the
 * remaining 8-bit are the flock domain allowing separation of applications
 * within the same flock id.
 *
 * This allows for up to 256 different domains per flock.
 */
struct flockent {
	u_int64_t		id;
	int			retain;
	struct flockdom		*domain;
	struct ambries		ambries;

	LIST_HEAD(, allow)	allows;
	LIST_HEAD(, flockdom)	domains;

	LIST_ENTRY(flockent)	list;
};

/*
 * A cross-flock that allows communication between sanctum instances
 * in different flocks.
 */
struct xflock {
	int			retain;
	u_int64_t		flock_a;
	u_int64_t		flock_b;
	struct ambries		ambries;

	LIST_ENTRY(xflock)	list;
};

static u_int64_t	cathedral_ms(void);
static void		cathedral_status_log(void);
static void		cathedral_status_reset(void);
static struct flockent	*cathedral_flock_lookup(u_int64_t);
static struct tunnel	*cathedral_tunnel_lookup(struct flockent *,
			    struct flockent *, u_int16_t);
static struct tunnel	*cathedral_tunnel_entry(struct flockent *,
			    struct flockent *, struct sanctum_info_offer *,
			    u_int32_t, u_int64_t, int, int);
static const char	*cathedral_tunnel_name_id(u_int64_t,
			    u_int64_t, u_int16_t);
static const char	*cathedral_tunnel_name(struct flockent *,
			    struct flockent *, u_int16_t);

static struct xflock	*cathedral_xflock_lookup(u_int64_t, u_int64_t);

static void		cathedral_ambry_purge(struct ambries *);
static void		cathedral_ambry_cache(const char *, struct ambries *);
static struct ambry	*cathedral_ambry_find(struct ambries *,
			    u_int64_t, u_int16_t);

static void	cathedral_peerstat_inc(struct peerstat *, int);
static void	cathedral_peerstat_dec(struct peerstat *, int);

static void	cathedral_flock_allows_clear(struct flockent *);
static void	cathedral_flock_domain_clear(struct flockdom *);
static void	cathedral_flock_domains_clear(struct flockent *);
static void	cathedral_packet_handle(struct sanctum_packet *, u_int64_t);

static void	cathedral_secret_path(char *, size_t, u_int64_t, u_int32_t);
static void	cathedral_pubkey_path(char *, size_t, u_int64_t, u_int32_t);

static void	cathedral_offer_federate(struct flockent *,
		    struct flockent *, struct sanctum_packet *);
static void	cathedral_offer_handle(struct sanctum_packet *,
		    u_int64_t, int, int);
static int	cathedral_offer_send(struct flockent *, const char *,
		    struct sanctum_packet *, struct sockaddr_in *);
static int	cathedral_offer_validate(struct flockent *,
		    struct sanctum_offer *, u_int32_t, int);
static void	cathedral_offer_info(struct sanctum_packet *,
		    struct flockent *, u_int64_t, int, int);
static void	cathedral_offer_liturgy(struct sanctum_packet *,
		    struct flockent *, u_int64_t, int);
static void	cathedral_offer_p2pinfo(struct sanctum_packet *,
		    struct flockent *, u_int64_t, int);

static void	cathedral_settings_reload(void);
static void	cathedral_settings_xflock(const char *);
static void	cathedral_settings_federate(const char *);
static void	cathedral_settings_allow(const char *, struct flockent *);
static void	cathedral_settings_ambry(const char *, struct flockent *);
static void	cathedral_settings_flock(const char *, struct flockent **);

static void	cathedral_ambry_send(struct flockent *, struct flockent *,
		    struct sanctum_info_offer *, struct sockaddr_in *,
		    u_int32_t);
static void	cathedral_info_send(struct flockent *, struct flockent *,
		    struct sanctum_info_offer *, struct sockaddr_in *,
		    u_int32_t);
static void	cathedral_liturgy_send(struct flockent *,
		    struct liturgy *, struct sockaddr_in *, u_int32_t);
static void	cathedral_p2pinfo_send(struct flockent *,
		    struct flockent *, struct tunnel *, u_int32_t);
static void	cathedral_remembrance_send(struct flockent *,
		    struct sockaddr_in *, u_int32_t);

static void	cathedral_tunnel_prune(struct flockent *);
static void	cathedral_tunnel_expire(struct flockent *, u_int64_t);
static int	cathedral_tunnel_update_allowed(struct flockent *,
		    u_int8_t, u_int32_t, u_int32_t *);

static int	cathedral_forward_offer(struct sanctum_packet *, u_int32_t);
static int	cathedral_forward_data(struct sanctum_packet *,
		    u_int32_t, u_int64_t);
static int	cathedral_forward_allowed(u_int64_t, u_int64_t,
		    struct flockent **, struct flockent **);

/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/* The list of federation cathedrals we can forward too. */
static LIST_HEAD(, tunnel)	federations;

/* The current number of configured active federations. */
static u_int8_t			federation_count = 0;

/* The list of configured flocks. */
static LIST_HEAD(, flockent)	flocks;

/* The list of configured allowed xflocks. */
static LIST_HEAD(, xflock)	xflocks;

/* The last modified time of the settings file. */
static time_t			settings_last_mtime = -1;

/* Connected peer statistics. */
static struct peerstat		peers;
static struct peerstat		liturgies;

/* Packet counters. */
static struct ifstats		offers;
static struct ifstats		traffic;

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
	struct flockent		*flock;
	int			sig, running;
	u_int64_t		now, next_expire, next_settings, next_status;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);
	PRECOND(sanctum->mode == SANCTUM_MODE_CATHEDRAL);

	sanctum_random_init();
	io = proc->arg;

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_trap(SIGUSR1);
	sanctum_signal_ignore(SIGINT);

	LIST_INIT(&flocks);
	LIST_INIT(&xflocks);
	LIST_INIT(&federations);

	sanctum_platform_sandbox(proc);
	cathedral_settings_reload();
	sanctum_proc_started(proc);

	running = 1;
	next_expire = 0;
	next_status = 0;
	next_settings = 0;

	while (running) {
		if ((sig = sanctum_last_signal()) != -1) {
			sanctum_log(LOG_NOTICE, "received signal %d", sig);
			switch (sig) {
			case SIGQUIT:
				running = 0;
				continue;
			case SIGUSR1:
				cathedral_status_reset();
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
			LIST_FOREACH(flock, &flocks, list)
				cathedral_tunnel_expire(flock, now);
		}

		if (now >= next_status) {
			next_status = now + CATHEDRAL_STATUS_NEXT;
			cathedral_status_log();
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
	struct tunnel			*srv;
	struct sanctum_proto_hdr	*hdr;
	struct sanctum_offer_hdr	*offer;
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
			    "CATACOMB update from unknown cathedral %s",
			    sanctum_inet_string(&pkt->addr));
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

			if (cathedral_forward_offer(pkt, spi) == -1)
				sanctum_packet_release(pkt);
		} else {
			if (cathedral_forward_data(pkt, spi, now) == -1)
				sanctum_packet_release(pkt);
		}
	}
}

/*
 * Attempt to verify and decrypt an incoming offer message from a client
 * or from another cathedral federating with us.
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
	PRECOND(catacomb == 0 || catacomb == 1);

	if (pkt->length < sizeof(*op))
		return;

	op = sanctum_packet_head(pkt);
	id = be32toh(op->hdr.spi);
	fid = be64toh(op->hdr.flock_src);

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
	case SANCTUM_OFFER_TYPE_P2P_INFO:
		if (catacomb)
			cathedral_offer_p2pinfo(pkt, flock, now, catacomb);
		break;
	default:
		break;
	}
}

/*
 * Encrypt and send a sanctum offer back to the client.
 */
static int
cathedral_offer_send(struct flockent *flock, const char *secret,
    struct sanctum_packet *pkt, struct sockaddr_in *sin)
{
	struct sanctum_offer		*op;
	struct sanctum_key		cipher;

	PRECOND(flock != NULL);
	PRECOND(secret != NULL);
	PRECOND(pkt != NULL);
	PRECOND(sin != NULL);

	op = sanctum_packet_head(pkt);
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	if (sanctum_offer_kdf(secret, SANCTUM_CATHEDRAL_KDF_LABEL,
	    &cipher, op->hdr.seed, sizeof(op->hdr.seed),
	    flock->id | flock->domain->id, 0) == -1) {
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
 *
 * After we succeed with decrypting the offer we always validate
 * the signature over it using the expected peer its public key.
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
		label = SANCTUM_CATHEDRAL_CATACOMB_LABEL;
	} else {
		cathedral_secret_path(path, sizeof(path), flock->id, id);
		secret = path;
		label = SANCTUM_CATHEDRAL_KDF_LABEL;
	}

	nyfe_zeroize_register(&cipher, sizeof(cipher));

	if (sanctum_offer_kdf(secret, label, &cipher,
	    op->hdr.seed, sizeof(op->hdr.seed),
	    flock->id | flock->domain->id, 0) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		return (-1);
	}

	if (sanctum_offer_decrypt(&cipher, op, SANCTUM_OFFER_VALID) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		return (-1);
	}

	nyfe_zeroize(&cipher, sizeof(cipher));
	cathedral_pubkey_path(path, sizeof(path), flock->id, id);

	/* CATACOMB messages of type p2p have no signatures. */
	if (catacomb == 1 && op->data.type == SANCTUM_OFFER_TYPE_P2P_INFO)
		return (0);

	if (sanctum_offer_verify(path, op) == -1) {
		sanctum_log(LOG_NOTICE,
		    "signature verification failed for %" PRIx64 ":%08x (%d)",
		    flock->id, id, catacomb);
		return (-1);
	}

	return (0);
}

/*
 * We received a tunnel info offer. Based on this we can create a new tunnel
 * entry or update an existing one.
 *
 * If everything checks out we federate the information to our other
 * cathedrals if we have any, unless this was already a CATACOMB message.
 */
static void
cathedral_offer_info(struct sanctum_packet *pkt, struct flockent *flock,
    u_int64_t now, int nat, int catacomb)
{
	u_int32_t			id;
	struct sanctum_offer		*op;
	struct flockent			*dst;
	struct tunnel			*tun;
	struct sanctum_info_offer	*info;
	u_int64_t			flock_dst;

	PRECOND(pkt != NULL);
	PRECOND(flock != NULL);
	PRECOND(pkt->length >= sizeof(*op));

	op = sanctum_packet_head(pkt);
	VERIFY(op->data.type == SANCTUM_OFFER_TYPE_INFO);

	id = be32toh(op->hdr.spi);
	flock_dst = be64toh(op->hdr.flock_dst);

	info = &op->data.offer.info;
	info->tunnel = be16toh(info->tunnel);
	info->instance = be64toh(info->instance);
	info->ambry_generation = be32toh(info->ambry_generation);

	if (cathedral_forward_allowed(flock->id | flock->domain->id,
	    flock_dst, NULL, &dst) == -1)
		return;

	tun = cathedral_tunnel_entry(flock, dst, info, id, now, nat, catacomb);
	if (tun == NULL)
		return;

	if (info->instance != tun->instance && nat == 0) {
		tun->peerinfo = 0;
		tun->p2p_cooldown = now + CATHEDRAL_P2P_COOLDOWN;
		sanctum_log(LOG_INFO, "%s peer restart detected",
		    cathedral_tunnel_name(flock, dst, info->tunnel));
	} else if (catacomb == 0 && nat == 0) {
		cathedral_ambry_send(flock, dst, info, &pkt->addr, id);

		if (tun->peerinfo)
			cathedral_info_send(flock, dst, info, &pkt->addr, id);

		if (now >= tun->update &&
		    (info->flags & SANCTUM_INFO_FLAG_REMEMBRANCE)) {
			tun->update = now + CATHEDRAL_REMEMBRANCE_NEXT;
			cathedral_remembrance_send(flock, &pkt->addr, id);
		}
	}

	if (nat) {
		if (tun->federated) {
			sanctum_log(LOG_INFO, "%s NAT for federated tunnel",
			    cathedral_tunnel_name(flock, dst, info->tunnel));
			return;
		}

		if ((tun->ip == pkt->addr.sin_addr.s_addr &&
		    tun->port != pkt->addr.sin_port) ||
		    tun->ip != pkt->addr.sin_addr.s_addr) {
			tun->p2p_ip = 0;
			tun->p2p_port = 0;
			tun->peerinfo = 0;
		} else if (now >= tun->p2p_cooldown) {
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
		if (tun->federated == 0) {
			cathedral_peerstat_dec(&peers, 0);
			cathedral_peerstat_inc(&peers, 1);
		}

		tun->federated = 1;
		tun->p2p_pending = 1;
	} else {
		if (tun->federated) {
			cathedral_peerstat_dec(&peers, 1);
			cathedral_peerstat_inc(&peers, 0);
		}

		tun->federated = 0;

		info->tunnel = htobe16(info->tunnel);
		info->instance = htobe64(info->instance);
		info->ambry_generation = htobe32(info->ambry_generation);

		if (now >= tun->at) {
			tun->at = now + CATHEDRAL_FEDERATE_NEXT;
			cathedral_offer_federate(flock, dst, pkt);
			cathedral_p2pinfo_send(flock, dst, tun, id);
		} else {
			sanctum_log(LOG_NOTICE,
			    "%s is sending offers too quickly",
			    cathedral_tunnel_name(flock, dst, info->tunnel));
		}
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
	const char			*mode;
	struct liturgy			*entry;
	u_int64_t			flock_dst;

	PRECOND(pkt != NULL);
	PRECOND(flock != NULL);
	PRECOND(flock->domain != NULL);
	PRECOND(pkt->length >= sizeof(*op));
	PRECOND(catacomb == 0 || catacomb == 1);

	op = sanctum_packet_head(pkt);
	VERIFY(op->data.type == SANCTUM_OFFER_TYPE_LITURGY);

	flock_dst = be64toh(op->hdr.flock_dst);
	flock_dst &= ~(CATHEDRAL_FLOCK_DOMAIN_MASK);

	if ((catacomb == 0 && flock_dst != 0) ||
	    (catacomb && flock_dst != flock->id)) {
		sanctum_log(LOG_NOTICE,
		    "refusing xflock liturgy (%" PRIx64 " <=> %" PRIx64 ")",
		    flock_dst, flock->id);
		return;
	}

	id = be32toh(op->hdr.spi);
	lit = &op->data.offer.liturgy;
	group = be16toh(lit->group);

	if (cathedral_tunnel_update_allowed(flock, lit->id, id, NULL) == -1) {
		sanctum_log(LOG_NOTICE, "%s is not tied to %08x",
		    cathedral_tunnel_name(flock, flock, lit->id), id);
		return;
	}

	LIST_FOREACH(entry, &flock->domain->liturgies, list) {
		if (entry->id == lit->id &&
		    (entry->flags & SANCTUM_LITURGY_FLAG_SIGNALING) ==
		    (lit->flags & SANCTUM_LITURGY_FLAG_SIGNALING))
			break;
	}

	if (entry == NULL) {
		if ((entry = calloc(1, sizeof(*entry))) == NULL)
			fatal("calloc: failed to allocate liturgy");

		entry->id = lit->id;
		entry->update = now;
		entry->flags = lit->flags;
		entry->federated = catacomb;

		cathedral_peerstat_inc(&liturgies, catacomb);
		LIST_INSERT_HEAD(&flock->domain->liturgies, entry, list);
	}

	if (entry->flags & SANCTUM_LITURGY_FLAG_SIGNALING)
		mode = "signaling";
	else
		mode = "discovery";

	if (entry->age == 0 || entry->group != group) {
		sanctum_log(LOG_INFO,
		    "%s liturgy for %s (%04x) (%d) (%u)",
		    mode, cathedral_tunnel_name(flock, flock, lit->id),
		    group, catacomb, lit->hidden);
	}

	entry->age = now;
	entry->group = group;
	entry->hidden = lit->hidden;

	entry->port = pkt->addr.sin_port;
	entry->ip = pkt->addr.sin_addr.s_addr;

	memcpy(entry->peers, lit->peers, sizeof(lit->peers));

	if (now >= entry->update &&
	    (lit->flags & SANCTUM_LITURGY_FLAG_REMEMBRANCE)) {
		entry->update = now + CATHEDRAL_REMEMBRANCE_NEXT;
		cathedral_remembrance_send(flock, &pkt->addr, id);
	}

	if (catacomb == 0) {
		if (entry->federated) {
			cathedral_peerstat_dec(&liturgies, 1);
			cathedral_peerstat_inc(&liturgies, 0);
		}

		entry->federated = 0;

		if (now >= entry->at) {
			entry->at = now + CATHEDRAL_FEDERATE_NEXT;
			cathedral_offer_federate(flock, flock, pkt);
			cathedral_liturgy_send(flock, entry, &pkt->addr, id);
		} else {
			sanctum_log(LOG_NOTICE,
			    "%s is sending liturgies too quickly",
			    cathedral_tunnel_name(flock, flock, lit->id));
		}
	} else {
		if (entry->federated == 0) {
			cathedral_peerstat_dec(&liturgies, 0);
			cathedral_peerstat_inc(&liturgies, 1);
		}

		entry->federated = 1;
	}
}

/*
 * We have received a p2p information offer about a sanctum instance.
 *
 * These offers may only be sent by cathedrals as part of the p2p_sync
 * setting. They carry information about a peer its external ip:port
 * that can be sent to other peers talking to it.
 *
 * We do not accept there if p2p_pending is not 1, this isn't a perfect
 * solution in any shape or form to prevent malicious cathedrals from
 * sending bad P2P_INFO which is then distributed to clients, but it's a start.
 *
 * Until I come up with a better mechanism, this is the lay of the land.
 */
static void
cathedral_offer_p2pinfo(struct sanctum_packet *pkt, struct flockent *flock,
    u_int64_t now, int catacomb)
{
	u_int32_t			id;
	u_int8_t			tid;
	struct sanctum_offer		*op;
	struct flockent			*dst;
	struct tunnel			*tun;
	struct sanctum_p2p_info_offer	*info;
	u_int64_t			flock_dst;

	PRECOND(pkt != NULL);
	PRECOND(flock != NULL);
	PRECOND(pkt->length >= sizeof(*op));
	PRECOND(catacomb == 1);

	op = sanctum_packet_head(pkt);
	VERIFY(op->data.type == SANCTUM_OFFER_TYPE_P2P_INFO);

	if (!(sanctum->flags & SANCTUM_FLAG_CATHEDRAL_P2P_SYNC))
		return;

	id = be32toh(op->hdr.spi);
	flock_dst = be64toh(op->hdr.flock_dst);

	info = &op->data.offer.p2pinfo;
	info->flags = be32toh(info->flags);
	info->tunnel = be16toh(info->tunnel);

	if (cathedral_forward_allowed(flock->id | flock->domain->id,
	    flock_dst, NULL, &dst) == -1)
		return;

	tid = info->tunnel >> 8;
	if (cathedral_tunnel_update_allowed(flock, tid, id, NULL) == -1) {
		sanctum_log(LOG_NOTICE, "%s is not tied to %08x",
		    cathedral_tunnel_name(flock, dst, info->tunnel), id);
		return;
	}

	if ((tun = cathedral_tunnel_lookup(flock, dst, info->tunnel)) == NULL) {
		sanctum_log(LOG_NOTICE, "p2pinfo for unknown tunnel %s",
		    cathedral_tunnel_name(flock, dst, info->tunnel));
		return;
	}

	if (tun->p2p_pending == 0) {
		sanctum_log(LOG_NOTICE, "out of order p2pinfo for %s",
		    cathedral_tunnel_name(flock, dst, info->tunnel));
		return;
	}

	if (tun->federated == 0) {
		sanctum_log(LOG_NOTICE, "p2pinfo for non-federated tunnel %s",
		    cathedral_tunnel_name(flock, dst, info->tunnel));
		return;
	}

	tun->p2p_pending = 0;
	tun->p2p_ip = info->ip;
	tun->p2p_port = info->port;
	tun->peerinfo = info->flags;
}

/*
 * Send out the offer inside of the given packet to all other cathedrals.
 */
static void
cathedral_offer_federate(struct flockent *flock, struct flockent *dst,
    struct sanctum_packet *update)
{
	struct sanctum_offer		*op;
	struct sanctum_packet		*pkt;
	u_int8_t			*ptr;
	struct sanctum_key		cipher;
	struct tunnel			*tunnel;

	PRECOND(flock != NULL);
	PRECOND(dst != NULL);
	PRECOND(update != NULL);

	if (update->length < sizeof(*op))
		fatal("%s: pkt length invalid (%zu)", __func__, update->length);

	/*
	 * We update the information in place without touching the data
	 * field as that is covered by the client signature.
	 *
	 * This is then re-encrypted with our synchronization key and
	 * sent to all cathedrals that are configured.
	 *
	 * We make sure to generate a new seed so malicious clients cannot
	 * control the outcome of our key derivation for federation.
	 */
	op = sanctum_packet_head(update);
	op->hdr.magic = htobe64(CATHEDRAL_CATACOMB_MAGIC);
	op->hdr.flock_dst = htobe64(dst->id | dst->domain->id);
	op->hdr.flock_src = htobe64(flock->id | flock->domain->id);
	sanctum_random_bytes(op->hdr.seed, sizeof(op->hdr.seed));

	nyfe_zeroize_register(&cipher, sizeof(cipher));

	if (sanctum_offer_kdf(sanctum->secret, SANCTUM_CATHEDRAL_CATACOMB_LABEL,
	    &cipher, op->hdr.seed, sizeof(op->hdr.seed),
	    flock->id | flock->domain->id, 0) == -1) {
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
 * Forward a key offer packet towards the correct peer using the
 * source and destination flock listed in the offer packet.
 *
 * Note that we currently just do an exhaustive search for
 * all the information we need here (flock, tunnels, etc).
 *
 * If it becomes apparent this is a bottle neck we can be
 * smarter about it, but until then this is fine.
 */
static int
cathedral_forward_offer(struct sanctum_packet *pkt, u_int32_t spi)
{
	u_int16_t			tid;
	struct sanctum_offer_hdr	*hdr;
	struct tunnel			*tunnel;
	struct flockent			*src, *dst;
	u_int8_t			src_id, dst_id;
	u_int64_t			flock_src, flock_dst;

	PRECOND(pkt != NULL);

	offers.pkts_in++;

	hdr = sanctum_packet_head(pkt);
	flock_src = be64toh(hdr->flock_src);
	flock_dst = be64toh(hdr->flock_dst);

	if (cathedral_forward_allowed(flock_src, flock_dst, &src, &dst) == -1)
		return (-1);

	tid = spi >> 16;
	if (cathedral_tunnel_lookup(src, dst, tid) == NULL) {
		sanctum_log(LOG_INFO, "sender %s not found for offer",
		    cathedral_tunnel_name(src, dst, tid));
		return (-1);
	}

	src_id = tid >> 8;
	dst_id = tid & 0xff;
	tid = ((u_int16_t)dst_id << 8) | src_id;

	if ((tunnel = cathedral_tunnel_lookup(dst, src, tid)) == NULL) {
		sanctum_log(LOG_INFO, "receiver %s not found for offer",
		    cathedral_tunnel_name(dst, src, tid));
		return (-1);
	}

	pkt->addr.sin_family = AF_INET;
	pkt->addr.sin_port = tunnel->port;
	pkt->addr.sin_addr.s_addr = tunnel->ip;

	pkt->target = SANCTUM_PROC_PURGATORY_TX;

	if (sanctum_ring_queue(io->purgatory, pkt) == -1)
		return (-1);

	offers.pkts_out++;
	offers.bytes += pkt->length;

	sanctum_proc_wakeup(SANCTUM_PROC_PURGATORY_TX);

	return (0);
}

/*
 * Forward the data packet towards the correct peer after applying
 * a bandwidth limitation on it. We use the flock source and
 * destination carried in the protocol header to figure
 * out what peer we forward it to.
 *
 * Note that we currently just do an exhaustive search for
 * all the information we need here (flock, tunnels, etc).
 *
 * If it becomes apparent this is a bottle neck we can be
 * smarter about it, but until then this is fine.
 */
static int
cathedral_forward_data(struct sanctum_packet *pkt, u_int32_t spi, u_int64_t now)
{
	u_int16_t			tid;
	struct sanctum_proto_hdr	*hdr;
	u_int32_t			drain;
	u_int64_t			delta;
	struct tunnel			*tunnel;
	struct flockent			*dst, *src;
	u_int64_t			flock_src, flock_dst;

	PRECOND(pkt != NULL);

	traffic.pkts_in++;

	hdr = sanctum_packet_head(pkt);
	flock_src = be64toh(hdr->flock.src);
	flock_dst = be64toh(hdr->flock.dst);

	if (cathedral_forward_allowed(flock_src, flock_dst, &src, &dst) == -1)
		return (-1);

	tid = spi >> 16;
	if ((tunnel = cathedral_tunnel_lookup(dst, src, tid)) == NULL) {
		sanctum_log(LOG_INFO, "receiver %s not found for traffic",
		    cathedral_tunnel_name(dst, src, tid));
		return (-1);
	}

	if (tunnel->rx_active != spi && tunnel->rx_pending != spi) {
		sanctum_log(LOG_INFO, "receiver %s has wrong spi for traffic",
		    cathedral_tunnel_name(dst, src, tid));
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

	traffic.pkts_out++;
	traffic.bytes += pkt->length;

	sanctum_proc_wakeup(SANCTUM_PROC_PURGATORY_TX);

	return (0);
}

/*
 * Check if we allow data to flow between flock_src and flock_dst.
 * If it turns out that we can forward data, we populate the src and
 * dst flocks so that the caller can use them.
 */
static int
cathedral_forward_allowed(u_int64_t flock_src, u_int64_t flock_dst,
    struct flockent **out_src, struct flockent **out_dst)
{
	struct xflock		*xfl;
	struct flockent		*src, *dst;

	if (out_src != NULL)
		*out_src = NULL;

	if (out_dst != NULL)
		*out_dst = NULL;

	if ((flock_src & CATHEDRAL_FLOCK_DOMAIN_MASK) !=
	    (flock_dst & CATHEDRAL_FLOCK_DOMAIN_MASK)) {
		sanctum_log(LOG_NOTICE,
		    "source and destination flock domains differ (%02x, %02x)",
		    (u_int8_t)(flock_src & CATHEDRAL_FLOCK_DOMAIN_MASK),
		    (u_int8_t)(flock_dst & CATHEDRAL_FLOCK_DOMAIN_MASK));
		return (-1);
	}

	if (flock_src != flock_dst) {
		xfl = cathedral_xflock_lookup(flock_src, flock_dst);
		if (xfl == NULL) {
			sanctum_log(LOG_NOTICE,
			    "xflock %" PRIx64 " <=> %" PRIx64 " not allowed",
			    flock_src, flock_dst);
			return (-1);
		}
	}

	if (out_src != NULL) {
		if ((src = cathedral_flock_lookup(flock_src)) == NULL) {
			sanctum_log(LOG_NOTICE,
			    "source flock %" PRIx64 " does not exist",
			    flock_src);
			return (-1);
		}

		*out_src = src;
	}

	if (out_dst != NULL) {
		if ((dst = cathedral_flock_lookup(flock_dst)) == NULL) {
			sanctum_log(LOG_NOTICE,
			    "destination flock %" PRIx64 " does not exist",
			    flock_dst);
			return (-1);
		}

		*out_dst = dst;
	}

	return (0);
}

/*
 * Find or create a tunnel entry for the given flock and tunnel.
 * Will return NULL if an entry is not found or cannot be created.
 */
static struct tunnel *
cathedral_tunnel_entry(struct flockent *flock, struct flockent *dst,
    struct sanctum_info_offer *info, u_int32_t id, u_int64_t now,
    int nat, int catacomb)
{
	u_int32_t		bw;
	u_int16_t		tid;
	struct tunnel		*tun;

	PRECOND(flock != NULL);
	PRECOND(dst != NULL);
	PRECOND(info != NULL);
	PRECOND(nat == 0 || nat == 1);
	PRECOND(catacomb == 0 || catacomb == 1);

	tid = info->tunnel >> 8;
	if (cathedral_tunnel_update_allowed(flock, tid, id, &bw) == -1) {
		sanctum_log(LOG_NOTICE, "%s is not tied to %08x",
		    cathedral_tunnel_name(flock, dst, tid), id);
		return (NULL);
	}

	if ((tun = cathedral_tunnel_lookup(flock, dst, info->tunnel)) != NULL)
		return (tun);

	if (nat) {
		sanctum_log(LOG_INFO, "%s NAT but no tunnel",
		    cathedral_tunnel_name(flock, dst, info->tunnel));
		return (NULL);
	}

	if ((tun = calloc(1, sizeof(*tun))) == NULL)
		fatal("calloc failed");

	tun->dst = dst->id | dst->domain->id;
	tun->src = flock->id | flock->domain->id;

	tun->update = now;
	tun->id = info->tunnel;
	tun->federated = catacomb;
	tun->instance = info->instance;
	tun->limit = (bw / 8) * 1024 * 1024;
	tun->drain_per_ms = tun->limit / 1000;

	cathedral_peerstat_inc(&peers, catacomb);
	LIST_INSERT_HEAD(&flock->domain->tunnels, tun, list);

	sanctum_log(LOG_INFO, "%s discovered (%u mbit/sec) (%d)",
	    cathedral_tunnel_name(flock, dst, info->tunnel), bw, catacomb);

	return (tun);
}

/*
 * See if we have peer information for the tunnel given in spi.
 */
static struct tunnel *
cathedral_tunnel_lookup(struct flockent *flock, struct flockent *target,
    u_int16_t id)
{
	struct tunnel		*tunnel;
	u_int64_t		src, dst;

	PRECOND(flock != NULL);
	PRECOND(target != NULL);
	PRECOND(flock->domain != NULL);

	src = flock->id | flock->domain->id;
	dst = target->id | target->domain->id;

	LIST_FOREACH(tunnel, &flock->domain->tunnels, list) {
		if (tunnel->src == src &&
		    tunnel->dst == dst && tunnel->id == id)
			return (tunnel);
	}

	return (NULL);
}

/*
 * Remove tunnels from the flock that are no longer configured.
 */
static void
cathedral_tunnel_prune(struct flockent *flock)
{
	const char		*name;
	struct allow		*allow;
	struct flockdom		*domain;
	struct tunnel		*tun, *next;

	PRECOND(flock != NULL);

	LIST_FOREACH(domain, &flock->domains, list) {
		for (tun = LIST_FIRST(&domain->tunnels);
		    tun != NULL; tun = next) {
			next = LIST_NEXT(tun, list);

			LIST_FOREACH(allow, &flock->allows, list) {
				if (allow->spi == tun->id >> 8)
					break;
			}

			name = cathedral_tunnel_name_id(tun->src,
			    tun->dst, tun->id >> 8);

			if (allow == NULL) {
				sanctum_log(LOG_INFO, "%s deleted", name);
				LIST_REMOVE(tun, list);
				free(tun);
			} else {
				sanctum_log(LOG_INFO, "%s retained", name);
			}
		}
	}
}

/*
 * Expire tunnel and liturgy entries that are too old and remove them
 * from the known list.
 */
static void
cathedral_tunnel_expire(struct flockent *flock, u_int64_t now)
{
	const char		*mode, *name;
	struct flockdom		*dom, *dom_next;
	struct tunnel		*tunnel, *tunnel_next;
	struct liturgy		*liturgy, *liturgy_next;

	PRECOND(flock != NULL);

	for (dom = LIST_FIRST(&flock->domains); dom != NULL; dom = dom_next) {
		dom_next = LIST_NEXT(dom, list);

		for (liturgy = LIST_FIRST(&dom->liturgies);
		    liturgy != NULL; liturgy = liturgy_next) {
			liturgy_next = LIST_NEXT(liturgy, list);

			if (liturgy->flags & SANCTUM_LITURGY_FLAG_SIGNALING)
				mode = "signaling";
			else
				mode = "discovery";

			if ((now - liturgy->age) >= CATHEDRAL_TUNNEL_MAX_AGE) {
				cathedral_peerstat_dec(&liturgies,
				    liturgy->federated);
				name = cathedral_tunnel_name(flock,
				    flock, liturgy->id);
				sanctum_log(LOG_INFO,
				    "%s liturgy %s (%02x) removed",
				    mode, name, liturgy->group);
				LIST_REMOVE(liturgy, list);
				free(liturgy);
			}
		}

		for (tunnel = LIST_FIRST(&dom->tunnels);
		    tunnel != NULL; tunnel = tunnel_next) {
			tunnel_next = LIST_NEXT(tunnel, list);

			if ((now - tunnel->age) >=
			    CATHEDRAL_TUNNEL_MAX_AGE) {
				cathedral_peerstat_dec(&peers,
				    tunnel->federated);
				name = cathedral_tunnel_name_id(tunnel->src,
				    tunnel->dst, tunnel->id);
				sanctum_log(LOG_INFO,
				    "tunnel %s removed", name);
				LIST_REMOVE(tunnel, list);
				free(tunnel);
			}
		}

		if (LIST_EMPTY(&dom->tunnels) &&
		    LIST_EMPTY(&dom->liturgies)) {
			LIST_REMOVE(dom, list);
			free(dom);
		}
	}
}

/*
 * Send the information required for both peers to establish a
 * connection towards each other, skipping the cathedral for traffic.
 */
static void
cathedral_info_send(struct flockent *flock, struct flockent *dst,
    struct sanctum_info_offer *info, struct sockaddr_in *sin, u_int32_t id)
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

	if ((peer = cathedral_tunnel_lookup(dst, flock, tunnel)) == NULL)
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

	if (cathedral_offer_send(flock, secret, pkt, sin) == -1)
		sanctum_packet_release(pkt);
}

/*
 * Send a liturgy offering to a client. In this message we will include
 * all peers in the same flock domain that are part of the same liturgy.
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
	int				visible, wanted;

	PRECOND(flock != NULL);
	PRECOND(src != NULL);
	PRECOND(sin != NULL);

	if ((pkt = sanctum_packet_get()) == NULL)
		return;

	op = sanctum_offer_init(pkt, id,
	    SANCTUM_CATHEDRAL_MAGIC, SANCTUM_OFFER_TYPE_LITURGY);

	lit = &op->data.offer.liturgy;
	lit->group = htobe16(src->group);

	LIST_FOREACH(entry, &flock->domain->liturgies, list) {
		if (entry == src)
			continue;

		if (src->hidden == 0 || entry->hidden == 0)
			visible = 1;
		else
			visible = 0;

		if ((entry->flags & SANCTUM_LITURGY_FLAG_SIGNALING) &&
		    (src->flags & SANCTUM_LITURGY_FLAG_SIGNALING)) {
			if (src->peers[entry->id] || entry->peers[src->id])
				wanted = 1;
			else
				wanted = 0;
		} else {
			wanted = 1;
		}

		if (entry->group == src->group && visible && wanted)
			lit->peers[entry->id] = 1;
	}

	cathedral_secret_path(secret, sizeof(secret), flock->id, id);

	if (cathedral_offer_send(flock, secret, pkt, sin) == -1)
		sanctum_packet_release(pkt);
}

/*
 * Send a list of all our currently configured federated cathedrals.
 * We include ourselves in this in the first slot of the response.
 */
static void
cathedral_remembrance_send(struct flockent *flock, struct sockaddr_in *sin,
    u_int32_t id)
{
	int					idx;
	struct sanctum_offer			*op;
	struct sanctum_packet			*pkt;
	struct sanctum_remembrance_offer	*list;
	struct tunnel				*cathedral;
	char					secret[1024];

	PRECOND(flock != NULL);
	PRECOND(sin != NULL);

	if ((pkt = sanctum_packet_get()) == NULL)
		return;

	op = sanctum_offer_init(pkt, id,
	    SANCTUM_CATHEDRAL_MAGIC, SANCTUM_OFFER_TYPE_REMEMBRANCE);

	idx = 1;
	list = &op->data.offer.remembrance;

	list->ports[0] = sanctum->local.sin_port;
	list->ips[0] = sanctum->local.sin_addr.s_addr;

	LIST_FOREACH(cathedral, &federations, list) {
		if (idx >= SANCTUM_CATHEDRALS_MAX)
			fatal("how did you configure too many cathedrals?");

		list->ips[idx] = cathedral->ip;
		list->ports[idx] = cathedral->port;

		idx++;
	}

	cathedral_secret_path(secret, sizeof(secret), flock->id, id);

	if (cathedral_offer_send(flock, secret, pkt, sin) == -1)
		sanctum_packet_release(pkt);
}

/*
 * Send a p2pinfo offer to all our federated cathedrals for the given tunnel.
 */
static void
cathedral_p2pinfo_send(struct flockent *flock, struct flockent *dst,
    struct tunnel *tun, u_int32_t id)
{
	struct sanctum_offer		*op;
	struct sanctum_packet		*pkt;
	struct sanctum_p2p_info_offer	*info;

	PRECOND(flock != NULL);
	PRECOND(dst != NULL);
	PRECOND(tun != NULL);

	if ((pkt = sanctum_packet_get()) == NULL)
		return;

	op = sanctum_offer_init(pkt, id,
	    CATHEDRAL_CATACOMB_MAGIC, SANCTUM_OFFER_TYPE_P2P_INFO);

	info = &op->data.offer.p2pinfo;
	info->tunnel = htobe16(tun->id);

	if (sanctum->flags & SANCTUM_FLAG_CATHEDRAL_P2P_SYNC) {
		info->ip = tun->ip;
		info->port = tun->port;
		info->flags = htobe32(tun->peerinfo);
	} else {
		info->ip = 0;
		info->port = 0;
		info->flags = 0;
	}

	pkt->length = sizeof(*op);

	cathedral_offer_federate(flock, dst, pkt);
	sanctum_packet_release(pkt);
}

/*
 * Check if we should send an ambry to the peer by checking if its
 * ambry generation mismatches from the one we have loaded.
 *
 * If it needs to be updated, we send the fresh wrapped ambry.
 */
static void
cathedral_ambry_send(struct flockent *flock, struct flockent *dst,
    struct sanctum_info_offer *info, struct sockaddr_in *s, u_int32_t id)
{
	struct sanctum_offer		*op;
	struct xflock			*xfl;
	struct sanctum_packet		*pkt;
	struct sanctum_ambry_offer	*offer;
	struct ambry			*ambry;
	struct ambries			*ambries;
	char				secret[1024];

	PRECOND(flock != NULL);
	PRECOND(dst != NULL);
	PRECOND(info != NULL);
	PRECOND(s != NULL);

	if (flock->id == dst->id) {
		ambries = &flock->ambries;
	} else {
		xfl = cathedral_xflock_lookup(flock->id, dst->id);
		if (xfl == NULL) {
			sanctum_log(LOG_NOTICE,
			    "no xflock %" PRIx64 " <=> %" PRIx64 " - ambry?",
			    flock->id, dst->id);
			return;
		}
		ambries = &xfl->ambries;
	}

	ambry = cathedral_ambry_find(ambries, flock->id, info->tunnel);
	if (ambry == NULL)
		return;

	if (info->ambry_generation == ambries->generation)
		return;

	if ((pkt = sanctum_packet_get()) == NULL)
		return;

	op = sanctum_offer_init(pkt, id,
	    SANCTUM_CATHEDRAL_MAGIC, SANCTUM_OFFER_TYPE_AMBRY);

	offer = &op->data.offer.ambry;
	offer->expires = htobe16(ambries->expires);
	offer->tunnel = htobe16(ambry->entry.tunnel);
	offer->generation = htobe32(ambries->generation);

	nyfe_memcpy(offer->key, ambry->entry.key, sizeof(offer->key));
	nyfe_memcpy(offer->tag, ambry->entry.tag, sizeof(offer->tag));
	nyfe_memcpy(offer->seed, ambries->seed, sizeof(ambries->seed));

	cathedral_secret_path(secret, sizeof(secret), flock->id, id);

	if (cathedral_offer_send(flock, secret, pkt, s) == -1)
		sanctum_packet_release(pkt);
}

/*
 * Lookup the flock for the given id, we explictly clear out the domain
 * bits so we can lookup the main flock. The returned flock has the
 * domain bits set inside of it, these are overwritten everytime
 * this is called with the correct bits so the rest of the code
 * following the cathedral_flock_lookup() call can use the
 * flockent data structure to refer to both id and domain.
 *
 * If the domain does not exist, an entry is explicitly created for it
 * which will automatically be expired once no more tunnels exist in it.
 */
static struct flockent *
cathedral_flock_lookup(u_int64_t id)
{
	struct flockdom		*dom;
	struct flockent		*flock;
	u_int8_t		domain;

	domain = id & CATHEDRAL_FLOCK_DOMAIN_MASK;
	id &= ~CATHEDRAL_FLOCK_DOMAIN_MASK;

	LIST_FOREACH(flock, &flocks, list) {
		if (flock->id == id) {
			LIST_FOREACH(dom, &flock->domains, list) {
				if (dom->id == domain) {
					flock->domain = dom;
					return (flock);
				}
			}

			if ((dom = calloc(1, sizeof(*dom))) == NULL)
				fatal("failed to allocate flockdom entry");

			dom->id = domain;
			LIST_INIT(&dom->tunnels);

			flock->domain = dom;
			LIST_INSERT_HEAD(&flock->domains, dom, list);

			return (flock);
		}
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
 * Clear all domains and their tunnels or liturgies.
 */
static void
cathedral_flock_domains_clear(struct flockent *flock)
{
	struct flockdom		*domain;

	while ((domain = LIST_FIRST(&flock->domains)) != NULL) {
		LIST_REMOVE(domain, list);
		cathedral_flock_domain_clear(domain);
		free(domain);
	}

	LIST_INIT(&flock->domains);
}

/*
 * Find an xflock for communication between two flocks.
 */
static struct xflock *
cathedral_xflock_lookup(u_int64_t flock_a, u_int64_t flock_b)
{
	struct xflock		*xfl;

	xfl = NULL;

	flock_a = flock_a & ~CATHEDRAL_FLOCK_DOMAIN_MASK;
	flock_b = flock_b & ~CATHEDRAL_FLOCK_DOMAIN_MASK;

	LIST_FOREACH(xfl, &xflocks, list) {
		if ((xfl->flock_a == flock_a && xfl->flock_b == flock_b) ||
		    (xfl->flock_a == flock_b && xfl->flock_b == flock_a))
			break;
	}

	return (xfl);
}

/*
 * Clear all all tunnels and liturgies from a flock domain.
 */
static void
cathedral_flock_domain_clear(struct flockdom *domain)
{
	struct tunnel		*tunnel;
	struct liturgy		*liturgy;

	PRECOND(domain != NULL);

	while ((tunnel = LIST_FIRST(&domain->tunnels)) != NULL) {
		cathedral_peerstat_dec(&peers, tunnel->federated);
		LIST_REMOVE(tunnel, list);
		free(tunnel);
	}

	while ((liturgy = LIST_FIRST(&domain->liturgies)) != NULL) {
		cathedral_peerstat_dec(&liturgies, liturgy->federated);
		LIST_REMOVE(liturgy, list);
		free(liturgy);
	}

	LIST_INIT(&domain->tunnels);
	LIST_INIT(&domain->liturgies);
}

/*
 * Find an ambry matching the given tunnel and flock.
 */
static struct ambry *
cathedral_ambry_find(struct ambries *ambries, u_int64_t src, u_int16_t tunnel)
{
	struct ambry		*ambry;

	PRECOND(ambries != NULL);

	src = src & ~CATHEDRAL_FLOCK_DOMAIN_MASK;

	if (ambries->flock_a != src && ambries->flock_b != src) {
		sanctum_log(LOG_NOTICE,
		    "invalid flock (%" PRIx64 ") for %" PRIx64 " <=> %" PRIx64,
		    src, ambries->flock_a, ambries->flock_b);
		return (NULL);
	}

	LIST_FOREACH(ambry, &ambries->entries, list) {
		if (ambry->entry.flock == src && ambry->entry.tunnel == tunnel)
			break;
	}

	if (ambry == NULL) {
		sanctum_log(LOG_NOTICE,
		    "no ambry found for %" PRIx64 " - %" PRIx64 " %04x",
		    ambries->flock_a, ambries->flock_b, tunnel);
		return (NULL);
	}

	return (ambry);
}

/*
 * Purge all ambries attached to the given cache.
 */
static void
cathedral_ambry_purge(struct ambries *ambries)
{
	struct ambry		*ambry;

	PRECOND(ambries != NULL);

	while ((ambry = LIST_FIRST(&ambries->entries)) != NULL) {
		LIST_REMOVE(ambry, list);
		nyfe_mem_zero(&ambry->entry, sizeof(ambry->entry));
		free(ambry);
	}

	LIST_INIT(&ambries->entries);
}

/*
 * Cache ambry entries under a flock or xflock. We purge any previously
 * cached entries if the ambry was actually updated.
 */
static void
cathedral_ambry_cache(const char *file, struct ambries *ambries)
{
	struct stat			st;
	size_t				ret;
	struct sanctum_ambry_head	hdr;
	struct sanctum_ambry_entry	entry;
	struct ambry			*ambry;
	int				fd, expected_len;

	PRECOND(file != NULL);
	PRECOND(ambries != NULL);

	if ((fd = sanctum_file_open(file, &st)) == -1) {
		sanctum_log(LOG_NOTICE,
		    "ambry '%s' cannot be opened", file);
		return;
	}

	if (ambries->flock_a == ambries->flock_b)
		expected_len = CATHEDRAL_AMBRY_BUNDLE_LEN;
	else
		expected_len = CATHEDRAL_AMBRY_INTERFLOCK_LEN;

	if (st.st_size != expected_len) {
		sanctum_log(LOG_NOTICE,
		    "ambry file '%s' has an abnormal size", file);
		goto out;
	}

	if (st.st_mtime == ambries->mtime)
		goto out;

	if (nyfe_file_read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
		sanctum_log(LOG_NOTICE,
		    "ambry file '%s' failed to read header", file);
		goto out;
	}

	hdr.expires = be16toh(hdr.expires);
	hdr.generation = be32toh(hdr.generation);

	if (hdr.generation == ambries->generation)
		goto out;

	cathedral_ambry_purge(ambries);

	if (sanctum_ambry_expired(hdr.expires) == -1) {
		sanctum_log(LOG_NOTICE, "ambry file '%s' has expired", file);
		goto out;
	}

	ambries->mtime = st.st_mtime;
	ambries->expires = hdr.expires;
	ambries->generation = hdr.generation;

	sanctum_log(LOG_INFO, "(re)caching ambry for %" PRIx64 " <=> %" PRIx64,
	    ambries->flock_a, ambries->flock_b);

	nyfe_memcpy(ambries->seed, hdr.seed, sizeof(hdr.seed));

	for (;;) {
		if ((ambry = calloc(1, sizeof(*ambry))) == NULL)
			fatal("calloc: failed to allocate ambry entry");

		ret = nyfe_file_read(fd, &ambry->entry, sizeof(ambry->entry));
		if (ret == 0) {
			free(ambry);
			break;
		}

		LIST_INSERT_HEAD(&ambries->entries, ambry, list);

		if (ret != sizeof(entry)) {
			sanctum_log(LOG_NOTICE,
			    "ambry file '%s' had partial entries, ignoring",
			    file);
			cathedral_ambry_purge(ambries);
			break;
		}

		ambry->entry.flock = be64toh(ambry->entry.flock);
		if (ambry->entry.flock != ambries->flock_a &&
		    ambry->entry.flock != ambries->flock_b) {
			sanctum_log(LOG_NOTICE,
			    "ambry file '%s' had bad flock, ignoring",
			    file);
			cathedral_ambry_purge(ambries);
			break;
		}

		ambry->entry.tunnel = be16toh(ambry->entry.tunnel);
	}

out:
	(void)close(fd);
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
 * Create the path to the public key for a peer using its flock and id.
 */
static void
cathedral_pubkey_path(char *buf, size_t buflen, u_int64_t flock, u_int32_t id)
{
	int		len;

	PRECOND(buf != NULL);
	PRECOND(buflen > 0);

	len = snprintf(buf, buflen, "%s/flock-%" PRIx64 "/%08x.pub",
	    sanctum->secretdir, flock, id);
	if (len == -1 || (size_t)len >= buflen)
		fatal("failed to construct path to pubkey");
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
	struct xflock		*xfl, *xnext;
	struct flockent		*flock, *fnext;
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

	LIST_FOREACH(xfl, &xflocks, list)
		xfl->retain = 0;

	while ((entry = LIST_FIRST(&federations)) != NULL) {
		LIST_REMOVE(entry, list);
		free(entry);
	}

	flock = NULL;
	federation_count = 0;
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
		} else if (!strcmp(kw, "xflock")) {
			cathedral_settings_xflock(option);
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

	for (xfl = LIST_FIRST(&xflocks); xfl != NULL; xfl = xnext) {
		xnext = LIST_NEXT(xfl, list);

		if (xfl->retain) {
			sanctum_log(LOG_INFO,
			    "xflock %" PRIx64 " <=> %" PRIx64 " retained",
			    xfl->flock_a, xfl->flock_b);
			continue;
		}

		sanctum_log(LOG_INFO,
		    "xflock %" PRIx64 " <=> %" PRIx64 " is gone",
		    xfl->flock_a, xfl->flock_b);

		LIST_REMOVE(xfl, list);

		cathedral_ambry_purge(&xfl->ambries);

		free(xfl);
	}

	for (flock = LIST_FIRST(&flocks); flock != NULL; flock = fnext) {
		fnext = LIST_NEXT(flock, list);

		if (flock->retain) {
			sanctum_log(LOG_INFO, "flock %" PRIx64 " retained",
			    flock->id);
			cathedral_tunnel_prune(flock);
			continue;
		}

		sanctum_log(LOG_INFO, "flock %" PRIx64 " is gone", flock->id);

		LIST_REMOVE(flock, list);

		cathedral_flock_allows_clear(flock);
		cathedral_flock_domains_clear(flock);
		cathedral_ambry_purge(&flock->ambries);

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

	if (federation_count >= SANCTUM_CATHEDRALS_MAX - 1) {
		sanctum_log(LOG_NOTICE, "too many configured federations");
		return;
	}

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

	federation_count++;
	LIST_INSERT_HEAD(&federations, tunnel, list);
}

/*
 * Allow xflock communication between the two given flocks using
 * ambries in the file that was specified.
 */
static void
cathedral_settings_xflock(const char *option)
{
	struct xflock		*xfl;
	char			path[1024];
	u_int64_t		flock_a, flock_b;

	PRECOND(option != NULL);

	if (sscanf(option, "%" PRIx64 " %" PRIx64 " %1023s",
	    &flock_a, &flock_b, path) != 3) {
		sanctum_log(LOG_NOTICE, "xflock '%s' is invalid", option);
		return;
	}

	if (cathedral_flock_lookup(flock_a) == NULL) {
		sanctum_log(LOG_NOTICE,
		    "xflock flock %" PRIx64 " does not exist", flock_a);
		return;
	}

	if (cathedral_flock_lookup(flock_b) == NULL) {
		sanctum_log(LOG_NOTICE,
		    "xflock flock %" PRIx64 " does not exist", flock_b);
		return;
	}

	if ((xfl = cathedral_xflock_lookup(flock_a, flock_b)) == NULL) {
		if ((xfl = calloc(1, sizeof(*xfl))) == NULL)
			fatal("calloc: failed to allocate new xflock");

		xfl->flock_a = flock_a;
		xfl->flock_b = flock_b;

		xfl->ambries.flock_a = xfl->flock_a;
		xfl->ambries.flock_b = xfl->flock_b;

		LIST_INIT(&xfl->ambries.entries);

		LIST_INSERT_HEAD(&xflocks, xfl, list);
	}

	xfl->retain = 1;
	cathedral_ambry_cache(path, &xfl->ambries);
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

	id = id & ~(CATHEDRAL_FLOCK_DOMAIN_MASK);
	if ((flock = cathedral_flock_lookup(id)) != NULL) {
		flock->retain = 1;
		cathedral_flock_allows_clear(flock);
	} else {
		if ((flock = calloc(1, sizeof(*flock))) == NULL)
			fatal("calloc: failed");

		flock->id = id;
		flock->retain = 1;

		flock->ambries.flock_a = flock->id;
		flock->ambries.flock_b = flock->id;

		LIST_INIT(&flock->allows);
		LIST_INIT(&flock->domains);
		LIST_INIT(&flock->ambries.entries);

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
cathedral_settings_ambry(const char *file, struct flockent *flock)
{
	PRECOND(file != NULL);

	if (flock == NULL) {
		sanctum_log(LOG_NOTICE, "ambry not inside of a flock config");
		return;
	}

	cathedral_ambry_cache(file, &flock->ambries);
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

/*
 * Create a tunnel name based on the given src flock, dst flock and tunnel id.
 */
static const char *
cathedral_tunnel_name(struct flockent *src, struct flockent *dst, u_int16_t tun)
{
	u_int64_t	src_id, dst_id;

	PRECOND(src != NULL);
	PRECOND(dst != NULL);

	src_id = src->id | src->domain->id;
	dst_id = dst->id | dst->domain->id;

	return (cathedral_tunnel_name_id(src_id, dst_id, tun));
}

/*
 * Create a tunnel name based on the given src flock, dst flock and tunnel id.
 */
static const char *
cathedral_tunnel_name_id(u_int64_t src, u_int64_t dst, u_int16_t tun)
{
	int		len;
	static char	buf[64];

	len = snprintf(buf, sizeof(buf),
	    "%" PRIx64 "-%" PRIx64 ":%04x", src, dst, tun);
	if (len == -1 || (size_t)len >= sizeof(buf))
		fatal("failed to create tunnel name");

	return (buf);
}

/*
 * Increment the given peerstat counter, either the local one
 * or the federated one depending on catacomb.
 */
static void
cathedral_peerstat_inc(struct peerstat *ps, int catacomb)
{
	PRECOND(ps != NULL);
	PRECOND(catacomb == 0 || catacomb == 1);

	if (catacomb)
		ps->federated++;
	else
		ps->local++;
}

/*
 * Decrement the given peerstat counter, either the local one
 * or the federated one depending on catacomb.
 */
static void
cathedral_peerstat_dec(struct peerstat *ps, int catacomb)
{
	PRECOND(ps != NULL);
	PRECOND(catacomb == 0 || catacomb == 1);

	if (catacomb)
		ps->federated--;
	else
		ps->local--;
}

/*
 * Log our current status.
 */
static void
cathedral_status_log(void)
{
	sanctum_log(LOG_INFO, "peer-stat local=%u federated=%u",
	    peers.local, peers.federated);

	sanctum_log(LOG_INFO, "liturgy-stat local=%u federated=%u",
	    liturgies.local, liturgies.federated);

	sanctum_log(LOG_INFO,
	    "traffic-stat in=%" PRIu64 " out=%" PRIu64 " fwd=%" PRIu64,
	    traffic.pkts_in, traffic.pkts_out, traffic.bytes);

	sanctum_log(LOG_INFO,
	    "offer-stat in=%" PRIu64 " out=%" PRIu64 " fwd=%" PRIu64,
	    offers.pkts_in, offers.pkts_out, offers.bytes);
}

/*
 * Reset status counters.
 */
static void
cathedral_status_reset(void)
{
	traffic.bytes = 0;
	traffic.pkts_in = 0;
	traffic.pkts_out = 0;

	offers.bytes = 0;
	offers.pkts_in = 0;
	offers.pkts_out = 0;

	sanctum_log(LOG_INFO, "traffic-stat and offer-stat reset");
}
