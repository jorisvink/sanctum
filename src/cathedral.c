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
#include <sys/stat.h>

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
	int			federated;
	LIST_ENTRY(tunnel)	list;
};

/*
 * A mapping of a secret key id that is used by an endpoint to send us
 * updates and the spis they are allowed to send updates for.
 */
struct allow {
	u_int32_t		id;
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

static void	cathedral_ambries_clear(void);
static void	cathedral_secret_path(char *, size_t, u_int32_t);

static void	cathedral_settings_reload(void);
static void	cathedral_settings_allow(const char *);
static void	cathedral_settings_ambry(const char *);
static void	cathedral_settings_federate_to(const char *);

static void	cathedral_packet_handle(struct sanctum_packet *, u_int64_t);

static void	cathedral_tunnel_expire(u_int64_t);
static void	cathedral_tunnel_federate(struct sanctum_packet *);
static int	cathedral_tunnel_forward(struct sanctum_packet *, u_int32_t);

static void	cathedral_tunnel_p2p(struct sockaddr_in *,
		    struct tunnel *, u_int32_t);
static void	cathedral_tunnel_update(struct sanctum_packet *,
		    u_int64_t, int);
static void	cathedral_tunnel_ambry(struct sockaddr_in *, struct ambry *,
		    u_int32_t);

/* The local queues. */
static struct sanctum_proc_io	*io = NULL;

/* The list of tunnel endpoints we know. */
static LIST_HEAD(, tunnel)	tunnels;

/* The list of federation cathedrals we can forward too. */
static LIST_HEAD(, tunnel)	federations;

/* The list of allowed id -> spi mappings. */
static LIST_HEAD(, allow)	allowlist;

/* The list of ambries that we have loaded in. */
static LIST_HEAD(, ambry)	ambries;

/* The current ambry generation. */
static u_int32_t		ambry_generation = 0;

/*
 * Cathedral - The place packets all meet and get exchanged.
 *
 * When running as a cathedral, we receive packets immediately
 * from the purgatory side. We check if we know the tunnel encoded inside
 * of the esp header and forward the packet to the correct endpoint.
 *
 * The cathedral can also send the endpoint its ambry for the tunnel.
 */
void
sanctum_cathedral(struct sanctum_proc *proc)
{
	struct sanctum_packet	*pkt;
	int			sig, running;
	u_int64_t		now, next_expire;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);
	PRECOND(sanctum->mode == SANCTUM_MODE_CATHEDRAL);

	nyfe_random_init();
	io = proc->arg;

	sanctum_signal_trap(SIGHUP);
	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	LIST_INIT(&ambries);
	LIST_INIT(&tunnels);
	LIST_INIT(&allowlist);
	LIST_INIT(&federations);

	sanctum_proc_privsep(proc);
	sanctum_platform_sandbox(proc);
	cathedral_settings_reload();

	running = 1;
	next_expire = 0;

	while (running) {
		if ((sig = sanctum_last_signal()) != -1) {
			sanctum_log(LOG_NOTICE, "received signal %d", sig);
			switch (sig) {
			case SIGQUIT:
				running = 0;
				continue;
			case SIGHUP:
				cathedral_settings_reload();
				break;
			}
		}

		sanctum_proc_suspend(1);
		now = sanctum_atomic_read(&sanctum->uptime);

		if (now >= next_expire) {
			next_expire = now + 10;
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
	u_int32_t			spi;
	struct sanctum_offer		*op;
	u_int16_t			tun;
	struct sanctum_info_offer	*info;
	struct nyfe_agelas		cipher;
	struct ambry			*ambry;
	const char			*label;
	struct tunnel			*tunnel;
	struct allow			*allow;
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
		cathedral_secret_path(path, sizeof(path), spi);
		secret = path;
		label = SANCTUM_CATHEDRAL_KDF_LABEL;
	}

	/* Derive the key we should use. */
	nyfe_zeroize_register(&cipher, sizeof(cipher));
	if (sanctum_cipher_kdf(secret, label, &cipher,
	    op->hdr.seed, sizeof(op->hdr.seed)) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		return;
	}

	/* Verify and decrypt the offer. */
	if (sanctum_offer_decrypt(&cipher, op, SANCTUM_OFFER_VALID) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		return;
	}

	nyfe_zeroize(&cipher, sizeof(cipher));

	/* Verify the type of offer we received. */
	if (op->data.type != SANCTUM_OFFER_TYPE_INFO)
		return;

	info = &op->data.offer.info;
	info->tunnel = be16toh(info->tunnel);
	info->ambry_generation = be32toh(info->ambry_generation);

	/* Verify that this key is allowed to update this entry. */
	LIST_FOREACH(allow, &allowlist, list) {
		if (allow->id == spi && (allow->spi == info->tunnel >> 8))
			break;
	}

	if (allow == NULL) {
		sanctum_log(LOG_NOTICE, "0x%x tried updating id 0x%x (%d)",
		    spi, info->tunnel >> 8, catacomb);
		return;
	}

	/* Check if we can and should send an ambry. */
	if (catacomb == 0 && info->ambry_generation != ambry_generation) {
		LIST_FOREACH(ambry, &ambries, list) {
			if (info->tunnel == ambry->entry.tunnel) {
				cathedral_tunnel_ambry(&pkt->addr, ambry, spi);
				break;
			}
		}
	}

	/* Let the endpoint know its peer its public ip:port, if we have it. */
	if (catacomb == 0) {
		tun = (info->tunnel & 0x00ff) << 8 | (info->tunnel >> 8);
		LIST_FOREACH(tunnel, &tunnels, list) {
			if (tunnel->id == tun)
				break;
		}

		/* Do not send peer info if its federated for now. */
		if (tunnel != NULL && tunnel->federated)
			tunnel = NULL;

		cathedral_tunnel_p2p(&pkt->addr, tunnel, spi);
	}

	/* Check if the tunnel exists, if it does we update the endpoint. */
	LIST_FOREACH(tunnel, &tunnels, list) {
		if (tunnel->id == info->tunnel) {
			tunnel->age = now;
			tunnel->port = pkt->addr.sin_port;
			tunnel->ip = pkt->addr.sin_addr.s_addr;
			if (catacomb == 0)
				cathedral_tunnel_federate(pkt);
			else
				tunnel->federated = 1;
			return;
		}
	}

	/* Nope, we add a new entry instead. */
	if ((tunnel = calloc(1, sizeof(*tunnel))) == NULL)
		fatal("calloc failed");

	tunnel->age = now;
	tunnel->id = info->tunnel;
	tunnel->port = pkt->addr.sin_port;
	tunnel->ip = pkt->addr.sin_addr.s_addr;

	LIST_INSERT_HEAD(&tunnels, tunnel, list);
	sanctum_log(LOG_INFO, "new tunnel 0x%04x discovered", tunnel->id);

	if (catacomb == 0)
		cathedral_tunnel_federate(pkt);
	else
		tunnel->federated = 1;
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

			pkt->target = SANCTUM_PROC_PURGATORY_TX;

			if (sanctum_ring_queue(io->purgatory, pkt) == -1)
				return (-1);

			sanctum_proc_wakeup(SANCTUM_PROC_PURGATORY_TX);
			return (0);
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
	struct sanctum_info_offer	*info;
	struct nyfe_agelas		cipher;
	struct tunnel			*tunnel;

	PRECOND(update != NULL);

	if (update->length != sizeof(*op))
		fatal("%s: pkt length invalid (%zu)", __func__, update->length);

	op = sanctum_packet_head(update);

	/* Set header to our own. */
	op->hdr.magic = htobe64(CATHEDRAL_CATACOMB_MAGIC);
	nyfe_random_bytes(op->hdr.seed, sizeof(op->hdr.seed));

	/* Update in the current timestamp. */
	(void)clock_gettime(CLOCK_REALTIME, &ts);
	op->data.timestamp = htobe64((u_int64_t)ts.tv_sec);

	/* Make sure we revert the tunnel back. */
	info = &op->data.offer.info;
	info->tunnel = htobe16(info->tunnel);

	/* Derive the key we should use. */
	nyfe_zeroize_register(&cipher, sizeof(cipher));
	if (sanctum_cipher_kdf(sanctum->secret, CATHEDRAL_CATACOMB_LABEL,
	    &cipher, op->hdr.seed, sizeof(op->hdr.seed)) == -1) {
		nyfe_zeroize(&cipher, sizeof(cipher));
		return;
	}

	/* Encrypt and authenticate entire message. */
	sanctum_offer_encrypt(&cipher, op);
	nyfe_zeroize(&cipher, sizeof(cipher));

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
		pkt->target = SANCTUM_PROC_PURGATORY_TX;

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
 * Send connection information to the endpoint, if peer is NULL we do not
 * know yet where its peer is located.
 */
static void
cathedral_tunnel_p2p(struct sockaddr_in *sin, struct tunnel *peer, u_int32_t id)
{
	struct timespec			ts;
	struct sanctum_offer		*op;
	struct sanctum_packet		*pkt;
	struct sanctum_info_offer	*info;
	struct nyfe_agelas		cipher;
	char				path[1024];

	PRECOND(sin != NULL);
	/* peer may be NULL. */

	if ((pkt = sanctum_packet_get()) == NULL)
		return;

	/* Get path to the cathedral secret for the client. */
	cathedral_secret_path(path, sizeof(path), id);

	/* We send the ambry with the magic set to KATEDRAL. */
	op = sanctum_packet_head(pkt);
	op->hdr.spi = htobe32(id);
	op->hdr.magic = htobe64(SANCTUM_CATHEDRAL_MAGIC);
	nyfe_random_bytes(op->hdr.seed, sizeof(op->hdr.seed));

	/*
	 * Add both the local and remote connection information.
	 * We may not have the remote yet however.
	 */
	op->data.type = SANCTUM_OFFER_TYPE_INFO;
	info = &op->data.offer.info;

	info->local_port = sin->sin_port;
	info->local_ip = sin->sin_addr.s_addr;

	if (peer != NULL) {
		info->peer_ip = peer->ip;
		info->peer_port = peer->port;
	}

	/* Update in the current timestamp. */
	(void)clock_gettime(CLOCK_REALTIME, &ts);
	op->data.timestamp = htobe64((u_int64_t)ts.tv_sec);

	/* Derive the key we should use. */
	nyfe_zeroize_register(&cipher, sizeof(cipher));
	if (sanctum_cipher_kdf(path, SANCTUM_CATHEDRAL_KDF_LABEL,
	    &cipher, op->hdr.seed, sizeof(op->hdr.seed)) == -1) {
		sanctum_packet_release(pkt);
		nyfe_zeroize(&cipher, sizeof(cipher));
		return;
	}

	/* Encrypt and authenticate entire message. */
	sanctum_offer_encrypt(&cipher, op);
	nyfe_zeroize(&cipher, sizeof(cipher));

	/* Submit it into purgatory. */
	pkt->length = sizeof(*op);
	pkt->target = SANCTUM_PROC_PURGATORY_TX;

	pkt->addr.sin_family = AF_INET;
	pkt->addr.sin_port = sin->sin_port;
	pkt->addr.sin_addr.s_addr = sin->sin_addr.s_addr;

	if (sanctum_ring_queue(io->purgatory, pkt) == -1) {
		sanctum_packet_release(pkt);
	} else {
		sanctum_proc_wakeup(SANCTUM_PROC_PURGATORY_TX);
	}
}

/*
 * Send an endpoint its wrapped ambry so it can use it for
 * session establishment with its peer.
 *
 * We encrypt the ambry entry with the key we share with the endpoint.
 */
static void
cathedral_tunnel_ambry(struct sockaddr_in *s, struct ambry *ambry, u_int32_t id)
{
	struct timespec			ts;
	struct sanctum_offer		*op;
	struct sanctum_packet		*pkt;
	struct sanctum_ambry_offer	*offer;
	struct nyfe_agelas		cipher;
	char				path[1024];

	PRECOND(s != NULL);
	PRECOND(ambry != NULL);

	if ((pkt = sanctum_packet_get()) == NULL)
		return;

	/* Get path to the cathedral secret for the client. */
	cathedral_secret_path(path, sizeof(path), id);

	/* We send the ambry with the magic set to KATEDRAL. */
	op = sanctum_packet_head(pkt);
	op->hdr.spi = htobe32(id);
	op->hdr.magic = htobe64(SANCTUM_CATHEDRAL_MAGIC);
	nyfe_random_bytes(op->hdr.seed, sizeof(op->hdr.seed));

	/* Copy the ambry information. */
	op->data.type = SANCTUM_OFFER_TYPE_AMBRY;
	offer = &op->data.offer.ambry;

	offer->tunnel = htobe16(ambry->entry.tunnel);
	offer->generation = htobe32(ambry_generation);

	nyfe_memcpy(offer->key, ambry->entry.key, sizeof(offer->key));
	nyfe_memcpy(offer->tag, ambry->entry.tag, sizeof(offer->tag));
	nyfe_memcpy(offer->seed, ambry->entry.seed, sizeof(offer->seed));

	/* Add in the current timestamp. */
	(void)clock_gettime(CLOCK_REALTIME, &ts);
	op->data.timestamp = htobe64((u_int64_t)ts.tv_sec);

	/* Derive the key we should use. */
	nyfe_zeroize_register(&cipher, sizeof(cipher));
	if (sanctum_cipher_kdf(path, SANCTUM_CATHEDRAL_KDF_LABEL,
	    &cipher, op->hdr.seed, sizeof(op->hdr.seed)) == -1) {
		sanctum_packet_release(pkt);
		nyfe_zeroize(&cipher, sizeof(cipher));
		return;
	}

	/* Encrypt and authenticate entire message. */
	sanctum_offer_encrypt(&cipher, op);
	nyfe_zeroize(&cipher, sizeof(cipher));

	/* Submit it into purgatory. */
	pkt->length = sizeof(*op);
	pkt->target = SANCTUM_PROC_PURGATORY_TX;

	pkt->addr.sin_family = AF_INET;
	pkt->addr.sin_port = s->sin_port;
	pkt->addr.sin_addr.s_addr = s->sin_addr.s_addr;

	if (sanctum_ring_queue(io->purgatory, pkt) == -1) {
		sanctum_packet_release(pkt);
	} else {
		sanctum_proc_wakeup(SANCTUM_PROC_PURGATORY_TX);
		sanctum_log(LOG_INFO, "ambry update for tunnel 0x%04x (0x%x)",
		    ambry->entry.tunnel, id);
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
 * Create the path to a cathedral secret for the given id.
 */
static void
cathedral_secret_path(char *buf, size_t buflen, u_int32_t id)
{
	int		len;

	PRECOND(buf != NULL);
	PRECOND(buflen > 0);

	len = snprintf(buf, buflen, "%s/0x%x.key", sanctum->secretdir, id);
	if (len == -1 || (size_t)len >= buflen)
		fatal("failed to construct path to secret");
}

/*
 * Reload the settings from disk and apply them to the cathedral.
 */
static void
cathedral_settings_reload(void)
{
	FILE			*fp;
	struct allow		*allow;
	struct tunnel		*tunnel;
	char			buf[256], *kw, *option;

	if (sanctum->settings == NULL)
		return;

	if ((fp = fopen(sanctum->settings, "r")) == NULL) {
		sanctum_log(LOG_NOTICE, "failed to open '%s': %s",
		    sanctum->settings, errno_s);
		return;
	}

	while ((tunnel = LIST_FIRST(&federations)) != NULL) {
		LIST_REMOVE(tunnel, list);
		free(tunnel);
	}

	while ((allow = LIST_FIRST(&allowlist)) != NULL) {
		LIST_REMOVE(allow, list);
		free(allow);
	}

	cathedral_ambries_clear();

	LIST_INIT(&ambries);
	LIST_INIT(&allowlist);
	LIST_INIT(&federations);

	while ((kw = sanctum_config_read(fp, buf, sizeof(buf))) != NULL) {
		if (strlen(kw ) == 0)
			continue;

		if ((option = strchr(kw, ' ')) == NULL) {
			sanctum_log(LOG_NOTICE,
			    "format error '%s' in settings", kw);
			continue;
		}

		*(option)++ = '\0';

		if (!strcmp(kw, "federate-to")) {
			cathedral_settings_federate_to(option);
		} else if (!strcmp(kw, "allow")) {
			cathedral_settings_allow(option);
		} else if (!strcmp(kw, "ambry")) {
			cathedral_settings_ambry(option);
		} else {
			sanctum_log(LOG_NOTICE,
			    "unknown keyword '%s' in settings", kw);
		}
	}

	sanctum_log(LOG_INFO, "settings reloaded");

	(void)fclose(fp);
}

/*
 * Adds a new federation to the cathedral.
 */
static void
cathedral_settings_federate_to(const char *option)
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

	if ((tunnel = calloc(1, sizeof(*tunnel))) == NULL)
		fatal("calloc: failed to allocate federation");

	tunnel->port = htobe16(port);
	tunnel->ip = sin.sin_addr.s_addr;

	LIST_INSERT_HEAD(&federations, tunnel, list);

	sanctum_log(LOG_INFO, "federation-to %s:%u", ip, port);
}

/*
 * Adds a new allow for a key ID and tunnel SPI.
 */
static void
cathedral_settings_allow(const char *option)
{
	u_int32_t	id;
	u_int8_t	spi;
	struct allow	*allow;

	PRECOND(option != NULL);

	if (sscanf(option, "%x spi %hhx", &id, &spi) != 2) {
		sanctum_log(LOG_NOTICE,
		    "format error '%s' in allow", option);
		return;
	}

	if ((allow = calloc(1, sizeof(*allow))) == NULL)
		fatal("calloc: failed to allocate allow entry");

	allow->id = id;
	allow->spi = spi;

	LIST_INSERT_HEAD(&allowlist, allow, list);

	sanctum_log(LOG_INFO, "allow id=0x%02x for id=0x%02x", id, spi);
}

/*
 * Load the ambry file containing wrapped secrets for clients.
 */
static void
cathedral_settings_ambry(const char *option)
{
	int				fd;
	struct stat			st;
	struct sanctum_ambry_head	hdr;
	struct sanctum_ambry_entry	entry;
	struct ambry			*ambry;
	size_t				len, count, ret;

	PRECOND(option != NULL);

	count = 0;
	if ((fd = sanctum_file_open(option)) == -1)
		return;

	if (fstat(fd, &st) == -1) {
		sanctum_log(LOG_NOTICE, "fstat on ambry file '%s' failed (%s)",
		    option, errno_s);
		goto out;
	}

	len = st.st_size;

	if (len < sizeof(hdr)) {
		sanctum_log(LOG_NOTICE, "ambry file has an abnormal size");
		goto out;
	}

	if (nyfe_file_read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
		sanctum_log(LOG_NOTICE, "failed to read ambry header");
		goto out;
	}

	ambry_generation = be32toh(hdr.generation);
	len -= sizeof(hdr);

	if ((len % sizeof(entry)) != 0) {
		sanctum_log(LOG_NOTICE, "ambry file has an abnormal size");
		goto out;
	}

	for (;;) {
		if ((ambry = calloc(1, sizeof(*ambry))) == NULL)
			fatal("calloc: failed to allocate ambry entry");

		ret = nyfe_file_read(fd, &ambry->entry, sizeof(ambry->entry));
		if (ret == 0) {
			free(ambry);
			break;
		}

		LIST_INSERT_HEAD(&ambries, ambry, list);

		if (ret != sizeof(entry)) {
			sanctum_log(LOG_NOTICE,
			    "ambry file had partial entries, ignoring file");
			cathedral_ambries_clear();
			break;
		}

		count++;
	}

	sanctum_log(LOG_INFO, "loaded %zu ambries, generation 0x%x",
	    count, ambry_generation);

out:
	(void)close(fd);
}

/*
 * Clear all ambries from memory.
 */
static void
cathedral_ambries_clear(void)
{
	struct ambry	*ambry;

	while ((ambry = LIST_FIRST(&ambries)) != NULL) {
		LIST_REMOVE(ambry, list);
		nyfe_mem_zero(&ambry->entry, sizeof(ambry->entry));
		free(ambry);
	}
}
