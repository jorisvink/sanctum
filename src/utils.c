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
#include <sys/shm.h>
#include <sys/ioctl.h>
#include <sys/un.h>

#include <arpa/inet.h>

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "sanctum.h"

/*
 * Log a message to either stdout or sanctum_log, prio is sanctum_log level.
 */
void
sanctum_log(int prio, const char *fmt, ...)
{
	va_list		args;

	PRECOND(prio >= 0);
	PRECOND(fmt != NULL);

	va_start(args, fmt);
	sanctum_logv(prio, fmt, args);
	va_end(args);
}

/*
 * Log a message to either stdout or sanctum_log, prio is sanctum_log level.
 */
void
sanctum_logv(int prio, const char *fmt, va_list args)
{
	struct timespec		ts;
	struct tm		*t;
	struct sanctum_proc	*proc;
	char			tbuf[32];

	PRECOND(prio >= 0);
	PRECOND(fmt != NULL);

	if (sanctum->flags & SANCTUM_FLAG_DAEMONIZED) {
		vsyslog(prio, fmt, args);
	} else {
		(void)clock_gettime(CLOCK_REALTIME, &ts);
		t = gmtime(&ts.tv_sec);

		if (strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", t) > 0)
			printf("%s.%03ld UTC ", tbuf, ts.tv_nsec / 1000000);

		if ((proc = sanctum_process()) != NULL)
			printf("[%s]: ", proc->name);
		else
			printf("[guardian]: ");

		vprintf(fmt, args);
		printf("\n");
		fflush(stdout);
	}
}

/*
 * Update the address of the peer if it does not match with the
 * one from the packet.
 *
 * If we're using a cathedral, do not allow a swap back to the cathedral
 * until a the required time has passed.
 *
 * This MUST ONLY be called AFTER integrity has been verified.
 */
void
sanctum_peer_update(u_int32_t ip, u_int16_t port)
{
	struct in_addr		in;
	u_int32_t		local;
	u_int64_t		now, next;

	local = sanctum_atomic_read(&sanctum->local_ip);
	if (local == ip)
		return;

	if (sanctum->flags & SANCTUM_FLAG_CATHEDRAL_ACTIVE) {
		now = sanctum_atomic_read(&sanctum->uptime);
		next = sanctum_atomic_read(&sanctum->peer_update);

		if (ip == sanctum->cathedral.sin_addr.s_addr) {
			if (next != 0 && now < next)
				return;
			sanctum_atomic_write(&sanctum->peer_update, 0);
		} else {
			sanctum_atomic_write(&sanctum->peer_update, now + 10);
		}
	}

	if (ip != sanctum->peer_ip || port != sanctum->peer_port) {
		in.s_addr = ip;
		sanctum_log(LOG_NOTICE, "peer address change (new=%s:%u)",
		    inet_ntoa(in), ntohs(port));

		sanctum_atomic_write(&sanctum->peer_ip, ip);
		sanctum_atomic_write(&sanctum->peer_port, port);
	}
}

/*
 * Erase the given sa if the key says it was erased.
 */
int
sanctum_key_erase(const char *s, struct sanctum_key *key, struct sanctum_sa *sa)
{
	int		ret;

	PRECOND(s != NULL);
	PRECOND(key != NULL);
	PRECOND(sa != NULL);

	if (!sanctum_atomic_cas_simple(&key->state,
	    SANCTUM_KEY_ERASE, SANCTUM_KEY_INSTALLING))
		return (-1);

	if (sa->spi == key->spi) {
		sanctum_sa_clear(sa);
		sanctum_log(LOG_NOTICE,
		    "%s SA erased (spi=0x%08x)", s, key->spi);

		ret = 0;
		if (!sanctum_atomic_cas_simple(&key->state,
		    SANCTUM_KEY_INSTALLING, SANCTUM_KEY_EMPTY))
			fatal("failed to swap key state to empty");
	} else {
		ret = -1;
		if (!sanctum_atomic_cas_simple(&key->state,
		    SANCTUM_KEY_INSTALLING, SANCTUM_KEY_ERASE))
			fatal("failed to swap key state to erasing");
	}

	return (ret);
}

/*
 * Install the key pending under the given `key` data structure into
 * the SA context `sa`.
 *
 * This is called from the bless or confess processes only.
 */
int
sanctum_key_install(struct sanctum_key *key, struct sanctum_sa *sa)
{
	struct sanctum_proc	*proc;

	PRECOND(key != NULL);
	PRECOND(sa != NULL);

	proc = sanctum_process();
	VERIFY(proc->type == SANCTUM_PROC_BLESS ||
	    proc->type == SANCTUM_PROC_CONFESS);

	if (sanctum_atomic_read(&key->state) != SANCTUM_KEY_PENDING)
		return (-1);

	if (!sanctum_atomic_cas_simple(&key->state,
	    SANCTUM_KEY_PENDING, SANCTUM_KEY_INSTALLING))
		fatal("failed to swap key state to installing");

	if (sa->cipher != NULL)
		sanctum_cipher_cleanup(sa->cipher);

	sa->cipher = sanctum_cipher_setup(key);
	sanctum_mem_zero(key->key, sizeof(key->key));

	sa->seqnr = 1;
	sa->pending = 1;
	sa->spi = sanctum_atomic_read(&key->spi);
	sa->salt = sanctum_atomic_read(&key->salt);
	sa->age = sanctum_atomic_read(&sanctum->uptime);

	if (!sanctum_atomic_cas_simple(&key->state,
	    SANCTUM_KEY_INSTALLING, SANCTUM_KEY_EMPTY))
		fatal("failed to swap key state to empty");

	return (0);
}

/*
 * Clear the entire given SA state, wiping its internal keys etc.
 */
void
sanctum_sa_clear(struct sanctum_sa *sa)
{
	PRECOND(sa != NULL);

	if (sa->cipher != NULL)
		sanctum_cipher_cleanup(sa->cipher);

	sanctum_mem_zero(sa, sizeof(*sa));
}

/*
 * Reset interface statistics for the given struct.
 */
void
sanctum_stat_clear(struct sanctum_ifstat *ifc)
{
	PRECOND(ifc != NULL);

	sanctum_atomic_write(&ifc->age, 0);
	sanctum_atomic_write(&ifc->spi, 0);
	sanctum_atomic_write(&ifc->pkt, 0);
	sanctum_atomic_write(&ifc->bytes, 0);
}

/*
 * Create a new UNIX socket at the given path, owned by the supplied
 * uid and gid and with 0700 permissions.
 */
int
sanctum_unix_socket(struct sanctum_sun *cfg)
{
	struct sockaddr_un	sun;
	int			fd, len, flags;

	PRECOND(cfg != NULL);

	if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", errno_s);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;

	len = snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", cfg->path);
	if (len == -1 || (size_t)len >= sizeof(sun.sun_path))
		fatal("path '%s' didnt fit into sun.sun_path", cfg->path);

	if (unlink(sun.sun_path) == -1 && errno != ENOENT)
		fatal("unlink(%s): %s", sun.sun_path, errno_s);

	if (bind(fd, (const struct sockaddr *)&sun, sizeof(sun)) == -1)
		fatal("bind(%s): %s", sun.sun_path, errno_s);

	if (chown(sun.sun_path, cfg->uid, cfg->gid) == -1)
		fatal("chown(%s): %s", sun.sun_path, errno_s);

	if (chmod(sun.sun_path, S_IRWXU) == -1)
		fatal("chmod(%s): %s", sun.sun_path, errno_s);

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		fatal("fcntl: %s", errno_s);

	flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) == -1)
		fatal("fcntl: %s", errno_s);

	return (fd);
}

/*
 * Allocate a shared memory segment with the given len as its size.
 * If key is not NULL, the shm key is written to it.
 *
 * The shared memory segment is attached automatically after allocation
 * and returned to the caller.
 *
 * Before returning the segment to the caller, it is marked for deletion
 * so that once the process exits the shared memory goes away.
 */
void *
sanctum_alloc_shared(size_t len, int *key)
{
	int		tmp;
	void		*ptr;

	tmp = shmget(IPC_PRIVATE, len, IPC_CREAT | IPC_EXCL | 0700);
	if (tmp == -1)
		fatal("%s: shmget: %s", __func__, errno_s);

	if ((ptr = shmat(tmp, NULL, 0)) == (void *)-1)
		fatal("%s: shmat: %s", __func__, errno_s);

	if (shmctl(tmp, IPC_RMID, NULL) == -1)
		fatal("%s: shmctl: %s", __func__, errno_s);

	if (key != NULL)
		*key = tmp;

	return (ptr);
}

/*
 * Detach from a shared memory segment.
 */
void
sanctum_shm_detach(void *ptr)
{
	if (ptr == NULL)
		return;

	if (shmdt(ptr) == -1)
		fatal("failed to detach from %p (%s)", ptr, errno_s);
}

/*
 * Poor mans memset() that isn't optimized away on the platforms I use it on.
 *
 * If you build this on something and don't test that it actually clears the
 * contents of the data, thats on you. You probably want to do some binary
 * verification.
 */
void
sanctum_mem_zero(void *ptr, size_t len)
{
	volatile char	*p;

	PRECOND(ptr != NULL);
	PRECOND(len > 0);

	p = (volatile char *)ptr;

	while (len-- > 0)
		*(p)++ = 0x00;
}

/*
 * Helper to parse an IPv4 address into a struct sockaddr_in its sin_addr.
 */
void
sanctum_inet_addr(void *saddr, const char *ip)
{
	struct sockaddr_in	*sin;

	PRECOND(saddr != NULL);
	PRECOND(ip != NULL);

	sin = saddr;
	memset(sin, 0, sizeof(*sin));

	sin->sin_family = AF_INET;

#if !defined(__linux__)
	sin->sin_len = sizeof(*sin);
#endif

	if (inet_pton(AF_INET, ip, &sin->sin_addr) != 1)
		fatal("'%s' not a valid IPv4 address", ip);
}

/*
 * Helper that takes a netmask in cidr form and stuff it into a sockaddr_in.
 */
void
sanctum_inet_mask(void *saddr, u_int32_t mask)
{
	struct sockaddr_in	*sin;

	PRECOND(saddr != NULL);
	PRECOND(mask <= 32);

	sin = saddr;
	memset(sin, 0, sizeof(*sin));

#if !defined(__linux__)
	sin->sin_len = sizeof(*sin);
#endif

	sin->sin_family = AF_INET;

	if (mask == 0)
		sin->sin_addr.s_addr = 0;
	else
		sin->sin_addr.s_addr = htonl(0xffffffff << (32 - mask));
}

/*
 * Returns the given struct sockaddr_in as a human string in ip:port format.
 */
const char *
sanctum_inet_string(struct sockaddr_in *sin)
{
	int		len;
	static char	buf[48];

	PRECOND(sin != NULL);

	len = snprintf(buf, sizeof(buf), "%s:%u",
	    inet_ntoa(sin->sin_addr), be16toh(sin->sin_port));
	if (len == -1 || (size_t)len >= sizeof(buf))
		fatal("snprintf on inet addr failed");

	return (buf);
}

/*
 * Open the given path as read-only and return the fd for it, or -1.
 */
int
sanctum_file_open(const char *path, struct stat *st)
{
	int		fd;
	struct stat	fst;

	PRECOND(path != NULL);
	/* st is optional */

	if ((fd = open(path, O_RDONLY | O_NOFOLLOW)) == -1) {
		sanctum_log(LOG_NOTICE,
		    "failed to open '%s': %s", path, errno_s);
		return (-1);
	}

	if (fstat(fd, &fst) == -1) {
		sanctum_log(LOG_NOTICE,
		    "failed to fstat '%s': %s", path, errno_s);
		(void)close(fd);
		return (-1);
	}

	if (!S_ISREG(fst.st_mode)) {
		sanctum_log(LOG_NOTICE,
		    "'%s': not a regular file", path);
		(void)close(fd);
		return (-1);
	}

	if (st != NULL)
		memcpy(st, &fst, sizeof(fst));

	return (fd);
}

/*
 * Derive a symmetrical key from the given secret, the given seed and
 * setup the given agelas cipher context.
 */
int
sanctum_cipher_kdf(const char *path, const char *label,
    struct sanctum_key *key, void *seed, size_t seed_len)
{
	int				fd;
	struct nyfe_kmac256		kdf;
	u_int8_t			len;
	u_int8_t			secret[SANCTUM_KEY_LENGTH];

	PRECOND(path != NULL);
	PRECOND(label != NULL);
	PRECOND(key != NULL);
	PRECOND(seed != NULL);
	PRECOND(seed_len == 64);

	if ((fd = sanctum_file_open(path, NULL)) == -1)
		return (-1);

	nyfe_zeroize_register(secret, sizeof(secret));

	if (nyfe_file_read(fd, secret, sizeof(secret)) != sizeof(secret)) {
		(void)close(fd);
		nyfe_zeroize(secret, sizeof(secret));
		sanctum_log(LOG_NOTICE,
		    "failed to read all data from '%s', will try again", path);
		return (-1);
	}

	(void)close(fd);

	nyfe_zeroize_register(&kdf, sizeof(kdf));

	len = sizeof(key->key);

	nyfe_kmac256_init(&kdf, secret, sizeof(secret), label, strlen(label));
	nyfe_zeroize(secret, sizeof(secret));

	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, seed, seed_len);
	nyfe_kmac256_final(&kdf, key->key, sizeof(key->key));
	nyfe_zeroize(&kdf, sizeof(kdf));

	return (0);
}

/*
 * Return a nonce containing a single 0x01 byte to the caller.
 * We use this for key offers, cathedral messages and ambries.
 *
 * This might look scary but this does not lead to (key, nonce) pair re-use
 * under a stream cipher as the keys for these type of messages are uniquely
 * derived per message. Don't blindly copy this idiom unless you know what
 * you are doing.
 */
void
sanctum_offer_nonce(u_int8_t *nonce, size_t nonce_len)
{
	PRECOND(nonce != NULL);
	PRECOND(nonce_len == SANCTUM_NONCE_LENGTH);

	nyfe_mem_zero(nonce, nonce_len);
	nonce[nonce_len - 1] = 0x01;
}

/*
 * Set the initial information for a sanctum_offer inside of the
 * given sanctum packet.
 */
struct sanctum_offer *
sanctum_offer_init(struct sanctum_packet *pkt, u_int32_t spi,
    u_int64_t magic, u_int8_t type)
{
	struct timespec		ts;
	struct sanctum_offer	*op;

	PRECOND(pkt != NULL);
	PRECOND(type == SANCTUM_OFFER_TYPE_KEY ||
	    type == SANCTUM_OFFER_TYPE_AMBRY ||
	    type == SANCTUM_OFFER_TYPE_INFO ||
	    type == SANCTUM_OFFER_TYPE_LITURGY ||
	    type == SANCTUM_OFFER_TYPE_REMEMBRANCE);

	op = sanctum_packet_head(pkt);

	op->data.type = type;
	op->hdr.spi = htobe32(spi);
	op->hdr.magic = htobe64(magic);

	nyfe_random_bytes(op->hdr.seed, sizeof(op->hdr.seed));
	nyfe_random_bytes(&op->hdr.flock, sizeof(op->hdr.flock));

	(void)clock_gettime(CLOCK_REALTIME, &ts);
	op->data.timestamp = htobe64((u_int64_t)ts.tv_sec);

	return (op);
}

/*
 * Encrypt and authenticate a sanctum_offer data structure.
 * Note: does not zeroize the key, this is the caller its responsibility.
 * Note: do not call this with the same key twice, the given key shall
 * be derived using sanctum_cipher_kdf() first.
 */
void
sanctum_offer_encrypt(struct sanctum_key *key, struct sanctum_offer *op)
{
	struct sanctum_cipher	cipher;
	u_int8_t		nonce[SANCTUM_NONCE_LENGTH];

	PRECOND(key != NULL);
	PRECOND(op != NULL);

	cipher.ctx = sanctum_cipher_setup(key);

	cipher.aad = &op->hdr;
	cipher.aad_len = sizeof(op->hdr);

	sanctum_offer_nonce(nonce, sizeof(nonce));
	cipher.nonce_len = sizeof(nonce);
	cipher.nonce = nonce;

	cipher.pt = &op->data;
	cipher.ct = &op->data;
	cipher.tag = &op->tag[0];
	cipher.data_len = sizeof(op->data);

	sanctum_cipher_encrypt(&cipher);
	sanctum_cipher_cleanup(cipher.ctx);
}

/*
 * Provide TFC for the offer when both tfc and encap are enabled, this hides
 * the fact that this is an offer on the wire.
 *
 * We have to include the ipsec header, tail and the cipher overhead
 * so that the offer is indistinguishable from traffic.
 *
 * The remaining bytes in the packet are filled with random data.
 */
void
sanctum_offer_tfc(struct sanctum_packet *pkt)
{
	u_int8_t	*data;
	size_t		offset;

	PRECOND(pkt != NULL);
	PRECOND(pkt->length == sizeof(struct sanctum_offer));

	if ((sanctum->flags & SANCTUM_FLAG_TFC_ENABLED) &&
	    (sanctum->flags & SANCTUM_FLAG_ENCAPSULATE)) {
		offset = pkt->length;
		pkt->length = sanctum->tun_mtu +
		    sizeof(struct sanctum_ipsec_hdr) +
		    sizeof(struct sanctum_ipsec_tail) +
		    SANCTUM_TAG_LENGTH;
		data = sanctum_packet_head(pkt);
		nyfe_random_bytes(&data[offset], pkt->length - offset);
	}
}

/*
 * Verify and decrypt a sanctum_offer packet.
 * Note: does not zeroize the key, this is the caller its responsibility.
 */
int
sanctum_offer_decrypt(struct sanctum_key *key,
    struct sanctum_offer *op, int valid)
{
	struct timespec		ts;
	struct sanctum_cipher	cipher;
	u_int8_t		nonce[SANCTUM_NONCE_LENGTH];

	PRECOND(key != NULL);
	PRECOND(op != NULL);
	PRECOND(valid > 0);

	cipher.ctx = sanctum_cipher_setup(key);

	cipher.aad = &op->hdr;
	cipher.aad_len = sizeof(op->hdr);

	sanctum_offer_nonce(nonce, sizeof(nonce));
	cipher.nonce_len = sizeof(nonce);
	cipher.nonce = nonce;

	cipher.ct = &op->data;
	cipher.pt = &op->data;
	cipher.tag = &op->tag[0];
	cipher.data_len = sizeof(op->data);

	if (sanctum_cipher_decrypt(&cipher) == -1) {
		sanctum_cipher_cleanup(cipher.ctx);
		return (-1);
	}

	sanctum_cipher_cleanup(cipher.ctx);

	(void)clock_gettime(CLOCK_REALTIME, &ts);
	op->data.timestamp = be64toh(op->data.timestamp);

	if (op->data.timestamp < ((u_int64_t)ts.tv_sec - valid) ||
	    op->data.timestamp > ((u_int64_t)ts.tv_sec + valid))
		return (-1);

	return (0);
}

/*
 * Install the given key offer to into the given state.
 */
void
sanctum_offer_install(struct sanctum_key *state, struct sanctum_offer *op)
{
	struct sanctum_key_offer	*key;

	PRECOND(state != NULL);
	PRECOND(op != NULL);
	PRECOND(op->data.type == SANCTUM_OFFER_TYPE_KEY);

	key = &op->data.offer.key;

	sanctum_install_key_material(state, op->hdr.spi, key->salt,
	    key->key, sizeof(key->key));
}

/*
 * We received a list of all cathedrals from the one we are currently
 * talking too. We save the list for later if a path for it was
 * configured, otherwise this is just ignored.
 */
void
sanctum_offer_remembrance(struct sanctum_offer *op, u_int64_t now)
{
	int					fd, i;
	struct sanctum_remembrance_offer	*list;

	PRECOND(op != NULL);
	PRECOND(op->data.type == SANCTUM_OFFER_TYPE_REMEMBRANCE);

	if (sanctum->cathedral_remembrance == NULL) {
		sanctum_log(LOG_NOTICE,
		    "cathedral sent an unsolicited remembrance");
		return;
	}

	if ((fd = open(sanctum->cathedral_remembrance,
	    O_CREAT | O_TRUNC | O_WRONLY, 0500)) == -1) {
		sanctum_log(LOG_NOTICE, "failed to open '%s': %s",
		    sanctum->cathedral_remembrance, errno_s);
		return;
	}

	sanctum->cathedral_idx = 0;
	list = &op->data.offer.remembrance;

	for (i = 0; i < SANCTUM_CATHEDRALS_MAX; i++) {
		if (list->ips[i] == 0 || list->ports[i] == 0)
			break;
		sanctum->cathedrals[i].sin_port = list->ports[i];
		sanctum->cathedrals[i].sin_addr.s_addr = list->ips[i];
	}

	nyfe_file_write(fd, list->ips, sizeof(list->ips));
	nyfe_file_write(fd, list->ports, sizeof(list->ports));

	if (close(fd) == -1) {
		sanctum_log(LOG_NOTICE, "close() failed on '%s': %s",
		    sanctum->cathedral_remembrance, errno_s);
	}
}

/*
 * Install the given spi, salt and key into the given state.
 */
void
sanctum_install_key_material(struct sanctum_key *state, u_int32_t spi,
    u_int32_t salt, const void *key, size_t len)
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

	nyfe_memcpy(state->key, key, len);
	sanctum_atomic_write(&state->spi, spi);
	sanctum_atomic_write(&state->salt, salt);

	if (!sanctum_atomic_cas_simple(&state->state,
	    SANCTUM_KEY_GENERATING, SANCTUM_KEY_PENDING))
		fatal("failed to swap key state to pending");
}

/*
 * Bind a socket to our configured local address and return it.
 */
int
sanctum_bind_local(struct sockaddr_in *sin)
{
	int		fd, val;

	PRECOND(sin != NULL);

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("%s: socket: %s", __func__, errno_s);

	sin->sin_family = AF_INET;

	if (bind(fd, (struct sockaddr *)sin, sizeof(*sin)) == -1)
		fatal("%s: bind: %s", __func__, errno_s);

	if ((val = fcntl(fd, F_GETFL, 0)) == -1)
		fatal("%s: fcntl: %s", __func__, errno_s);

	val |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, val) == -1)
		fatal("%s: fcntl: %s", __func__, errno_s);

#if defined(__linux__)
	val = IP_PMTUDISC_DO;
	if (setsockopt(fd, IPPROTO_IP,
	    IP_MTU_DISCOVER, &val, sizeof(val)) == -1)
		fatal("%s: setsockopt: %s", __func__, errno_s);
#elif !defined(__OpenBSD__)
	val = 1;
	if (setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &val, sizeof(val)) == -1)
		fatal("%s: setsockopt: %s", __func__, errno_s);
#endif

	return (fd);
}

/*
 * Check if we can detect if our current cathedral has timed out and if
 * so we will select the next one from our remembrance list.
 * This will only have an effect if remembrance was enabled.
 */
void
sanctum_cathedral_timeout(u_int64_t now)
{
	PRECOND(sanctum->flags & SANCTUM_FLAG_CATHEDRAL_ACTIVE);

	if (sanctum->cathedral_remembrance == NULL)
		return;

	if ((now - sanctum->cathedral_last) < 30)
		return;

	sanctum->cathedral_last = now;
	sanctum_log(LOG_INFO, "cathedral %s is unresponsive",
	    sanctum_inet_string(&sanctum->cathedral));

	if (sanctum->cathedrals[0].sin_addr.s_addr == 0)
		return;

	sanctum->cathedral_idx = (sanctum->cathedral_idx + 1) &
	    (SANCTUM_CATHEDRALS_MAX - 1);

	if (sanctum->cathedrals[sanctum->cathedral_idx].sin_addr.s_addr == 0)
		sanctum->cathedral_idx = 0;

	sanctum->cathedral = sanctum->cathedrals[sanctum->cathedral_idx];

	sanctum_log(LOG_INFO, "switching to cathedral %s",
	    sanctum_inet_string(&sanctum->cathedral));
}

/*
 * Load previously stored cathedrals from the configured cathedral_remembrance
 * file. This should only be called when we have a cathedral configured and a
 * remembrance file was configured.
 */
void
sanctum_cathedrals_remembrance(void)
{
	int		fd, i;
	u_int32_t	ips[SANCTUM_CATHEDRALS_MAX];
	u_int16_t	ports[SANCTUM_CATHEDRALS_MAX];

	PRECOND(sanctum->flags & SANCTUM_FLAG_CATHEDRAL_ACTIVE);
	PRECOND(sanctum->cathedral_remembrance != NULL);

	nyfe_mem_zero(&sanctum->cathedrals, sizeof(sanctum->cathedrals));

	fd = sanctum_file_open(sanctum->cathedral_remembrance, NULL);
	if (fd == -1)
		return;

	if (nyfe_file_read(fd, ips, sizeof(ips)) != sizeof(ips) ||
	    nyfe_file_read(fd, ports, sizeof(ports)) != sizeof(ports)) {
		sanctum_log(LOG_NOTICE,
		    "ignoring malformed cathedral_remembrance file");
		goto cleanup;
	}

	for (i = 0; i < SANCTUM_CATHEDRALS_MAX; i++) {
		if (ips[i] == 0 || ports[i] == 0)
			break;

		sanctum->cathedrals[i].sin_port = ports[i];
		sanctum->cathedrals[i].sin_addr.s_addr = ips[i];
	}

	sanctum_log(LOG_INFO, "%d cathedrals in remembrance", i);

cleanup:
	(void)close(fd);
}
