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

#ifndef __H_SANCTUM_H
#define __H_SANCTUM_H

#if defined(__APPLE__)
#define daemon portability_is_king
#endif

#include <sys/types.h>
#include <sys/queue.h>

#include <netinet/in.h>

#if defined(__linux__)
#include <linux/if_ether.h>
#endif

#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#if defined(__APPLE__)
#undef daemon
extern int daemon(int, int);

#include <libkern/OSByteOrder.h>
#define htobe32(x)		OSSwapHostToBigInt32(x)
#define htobe64(x)		OSSwapHostToBigInt64(x)
#define be32toh(x)		OSSwapBigToHostInt32(x)
#define be64toh(x)		OSSwapBigToHostInt64(x)
#endif

#include "sanctum_ctl.h"

/* A few handy macros. */
#define errno_s		strerror(errno)

#define PRECOND(x)							\
	do {								\
		if (!(x)) {						\
			fatal("precondition failed in %s:%s:%d\n",	\
			    __FILE__, __func__, __LINE__);		\
		}							\
	} while (0)

#define VERIFY(x)							\
	do {								\
		if (!(x)) {						\
			fatal("verification failed in %s:%s:%d\n",	\
			    __FILE__, __func__, __LINE__);		\
		}							\
	} while (0)

/*
 * Atomic operations used in sanctum.
 */
#define sanctum_atomic_read(x)		\
    __atomic_load_n(x, __ATOMIC_SEQ_CST)

#define sanctum_atomic_write(x, v)	\
    __atomic_store_n(x, v, __ATOMIC_SEQ_CST)

#define sanctum_atomic_cas(x, e, d)	\
    __atomic_compare_exchange(x, e, d, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)

#define sanctum_atomic_cas_simple(x, e, d)	\
    __sync_bool_compare_and_swap(x, e, d)

#define sanctum_atomic_add(x, e)	\
    __atomic_fetch_add(x, e, __ATOMIC_SEQ_CST)

/*
 * Use architecture specific instructions to hint to the CPU that
 * we are in a spinloop hopefully avoiding a memory order violation
 * which would incur a performance hit.
 */
#if defined(__arm64__) || defined(__aarch64__)
#define sanctum_cpu_pause()					\
	do {							\
		__asm__ volatile("yield" ::: "memory");		\
	} while (0)
#elif defined(__x86_64__)
#define sanctum_cpu_pause()					\
	do {							\
		__asm__ volatile("pause" ::: "memory");		\
	} while (0)
#else
#error "unsupported architecture"
#endif

/* Length of our symmetrical keys, in bytes. */
#define SANCTUM_KEY_LENGTH		32

/* ESP next_proto value for a heartbeat. */
#define SANCTUM_PACKET_HEARTBEAT	0xfc

/* The number of seconds between heartbeats. */
#define SANCTUM_HEARTBEAT_INTERVAL	15

/* Maximum number of packets that can be sent under an SA. */
#define SANCTUM_SA_PACKET_SOFT		(1ULL << 33)
#define SANCTUM_SA_PACKET_HARD		(1ULL << 34)

/* Maximum number of seconds an SA can be alive. */
#define SANCTUM_SA_LIFETIME_SOFT	3500
#define SANCTUM_SA_LIFETIME_HARD	3600

/* Process types */
#define SANCTUM_PROC_HEAVEN		1
#define SANCTUM_PROC_PURGATORY		2
#define SANCTUM_PROC_BLESS		3
#define SANCTUM_PROC_CONFESS		4
#define SANCTUM_PROC_CHAPEL		5
#define SANCTUM_PROC_CONTROL		6
#define SANCTUM_PROC_MAX		7

/* The magic for a key offer packet (SACRISTY). */
#define SANCTUM_KEY_OFFER_MAGIC		0x5341435249535459

/* The length of the seed in a key offer packet. */
#define SANCTUM_KEY_OFFER_SALT_LEN	64

/*
 * Packets used when doing key offering.
 */
struct sanctum_offer_hdr {
	u_int64_t		magic;
	u_int32_t		spi;
	u_int8_t		seed[SANCTUM_KEY_OFFER_SALT_LEN];
} __attribute__((packed));

struct sanctum_offer_data {
	u_int32_t		salt;
	u_int64_t		timestamp;
	u_int8_t		key[SANCTUM_KEY_LENGTH];
} __attribute__((packed));

struct sanctum_offer {
	struct sanctum_offer_hdr	hdr;
	struct sanctum_offer_data	data;
	u_int8_t			tag[32];
} __attribute__((packed));

/* Key states. */
#define SANCTUM_KEY_EMPTY		0
#define SANCTUM_KEY_GENERATING		1
#define SANCTUM_KEY_PENDING		2
#define SANCTUM_KEY_INSTALLING		3
#define SANCTUM_KEY_ERASE		4

/*
 * Used to swap TX / RX keys between chapel and encrypt and decrypt processes.
 */
struct sanctum_key {
	volatile u_int32_t	spi;
	volatile u_int32_t	salt;
	volatile int		state;
	u_int8_t		key[SANCTUM_KEY_LENGTH];
};

/*
 * An SA context with an SPI, salt, sequence number and underlying cipher.
 */
struct sanctum_sa {
	u_int64_t		age;
	u_int32_t		spi;
	u_int32_t		salt;
	u_int64_t		seqnr;
	u_int64_t		bitmap;
	u_int8_t		pending;
	void			*cipher;
};

/*
 * A process under the control of the parent process.
 */
struct sanctum_proc {
	pid_t			pid;
	uid_t			uid;
	gid_t			gid;
	u_int16_t		type;
	void			*arg;
	const char		*name;
	void			(*entry)(struct sanctum_proc *);

	LIST_ENTRY(sanctum_proc)	list;
};

#define SANCTUM_ARWIN_SIZE	64

/*
 * Used to pass all the queues to the clear (heaven) and crypto (purgatory).
 * Each process is responsible for removing the queues they
 * do not need themselves.
 */
struct sanctum_proc_io {
	struct sanctum_key	*tx;
	struct sanctum_key	*rx;

	struct sanctum_ring	*offer;
	struct sanctum_ring	*bless;
	struct sanctum_ring	*chapel;
	struct sanctum_ring	*heaven;
	struct sanctum_ring	*confess;
	struct sanctum_ring	*purgatory;
};

/*
 * A shared memory ring queue with space for up to 4096 elements.
 * The actual size is given via sanctum_ring_init() and must be <= 4096.
 */
struct sanctum_ring_span {
	volatile u_int32_t	head;
	volatile u_int32_t	tail;
};

struct sanctum_ring {
	size_t				elm;
	u_int32_t			mask;
	struct sanctum_ring_span	producer;
	struct sanctum_ring_span	consumer;
	volatile uintptr_t		data[4096];
};

/*
 * A shared memory object pool.
 */
struct sanctum_pool {
	size_t			len;
	u_int8_t		*base;
	struct sanctum_ring	queue;
};

/*
 * An encrypted packet its head, includes the ESP header *and* the
 * 64-bit packet number used as part of the nonce later.
 */
struct sanctum_ipsec_hdr {
	struct {
		u_int32_t		spi;
		u_int32_t		seq;
	} esp;
	u_int64_t		pn;
} __attribute__((packed));

/* ESP trailer, added to the plaintext before encrypted. */
struct sanctum_ipsec_tail {
	u_int8_t		pad;
	u_int8_t		next;
} __attribute__((packed));

/* The available head room is the entire size of an sanctum_ipsec_hdr. */
#define SANCTUM_PACKET_HEAD_LEN		sizeof(struct sanctum_ipsec_hdr)

/*
 * Maximum packet sizes we can receive from the interfaces.
 */
#if defined(SANCTUM_HIGH_PERFORMANCE)
#define SANCTUM_PACKET_DATA_LEN		9000
#else
#define SANCTUM_PACKET_DATA_LEN		1500
#endif

/*
 * The total space available in a packet buffer, we're lazy and just
 * made it large enough to hold the head room, packet data and
 * any tail that is going to be added to it.
 */
#define SANCTUM_PACKET_MAX_LEN		(SANCTUM_PACKET_DATA_LEN + 64)

/* The minimum size we can read from an interface. */
#define SANCTUM_PACKET_MIN_LEN		12

/*
 * A network packet.
 */
struct sanctum_packet {
	struct sockaddr_in	addr;
	u_int8_t		next;
	size_t			length;
	u_int32_t		target;
	u_int8_t		buf[SANCTUM_PACKET_MAX_LEN];
};

/*
 * A configuration for a UNIX socket, where it gets
 * created, who owns it etc.
 */
struct sanctum_sun {
	uid_t		uid;
	gid_t		gid;
	char		path[256];		/* XXX */
};

/* Sanctum was started in the background. */
#define SANCTUM_FLAG_DAEMONIZED		(1 << 0)

/*
 * The shared state between processes.
 */
struct sanctum_state {
	/* Sanctum flags. */
	u_int32_t		flags;

	/* Time maintained by overwatch. */
	volatile u_int64_t	uptime;

	/* Local and remote addresses. */
	struct sockaddr_in	peer;
	struct sockaddr_in	local;

	/* The actual peer ip and port. */
	volatile u_int32_t	peer_ip;
	volatile u_int16_t	peer_port;

	/* The path to the secret, for chapel. */
	char			*secret;

	/* The users the different processes runas. */
	char			*runas[SANCTUM_PROC_MAX];

	/* The chapel socket. */
	struct sanctum_sun	chapel;

	/* Should a communion take place in the Chapel? */
	u_int8_t		communion;

	/* The control socket. */
	struct sanctum_sun	control;

	/* The sanctum instance name. */
	char			instance[16];	/* XXX */

	/* Tx and Rx statistics. */
	struct sanctum_ifstat	tx;
	struct sanctum_ifstat	rx;

	/* Last valid sequence number for the current RX SA. */
	volatile u_int64_t	last_pn;

	/* RX SA pending. */
	volatile u_int32_t	rx_pending;

	/* The last heartbeat received from the peer. */
	volatile u_int64_t	heartbeat;
};

extern struct sanctum_state	*sanctum;

/* src/config.c */
void	sanctum_config_init(void);
void	sanctum_config_load(const char *);

/* src/sanctum.c */
void	sanctum_signal_trap(int);
int	sanctum_last_signal(void);
void	sanctum_signal_ignore(int);
void	fatal(const char *, ...) __attribute__((format (printf, 1, 2)))
	    __attribute__((noreturn));

/* src/proc. */
void	sanctum_proc_reap(void);
void	sanctum_proc_start(void);
void	sanctum_proc_killall(int);
void	sanctum_proc_init(char **);
void	sanctum_proc_shutdown(void);
void	sanctum_proc_title(const char *);
void	sanctum_proc_privsep(struct sanctum_proc *);
void	sanctum_proc_create(u_int16_t,
	    void (*entry)(struct sanctum_proc *), void *);

struct sanctum_proc	*sanctum_process(void);

/* src/packet.c */
void	sanctum_packet_init(void);
void	sanctum_packet_release(struct sanctum_packet *);
int	sanctum_packet_crypto_checklen(struct sanctum_packet *);

void	*sanctum_packet_info(struct sanctum_packet *);
void	*sanctum_packet_data(struct sanctum_packet *);
void	*sanctum_packet_tail(struct sanctum_packet *);
void	*sanctum_packet_head(struct sanctum_packet *);

struct sanctum_packet	*sanctum_packet_get(void);

/* src/pool.c */
void	*sanctum_pool_get(struct sanctum_pool *);
void	sanctum_pool_put(struct sanctum_pool *, void *);

struct sanctum_pool	*sanctum_pool_init(size_t, size_t);

/* src/ring.c */
size_t	sanctum_ring_pending(struct sanctum_ring *);
void	*sanctum_ring_dequeue(struct sanctum_ring *);
size_t	sanctum_ring_available(struct sanctum_ring *);
void	sanctum_ring_init(struct sanctum_ring *, size_t);
int	sanctum_ring_queue(struct sanctum_ring *, void *);

struct sanctum_ring	*sanctum_ring_alloc(size_t);

/* src/utils.c */
void	sanctum_log(int, const char *, ...)
	    __attribute__((format (printf, 2, 3)));
void	sanctum_logv(int, const char *, va_list);
void	sanctum_shm_detach(void *);
void	sanctum_mem_zero(void *, size_t);
void	*sanctum_alloc_shared(size_t, int *);
void	sanctum_sa_clear(struct sanctum_sa *);
int	sanctum_unix_socket(struct sanctum_sun *);
void	sanctum_stat_clear(struct sanctum_ifstat *);
void	sanctum_peer_update(struct sanctum_packet *);
int	sanctum_key_install(struct sanctum_key *, struct sanctum_sa *);
int	sanctum_key_erase(const char *, struct sanctum_key *,
	    struct sanctum_sa *);

/* platform bits. */
int	sanctum_platform_tundev_create(void);
ssize_t	sanctum_platform_tundev_read(int, struct sanctum_packet *);
ssize_t	sanctum_platform_tundev_write(int, struct sanctum_packet *);

/* Worker entry points. */
void	sanctum_bless(struct sanctum_proc *) __attribute__((noreturn));
void	sanctum_heaven(struct sanctum_proc *) __attribute__((noreturn));
void	sanctum_control(struct sanctum_proc *) __attribute__((noreturn));
void	sanctum_chapel(struct sanctum_proc *) __attribute__((noreturn));
void	sanctum_confess(struct sanctum_proc *) __attribute__((noreturn));
void	sanctum_purgatory(struct sanctum_proc *) __attribute__((noreturn));

/* The cipher goo. */
size_t	sanctum_cipher_overhead(void);
void	sanctum_cipher_cleanup(void *);
void	*sanctum_cipher_setup(struct sanctum_key *);
void	sanctum_cipher_encrypt(void *, const void *, size_t, const void *,
	    size_t, struct sanctum_packet *);
int	sanctum_cipher_decrypt(void *, const void *, size_t, const void *,
	    size_t, struct sanctum_packet *);

#endif
