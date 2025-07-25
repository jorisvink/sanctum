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

#ifndef __H_SANCTUM_H
#define __H_SANCTUM_H

/* Sanctum version info from obj/version.c. */
extern const char	*sanctum_build_rev;
extern const char	*sanctum_build_date;

#if defined(__APPLE__)
#define daemon portability_is_king
#endif

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include <netinet/in.h>

#if defined(__linux__)
#include <linux/if_ether.h>
#endif

#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "sanctum_portability.h"
#include "sanctum_cipher.h"
#include "sanctum_ambry.h"
#include "sanctum_ctl.h"

#include "libnyfe.h"

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
#elif defined(__riscv)
#define sanctum_cpu_pause()						\
	do {								\
		__asm__ volatile(".4byte 0x100000F" ::: "memory");	\
	} while (0)
#else
#error "unsupported architecture"
#endif

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

/* The amount of peers per flock. */
#define SANCTUM_PEERS_PER_FLOCK		255

/* Process types */
#define SANCTUM_PROC_HEAVEN_RX		1
#define SANCTUM_PROC_HEAVEN_TX		2
#define SANCTUM_PROC_PURGATORY_RX	3
#define SANCTUM_PROC_PURGATORY_TX	4
#define SANCTUM_PROC_BLESS		5
#define SANCTUM_PROC_CONFESS		6
#define SANCTUM_PROC_CHAPEL		7
#define SANCTUM_PROC_CONTROL		8
#define SANCTUM_PROC_PILGRIM		9
#define SANCTUM_PROC_SHRINE		10
#define SANCTUM_PROC_CATHEDRAL		11
#define SANCTUM_PROC_LITURGY		12
#define SANCTUM_PROC_BISHOP		13
#define SANCTUM_PROC_MAX		14

/* KDF purposes for use with our shared secret. */
#define SANCTUM_KDF_PURPOSE_OFFER	1
#define SANCTUM_KDF_PURPOSE_TRAFFIC_RX	2
#define SANCTUM_KDF_PURPOSE_TRAFFIC_TX	3
#define SANCTUM_KDF_PURPOSE_KEK_UNWRAP	4

/* The KDF label for offer key derivation from shared secret. */
#define SANCTUM_KEY_OFFER_KDF_LABEL	"SANCTUM.KEY.OFFER.KDF"

/* The KDF label for traffic key derivation from shared secret (RX). */
#define SANCTUM_KEY_TRAFFIC_RX_KDF_LABEL	"SANCTUM.KEY.TRAFFIC.RX.KDF"

/* The KDF label for traffic key derivation from shared secret (TX). */
#define SANCTUM_KEY_TRAFFIC_TX_KDF_LABEL	"SANCTUM.KEY.TRAFFIC.TX.KDF"

/* The half-time window in which offers are valid. */
#define SANCTUM_OFFER_VALID		10

/* The magic for a key offer packet (SACRAMNT). */
#define SANCTUM_KEY_OFFER_MAGIC		0x53414352414D4E54

/* The length of the seed in a key offer packet. */
#define SANCTUM_KEY_OFFER_SALT_LEN	64

/* The magic for cathedral messages (KATEDRAL). */
#define SANCTUM_CATHEDRAL_MAGIC		0x4b4154454452414c

/* The magic for NAT detection messages (CIBORIUM). */
#define SANCTUM_CATHEDRAL_NAT_MAGIC	0x4349424f5249554d

/* The KDF label for the cathedral. */
#define SANCTUM_CATHEDRAL_KDF_LABEL	"SANCTUM.CATHEDRAL.KDF"

/* The KDF label for traffic encapsulation. */
#define SANCTUM_ENCAP_LABEL		"SANCTUM.ENCAP.KDF"

/* The KDF label for traffic key derivation. */
#define SANCTUM_TRAFFIC_KDF_LABEL	"SANCTUM.TRAFFIC.KDF"

/* The maximum number of federated cathedrals we can have. */
#define SANCTUM_CATHEDRALS_MAX		32

/* Number of seconds after which we consider a cathedral timed out. */
#define SANCTUM_CATHEDRAL_TIMEOUT	45

/*
 * Packets used when doing key offering or cathedral forward registration.
 *
 * Note that the internal seed and tag in sanctum_offer_data is only
 * populated when the cathedral sends an ambry.
 *
 * An offer can either be:
 *	1) A symmetric key offering (between peers)
 *	2) An ambry offering (from cathedral to us)
 *	3) An info offering (from us to cathedral, or cathedral to us)
 *	4) A liturgy offering (from us to cathedral, or cathedral to us)
 *	5) A remembrance offering (from cathedral to us)
 *	6) A key exchange offering (between peers)
 */

#define SANCTUM_OFFER_TYPE_KEY		1
#define SANCTUM_OFFER_TYPE_AMBRY	2
#define SANCTUM_OFFER_TYPE_INFO		3
#define SANCTUM_OFFER_TYPE_LITURGY	4
#define SANCTUM_OFFER_TYPE_REMEMBRANCE	5
#define SANCTUM_OFFER_TYPE_EXCHANGE	6

struct sanctum_offer_hdr {
	u_int64_t		magic;
	u_int64_t		flock_src;
	u_int64_t		flock_dst;
	u_int32_t		spi;
	u_int8_t		seed[SANCTUM_KEY_OFFER_SALT_LEN];
} __attribute__((packed));

/* The maximum number of fragments sent in a KEM offer. */
#define SANCTUM_OFFER_KEM_FRAGMENTS		4

/* The value we get when all packets are received. */
#define SANCTUM_OFFER_KEM_FRAGMENTS_DONE	\
    ((1 << SANCTUM_OFFER_KEM_FRAGMENTS) - 1)

/* This is ML-KEM-1024 its pubkey len / fragments. */
#define SANCTUM_OFFER_KEM_FRAGMENT_SIZE		\
    (SANCTUM_MLKEM_1024_PUBLICKEYBYTES / SANCTUM_OFFER_KEM_FRAGMENTS)

/* Does the exchange offer include an ML-KEM-1024 public key fragment. */
#define SANCTUM_OFFER_STATE_KEM_PK_FRAGMENT	1

/* Does the exchange offer include an ML-KEM-1024 cipher text fragment. */
#define SANCTUM_OFFER_STATE_KEM_CT_FRAGMENT	2

struct sanctum_exchange_offer {
	u_int64_t		id;
	u_int32_t		spi;
	u_int32_t		salt;
	u_int8_t		state;
	u_int8_t		fragment;
	u_int8_t		ecdh[SANCTUM_KEY_LENGTH];
	u_int8_t		kem[SANCTUM_OFFER_KEM_FRAGMENT_SIZE];
} __attribute__((packed));

struct sanctum_key_offer {
	u_int64_t		id;
	u_int32_t		salt;
	u_int8_t		key[SANCTUM_KEY_LENGTH];
} __attribute__((packed));

struct sanctum_ambry_offer {
	u_int16_t		tunnel;
	u_int32_t		generation;
	u_int8_t		seed[SANCTUM_AMBRY_SEED_LEN];
	u_int8_t		key[SANCTUM_AMBRY_KEY_LEN];
	u_int8_t		tag[SANCTUM_AMBRY_TAG_LEN];
} __attribute__((packed));

struct sanctum_remembrance_offer {
	u_int32_t		ips[SANCTUM_CATHEDRALS_MAX];
	u_int16_t		ports[SANCTUM_CATHEDRALS_MAX];
} __attribute__((packed));

/* Set in an info offer if peer wants remembrance. */
#define SANCTUM_INFO_FLAG_REMEMBRANCE		(1 << 0)

struct sanctum_info_offer {
	u_int32_t		flags;

	u_int32_t		peer_ip;
	u_int16_t		peer_port;

	u_int32_t		local_ip;
	u_int16_t		local_port;

	u_int16_t		tunnel;
	u_int32_t		ambry_generation;

	u_int32_t		rx_active;
	u_int32_t		rx_pending;

	u_int64_t		instance;
} __attribute__((packed));

/* Liturgy offer flags. */
#define SANCTUM_LITURGY_FLAG_REMEMBRANCE	SANCTUM_INFO_FLAG_REMEMBRANCE
#define SANCTUM_LITURGY_FLAG_SIGNALING		(1 << 1)

struct sanctum_liturgy_offer {
	u_int8_t		id;
	u_int16_t		group;
	u_int8_t		peers[SANCTUM_PEERS_PER_FLOCK];
	u_int8_t		hidden;
	u_int32_t		flags;
} __attribute__((packed));

struct sanctum_offer_data {
	u_int8_t		type;
	u_int64_t		timestamp;

	union {
		struct sanctum_key_offer		key;
		struct sanctum_info_offer		info;
		struct sanctum_ambry_offer		ambry;
		struct sanctum_liturgy_offer		liturgy;
		struct sanctum_exchange_offer		exchange;
		struct sanctum_remembrance_offer	remembrance;
	} offer;
} __attribute__((packed));

struct sanctum_offer {
	struct sanctum_offer_hdr	hdr;
	struct sanctum_offer_data	data;
	u_int8_t			tag[SANCTUM_TAG_LENGTH];
} __attribute__((packed));

/*
 * Data structure passed between liturgy<>bishop to convey the
 * starting or stopping of sanctum instances when in liturgy mode.
 */
struct sanctum_liturgy {
	int			present;
	u_int16_t		instance;
};

/* Key states. */
#define SANCTUM_KEY_EMPTY		0
#define SANCTUM_KEY_GENERATING		1
#define SANCTUM_KEY_PENDING		2
#define SANCTUM_KEY_INSTALLING		3
#define SANCTUM_KEY_ERASE		4

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
	int			nat;
	int			clear;
	int			crypto;

	struct sanctum_key	*tx;
	struct sanctum_key	*rx;

	struct sanctum_ring	*offer;
	struct sanctum_ring	*bless;
	struct sanctum_ring	*bishop;
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
	u_int32_t			elm;
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
 * An encrypted packet its head, includes the ESP header, the
 * 64-bit packet number used as part of the nonce later and
 * potential flock src/dst numbers.
 */
struct sanctum_proto_hdr {
	struct {
		u_int32_t		spi;
		u_int32_t		seq;
	} esp;

	u_int64_t			pn;

	struct {
		u_int64_t		src;
		u_int64_t		dst;
	} flock;
} __attribute__((packed));

/* ESP trailer, added to the plaintext before encrypted. */
struct sanctum_proto_tail {
	u_int8_t		pad;
	u_int8_t		next;
} __attribute__((packed));

/*
 * The encapsulation header consisting of a normal ESP header
 * in combination with a 16 byte seed. The entire header is
 * used for mask generation when encapsulating an outgoing packet.
 * The mask is then used to hide the inner sanctum header entirely.
 */
struct sanctum_encap_hdr {
	struct {
		struct {
			u_int32_t	spi;
			u_int32_t	seq;
		} esp;

		u_int64_t		pn;
	} ipsec;

	u_int8_t			seed[16];
} __attribute__((packed));

/*
 * The length of the mask we XOR onto the packet if encapsulation is enabled.
 * The 20 bytes stems from the sanctum_offer_hdr having 4 bytes more than
 * a normal ESP header + packet number. So this is essentially
 * sizeof(struct sanctum_offer_hdr) - SANCTUM_KEY_OFFER_SALT_LEN.
 */
#define SANCTUM_ENCAP_MASK_LEN		\
    (sizeof(struct sanctum_offer_hdr) - SANCTUM_KEY_OFFER_SALT_LEN)

/* Preseed is used for when outer encapsulation is enabled. */
#define SANCTUM_PACKET_ENCAP_LEN	sizeof(struct sanctum_encap_hdr)

/* The header starts after our potential encapsulation. */
#define SANCTUM_PACKET_HEAD_OFFSET	SANCTUM_PACKET_ENCAP_LEN

/* The data starts after the header. */
#define SANCTUM_PACKET_DATA_OFFSET	\
    (SANCTUM_PACKET_HEAD_OFFSET + sizeof(struct sanctum_proto_hdr))

/*
 * Maximum packet sizes we can receive from the interfaces.
 */
#if defined(SANCTUM_JUMBO_FRAMES)
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

/* The length of an ethernet MAC address. */
#define SANCTUM_ETHERNET_MAC_LEN	6

/* The ethertypes for IPv4, IPv6, ARP and VLAN tagged traffic. */
#define SANCTUM_ETHER_TYPE_VLAN		0x8100
#define SANCTUM_ETHER_TYPE_ARP		0x0806
#define SANCTUM_ETHER_TYPE_IPV4		0x0800
#define SANCTUM_ETHER_TYPE_IPV6		0x86dd

/*
 * An ethernet header, defined here for portability sake.
 */
struct sanctum_ether {
	u_int8_t	dst[SANCTUM_ETHERNET_MAC_LEN];
	u_int8_t	src[SANCTUM_ETHERNET_MAC_LEN];
	u_int16_t	proto;
} __attribute__((packed));

/* Sanctum was started in the background. */
#define SANCTUM_FLAG_DAEMONIZED		(1 << 0)

/* The peer address is automatically discovered. */
#define SANCTUM_FLAG_PEER_AUTO		(1 << 1)

/* A cathedral was configured. */
#define SANCTUM_FLAG_CATHEDRAL_ACTIVE	(1 << 2)

/* If Traffic Flow Condidentiality is enabled (TFC) */
#define SANCTUM_FLAG_TFC_ENABLED	(1 << 3)

/* Set if a peer was configured manually in the configuration. */
#define SANCTUM_FLAG_PEER_CONFIGURED	(1 << 4)

/* If purgatory is encapsulating / decapsulating for traffic protection. */
#define SANCTUM_FLAG_ENCAPSULATE	(1 << 5)

/* If we should create a tap device instead of a tun device. */
#define SANCTUM_FLAG_USE_TAP		(1 << 6)

/* P2P federated sync is enabled in a cathedral. */
#define SANCTUM_FLAG_CATHEDRAL_P2P_SYNC	(1 << 7)

/* When in liturgy mode, are we hiding ourselves or not. */
#define SANCTUM_FLAG_LITURGY_HIDE	(1 << 8)

/*
 * The modes in which sanctum can run.
 *
 * tunnel - Sanctum will be able to send and receive encrypted data (default).
 * pilgrim - Sanctum will only be able to send encrypted data, not receive.
 * shrine - Sanctum will only be able to receive encrypted data, not send.
 * cathedral - Sanctum acts as a cathedral.
 * liturgy - Sanctum will run in liturgy mode.
 */
#define SANCTUM_MODE_TUNNEL		1
#define SANCTUM_MODE_PILGRIM		2
#define SANCTUM_MODE_SHRINE		3
#define SANCTUM_MODE_CATHEDRAL		4
#define SANCTUM_MODE_LITURGY		5

/*
 * The shared state between processes.
 */
struct sanctum_state {
	/* Startup mode. */
	u_int16_t		mode;

	/* Sanctum flags. */
	u_int32_t		flags;

	/* Time maintained by overwatch. */
	volatile u_int64_t	uptime;

	/* The local address from the configuration. */
	struct sockaddr_in	local;

	/* The current selected cathedral remote address (tunnel mode only). */
	struct sockaddr_in	cathedral;

	/* The current index into the cathedrals remembrance list. */
	u_int8_t		cathedral_idx;

	/* The last time we heard from cathedral (tunnel mode only). */
	u_int64_t		cathedral_last;

	/* All cathedrals in remembrance (tunnel mode only). */
	struct sockaddr_in	cathedrals[SANCTUM_CATHEDRALS_MAX];

	/* Our own public ip:port (when cathedral is in use only). */
	volatile u_int32_t	local_ip;
	volatile u_int16_t	local_port;

	/* The peer ip and port we send encrypted traffic too. */
	volatile u_int32_t	peer_ip;
	volatile u_int16_t	peer_port;

	/* Next time we can update the peer (when cathedral is in use only) */
	volatile u_int64_t	peer_update;

	/* The tunnel configuration. */
	struct sockaddr_in	tun_ip;
	struct sockaddr_in	tun_mask;
	u_int16_t		tun_mtu;
	u_int16_t		tun_spi;

	/* The path to the pidfile. */
	char			*pidfile;

	/* The path to the traffic secret. */
	char			*secret;

	/* The path to the kek, if any (tunnel mode only). */
	char			*kek;

	/* The network prefix for liturgy (liturgy mode only). */
	struct sockaddr_in	liturgy_prefix;

	/* The group to join in liturgy mode (liturgy mode only). */
	u_int16_t		liturgy_group;

	/* The ID to use when talking to a cathedral (tunnel mode only). */
	u_int32_t		cathedral_id;

	/* The flock we are part of for a cathedral (tunnel mode only). */
	u_int64_t		cathedral_flock;

	/* The flock we are talking to for a cathedral (tunnel mode only). */
	u_int64_t		cathedral_flock_dst;

	/* The path to the cathedral secret (!cathedral mode). */
	char			*cathedral_secret;

	/* The cathedral remembrance path (tunnel mode only). */
	char			*cathedral_remembrance;

	/* The cathedral nat discovery port (tunnel and cathedral only). */
	u_int16_t		cathedral_nat_port;

	/* The path to the secredir directory (cathedral mode only). */
	char			*secretdir;

	/* The path to the cathedral settings (cathedral mode only). */
	char			*settings;

	/* The users the different processes runas. */
	char			*runas[SANCTUM_PROC_MAX];

	/* The control socket. */
	struct sanctum_sun	control;

	/* The sanctum instance name. */
	char			instance[32];	/* XXX */

	/* The sanctum instance description. */
	char			descr[32];	/* XXX */

	/* The traffic encapsulation key, if set. */
	u_int8_t		tek[SANCTUM_KEY_LENGTH];

	/* Tx and Rx statistics. */
	struct sanctum_ifstat	tx;
	struct sanctum_ifstat	rx;

	/* Last valid sequence number for the current RX SA. */
	volatile u_int64_t	last_pn;

	/* RX SA pending. */
	volatile u_int32_t	rx_pending;

	/* The last heartbeat received from the peer. */
	volatile u_int64_t	heartbeat;

	/* Do hole punching (by sending many heartbeats for a bit). */
	volatile u_int64_t	holepunch;

	/* Process wakeup states. */
	u_int32_t		wstate[SANCTUM_PROC_MAX];

	/* Process startup signaling. */
	u_int32_t		started[SANCTUM_PROC_MAX];
};

extern struct sanctum_state	*sanctum;
extern const char		*sanctum_kem;
extern const char		*sanctum_cipher;
extern const char		*sanctum_random;
extern const char		*sanctum_asymmetry;

/* src/config.c */
void	sanctum_config_init(void);
void	sanctum_config_routes(void);
void	sanctum_config_load(const char *);
int	sanctum_config_routable(in_addr_t);

/* src/sanctum.c */
void	sanctum_signal_trap(int);
int	sanctum_last_signal(void);
void	sanctum_signal_ignore(int);
void	fatal(const char *, ...) __attribute__((format (printf, 1, 2)))
	    __attribute__((noreturn));

/* src/proc. */
int	sanctum_proc_reap(void);
void	sanctum_proc_start(void);
void	sanctum_proc_killall(int);
void	sanctum_proc_init(char **);
void	sanctum_proc_shutdown(void);
void	sanctum_proc_suspend(int64_t);
void	sanctum_proc_wakeup(u_int16_t);
void	sanctum_proc_title(const char *);
void	sanctum_proc_started(struct sanctum_proc *);
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
void	*sanctum_packet_start(struct sanctum_packet *);

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
void	sanctum_cathedrals_remembrance(void);
void	sanctum_cathedral_timeout(u_int64_t);
int	sanctum_file_open(const char *, struct stat *);
void	sanctum_log(int, const char *, ...)
	    __attribute__((format (printf, 2, 3)));
void	sanctum_logv(int, const char *, va_list);
void	sanctum_shm_detach(void *);
void	sanctum_mem_zero(void *, size_t);
void	*sanctum_alloc_shared(size_t, int *);
void	sanctum_inet_mask(void *, u_int32_t);
void	sanctum_sa_clear(struct sanctum_sa *);
void	sanctum_inet_addr(void *, const char *);
int	sanctum_bind_local(struct sockaddr_in *);
void	sanctum_peer_update(u_int32_t, u_int16_t);
int	sanctum_unix_socket(struct sanctum_sun *);
void	sanctum_stat_clear(struct sanctum_ifstat *);
char	*sanctum_config_read(FILE *, char *, size_t);
int	sanctum_traffic_kdf(struct sanctum_kex *, u_int8_t *, size_t);
int	sanctum_key_install(struct sanctum_key *, struct sanctum_sa *);
int	sanctum_key_erase(const char *, struct sanctum_key *,
	    struct sanctum_sa *, struct sanctum_sa *);
int	sanctum_offer_kdf(const char *, const char *,
	    struct sanctum_key *, void *, size_t, u_int64_t, u_int64_t);
void	sanctum_offer_nonce(u_int8_t *, size_t);
void	sanctum_offer_tfc(struct sanctum_packet *);
void	sanctum_offer_remembrance(struct sanctum_offer *, u_int64_t);
void	sanctum_offer_encrypt(struct sanctum_key *, struct sanctum_offer *);
void	sanctum_offer_install(struct sanctum_key *, struct sanctum_offer *);
int	sanctum_offer_decrypt(struct sanctum_key *,
	    struct sanctum_offer *, int);
void	sanctum_install_key_material(struct sanctum_key *, u_int32_t,
	    u_int32_t, const void *, size_t);
int	sanctum_base_key(const char *, u_int64_t, u_int64_t,
	    u_int32_t, void *, size_t);

const char		*sanctum_inet_string(struct sockaddr_in *);
struct sanctum_offer	*sanctum_offer_init(struct sanctum_packet *pkt,
			    u_int32_t, u_int64_t, u_int8_t);

/* platform bits. */
void	sanctum_platform_init(void);
int	sanctum_platform_tundev_create(void);
void	sanctum_platform_ip_fragmentation(int, int);
void	sanctum_platform_sandbox(struct sanctum_proc *);
ssize_t	sanctum_platform_tundev_read(int, struct sanctum_packet *);
ssize_t	sanctum_platform_tundev_write(int, struct sanctum_packet *);
void	sanctum_platform_tundev_route(struct sockaddr_in *,
	    struct sockaddr_in *);

void	sanctum_platform_wakeup(u_int32_t *);
void	sanctum_platform_suspend(u_int32_t *, int64_t);

#if defined(__linux__)
void	sanctum_linux_trace_start(struct sanctum_proc *);
int	sanctum_linux_seccomp(struct sanctum_proc *, int);
#endif

/* Worker entry points. */
void	sanctum_bless(struct sanctum_proc *) __attribute__((noreturn));
void	sanctum_bishop(struct sanctum_proc *) __attribute__((noreturn));
void	sanctum_chapel(struct sanctum_proc *) __attribute__((noreturn));
void	sanctum_shrine(struct sanctum_proc *) __attribute__((noreturn));
void	sanctum_pilgrim(struct sanctum_proc *) __attribute__((noreturn));
void	sanctum_control(struct sanctum_proc *) __attribute__((noreturn));
void	sanctum_confess(struct sanctum_proc *) __attribute__((noreturn));
void	sanctum_cathedral(struct sanctum_proc *) __attribute__((noreturn));
void	sanctum_liturgy(struct sanctum_proc *) __attribute__((noreturn));
void	sanctum_heaven_rx(struct sanctum_proc *) __attribute__((noreturn));
void	sanctum_heaven_tx(struct sanctum_proc *) __attribute__((noreturn));
void	sanctum_purgatory_rx(struct sanctum_proc *) __attribute__((noreturn));
void	sanctum_purgatory_tx(struct sanctum_proc *) __attribute__((noreturn));

#endif
