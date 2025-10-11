# Protocol description

## User data

User data that is encrypted is transported using a format
that somewhat mimics ESP encapsulation in tunnel mode. This
means we carry an ESP-like header encapsulated payload in
a UDP packet.

The format loosely is based on rfc4106 (GCM in IPSec).

A short version of that is here:

```
sanctum_header {
	spi		- 32-bit
	seq		- 32-bit
	flock_src	- 64-bit
	flock_dst	- 64-bit
}

esp_tail {
	next_proto	- 8-bit
	padding		- 8-bit
}

packet_counter - 64-bit
payload = AES-GCM256(packet || esp_tail, aad=sanctum_header)

+------------------------------------------------------+
| ip | udp | sanctum_header | packet_counter | payload |
+------------------------------------------------------+
```

## Management data

Management traffic such as key exchanges of cathedral messages
are called **offers**. Several different types of offers
exist, below is a list of them.

```
1) A symmetric key offering (between peers)
2) An ambry offering (from cathedral to us)
3) An info offering (from us to cathedral, or cathedral to us)
4) A liturgy offering (from us to cathedral, or cathedral to us)
5) A remembrance offering (from cathedral to us)
6) A key exchange offering (between peers)
```

An offer packet is defined as follows:

```
struct sanctum_offer {
	struct sanctum_offer_hdr	hdr;
	struct sanctum_offer_data	data;
	u_int8_t			sig[SANCTUM_ED25519_SIGN_LENGTH];
	u_int8_t			tag[SANCTUM_TAG_LENGTH];
} __attribute__((packed));
```

The **hdr** field is transmitted in plaintext while the **data** and
**sig** fields are encrypted under offer_key (see docs/crypto.md). The
**tag** field contains the authentication tag for said encrypted data.

Offers sent to the cathedral by clients are also signed using ed25519
under the client its private key, this signature is calculated over
the **data** field and written to **sig**.

Note that **hdr** is added as AAD.

### Offer header

```
struct sanctum_offer_hdr {
	u_int64_t		magic;
	u_int64_t		flock_src;
	u_int64_t		flock_dst;
	u_int32_t		spi;
	u_int8_t		seed[SANCTUM_KEY_OFFER_SALT_LEN];
} __attribute__((packed));
```

The offer header contains a **magic** field that is set to the
type of offer the packet contains:

```
Key exchange offers magic value     = 0x53414352414D4E54 (SACRAMNT)
Cathedral offers magic value        = 0x4b4154454452414c (KATEDRAL)
Cathedral nat detection magic value = 0x4349424f5249554d (CIBORIUM)
```

The header also contains **flock_src** and **flock_dst** flock identities
in case the packet traverses a cathedral, this way the cathedral knows the
source and destination flocks required to forward the offer.

The header **spi** member contains the local instance its current spi.

The header **seed** member contains the seed used to derive the
encryption key from the offer_key (see docs/crypto.md) for this
specific offer packet.

### Offer data

The offer data is encrypted.

```
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
```
The type of data that is carried in the offer depends on the **type**
member in the data structure.

A **timestamp** is given so that offers can get some form of replay
protection. Offers that are out of range of -5,+5 seconds of the
receiver their clock are dropped.

## Liturgies

A liturgy is a feature of a cathedral that clients can use
when talking to said cathedral to do auto-discovery of peers
in the same flock.

Liturgies are carried in an **offer**.

```
struct sanctum_liturgy_offer {
	u_int8_t		id;
	u_int16_t		group;
	u_int8_t		peers[SANCTUM_PEERS_PER_FLOCK];
	u_int8_t		hidden;
	u_int32_t		flags;
} __attribute__((packed));
```

The **id** member carries the peer id in the flock.

The **group** member designates in which group this liturgy lives, allowing
different liturgies at the same time for different purposes.

The **peers** array carries the peers that are online or are signaling
when this message is received from the cathedral. When sending this
message to the cathedral it carries the peers you are trying to signal,
or is zeroed for discovery.

The **hidden** member indicates if a peer is hidden in discovery mode,
this can be used to build automatic hub-and-spoke networks where hubs
set **hidden** to 0 while the spokes set it to 1. It is unfortunate that
this was never rolled into the **flags** member.

The **flags** member indicate if a peer is interested in a discovery
or signaling (1 << 1) mode and wether or not it wants a remembrance (1 << 0).

There are two types of liturgies:

### Discovery

The discovery liturgy can be used to auto-discover what other
peers in the same flock are currently also online.

### Signaling

The signaling liturgy can be used to signal to other peers
in the same flock that you are trying to reach them.
