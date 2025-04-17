# Protocol description

## User data

User data that is encrypted is transported using a format
that mimics ESP encapsulation in tunnel mode. This means
we carry the ESP encapsulated payload in a UDP packet.

The exact format is based on rfc4106 (GCM in IPSec).

A short version of that is here:

```
esp_header {
	spi	- 32-bit
	seq	- 32-bit
}

esp_tail {
	next_proto	- 8-bit
	padding		- 8-bit
}

packet_counter - 64-bit
payload = AES-GCM256(packet || esp_tail, aad=esp_header)

+--------------------------------------------------+
| ip | udp | esp_header | packet_counter | payload |
+--------------------------------------------------+
```

## Manager data

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
	u_int8_t			tag[SANCTUM_TAG_LENGTH];
} __attribute__((packed));
```

### Offer header

```
struct sanctum_offer_hdr {
	u_int64_t		magic;
	u_int64_t		flock;
	u_int32_t		spi;
	u_int8_t		seed[SANCTUM_KEY_OFFER_SALT_LEN];
} __attribute__((packed));
```

The **hdr** field is transmitted in plaintext while the **data** field
is encrypted under offer_key (see docs/crypto.md) and **tag** contains
an AES-GCM authentication tag for said encrypted data.

The offer header contains a **magic** field that is set to the
type of offer the packet contains:

```
Key exchange offers magic value     = 0x53414352414D4E54 (SACRAMNT)
Cathedral offers magic value        = 0x4b4154454452414c (KATEDRAL)
Cathedral nat detection magic value = 0x4349424f5249554d (CIBORIUM)
```

The header also contains a **flock* identity in case the packet
traverses a cathedral, this way the cathedral knows in which
flock it needs to look for forwarding the offer.

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
