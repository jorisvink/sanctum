# Cryptographic description

## Algorithms

The algorithm used to provide confidentiality and integrity for
user traffic and management traffic is AES256-GCM, alternatively
Agelas if selected at compile-time.

For user traffic, unique session keys (defined below) are used in each
direction with a 64-bit packet counter used to construct the nonce
value (in combination with a unique salt). The ESP header and tail are
included in the AAD.

For management traffic, unique encryption keys are derived from the
shared symmetric secret (defined below) per packet. In this case
because the keys are freshly derived the nonces used in this
construction are fixed as there is no risk for (key, nonce)
pair re-use in this specific scenario.

Key derivation for session keys is done by combing unique
per-direction shared secrets from ECDH (x25519) and ML-KEM-1024,
together with a derivative of our shared symmetrical key.

IKM = len(ecdh_ss) || ecdh_ss || len(mlkem1024_ss) || mlkem1024_ss ||
      len(local.pub) || local.pub || len(offer.pub) || offer.pub

This IKM is run through KMAC256() instantiated with the derived
key from the shared symmetrical secret, to produce strong and unique
session keys in both RX and TX directions.

## Keys

Sanctum uses several different secrets and keys to provide
confidentiality and integrity for both traffic and authentication
purposes.

It is paramount that these keys - with the exception of Ambries -
are handled as red keys (https://csrc.nist.gov/glossary/term/red_key).

An ambry is can be handled as an encrypted key
(https://csrc.nist.gov/glossary/term/encrypted_key).

This document describes all key material, where it comes from
and how it is used.

### TL;DR

| Key | Description | Type |
| --- | ----------- | ---- |
| SS | The shared secret between two peers used for key exchanges. | Red
| SK | A session key used to provide traffic confidentiality and integrity. | Red
| CS | The cathedral secret, used to talk to a cathedral if enabled. | Red
| KEK | A key-encryption-key, used for wrapping an Ambry. | Red
| TEK | Traffic encapsulation key, used to prevent traffic analysis. | Traffic
| Ambry | A shared secret (SS) wrapped with a KEK. | Black

## Separation

All keys are located in one of the key processes like chapel, cathedral,
shrine or pilgrim and are not available from any of the other processes.

The exception is the TEK (Traffic Encapsulation Key) as this key is only
used to prevent traffic analysis. This key is available in purgatory-rx
and purgatory-tx, but does not need to be explicitly wiped from other
processes due to its nature.

## The shared secret (SS)

The shared secret is a 256-bit symmetrical key shared between two
peers that wish to communicate with each other.

The SS is used to provide confidentiality and integrity for key offers
and to provide additional strength to the session key derivation.

The SS is not used directly, but instead three derivations are taken,
one for each specific purpose:

```
    ss = shared secret, loaded from disk
    flock = cathedral_flock or 0 if no cathedral is in use, 64-bit

    offer_base = KMAC256(ss, "SANCTUM.KEY.OFFER.KDF", domain), 256-bit
    traffic_base_rx = KMAC256(ss, "SANCTUM.KEY.TRAFFIC.RX.KDF", flock), 256-bit
    traffic_base_tx = KMAC256(ss, "SANCTUM.KEY.TRAFFIC.TX.KDF", flock), 256-bit
```

Shared secrets can either be distributed invididually to all locations, or
these can be distributed via a cathedral as an ambry, see docs/cathedral.md.

## A session key (SK)

Session keys (SK) are derived from the **traffic_base_rx** or
**traffic_base_tx** keys in combination with directional unique
ECDH (x25519) and ML-KEM-1024 shared secrets, using KMAC256() as the KDF.

Both sides start by sending out offerings that contain an ML-KEM-1024
public key and an x25519 public key.

Both sides upon receiving these offerings will perform ML-KEM-1024
encapsulation and send back the ciphertext and their own x25519
public key which differs from the one sent in the initial offering.

When a side performs encapsulation it will derive a fresh
RX session key using all of that key material and install the
key as a pending RX key.

When a side performs decapsulation it will derive a fresh
TX session key using all of that key material and install the
key as the active TX key.

In both cases this results in unique shared secrets for x25519
and ML-KEM-1024 in each direction, while allowing us to gracefully
install pending RX keys so that we do not miss a beat.

New offerings are sent when too many packets have been sent on a given
key or when the keys become too old.

```
derive_offer_encryption_key(seed):
    input = len(seed) || seed
    wk = KMAC256(offer_base, "SANCTUM.SACRAMENT.KDF", input), 256-bit
    return wk

offer_create():
    offer.ecdh = X25519-KEYGEN()
    offer.kem  = ML-KEM-1024-KEYGEN()
    offer.now  = TIME(WALL_CLOCK), 64-bit
    offer.id   = PRNG(64-bit), unique sanctum id
    offer.salt = PRNG(32-bit), salt for nonce construction
    offer.spi  = PRNG(32-bit), the spi for this association

    offer.internal_seed = unused and set to random data
    offer.internal_tag  = unused and set to random data

    return offer

offer_send_pk(offer):
    seed = PRNG(512-bit)
    dk = derive_offer_encryption_key(seed)

    header = 0x53414352414D4E54 || offer.spi || seed
    pt = id || salt || now || internal_seed ||
         offer.ecdh.pub || offer.kem.pk || internal_tag
    encdata = AES256-GCM(dk, nonce=1, aad=header, pt)

    packet.header = header
    packet.data = encdata
    send(packet)

offer_recv_pk(offer):
    packet = recv()

    dk = derive_offer_encryption_key(packet.header.seed)
    pt = AES256-GCM(dk, nonce=1, aad=packet.header, packet.data)

    ecdh_ss = X25519-SCALAR-MULT(pt.ecdh.pub, offer.ecdh.private)
    offer.kem.ct, kem_ss = ML-KEM-1024-ENCAP(pt.kem.pk)

    if pt.instance < local_id
        traffic_key = traffic_base_rx
    else
        traffic_key = traffic_base_tx

    x = len(ecdh_ss) || ecdh_ss || len(kem_ss) || kem_ss ||
        len(ecdh.pub) || ecdh.pub || len(pt.ecdh.pub) || pt.ecdh.pub
    rx = KMAC256(traffic_key, "SANCTUM.TRAFFIC.KDF", x), 256-bit

    return rx

offer_send_ct(offer):
    seed = PRNG(512-bit)
    dk = derive_offer_encryption_key(seed)

    header = 0x53414352414D4E54 || spi || seed
    pt = id || salt || now || internal_seed ||
         offer.ecdh.pub || offer.kem.ct || internal_tag
    encdata = AES256-GCM(dk, nonce=1, aad=header, pt)

    packet.header = header
    packet.data = encdata
    send(packet)

offer_recv_ct(offer):
    packet = recv()

    dk = derive_offer_encryption_key(packet.header.seed)
    pt = AES256-GCM(dk, nonce=1, aad=packet.header, packet.data)

    ecdh_ss = X25519-SCALAR-MULT(pt.ecdh.pub, offer.ecdh.private)
    kem_ss = ML-KEM-1024-DECAP(offer.kem, pt.kem.ct)

    if pt.instance < local_id
        traffic_key = traffic_base_tx
    else
        traffic_key = traffic_base_rx

    x = len(ecdh_ss) || ecdh_ss || len(kem_ss) || kem_ss ||
        len(ecdh.pub) || ecdh.pub || len(pt.ecdh.pub) || pt.ecdh.pub
    tx = KMAC256(traffic_key, "SANCTUM.TRAFFIC.KDF", x), 256-bit

    return tx

key exchange:
    my_offer = offer_create()
    peer_offer = offer_create()

    offer_send_pk(my_offer)
    tx = offer_recv_ct(my_offer)

    rx = offer_recv_pk(peer_offer)
    offer_send_ct(peer_offer)
```

## Key-Encryption-Key (KEK)

The KEK is a 256-bit symmetrical key that is unique per peer and
is used to wrap ambries carrying a new SS.

```
kek_derive_key_for_wrapping_ambry(seed):
    kek = key-encryption-key, 256-bit
    wk = KMAC256(kek, "SANCTUM.AMBRY.KDF", len(seed) || seed), 256-bit
    return wk
```

## Ambry

An ambry is a shared secret (SS) that is wrapped using the peer KEK.

```
ambry:
    seed = seed selected uniformly at random, 512-bit
    dk = kek_derive_key_for_wrapping_ambry(seed)

    tunnel = the tunnel this ambry is valid for
    tag = the authentication tag for the wrapped data
    key = the new SS, selected uniformly at random, 256-bit

    ambry = AES256-GCM(dk, nonce=1, aad=tunnel || seed, key)
```

## Cathedral secret (CS)

A cathedral secret is a 256-bit symmetrical key used to provide
confidentiality and integrity for messages that are sent and
received to and from the cathedral.

Each CS on the cathedral is tied to a 32-bit identifier.
For more information on cathedrals, see docs/cathedral.md.

Note that a cathedral does not hold the keys to unwrap Ambries.

```
cathedral_derive(seed):
    ck = cathedral secret, 256-bit
    wk = KMAC256(ck, "SANCTUM.CATHEDRAL.KDF", len(seed) || seed), 512-bit
    return wk

Peer to cathedral notify message:
    now  = seconds since boot, 64-bit
    spi  = set to the CS identifier, 32-bit
    salt = the current ambry generation, 32-bit
    id   = the tunnel spi that we want traffic for, 64-bit

    key           = unused and set to random data
    internal_seed = unused and set to random data
    internal_tag  = unused and set to random data

    seed = seed selected uniformly at random, 512-bit
    dk = cathedral_derive(seed)

    magic = 0x4b4154454452414c, 64-bit

    header = magic || spi || seed
    encdata = id || salt || now || internal_seed || key || internal_tag
    encdata = AES256-GCM(dk, nonce=1, aad=header, encdata)

    send(header || encdata)

Cathedral to peer ambry message:
    now  = seconds since boot, 64-bit
    spi  = set to the CS identifier, 32-bit
    salt = the current ambry generation, 32-bit
    id   = the tunnel spi that this ambry is for, 64-bit

    internal_seed = set to the ambry seed.
    internal_tag  = set to the ambry authentication tag
    key           = set to the ambry shared secret (SS)

    dk = cathedral_derive()
    magic = 0x4b4154454452414c, 64-bit

    header = magic || spi || se
    encdata = id || salt || now || internal_seed || sk || internal_tag
    encdata = AES256-GCM(dk, nonce=1, aad=header, encdata)

    send(header || encdata)
```

## Traffic Encapsulation Key (TEK)

The TEK is used when traffic encapsulation is turned on. When it is active,
a 128-bit mask is derived using the TEK and KMAC256() based on an outer ESP
header and a 128-bit seed.

This mask is then XOR'd onto the inner ESP header and the outer header
is stripped, leaving us with the original to be transported packet.

With traffic encapsulation all sanctum traffic will be indistinguishable
from other implementations their IPSec traffic.
