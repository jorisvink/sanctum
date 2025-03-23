# Cryptographic description

## Algorithm

The algorithm used to provide confidentiality and integrity for
user traffic and management traffic is AES256-GCM.

For user traffic, unique session keys (defined below) are used in both
directions with a 64-bit packet counter used to construct the nonce
value (in combination with a unique salt). The ESP header and tail are
included in the AAD.

For management traffic, unique encryption keys are derived from the
shared secret (defined below) per packet. In this case because the
keys are freshly derived the nonces used in this construction
are fixed as there is no risk for (key, nonce) pair re-use
in this specific scenario.

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

The shared secret is a 256-bit symmetrical key shared between two peers
used to derive keys for wrapping session keys.

These are either distributed invididually to all locations, or
these can be distributed via a cathedral as an ambry, see docs/cathedral.md.

## A session key (SK)

Session keys are 256-bit symmetrical keys selected uniformly at random
when generated and are created by both peers when no previous session
exists or, when a session has sent too many packets or is 1 hour old.

These SK's are encrypted with keys derived from the SS and are exchanged
between both peers.

Once the session keys have been exchanged they are used to provide
traffic confidentiality and integrity using AES256-GCM.

```
derive_key(seed):
    ss = shared secret, 256-bit
    wk = KMAC256(ss, "SANCTUM.SACRAMENT.KDF", len(seed) || seed), 512-bit
    return wk

Key offer:
    now  = wall time in seconds, 64-bit
    sk   = session key selected uniformly at random, 256-bit
    id   = unique sanctum ID selected uniformly at random at start, 64-bit
    salt = salt for nonce construction, selected uniformly at random, 32-bit
    spi  = the spi for this association, selected uniformly at random, 32-bit

    internal_seed = unused and set to random data
    internal_tag  = unused and set to random data

    seed = seed selected uniformly at random, 512-bit
    dk = derive_key(seed)

    magic = 0x53414352414D4E54, 64-bit

    header = magic || spi || seed
    encdata = id || salt || now || internal_seed || sk || internal_tag
    encdata = AES256-GCM(dk, nonce=1, aad=header, encdata)

    send(header || encdata)
```

## Key-Encryption-Key (KEK)

The KEK is a 256-bit symmetrical key that is unique per peer and
is used to wrap ambries carrying a new SS.

```
kek_derive_key_for_wrapping_ambry(seed):
    kek = key-encryption-key, 256-bit
    wk = KMAC256(kek, "SANCTUM.AMBRY.KDF", len(seed) || seed), 512-bit
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
