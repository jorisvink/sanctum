# Keys

Sanctum uses several different secrets and keys to provide
confidentiality and integrity for both traffic and authentication
purposes.

It is paramount that these keys - with the exception of Ambries -
are handled as red keys (https://csrc.nist.gov/glossary/term/red_key).

An ambry is can be handled as an encrypted key
(https://csrc.nist.gov/glossary/term/encrypted_key).

This document describes all key material, where it comes from
and how it is used.

## TL;DR

| Key | Description | Type |
| --- | ----------- | ---- |
| SS | The shared secret between two peers used for key exchanges. | Red
| SK | A session key used to provide traffic confidentiality and integrity. | Red
| CS | The cathedral secret, used to talk to a cathedral if enabled. | Red
| KEK | A key-encryption-key, used for wrapping an Ambry. | Red
| Ambry | A shared secret (SS) wrapped with a KEK. | Black

## Separation

All keys are located in one of the key processes like chapel, cathedral,
shrine or pilgrim and are not available from any of the other processes.

## Wrapping algorithm

The algorithm used to provide confidentiality and integrity for
key offers, cathedral messages or wrapped Ambries is Agelas,
an AEAD cipher based on Keccak-1600.

Note that this is highly experimental.

## The shared secret (SS)

The shared secret is a 256-bit symmetrical key shared between two peers
used to derive keys for wrapping session keys.

These are either distributed invididually to all locations, or
these can be distributed via a cathedral as an ambry, see docs/cathedral.md.

## A session key (SK)

Session keys are 256-bit symmetrical keys selected uniformly at random
when generated and are created by both peers when no previous session
exists or, when a session has sent too many packets or is 1 hour old.

Once the session keys have been exchanged they are used to provide
traffic confidentiality and integrity using either AES256-GCM or Agelas,
depending on how Sanctum was compiled (defaulting to AES256-GCM).

```
derive_key(seed):
    ss = shared secret, 256-bit
    wk = KMAC256(ss, "SANCTUM.SACRAMENT.KDF", len(seed) || seed), 512-bit
    return wk

Key offer:
    now  = seconds since boot, 64-bit
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
    encdata = Agelas(dk, aad=header, encdata)

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

    ambry = Agelas(dk, aad=tunnel || seed, key)
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
    encdata = Agelas(dk, aad=header, encdata)

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
    encdata = Agelas(dk, aad=header, encdata)

    send(header || encdata)
```
