# Sanctum

## About

This is a small, reviewable, capable, pq-safe and fully privilege
separated VPN daemon for OpenBSD, Linux and MacOS.

Due to its privilege separated design, sanctum guarantees that
all of its important assets are separated from the processes
that talk to the internet or handle non-cryptography related
things.

Sanctum tunnels are always peer-to-peer and end-to-end encrypted.

If one or both peers are behind NAT you can use sanctum's cathedral
mode as a discovery and relay service (relay only if p2p does not
work due to NAT constraints).

See [The Reliquary](https://reliquary.se), a community driven
sanctum cathedral setup.

It is entirely possible to set up your own cathedrals.

## Privilege separation

There are several processes that make up a sanctum instance:

| Process name | Description  |
| ------------ | ------------ |
| bless | The process responsible for encrypting packets.
| confess | The process responsible for decrypting packets.
| chapel | The process responsible for deriving new TX/RX keys from a key.
| heaven-rx | The process receiving packets on the inner interface.
| heaven-tx | The process sending packets on the inner interface.
| purgatory-rx | The process receiving packets on the outer interface.
| purgatory-tx | The process sending packets on the outer interface.
| pilgrim | The process handling TX keys when running in pilgrim mode.
| shrine | The process handling RX keys when running in shrine mode.
| cathedral | The process forwarding traffic when running in cathedral mode.
| liturgy | The process responsible for autodiscovery of peers in a cathedral.
| bishop | The process responsible for configuring autodiscovered tunnels.
| guardian | The process monitoring all other processes.

Each process runs as its own user.

Each process is fully sandboxed and only has access to the system
calls required to perform its task. There are two exceptions: guardian
(the main process), and bishop (liturgy manager), neither of these
are sandboxed due what they are responsible for.

The guardian process is only monitoring its child processes and has no
other external interfaces. The bishop process must be privileged due to
the fact it is fork+exec'ing the hymn configuration tool for setting up
new tunnels when using liturgy mode.

## Packet flow

The processes share packets between each other in a very well defined way.

For incoming packets:

```
purgatory-rx (black) -> confess (decryption) -> heaven-tx (red)
```

For outgoing packets:

```
heaven-rx (red) -> bless (encrypt) -> purgatory-tx (black)
```

When the processes start they will remove any of the queues they do not
need for operating.

As an example of why this is important, it is impossible for a packet
that arrives on the plaintext interface to be moved to the ciphertext
interface without passing the encryption process.

## Key Exchange

Sanctum is post-quantum safe due to its unique approach to
deriving session keys based on a shared symmetrical secret in
combination with a hybridized asymmetrical exchange. It combines
both classic ECDH (x25519) and the PQ-safe NIST standardized
ML-KEM-1024.

See [docs/crypto.md](docs/crypto.md) for details on the key exchange.

## Traffic encryption

Traffic is encapsulated with the sanctum protocol header which in turn is
carried in a UDP packet, using incrementing 64-bit sequence numbers.

Traffic is encrypted under AES256-GCM using keys negotiated as described above.

A 96-bit nonce is used, constructed as follows:

```
nonce = 32-bit salt from key exchange || 64-bit packet counter
```

You can select what cipher sanctum will use by specifying a CIPHER environment
variable at compile time with one of the following:

- libsodium-aes-gcm (AES256-GCM via libsodium) **[default]**
- mbedtls-aes-gcm (AES256-GCM via mbedtls 3.x its mbedcrypto lib).
- intel-aes-gcm (AES256-GCM via Intel its highly performant libisal_crypto lib).
- nyfe-agelas (Agelas via nyfe, an AEAD cipher based on Keccak).

Note that no matter which CIPHER is selected libsodium is always
a dependency as it is used for x25519.

## One-directional tunnels

Sanctum supports one-directional tunnels, this is called the pilgrim
and shrine mode.

In pilgrim mode, sanctum will be able to send encrypted traffic to its
shrine peer. It will however never send an **RX** key to its peer (a shrine).

In shrine mode, sanctum will be able to verify and decrypt the arriving traffic
but will never receive a **TX** key from its peer.

This allows one-way traffic to flow from a pilgrim to the shrine
with a strong guarantee that the shrine cannot send data back
(there are no keys nor are there any processes to do so).

Note that no asymmetry is available for one-directional tunnels.

## Cathedrals

A cathedral is a sanctum mode that can run on a machine somewhere
and is an authenticated relay and key distribution point. A cathedral
can never read, modify or inject valid traffic as it does not hold
any of the session keys.

Peers can use a cathedral to move to a peer-to-peer end-to-end encrypted
connection if both peers are behind a not too restrictive NAT.

A cathedral may also be used as an Ambry distribution point for
shared secret rollover. These ambry bundles are wrapped with
unique per-device KEKs and are unable to be read by the cathedral.

This essentially solves the key distribution problem with symmetrical
keys by providing you with a way to allow the cathedrals to hand out
black keys to devices.

See [docs/crypto.md](docs/crypto.md) for details on the ambries and
[docs/cathedral.md](docs/cathedral.md) for details on a cathedral.

## Building

A default build requires pkg-config and libsodium.

```
$ git clone https://github.com/jorisvink/sanctum
$ cd sanctum
$ make
# make install
```

It is entirely possible to swap the underlying kem, ecdh, cipher and random
implementations used in sanctum, please see the **mk** directory how this
is configured and done.

## Platforms

Sanctum builds on MacOS 13+, OpenBSD 6.8+ and Linux-y things like Ubuntu 22.04.

## Configuring

Sanctum uses a configuration file. Find an example of
a simple configuration below.

```config
# Name of this sanctum instance.
instance laptop

# Uncomment if you want l2 instead of l3.
#tap yes

# Path to the shared secret.
secret /etc/sanctum/laptop_secret.key

# The control socket for pontifex.
run control as joris
control /tmp/sanctum-control joris

# The tunnel configuration
tunnel 1.0.0.1/30 1422

# Add additional routes over the tunnel
route 2.0.0.0/24

# The local address to which sanctum binds.
local x.x.x.x:2333

# Optional peer address, ignore if you have a peer that
# moves networks a lot.
peer y.y.y.y:2333

# The encryption and decryption processes.
run bless as _bless
run confess as _confess

# Run the internal io processes as one user.
run heaven-rx as _heaven
run heaven-tx as _heaven

# Run the external io processes as another.
run purgatory-rx as _purgatory
run purgatory-tx as _purgatory

# Run the bishop as privileged root.
run bishop as root

# Run chapel for the key exchange as yet another user.
run chapel as _chapel
```

## As a library

You can use [libkyrka](https://github.com/jorisvink/libkyrka) to implement
the sanctum protocol and tunnels into your application directly. Note that
this does not provide the same type of sandboxing as the daemon.
