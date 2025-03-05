# Sanctum

"Thee packets that are chosen needeth not fear purgatory, for thee
shall be safe with my blessing. Confess thy sins and thy shall enter
the heavens."

Sanctum 1:1

## About

This is a very small, reviewable, capable, experimental and fully privilege
seperated VPN daemon capable of transporting encrypted network traffic
between two peers.

**WARNING: This code uses an experimental AEAD cipher based on
Keccak-f[1600,24] to provide confidentiality and integrity
for transmitted session keys during the key exchange.**

Due to its privilege separated design, sanctum guarantees that
all of its important assets are separated from the processes
that talk to the internet or handle non-cryptography related
things.

### Mythology

Whats with the weird mythology around this project?

It's fun, but it doesn't make it less of a serious project.

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

Each process can run as its own user.

Each process is sandboxed and only has access to the system calls
required to perform its task. There are two exceptions, guardian
(the main process) is not sandboxed nor seccomped, and bishop.

The guardian process is only monitoring its child processes and has no
other external interfaces. The bishop process must be privileged due to
the fact it is fork+exec'ing the hymn configuration tool for setting up
new tunnels.

## Packets

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

A sanctum instance is responsible for sending its **RX** key to
the other side. It does this by periodically generating a new
key uniformly at random and wrapping it with a secret derived
from the underlying shared secret between both parties.

See docs/crypto.md for details on the session key and shared secrets.

Note that sanctum only supports symmetrical keying and does not
implement any asymmetrical key exchange method.

Your shared secret must be handled with **great care** and
must be rotated **often**. When using a cathedral you can use
the Ambry distribution to update shared secrets.

## Traffic

The encrypted traffic is encapsulated with ESP in tunnel mode, using
incrementing 64-bit sequence numbers. The traffic is either encrypted
with AES256-GCM or Agelas and are encrypted under keys exchanged as described
above.

In both cases a 96-bit nonce constructed as follows is used:

```
nonce = 32-bit salt from key exchange || 64-bit packet counter
```

You can select what cipher to use by specifying a CIPHER environment
variable at compile time with either:

- nyfe-agelas (Agelas as provided by Nyfe).
- openssl-aes-gcm (AES256-GCM via OpenSSL its low level API).
- intel-aes-gcm (AES256-GCM via Intel its highly performant libisal_crypto lib).

## Unidirectional tunnels

Sanctum supports unidirectional tunnels, this is called the pilgrim
or shrine mode.

In pilgrim mode, sanctum will be able to send encrypted traffic to its
shrine peer. It will however never send an **RX** key to its peer (a shrine).

In shrine mode, sanctum will be able to verify and decrypt the arriving traffic
but will never receive a **TX** key from its peer.

This allows one-way traffic to flow from a pilgrim to the shrine
with a strong guarantee that the shrine cannot send data back
(there are no keys).

## Cathedrals

A cathedral is a sanctum mode that can run on a machine somewhere
and will relay packets between tunnel end-points without being able
to read, inject or modify packets.

Peers can use a cathedral to move to a peer-to-peer end-to-end encrypted
connection if both peers are behind a not too restrictive NAT.

A cathedral may also be used as an Ambry distribution point for
shared secret rollover.

Please read docs/cathedral.md for more.

## Building

A default build requires pkg-config and libssl-dev.

```
$ git clone https://github.com/jorisvink/sanctum
$ cd sanctum
$ make
# make install
```

If this is to complicated for you, this isn't your software.

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

# Run chapel for the key exchange as yet another user.
run chapel as _chapel
```
