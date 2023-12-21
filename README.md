<p align="center">
<img src="images/sanctum_logo.png" alt="sanctum" width="256px" />
</p>

# Sanctum

"Thee packets that are chosen needeth not fear purgatory, for thee
shall be safe with my blessing. Confess thy sins and moveth into heaven."

Sanctum 1:1

## About

This is a very small, reviewable, capable, experimental and fully privilege
seperated VPN daemon capable of transporting encrypted network traffic
between two peers.

**NOTE: This is a work in progress.**

**WARNING: Experimental duplex-sponge based cryptography.**

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
| heaven | The process receiving and sending packets on the inner interface.
| purgatory | The process receiving and sending packets on the outer interface.
| pilgrim | The process handling TX keys when running in pilgrim mode.
| shrine | The process handling RX keys when running in shrine mode.
| cathedral | The process forwarding traffic when running in cathedral mode.

Each process can run as its own user.

Each process is sandboxed and only has access to the system calls
required to perform its task.

## Packets

The processes share packets between each other in a very well defined way.

For incoming packets:

```
purgatory (crypto) -> confess (decryption) -> heaven (clear)
```

For outgoing packets:

```
heaven (clear) -> bless (encrypt) -> purgatory (crypto)
```

Due to the design of sanctum it is impossible to move a packet straight
from the clear side to the crypto side without passing the encryption
process.

## Key Exchange

The chapel process is responsible for sending fresh keys on certain
intervals to the configured peer.

The keys are derived from a shared symmetrical secret that both
sides must have on disk.

The exchange is protected in transit by a duplex-sponge based
cryptographic AE cipher, while the keys are derived using KMAC256.

## Traffic

The encrypted traffic is encapsulated with ESP in tunnel mode, using
64-bit sequence numbers and encrypted under AES256-GCM using keys
exchanged via the chapel sacristy key exchange.

## Building

```
$ git clone https://github.com/jorisvink/sanctum
$ cd sanctum
$ make
# make install
```

If this is to complicated for you, this isn't your software.

## Platforms

Sanctum builds on MacOS 13+, OpenBSD 6.8+ and Linux-y things like Ubuntu 22.04.

## High performance mode

When sanctum is built with the CIPHER=intel-aes-gcm and HPERF=1,
high performance mode is enabled.

In this mode, sanctum is able to reach 10gbps speeds on certain platforms
and depending on what hardware is used.

## Configuring

Sanctum uses a configuration file. Find an example of
a simple configuration below.

```config
# Name of this sanctum instance.
instance laptop

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

# Processes can run as different users.
run bless as _sanctum
run heaven as _sanctum
run confess as _sanctum
run purgatory as _sanctum

# Run chapel as different user.
run chapel as _chapel
```
