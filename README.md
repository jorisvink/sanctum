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
| heaven-rx | The process receiving packets on the inner interface.
| heaven-tx | The process sending packets on the inner interface.
| purgatory-rx | The process receiving packets on the outer interface.
| purgatory-tx | The process sending packets on the outer interface.
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
purgatory-rx (black) -> confess (decryption) -> heaven-tx (red)
```

For outgoing packets:

```
heaven-rx (red) -> bless (encrypt) -> purgatory-tx (black)
```

Due to the design of sanctum it is impossible to move a packet straight
from the clear side to the crypto side without passing the encryption
process.

## Key Exchange

The key exchange in sanctum happens via either the chapel, pilgrim or
shrine processes (depending on what mode is configured) but is generally
the same approach.

A sanctum instance is responsible for sending its **RX** key to
the other side. It does this by periodically generating a new
key uniformly at random and wrapping it with a secret derived
from the underlying shared secret between both parties.

This wrapped **RX** key is then transmitted to the other side where
it is unwrapped and installed as the **TX** key.

This wrapping and unwrapping happens using a duplex-sponge
based cryptographic AE cipher while the key used is derived
from the underlying shared secret using KMAC256.

While this alone does not provide PFS, the underlying key
may be swapped out OOB by other means while sanctum is running.

I recommend you rotate this key often.

## Traffic

The encrypted traffic is encapsulated with ESP in tunnel mode, using
64-bit sequence numbers. The traffic is either encrypted with AES256-GCM
or Agelas and are encrypted under keys exchanged as described above.

You can select what cipher to use by specifying a CIPHER environment
variable at compile time with either:

- openssl-aes-gcm (AES256-GCM via OpenSSL its low level API).
- intel-aes-gcm (AES256-GCM via Intel its highly performant libisal_crypto lib).
- nyfe-agelas (Agelas as provided by Nyfe).

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
