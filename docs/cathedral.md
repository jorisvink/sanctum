# Cathedrals

A cathedral is a sanctum process on a server somewhere that can
relay packets to peers and is able to distribute wrapped ambries
to peers when required.

It makes it possible for peers to talk to each other, end-to-end
encrypted, when behind NAT or when you don't want to know where
the peer is located.

A cathedral can never read, alter or insert new encrypted packets.

## Time

It is imperative that peers and cathedrals their clocks are in-sync as
messages include timestamps which are checked after the integrity
of the packets are validated.

Clocks are allowed to be out of sync within a period of 20 seconds,
from -10 seconds to +10 seconds.

## Flocks

A cathedral can create different flocks (networks) that allows for
separation of different clients while sharing the same identity
and tunnel names.

Each flock consists of a 64-bit id that is separated into two parts:

* 56-bit flock id
* 8-bit flock domain

The domain allows separation inside of the same flock so that you
can use the same shared secrets and tunnel setups for different purposes.

The key derivation takes this into account and generates different
base keys for each different domain in the same flock.

See below for an example.

## Authentication

When a client notifies a cathedral about its presence, this packet is
encrypted and authenticated via the cathedral secret (CS, see docs/key.md).

This secret is mapped with the identity configured (see allow above).

## Ambry

A cathedral can be used to distribute new shared secrets (SS, see docs/keys.md)
to clients. A wrapped SS is called an Ambry and the cathedral is never able
to unwrap these keys.

Each flock can have their own Ambry bundle.

## Federation

Multiple cathedrals may federate to each other, allowing peers to be
distributed across these.

Note that federation is global and not per flock.

## Configuration

Below is an example cathedral configuration that puts sanctum
in cathedral mode and sets up a bunch of required options.

```
mode cathedral
instance cathedral

pidfile /tmp/cathedral.pid
local 1.2.3.4:4500
secret /home/cathedral/sync.secret
secretdir /home/cathedral/shared/identities
settings /home/cathedral/shared/settings.conf

cathedral_p2p_sync yes
cathedral_nat_port 4501

run control as root
run cathedral as cathedral
run purgatory-rx as purgatory
run purgatory-tx as purgatory
```

The settings file contains the flocks and their configuration
and can be reloaded while the cathedral is running.

```
flock cafeba00 {
    allow deadbeef spi 01
    allow badf00d spi 02

    ambry /home/cathedral/shared/ambries/ambry-cafebabe
}
```
