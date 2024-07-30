# Cathedrals

A cathedral is a sanctum process on a server somewhere that can
relay packets to peers and is able to distribute wrapped ambries
to peers when required.

It makes it possible for peers to talk to each other, end-to-end encrypted,
when behind NAT or when you don't want to know where the peer is located.

A cathedral can never read or alter encrypted packets.

## Time

It is imperative that peers and cathedrals their clocks are in-sync as
messages include timestamps which are checked after the integrity
of the packets are validated.

Packets are only valid for 10 seconds.

## Authentication

When a peer notifies a cathedral about its presence, this packet is
encrypted and authenticated via the cathedral secret (CS, see docs/key.md).

## Ambry

A cathedral can be used to distribute new shared secrets (SS, see docs/keys.md)
to peers. A wrapped SS is called an Ambry and the cathedral is never able
to unwrap these keys.

When a cathedral sends an Ambry to a peer, the message itself is encrypted
and authenticated via the cathedral secret (CS, see docs/key.md).

## Federation

Multiple cathedrals may federate to each other, allowing peers to be
distributed across these.
