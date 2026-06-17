# Sanctum

## About

Sanctum is a small, reviewable, capable, pq-secure and
[fully privilege separated](https://sanctorum.se/privsep.html)
VPN daemon for OpenBSD, Linux and MacOS. It is designed from the
ground up with security in mind and will always be open and free,
licensed under the ISC license.

Sanctum uses strong cryptography and a unique hybridized key exchange
that combines symmetrical keying with classical and PQ-secure asymmetry.
See [docs/crypto.md](docs/crypto.md) for a detailed description of the
cryptosystem in sanctum.

It allows the creation of different
[topologies](https://sanctorum.se/topologies.html) from traditional
site-to-site or client-to-site tunnels, to one-way tunnels or p2p e2ee
secure links between devices, even when behind NAT.

Sanctum is often used to create more secure replacements for things
like Tailscale or Zerotier.

A community driven sanctum cathedral network can be found at
[The Reliquary](https://reliquary.se).

## Building

See [docs/building.md](docs/building.md) for building instructions.

## Hacking

Please send your git patches to priests@sanctorum.se.

## Configuring

See [share/example.conf](share/example.conf) for a simple
example configuration.

For more hands on examples, see through the different guides:

* [Manual setup guide](https://sanctorum.se/guide.html) 
* [Hymn based setup guide](https://sanctorum.se/guide.html#hymn) 
* [Liturgy guide](https://sanctorum.se/liturgy.html)
* [Cathedral guide](https://sanctorum.se/cathedral.html)

## Talks

[SEC-T 2025](https://conclave.se/sect-2025.pdf)

[SEC-T 2024](https://conclave.se/sect-2024.pdf)

## Library

You can use [libkyrka](https://github.com/jorisvink/libkyrka) to implement
the sanctum protocol and p2p e2ee tunnels into your application directly.
