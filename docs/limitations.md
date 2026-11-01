# Known limitations

This is a list of known limitations that are actively being worked on.

## No sanctum-only recovery path for compromised cathedral secrets.

The cathedral secrets are used to derive keys for encrypting
communication between a sanctum client and a cathedral.

If a cathedral is compromised and the cathedral secrets are leaked
there is no recovery path by only using Sanctum. You would need
to use external tooling to recover from this.

A compromised cathedral secret also means any shrouds can be
unmasked to reveal meta-data about the packets.

## Comprimised cathedrals can re-use not yet expired ambries.

A cathedral that is compromised can still serve ambries that are not
expired to clients who accept them. This is as-intended.

What is not intended is that when a new ambry is uploaded to revoke
a device its KEK a compromised cathedral can simply use a non-expired
ambry to overcome this behaviour.

This is reduced by having multiple cathedrals, all of which would
have to be compromised at the same time in order for all clients
to obtain the same old ambry.

## Shroud is expensive.

Using shroud means calculating a mask using KMAC256 for every
packet that comes in. On a cathedral with many clients this
is done pre-auth and can be a bottleneck.
