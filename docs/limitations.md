# Known limitations

This is a list of known limitations that are actively being worked on.

## Comprimised cathedrals can re-use not yet expired ambries.

A cathedral that is compromised can still serve ambries that are not
expired to clients who accept them. This is as-intended.

What is not intended is that when a new ambry is uploaded to revoke
a device its KEK a compromised cathedral can simply use a non-expired
ambry to overcome this behaviour.

## Pilgrim-shrine replayability.

If a shrine restarts previously captured traffic can be replayed
by an attacker if they beat the pilgrim its first packet sent
to the shrine.

## Shroud is expensive.

Using shroud means calculating a mask using KMAC256 for every
packet that comes in. On a cathedral with many clients this
is done pre-auth and can be a bottleneck.
