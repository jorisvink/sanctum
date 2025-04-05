# Liturgy mode

A sanctum instance can be in liturgy mode.

This mode is used for autodiscovery of other peers also running
in liturgy mode when using one or more cathedrals.

In this mode the sanctum instance receives information from its
cathedral regarding other peers that are currently available in
the same flock and liturgy group, and automatically establishes
tunnels to these. These tunnel configurations are added to the
system and managed by the sanctum instance using the **hymn** tool.

This allows you to join multiple devices into the same liturgy group
and they will automatically establish tunnels between each other.

This effectively creates a mesh net topology with unique peer-to-peer
and end-to-end encrypted tunnels between each device.

## Configuration

To configure liturgy mode, specify the mode in the configuration in
combination with which group you would like to use and a network prefix.

```
mode liturgy

liturgy_group 0xcafe
liturgy_prefix 172.31.0.0
```

You will also need to configure cathedral settings as this mode requires
a cathedral setup.

You can then configure the rest of the sanctum instance as you
normally would do by specifying runas users, control paths
and a pid file.

You can also add liturgy configurations via the **hymn** tool.

```
# hymn liturgy 493abf95a07e0c52-01 cathedral 1.2.3.4:1234 \
    identity cafebabe:/etc/hymn/id-cafebabe kek /etc/hymn/kek-0x01 \
    prefix 172.31.0.0 group 0xcafe natport 4501
```
