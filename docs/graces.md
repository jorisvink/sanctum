# Graces

## What are they

A grace is a packet sent as part of a secure link that was established
between two peers.

It is designed as a way of communicate information between the peers
once a secure link is online.

A grace packet must contain at least this header:

```c
struct sanctum_grace {
	u_int16_t	type;
} __attribute__((packed));
```

Where **type** is one of the following:

| Name | Description | Value |
| --- | ----------- | ---- |
| SANCTUM_GRACE_TYPE_HEARTBEAT | A heartbeat sent between two peers to indicate that the peer is still alive. It contains no futher payload. | 1 |
| SANCTUM_GRACE_TYPE_MTU_PROBE | A probe sent from one peer to another with a certain size, in order to help discover the optimal MTU for the path. | 2 |
| SANCTUM_GRACE_TYPE_MTU_ACK | An ack sent after receiving a probe, indicating to our peer that we succesfully received it. | 3 | 

## Heartbeats

These grace types contain no further payload and are sent once every
15 seconds to the peer, regardless of previous TX traffic or not.

They are also used when holepunching to open NAT states when having
received new session keys or when a peer address changes.

## MTU discovery

The graces are used to send MTU probes and actively ack them once they
arrive. MTU discovery is triggered upon new session keys and once every
600 seconds afterwards.

MTU graces must send the following information:

```c
struct sanctum_grace_mtu {
	struct sanctum_grace	hdr;
	u_int16_t		size;
} __attribute__((packed));
```
