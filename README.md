<p align="center">
<img src="images/sanctum_logo.png" alt="sanctum" width="256px" />
</p>

# Sanctum

"Thee packets that are chosen needeth not fear purgatory, for thee
shall be safe with my blessing. Confess thy sins and moveth into heaven."

Sanctum 1:1

## About

This is a very small, reviewable, experimental and fully privilege
seperated VPN daemon capable of transporting encrypted network traffic
between two peers.

This is a work in progress and is not considered done yet.

### Mythology

Whats with the weird mythology around this project?

It's fun, but doesn't make it less of a serious project.

## Privilege separation

sanctum consists of 5 processes:

| Process name | Description  |
| ------------ | ------------ |
| bless | The process responsible for encrypting packets.
| confess | The process responsible for decrypting packets.
| chapel | The process responsible for deriving new TX/RX keys from a key.
| heaven | The process receiving and sending packets on the inner interface.
| purgatory | The process receiving and sending packets on the outer interface.

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

## Traffic

The encrypted traffic is encapsulated with ESP in tunnel mode, using
64-bit sequence numbers and encrypted under AES256-GCM using keys
derived from a shared symmetrical key.

## High performance mode

When sanctum is built with the CIPHER=intel-aes-gcm and HPERF=1,
high performance mode is enabled.

In this mode, sanctum is able to reach 10gbps speeds, depending on hardware.
