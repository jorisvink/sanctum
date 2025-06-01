# Cheatsheet

This is a cheatsheet for all the naming going on for sanctum and
projects directly related to sanctum.

## Sanctum

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
| liturgy | The process responsible for autodiscovery of peers in a cathedral.
| bishop | The process responsible for configuring autodiscovered tunnels.
| guardian | The process monitoring all other processes.

## Terminology

### Tools

| Tool | Description |
| ---- | ----------- |
| hymn | A tool to manage system tunnels. |
| ambry | A tool to manage ambry bundles and device unique KEKs. |
| vicar | A tool to create encrypted configurations for distribution. |

### Features

| Term | Description |
| ---- | ----------- |
| ambry | An encrypted file containing shared secrets for distribution. |
| cathedral | An authenticated relay and discovery service for sanctum. |
| liturgy | A cathedral feature that helps with auto-discovery of peers. |
| remembrance | A cathedral feature for sharing federated ip:port information. |

## Descendants

| Name | Description |
| ---- | ----------- |
| libkyrka | A library implementation of the sanctum protocol. |
| confessions | A cli tool for voice chat over the sanctum protocol. |
| litany | A qt6 application for text chat over the sanctum protocol. |

## Other

| Name | Description |
| ---- | ----------- |
| reliquary | A community driven service running several cathedrals. |
