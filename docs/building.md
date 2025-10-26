# Building

Sanctum builds out of the box on several different operating systems.

* MacOS 13+
* Linux 5.x+
* OpenBSD 6.8+

A default build requires at least pkg-config and libsodium.
Note that on OpenBSD you will need gmake installed.

Quick build start:

```
$ git clone https://github.com/jorisvink/sanctum
$ cd sanctum
$ make
# make install
```

# Customization

Sanctum can be built with different cryptographic libraries,
allowing you to build your own backend for all or specific
components.

Components can be mixed so that you for example build with
one component for encryption but another one for x25519.

Even the KDF labels can be customized.

If you want to introduce your own backends please take
a look at the **mk/<component>** paths and how the
existing backends their **.mk** files are constructed.

## Labels

All of the labels for the KDF that Sanctum uses (KMAC256) are
prefixed with "SANCTUM.". This can be overriden to provide
domain separation between applications or tunnels at compile
time by specifying SANCTUM_KDF_PREFIX as a define under CFLAGS.

You may also choose to override the KDF labels specific to cathedral
communication if you wish by setting SANCTUM_CATHEDRAL_KDF_PREFIX
in the same manner.

```
$ CFLAGS=-DSANCTUM_KDF_PREFIX='\"MY_PREFIX.\"' make
```

```
$ CFLAGS=-DSANCTUM_KDF_PREFIX='\"MY_PREFIX.\"' \
         -DSANCTUM_CATHEDRAL_KDF_PREFIX='\"CUSTOM_CATHEDRAL.\"' make
```

## Encryption

For the encryption Sanctum comes with backends for the
following libraries:

* nyfe-agelas
* libsodium-aes-gcm (default)
* mbedtls-aes-gcm (mbedtls 3.x)

These can be selected by setting the **CIPHER** environment
variable at compile time.

```
$ CIPHER=mbedtls-aes-gcm make
```

## Classical ECDH

For the classical key exchange part of the hybrid key negotiation
Sanctum comes with backends for the following libraries:

* libsodium-x25519 (default)
* mbedtls-x25519 (mbedtls 3.x)

These can be selected by setting the **ASYMMETRY** environment
variable at compile time.

```
$ ASYMMETRY=mbedtls-x25519 make
```

## PQ-secure KEM

For the PQ-secure key exchange part of the hybrid key negotiation
Sanctum comes with backends for the following libraries:

* mlkem1024-ref (pqcrystals reference implementation)

These can be selected by setting the **KEM** environment
variable at compile time.

```
$ KEM=custom-kem-backend make
```

## Random

For providing cryptographically strong random numbers
Sanctum comes with backends for the following:

* nyfe-random

These can be selected by setting the **PRNG** environment
variable at compile time.

```
$ PRNG=custom-random-backend make
```

## Signature

For signing and signature verification Sanctum comes
with backends for the following libraries:

* libsodium-ed25519

These can be selected by setting the **SIGNATURE** environment
variable at compile time.

```
$ SIGNATURE=custom-signature-backend make
```
