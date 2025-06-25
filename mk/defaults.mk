#
# Default values for parts that can be swapped at compile time.
#

CC?=cc
LIBNYFE=$(TOPDIR)/nyfe/libnyfe.a

DESTDIR?=
PREFIX?=/usr/local
MAN_DIR?=$(PREFIX)/share/man
INSTALL_DIR=$(PREFIX)/bin
SHARE_DIR=$(PREFIX)/share/sanctum
DARWIN_SB_PATH?=$(SHARE_DIR)/sb

PRNG?=nyfe
KEM?=mlkem1024-ref
CIPHER?=libsodium-aes-gcm
ASYMMETRY?=libsodium-x25519

KEM_MK_PATH?=$(TOPDIR)/mk/kem/$(KEM).mk
RANDOM_MK_PATH?=$(TOPDIR)/mk/random/$(PRNG).mk
CIPHER_MK_PATH?=$(TOPDIR)/mk/ciphers/$(CIPHER).mk
ASYMMETRY_MK_PATH?=$(TOPDIR)/mk/asymmetry/$(ASYMMETRY).mk

export CC
export PREFIX
export DESTDIR
export LIBNYFE
export MAN_DIR
export SHARE_DIR
export INSTALL_DIR
export DARWIN_SB_PATH

export KEM
export PRNG
export CIPHER
export ASYMMETRY

export KEM_MK_PATH
export RANDOM_MK_PATH
export CIPHER_MK_PATH
export ASYMMETRY_MK_PATH
