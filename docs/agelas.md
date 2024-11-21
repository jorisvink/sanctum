# Agelas

Agelas is an AEAD stream cipher based on Keccak-f[1600,24] in duplex mode,
providing at least 256-bit of security for confidentiality and integrity.

The underlying keccak state is initialized with a capacity of 512-bits.
This puts the rate at 136 bytes.

Agelas operates on 128 byte blocks as it retains 8 bytes per block for a
56-bit state counter and a single domain seperation byte.

As long as Keccak-f[1600,24] its security guarantees hold, Agelas is
safe to use.

```
init(key):
	K_1 = bytepad(0x20 || key[ 0..31], 136)
	K_1[135] = 0x01
	K_2 = bytepad(0x20 || key[32..63], 136)
	K_2[135] = 0x03
	keccak = KECCAK[512]
	keccak.absorb(K_1)
	State <- keccak.squeeze(136)
```

```
encryption(pt):
	for each 128 byte block, do
		for i = 0 -> i = 127, do
			ct[i] = pt[i] ^ State[i]
			State[i] = pt[i]
		clen += len(pt)
		State[128..134] = counter
		State[135] = 0x07
		keccak.absorb(State)
		counter = counter + 1
		State <- keccak.squeeze(136)
```

```
decryption(ct):
	for each 128 byte block, do
		for i = 0 -> i = 127, do
			pt[i] = ct[i] ^ State[i]
			State[i] = pt[i]
		clen += len(ct)
		State[128..134] = counter
		State[135] = 0x07
		keccak.absorb(State)
		counter = counter + 1
		State <- keccak.squeeze(136)
```

Additional Authenticated Data may be added at any time as long as it is
done at the same position in the stream in both the encryption and
decryption process.

Each AAD call must fit in a single agelas_bytepad() block.

```
add_aad(aad):
	aad_padded = bytepad(aad, 136)
	aad_padded[135] = 0x0f
	keccak.absorb(aad_padded)
	alen += len(aad)
```

The authentication tag is obtained at the end. The authentication step
includes the length of the AAD and data operated on.

```
authenticate(tag, taglen):
	L = bytepad(alen, 136)
	L[135] = 0x1f
	keccak.absorb(L)
	L = bytepad(clen, 136)
	L[135] = 0x1f
	keccak.absorb(L)
	State[128..134] = counter
	State[135] = 0x3f
	keccak.absorb(State)
	keccak.absorb(K_2)
	tag <- keccak.squeeze(taglen)
```

## Caveats

Be extremely careful to not use the same key to encrypt different
plaintexts as that will lead to the loss of confidentiality for the
entire first 128-byte block.

You are warned.

A nonce-like construct may be used by first encrypting an 128-byte block
that contains the nonce, this will effectively make the rest of keystream
depend on it.

Not fully formally reviewed.
