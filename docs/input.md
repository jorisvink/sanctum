# Packet input (crypto side)

## purgatory-rx

### Input validation

Packets received by purgatory-rx get sanity checked by purgatory-rx
itself before it hands it over to confess.

The purgatory-rx process does the following:

* If the packet was encapsulated, decapsulate it.
* Check if the packet is long enough to at least contain the protocol
  header, tail and tag length.
* Check if the spi is known to us.
* Perform an initial anti-replay window check by verifying that
  the sequence number falls within current window + 1023 packets. The 1023
  number comes from the fact that sanctum has a packet pool of 1024 packets
  in total and we account for the fact that 1023 packets may be waiting
  in the ring queue for confess.

Note that the anti-replay checks are done again in the confess process.
If everything checks out the packet is given to the confess process.

## confess

### Tag validation

The confess process receives packets from purgatory-rx. It performs
a lot of the same packet validation that purtatory-rx did.

It will do the following:

* Check if the packet is long enough to at least contain the protocol
  header, tail and tag length.
* Check if the spi is known to us.
* Perform the initial anti-replay check to see if the packet falls
  in the anti-replay window (of 64 packets wide).

After these initial checks it will attempt to verify and decrypt
the packet using the current RX key. If this succeeds the packet
is given to heaven-tx so it can be transmitted onto the tunnel
interface.

If it fails and we have a pending RX key, confess will attempt to
verify and decrypt the packet with the pending RX key. If this
succeeds the packet is also given to heaven-tx and confess will
move the pending RX key to active, overriding the previous active
RX key. 

After these steps, the anti-replay window is updated.
