# purgatory-rx (crypto side receiving)

## Input validation

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
