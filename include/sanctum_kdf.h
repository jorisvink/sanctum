/*
 * Copyright (c) 2025-2026 Joris Vink <joris@sanctorum.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __H_SANCTUM_KDF_H
#define __H_SANCTUM_KDF_H

/*
 * All labels used by sanctum when performing KDF for different purposes.
 *
 * Both the traffic KDF labels for tunnels and cathedral KDF labels
 * for talking to cathedrals can be overriden at compile time.
 */

#if !defined(SANCTUM_KDF_PREFIX)
#define SANCTUM_KDF_PREFIX		"SANCTUM."
#endif

#if !defined(SANCTUM_CATHEDRAL_KDF_PREFIX)
#define SANCTUM_CATHEDRAL_KDF_PREFIX	"SANCTUM."
#endif

#define LABEL(x)	SANCTUM_KDF_PREFIX#x
#define CLABEL(x)	SANCTUM_CATHEDRAL_KDF_PREFIX#x

/* The KDF label when generating base keys for offers to peers. */
#define SANCTUM_PEER_OFFER_KDF_LABEL		LABEL(PEER.OFFER.KDF)

/* The KDF label when generating base keys for traffic RX derivation. */
#define SANCTUM_KEY_TRAFFIC_RX_KDF_LABEL	LABEL(KEY.TRAFFIC.RX.KDF)

/* The KDF label when generating base keys for traffic TX derivation. */
#define SANCTUM_KEY_TRAFFIC_TX_KDF_LABEL	LABEL(KEY.TRAFFIC.TX.KDF)

/* The KDF label when generating base keys for ambry KEK derivation. */
#define SANCTUM_KEY_KEK_UNWRAP_KDF_LABEL	LABEL(KEY.KEK.UNWRAP.KDF)

/* The KDF label for traffic encapsulation. */
#define SANCTUM_ENCAP_LABEL			LABEL(ENCAP.KDF)

/* The KDF label for traffic key derivation. */
#define SANCTUM_TRAFFIC_KDF_LABEL		LABEL(TRAFFIC.KDF)

/* The PILGRIM KDF label. */
#define SANCTUM_SHRINE_PILGRIM_DERIVE_LABEL	LABEL(PILGRIMAGE.KDF)

/* The SACRAMENT KDF label. */
#define SANCTUM_CHAPEL_DERIVE_LABEL		LABEL(SACRAMENT.KDF)

/* The KDF label for an ambry. */
#define SANCTUM_AMBRY_KDF			LABEL(AMBRY.KDF)

/* The KDF label for talking to a cathedral. */
#define SANCTUM_CATHEDRAL_KDF_LABEL		CLABEL(CATHEDRAL.KDF)

/* The KDF label for the cathedral federation. */
#define SANCTUM_CATHEDRAL_CATACOMB_LABEL	CLABEL(CATHEDRAL.CATACOMB)

/* The KDF label when generating base keys for offers to cathedrals. */
#define SANCTUM_CATHEDRAL_OFFER_KDF_LABEL	CLABEL(CATHEDRAL.OFFER.KDF)

#endif
