/*
 * Copyright (c) 2025 Joris Vink <joris@sanctorum.se>
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

#include <sys/types.h>

#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>

#include <unistd.h>

#include "sanctum.h"

static int	asymmetry_random_bytes(void *, unsigned char *, size_t);

/* The indicator for -v. */
const char	*sanctum_asymmetry = "mbedtls-x25519";

/*
 * Perform any one-time asymmetry initialization.
 */
void
sanctum_asymmetry_init(void)
{
}

/*
 * Generate a new x25519 private key and derive its public key from it.
 */
int
sanctum_asymmetry_keygen(u_int8_t *priv, size_t privlen,
    u_int8_t *pub, size_t publen)
{
	int			ret;
	mbedtls_ecp_group	grp;
	mbedtls_ecp_point	pub_key;
	mbedtls_mpi		priv_key;

	PRECOND(priv != NULL);
	PRECOND(privlen == 32);
	PRECOND(pub != NULL);
	PRECOND(publen == 32);

	ret = -1;
	mbedtls_mpi_init(&priv_key);
	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&pub_key);

	if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) != 0)
		goto cleanup;

	if (mbedtls_ecdh_gen_public(&grp, &priv_key, &pub_key,
	    asymmetry_random_bytes, NULL) != 0)
		goto cleanup;

	if (mbedtls_mpi_write_binary_le(&priv_key, priv, privlen) != 0)
		goto cleanup;

	if (mbedtls_mpi_write_binary_le(&pub_key.private_X, pub, publen) != 0)
		goto cleanup;

	ret = 0;

cleanup:
	mbedtls_mpi_free(&priv_key);
	mbedtls_ecp_group_free(&grp);
	mbedtls_ecp_point_free(&pub_key);

	return (ret);
}

/*
 * Using the peer its public key derive a shared secret.
 */
int
sanctum_asymmetry_derive(struct sanctum_kex *kex, u_int8_t *out, size_t len)
{
	int			ret;
	mbedtls_ecp_group	grp;
	mbedtls_ecp_point	pub_key;
	mbedtls_mpi		priv_key, ss;

	PRECOND(kex != NULL);
	PRECOND(out != NULL);
	PRECOND(len == 32);

	ret = -1;
	mbedtls_mpi_init(&ss);
	mbedtls_mpi_init(&priv_key);
	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&pub_key);

	if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) != 0)
		goto cleanup;

	if (mbedtls_mpi_lset(&pub_key.private_Z, 1) != 0)
		goto cleanup;

	if (mbedtls_mpi_read_binary_le(&pub_key.private_X,
	    kex->remote, sizeof(kex->remote)) != 0)
		goto cleanup;

	if (mbedtls_mpi_read_binary_le(&priv_key,
	    kex->private, sizeof(kex->private)) != 0)
		goto cleanup;

	if (mbedtls_ecdh_compute_shared(&grp, &ss, &pub_key,
	    &priv_key, asymmetry_random_bytes, NULL) != 0)
		goto cleanup;

	if (mbedtls_mpi_write_binary_le(&ss, out, len) != 0)
		goto cleanup;

	ret = 0;

cleanup:
	mbedtls_mpi_free(&ss);
	mbedtls_mpi_free(&priv_key);
	mbedtls_ecp_group_free(&grp);
	mbedtls_ecp_point_free(&pub_key);

	return (ret);
}

static int
asymmetry_random_bytes(void *udata, unsigned char *buf, size_t len)
{
	PRECOND(udata == NULL);
	PRECOND(buf != NULL);
	PRECOND(len > 0);

	sanctum_random_bytes(buf, len);

	return (0);
}
