/*
 * Copyright (c) 2023 Joris Vink <joris@sanctorum.se>
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

#ifndef __H_SANCTUM_CTL_H
#define __H_SANCTUM_CTL_H

/*
 * Some statistics that can be kept around.
 */
struct sanctum_ifstat {
	volatile u_int32_t	spi;
	volatile u_int64_t	age;
	volatile u_int64_t	pkt;
	volatile u_int64_t	last;
	volatile u_int64_t	bytes;
};

/* ctl requests, some go to keying, some go to status. */
#define SANCTUM_CTL_STATUS		1

/*
 * A request to the status process for sanctum.
 */
struct sanctum_ctl_status {
	u_int8_t	cmd;
};

/*
 * The response to a SANCTUM_CTL_STATUS_GET.
 */
struct sanctum_ctl_status_response {
	struct sanctum_ifstat	tx;
	struct sanctum_ifstat	rx;
};

#endif
