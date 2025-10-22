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

#ifndef __H_NYFE_ESP32_H
#define __H_NYFE_ESP32_H

/*
 * This is the ESP32 portability header allowing libnyfe
 * to compile using esp32 toolchains (only tested with ESP-IDF).
 */

#if !defined(ESP_PLATFORM)
#error "portable_esp.h is only for esp32 platforms"
#endif

/* libnyfe will use this to determine if we're on ESP32. */
#define NYFE_ESP32_PLATFORM		1

#define htobe64(x)	__bswap64(x)
#define htobe32(x)	__bswap32(x)
#define htobe16(x)	__bswap16(x)

#define be64toh(x)	__bswap64(x)
#define be32toh(x)	__bswap32(x)
#define be16toh(x)	__bswap16(x)

#endif
