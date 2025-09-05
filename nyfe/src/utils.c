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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "libnyfe.h"

/* The application installed error callback. */
static void	(*fatal_callback)(const char *, va_list) = NULL;

/*
 * Set the callback that nyfe calls upon encountering a very fatal error.
 *
 * This function should perform whatever operations required to cleanup
 * assets and log the error message and should call exit when done.
 *
 * If it does not call exit, nyfe_fatal() will do so.
 */
void
nyfe_fatal_callback(void (*cb)(const char *, va_list))
{
	fatal_callback = cb;
}

/*
 * A fatal error occurred and we will need to clean up even when this means
 * blowing up the application with us.
 *
 * We call the application its installed nyfe_fatal_error() callback
 * before we do so, if none was set we do a best effort attempt.
 */
void
nyfe_fatal(const char *fmt, ...)
{
	va_list		args;
#if !defined(NYFE_PLATFORM_WINDOWS)
	sigset_t	sig;

	if (sigfillset(&sig) == -1)
		printf("warning: sigfillset failed\n");

	(void)sigprocmask(SIG_BLOCK, &sig, NULL);
#endif

	nyfe_zeroize_all();
	nyfe_file_remove_lingering();

	va_start(args, fmt);

	if (fatal_callback == NULL) {
		fprintf(stderr, "nyfe error: ");
		vfprintf(stderr, fmt, args);
		fprintf(stderr, "\n");
	} else {
		fatal_callback(fmt, args);
	}

	va_end(args);
	exit(1);
}
