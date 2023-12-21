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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "sanctum.h"

static void	control_handle_request(int);
static void	control_status_request(int, struct sockaddr_un *);

/*
 * The control process, handles incoming control requests.
 */
void
sanctum_control(struct sanctum_proc *proc)
{
	struct pollfd	pfd;
	int		sig, running;

	PRECOND(proc != NULL);
	PRECOND(proc->arg == NULL);

	sanctum_signal_trap(SIGQUIT);
	sanctum_signal_ignore(SIGINT);

	pfd.fd = sanctum_unix_socket(&sanctum->control);

	running = 1;

	sanctum_proc_privsep(proc);
	sanctum_platform_sandbox(proc);

	while (running) {
		if ((sig = sanctum_last_signal()) != -1) {
			sanctum_log(LOG_NOTICE, "received signal %d", sig);
			switch (sig) {
			case SIGQUIT:
				running = 0;
				continue;
			}
		}

		pfd.events = POLLIN;

		if (poll(&pfd, 1, -1) == -1) {
			if (errno == EINTR)
				continue;
			fatal("poll: %s", errno_s);
		}

		if (pfd.revents & POLLIN)
			control_handle_request(pfd.fd);

	}

	sanctum_log(LOG_NOTICE, "exiting");

	exit(0);
}

/*
 * Handle a request on the control socket.
 */
static void
control_handle_request(int fd)
{
	ssize_t				ret;
	struct sanctum_ctl		ctl;
	struct sockaddr_un		peer;
	socklen_t			socklen;

	PRECOND(fd >= 0);

	socklen = sizeof(peer);

	for (;;) {
		if ((ret = recvfrom(fd, &ctl, sizeof(ctl), 0,
		    (struct sockaddr *)&peer, &socklen)) == -1) {
			if (errno == EINTR)
				continue;
			fatal("recvfrom: %s", errno_s);
		}

		if (ret == 0)
			fatal("eof on keying socket");

		if ((size_t)ret != sizeof(ctl))
			break;

		switch (ctl.cmd) {
		case SANCTUM_CTL_STATUS:
			control_status_request(fd, &peer);
			break;
		case SANCTUM_CTL_COMMUNION:
			sanctum_atomic_write(&sanctum->communion, 1);
			break;
		}

		break;
	}
}

/*
 * Send some generic statistics to the client.
 */
static void
control_status_request(int fd, struct sockaddr_un *peer)
{
	struct sanctum_ctl_status_response	resp;

	PRECOND(fd >= 0);
	PRECOND(peer != NULL);

	memset(&resp, 0, sizeof(resp));

	resp.tx.age = sanctum_atomic_read(&sanctum->tx.age);
	resp.tx.spi = sanctum_atomic_read(&sanctum->tx.spi);
	resp.tx.pkt = sanctum_atomic_read(&sanctum->tx.pkt);
	resp.tx.last = sanctum_atomic_read(&sanctum->tx.last);
	resp.tx.bytes = sanctum_atomic_read(&sanctum->tx.bytes);

	resp.rx.age = sanctum_atomic_read(&sanctum->rx.age);
	resp.rx.spi = sanctum_atomic_read(&sanctum->rx.spi);
	resp.rx.pkt = sanctum_atomic_read(&sanctum->rx.pkt);
	resp.rx.last = sanctum_atomic_read(&sanctum->rx.last);
	resp.rx.bytes = sanctum_atomic_read(&sanctum->rx.bytes);

	if (sendto(fd, &resp, sizeof(resp), 0,
	    (const struct sockaddr *)peer, sizeof(*peer)) == -1) {
		sanctum_log(LOG_NOTICE,
		    "failed to send status to peer: %s", errno_s);
	}
}
