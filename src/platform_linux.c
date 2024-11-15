/*
 * Copyright (c) 2023-2024 Joris Vink <joris@sanctorum.se>
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
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <arpa/inet.h>

#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <linux/futex.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/ptrace.h>
#include <linux/seccomp.h>

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sched.h>
#include <unistd.h>

#include "sanctum.h"
#include "seccomp.h"

static void	linux_configure_tundev(struct ifreq *);
static void	linux_sandbox_netns(struct sanctum_proc *);
static void	linux_sandbox_seccomp(struct sanctum_proc *);
static void	linux_seccomp_violation(struct sanctum_proc *);
static void	linux_rt_sin(struct nlmsghdr *, void *, u_int16_t,
		    struct sockaddr_in *);

#if defined(__x86_64__)
#define SECCOMP_AUDIT_ARCH		AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define SECCOMP_AUDIT_ARCH		AUDIT_ARCH_AARCH64
#elif defined(__arm)
#define SECCOMP_AUDIT_ARCH		AUDIT_ARCH_ARM
#elif defined(__riscv)
#define SECCOMP_AUDIT_ARCH		AUDIT_ARCH_RISCV64
#else
#error "unsupported architecture"
#endif

#define SECCOMP_KILL_POLICY		SECCOMP_RET_KILL

/*
 * The seccomp bpf program its prologue.
 *
 * Verifies that the running architecture matches the one we're built for
 * and preps the system call number to be verified.
 */
static struct sock_filter filter_prologue[] = {
	KORE_BPF_LOAD(arch, 0),
	KORE_BPF_CMP(SECCOMP_AUDIT_ARCH, 1, 0),
	KORE_BPF_RET(SECCOMP_RET_KILL),
	KORE_BPF_LOAD(nr, 0),
};

/*
 * The seccomp bpf program its epilogue.
 *
 * This applies the selected seccomp policy if none of the system
 * calls matched the filters.
 */
static struct sock_filter filter_epilogue[] = {
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_KILL_POLICY)
};

static struct sock_filter common_seccomp_filter[] = {
	KORE_SYSCALL_ALLOW(brk),
	KORE_SYSCALL_ALLOW(close),
	KORE_SYSCALL_ALLOW(futex),
	KORE_SYSCALL_ALLOW(sendto),
	KORE_SYSCALL_ALLOW(getpid),
	KORE_SYSCALL_ALLOW(exit_group),
	KORE_SYSCALL_ALLOW(rt_sigreturn),
	KORE_SYSCALL_ALLOW(clock_gettime),
	KORE_SYSCALL_ALLOW(clock_nanosleep),
	KORE_SYSCALL_ALLOW(restart_syscall),
	KORE_SYSCALL_ALLOW_ARG(write, 0, STDOUT_FILENO),
};

static struct sock_filter heaven_rx_seccomp_filter[] = {
#if defined(SYS_poll)
	KORE_SYSCALL_ALLOW(poll),
#endif
	KORE_SYSCALL_ALLOW(ppoll),
	KORE_SYSCALL_ALLOW(read),
	KORE_SYSCALL_ALLOW(close),
};

static struct sock_filter heaven_tx_seccomp_filter[] = {
	KORE_SYSCALL_ALLOW(close),
	KORE_SYSCALL_ALLOW(write),
};

static struct sock_filter purgatory_rx_seccomp_filter[] = {
#if defined(SYS_poll)
	KORE_SYSCALL_ALLOW(poll),
#endif
	KORE_SYSCALL_ALLOW(ppoll),
	KORE_SYSCALL_ALLOW(close),
	KORE_SYSCALL_ALLOW(recvfrom),
};

static struct sock_filter purgatory_tx_seccomp_filter[] = {
	KORE_SYSCALL_ALLOW(getrandom),
};

static struct sock_filter keying_seccomp_filter[] = {
	KORE_SYSCALL_ALLOW(read),
	KORE_SYSCALL_ALLOW(write),
	KORE_SYSCALL_ALLOW(close),
	KORE_SYSCALL_ALLOW(fstat),
#if defined(SYS_unlink)
	KORE_SYSCALL_ALLOW(unlink),
#endif
#if defined(SYS_unlinkat)
	KORE_SYSCALL_ALLOW(unlinkat),
#endif
#if defined(SYS_rename)
	KORE_SYSCALL_ALLOW(rename),
#endif
#if defined(SYS_renameat2)
	KORE_SYSCALL_ALLOW(renameat2),
#endif
#if defined(SYS_open)
	KORE_SYSCALL_ALLOW(open),
#endif
	KORE_SYSCALL_ALLOW(openat),
	KORE_SYSCALL_ALLOW(getrandom),
	KORE_SYSCALL_ALLOW(newfstatat),
};

static struct sock_filter control_seccomp_filter[] = {
#if defined(SYS_poll)
	KORE_SYSCALL_ALLOW(poll),
#endif
	KORE_SYSCALL_ALLOW(read),
	KORE_SYSCALL_ALLOW(close),
	KORE_SYSCALL_ALLOW(lseek),
	KORE_SYSCALL_ALLOW(ppoll),
	KORE_SYSCALL_ALLOW(openat),
	KORE_SYSCALL_ALLOW(sendto),
	KORE_SYSCALL_ALLOW(recvfrom),
	KORE_SYSCALL_ALLOW(newfstatat),
};

/* If we are doing seccomp tracing (set via SANCTUM_SECCOMP_TRACE). */
static int		seccomp_tracing = 0;

/*
 * Setup the required platform bits and bobs.
 */
void
sanctum_platform_init(void)
{
	const char	*ptr;

	if ((ptr = getenv("SANCTUM_SECCOMP_TRACE")) != NULL) {
		if (!strcmp(ptr, "1"))
			seccomp_tracing = 1;
	}
}

/*
 * Linux tunnel device creation. The device is created and a
 * file descriptor for it is returned to the caller.
 */
int
sanctum_platform_tundev_create(void)
{
	struct ifreq		ifr;
	int			len, fd, flags;

	memset(&ifr, 0, sizeof(ifr));

	if ((fd = open("/dev/net/tun", O_RDWR)) == -1)
		fatal("failed to open /dev/net/tun: %s", errno_s);

	len = snprintf(ifr.ifr_name, sizeof(ifr.ifr_name),
	    "%s", sanctum->instance);
	if (len == -1 || (size_t)len >= sizeof(ifr.ifr_name))
		fatal("sanctum.clr interface name too large");

	if (sanctum->flags & SANCTUM_FLAG_USE_TAP)
		ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	else
		ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	if (ioctl(fd, TUNSETIFF, &ifr) == -1)
		fatal("ioctl: %s", errno_s);

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		fatal("fcntl: %s", errno_s);

	flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) == -1)
		fatal("fcntl: %s", errno_s);

	linux_configure_tundev(&ifr);

	return (fd);
}

/*
 * Read a single packet from the tunnel device and return it to the caller.
 */
ssize_t
sanctum_platform_tundev_read(int fd, struct sanctum_packet *pkt)
{
	u_int8_t	*data;

	PRECOND(fd >= 0);
	PRECOND(pkt != NULL);

	data = sanctum_packet_data(pkt);

	return (read(fd, data, SANCTUM_PACKET_DATA_LEN));
}

/*
 * Write the given packet into the tunnel device.
 */
ssize_t
sanctum_platform_tundev_write(int fd, struct sanctum_packet *pkt)
{
	u_int8_t	*data;

	PRECOND(fd >= 0);
	PRECOND(pkt != NULL);

	data = sanctum_packet_data(pkt);

	return (write(fd, data, pkt->length));
}

/*
 * Apply sandboxing rules according to the current process.
 */
void
sanctum_platform_sandbox(struct sanctum_proc *proc)
{
	PRECOND(proc != NULL);

	linux_sandbox_netns(proc);
	linux_sandbox_seccomp(proc);
}

/*
 * Wait for the process to signal us and let us send a SIGCONT to it.
 */
void
sanctum_linux_trace_start(struct sanctum_proc *proc)
{
	int		status;

	PRECOND(proc != NULL);

	if (seccomp_tracing == 0)
		return;

	if (waitpid(proc->pid, &status, 0) > 0)
		sanctum_linux_seccomp(proc, status);
}

/*
 * Check the status for a process after we got a SIGCHLD for it
 * and attempt to figure out if it triggered a seccomp violation.
 *
 * If it did, we will log it.
 */
int
sanctum_linux_seccomp(struct sanctum_proc *proc, int status)
{
	int	evt;

	PRECOND(proc != NULL);

	if (seccomp_tracing == 0)
		return (-1);

	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
		if (ptrace(PTRACE_SETOPTIONS, proc->pid, NULL,
		    PTRACE_O_TRACESECCOMP | PTRACE_O_TRACECLONE |
		    PTRACE_O_TRACEFORK) == -1)
			fatal("ptrace: %s", errno_s);
		if (ptrace(PTRACE_CONT, proc->pid, NULL, NULL) == -1)
			fatal("ptrace: %s", errno_s);
		return (0);
	}

	if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
		evt = status >> 8;
		if (evt == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8)))
			linux_seccomp_violation(proc);
		if (ptrace(PTRACE_CONT, proc->pid, NULL, NULL) == -1)
			fatal("ptrace: %s", errno_s);
		return (0);
	}

	if (WIFSTOPPED(status) && WSTOPSIG(status) != SIGINT) {
		if (ptrace(PTRACE_CONT, proc->pid, NULL,
		    WSTOPSIG(status)) == -1)
			fatal("ptrace: %s", errno_s);
		return (0);
	}

	return (-1);
}

/*
 * Adds a new route via our tunnel device.
 */
void
sanctum_platform_tundev_route(struct sockaddr_in *net, struct sockaddr_in *mask)
{
	int			s;
	u_int32_t		m;
	ssize_t			ret;
	struct rtmsg		*rt;
	struct nlmsghdr		*hdr;
	struct nlmsgerr		*error;
	u_int8_t		buf[512];

	PRECOND(net != NULL);
	PRECOND(mask != NULL);

	memset(buf, 0, sizeof(buf));

	hdr = (struct nlmsghdr *)&buf;
	hdr->nlmsg_seq = 0;
	hdr->nlmsg_pid = getpid();
	hdr->nlmsg_type = RTM_NEWROUTE;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE |
	    NLM_F_EXCL | NLM_F_ACK;
	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(*rt));

	rt = (struct rtmsg *)&buf[NLMSG_HDRLEN];
	rt->rtm_family = AF_INET;
	rt->rtm_type = RTN_UNICAST;
	rt->rtm_table = RT_TABLE_MAIN;
	rt->rtm_protocol = RTPROT_STATIC;
	rt->rtm_scope = RT_SCOPE_UNIVERSE;

	rt->rtm_dst_len = 0;
	m = ntohl(mask->sin_addr.s_addr);

	while (m) {
		if (m & 1)
			rt->rtm_dst_len++;
		m = m >> 1;
	}

	linux_rt_sin(hdr, &buf[hdr->nlmsg_len], RTA_DST, net);
	linux_rt_sin(hdr, &buf[hdr->nlmsg_len], RTA_GATEWAY, &sanctum->tun_ip);

	if ((s = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) == -1)
		fatal("socket(AF_NETLINK): %s", errno_s);

	if ((ret = write(s, buf, hdr->nlmsg_len)) == -1)
		fatal("write: %s", errno_s);

	if ((size_t)ret != hdr->nlmsg_len)
		fatal("short write %zd/%u", ret, hdr->nlmsg_len);

	if ((ret = read(s, buf, sizeof(buf))) == -1)
		fatal("read: %s", errno_s);

	if (ret == 0)
		fatal("eof on netlink socket");

	if ((size_t)ret < (sizeof(*hdr) + sizeof(*error)))
		fatal("too short message from netlink (%zd)", ret);

	if (hdr->nlmsg_type != NLMSG_ERROR)
		fatal("unexpected type %u", hdr->nlmsg_type);

	error = (struct nlmsgerr *)&buf[NLMSG_HDRLEN];
	if (error->error != 0)
		fatal("failed to add route: %d", error->error);

	(void)close(s);
}

/*
 * Suspend the calling process using the synchronization addr.
 * If we were already told to be awake, we simply return and do not block.
 */
void
sanctum_platform_suspend(u_int32_t *addr, int64_t sleep)
{
	struct timespec		tv, *tptr;

	PRECOND(addr != NULL);

	if (sanctum_atomic_cas_simple(addr, 1, 0))
		return;

	tv.tv_nsec = 0;
	tv.tv_sec = sleep;

	if (sleep < 0)
		tptr = NULL;
	else
		tptr = &tv;

	if (syscall(SYS_futex, addr, FUTEX_WAIT, 0, tptr, NULL, 0) == -1) {
		if (errno != EINTR && errno != ETIMEDOUT && errno != EAGAIN)
			sanctum_log(LOG_NOTICE, "futex wait: %s", errno_s);
	}
}

/*
 * Wakeup whoever is suspended on the synchronization address in addr,
 * unless they are already awake.
 */
void
sanctum_platform_wakeup(u_int32_t *addr)
{
	long		ret;

	PRECOND(addr != NULL);

	if (sanctum_atomic_cas_simple(addr, 0, 1)) {
		ret = syscall(SYS_futex, addr, FUTEX_WAKE, 1, NULL, NULL, 0);
		if (ret == -1)
			sanctum_log(LOG_NOTICE, "futex wake: %s", errno_s);
	}
}

/* Helper to stuff a sockaddr_in into an rtattr for netlink. */
static void
linux_rt_sin(struct nlmsghdr *hdr, void *attr, u_int16_t type,
    struct sockaddr_in *sin)
{
	struct rtattr		*rta;

	PRECOND(hdr != NULL);
	PRECOND(attr != NULL);
	PRECOND(sin != NULL);

	rta = attr;

	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(sizeof(sin->sin_addr));

	memcpy(RTA_DATA(rta), &sin->sin_addr, sizeof(sin->sin_addr));
	hdr->nlmsg_len = NLMSG_ALIGN(hdr->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

/* Configure the tunnel device. */
static void
linux_configure_tundev(struct ifreq *ifr)
{
	int		fd;

	PRECOND(ifr != NULL);

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", errno_s);

	if (sanctum->tun_ip.sin_addr.s_addr != 0) {
		memcpy(&ifr->ifr_addr,
		    &sanctum->tun_ip, sizeof(sanctum->tun_ip));

		if (ioctl(fd, SIOCSIFADDR, ifr) == -1)
			fatal("ioctl(SIOCSIFADDR): %s", errno_s);

		if (!(sanctum->flags & SANCTUM_FLAG_USE_TAP)) {
			if (ioctl(fd, SIOCSIFDSTADDR, ifr) == -1)
				fatal("ioctl(SIOCSIFDSTADDR): %s", errno_s);
		}

		memcpy(&ifr->ifr_addr,
		    &sanctum->tun_mask, sizeof(sanctum->tun_mask));
		if (ioctl(fd, SIOCSIFNETMASK, ifr) == -1)
			fatal("ioctl(SIOCSIFNETMASK): %s", errno_s);
	}

	if (ioctl(fd, SIOCGIFFLAGS, ifr) == -1)
		fatal("ioctl(SIOCSIFFLAGS): %s", errno_s);

	ifr->ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(fd, SIOCSIFFLAGS, ifr) == -1)
		fatal("ioctl(SIOCSIFFLAGS): %s", errno_s);

	if (sanctum->tun_mtu != 0) {
		ifr->ifr_mtu = sanctum->tun_mtu;
		if (ioctl(fd, SIOCSIFMTU, ifr) == -1)
			fatal("ioctl(SIOCSIFMTU): %s", errno_s);
	}

	(void)close(fd);
}

/*
 * Move all processes except cathedral and purgatory-tx into a
 * new network namespace.
 */
static void
linux_sandbox_netns(struct sanctum_proc *proc)
{
	if (proc->type != SANCTUM_PROC_HEAVEN_RX &&
	    proc->type != SANCTUM_PROC_HEAVEN_TX &&
	    proc->type != SANCTUM_PROC_PURGATORY_RX &&
	    proc->type != SANCTUM_PROC_PURGATORY_TX &&
	    proc->type != SANCTUM_PROC_CATHEDRAL) {
		if (unshare(CLONE_NEWNET) == -1)
			fatal("unshare: %s", errno_s);
	}
}

/*
 * Apply the correct seccomp rules based on the process that is starting.
 */
static void
linux_sandbox_seccomp(struct sanctum_proc *proc)
{
	struct sock_filter		*sf;
	struct sock_fprog		prog, pf;
	size_t				len, idx, off;

	PRECOND(proc != NULL);

	/*
	 * If we are going to be doing seccomp tracing, do the ptrace()
	 * dance now so our parent can get cracking.
	 */
	if (seccomp_tracing) {
		filter_epilogue[0].k = SECCOMP_RET_TRACE;
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
			fatal("ptrace: %s", errno_s);
		if (kill(proc->pid, SIGSTOP) == -1)
			fatal("kill: %s", errno_s);
	}

	len = KORE_FILTER_LEN(filter_prologue);

	switch (proc->type) {
	case SANCTUM_PROC_BLESS:
	case SANCTUM_PROC_CONFESS:
		/* Only uses the common filter with the bare minimum. */
		pf.len = 0;
		pf.filter = NULL;
		break;
	case SANCTUM_PROC_CHAPEL:
	case SANCTUM_PROC_SHRINE:
	case SANCTUM_PROC_PILGRIM:
	case SANCTUM_PROC_CATHEDRAL:
		pf.filter = keying_seccomp_filter;
		pf.len = KORE_FILTER_LEN(keying_seccomp_filter);
		break;
	case SANCTUM_PROC_CONTROL:
		pf.filter = control_seccomp_filter;
		pf.len = KORE_FILTER_LEN(control_seccomp_filter);
		break;
	case SANCTUM_PROC_HEAVEN_TX:
		pf.filter = heaven_tx_seccomp_filter;
		pf.len = KORE_FILTER_LEN(heaven_tx_seccomp_filter);
		break;
	case SANCTUM_PROC_HEAVEN_RX:
		pf.filter = heaven_rx_seccomp_filter;
		pf.len = KORE_FILTER_LEN(heaven_rx_seccomp_filter);
		break;
	case SANCTUM_PROC_PURGATORY_TX:
		pf.filter = purgatory_tx_seccomp_filter;
		pf.len = KORE_FILTER_LEN(purgatory_tx_seccomp_filter);
		break;
	case SANCTUM_PROC_PURGATORY_RX:
		pf.filter = purgatory_rx_seccomp_filter;
		pf.len = KORE_FILTER_LEN(purgatory_rx_seccomp_filter);
		break;
	default:
		fatal("%s: unknown process type %d", __func__, proc->type);
	}

	len += KORE_FILTER_LEN(common_seccomp_filter);
	len += pf.len;
	len += KORE_FILTER_LEN(filter_epilogue);

	if ((sf = calloc(len, sizeof(*sf))) == NULL)
		fatal("calloc(%zu): %s", len, errno_s);

	off = 0;

	for (idx = 0; idx < KORE_FILTER_LEN(filter_prologue); idx++)
		sf[off++] = filter_prologue[idx];

	for (idx = 0; idx < KORE_FILTER_LEN(common_seccomp_filter); idx++)
		sf[off++] = common_seccomp_filter[idx];

	if (pf.len > 0) {
		for (idx = 0; idx < pf.len; idx++)
			sf[off++] = pf.filter[idx];
	}

	for (idx = 0; idx < KORE_FILTER_LEN(filter_epilogue); idx++)
		sf[off++] = filter_epilogue[idx];

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		fatal("prctl(privs): %s", errno_s);

	prog.len = len;
	prog.filter = sf;

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
		fatal("prctl(seccomp): %s", errno_s);
}

/*
 * Log a seccomp violation, used when SANCTUM_SECCOMP_TRACE is enabled
 * and a worker triggers a seccomp violation.
 */
static void
linux_seccomp_violation(struct sanctum_proc *proc)
{
	struct iovec			iov;
#if defined(__arm__)
	struct pt_regs			regs;
#else
	struct user_regs_struct		regs;
#endif
	long				sysnr;

	PRECOND(proc != NULL);

	iov.iov_base = &regs;
	iov.iov_len = sizeof(regs);

	if (ptrace(PTRACE_GETREGSET, proc->pid, 1, &iov) == -1)
		fatal("ptrace: %s", errno_s);

#if SECCOMP_AUDIT_ARCH == AUDIT_ARCH_X86_64
	sysnr = regs.orig_rax;
#elif SECCOMP_AUDIT_ARCH == AUDIT_ARCH_AARCH64
	sysnr = regs.regs[8];
#elif SECCOMP_AUDIT_ARCH == AUDIT_ARCH_ARM
	sysnr = regs.uregs[7];
#elif SECCOMP_AUDIT_ARCH == AUDIT_ARCH_RISCV64
	sysnr = regs.a7;
#else
#error "platform not supported"
#endif

	sanctum_log(LOG_INFO, "heresy from %s pid=%d, syscall=%ld",
	    proc->name, proc->pid, sysnr);
}
