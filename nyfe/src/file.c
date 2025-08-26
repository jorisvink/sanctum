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
#include <sys/stat.h>

#include <fcntl.h>
#include <unistd.h>

#include "nyfe.h"
#include "queue.h"

struct file {
	int			fd;
	char			*path;
	LIST_ENTRY(file)	list;
};

static LIST_HEAD(, file)	files;

/* Initialize the file list. */
void
nyfe_file_init(void)
{
	LIST_INIT(&files);
}

/*
 * Remove all lingering files from the files list.
 */
void
nyfe_file_remove_lingering(void)
{
	struct file		*file;

	while ((file = LIST_FIRST(&files)) != NULL) {
		LIST_REMOVE(file, list);

		if (unlink(file->path) == -1 && errno != ENOENT) {
			printf("WARNING: failed to remove '%s', do not use\n",
			    file->path);
		}

		free(file->path);
		free(file);
	}
}

/*
 * Open the file at the given path, the mode depends on the `which`
 * parameter which is either NYFE_FILE_READ or NYFE_FILE_CREATE.
 *
 * If NYFE_FILE_CREATE is given, the file must not exist and will be
 * created with mode 0500.
 *
 * For NYFE_FILE_READ it is made sure the file is a regular file, not
 * a symbolic link or anything else.
 *
 * For NYFE_FILE_CREATE, the file is added to a list of files that may
 * be removed in case of a nyfe_fatal() error.
 */
int
nyfe_file_open(const char *path, int which)
{
	int			fd;
	struct stat		st;
	struct file		*file;

	PRECOND(path != NULL);
	PRECOND(which == NYFE_FILE_READ || which == NYFE_FILE_CREATE);

	if (which == NYFE_FILE_READ) {
		if ((fd = open(path, O_RDONLY | O_NOFOLLOW)) == -1)
			nyfe_fatal("failed to open '%s': %s", path, errno_s);

		if (fstat(fd, &st) == -1)
			nyfe_fatal("fstat failed: %s", errno_s);

		if (!S_ISREG(st.st_mode))
			nyfe_fatal("%s: not a file", path);
	} else {
		if ((fd = open(path,
		    O_CREAT | O_EXCL | O_WRONLY | O_TRUNC, 0500)) == -1)
			nyfe_fatal("failed to open '%s': %s", path, errno_s);

		if ((file = calloc(1, sizeof(*file))) == NULL)
			nyfe_fatal("failed to allocate file structure");

		if ((file->path = strdup(path)) == NULL)
			nyfe_fatal("failed to copy file path");

		file->fd = fd;

		LIST_INSERT_HEAD(&files, file, list);
	}

	return (fd);
}

/*
 * Close a file descriptor that was used for writing. In the close()
 * system call failed we remove the file from disk as it is inconsistent.
 */
void
nyfe_file_close(int fd)
{
	struct file		*file;

	PRECOND(fd >= 0);

	LIST_FOREACH(file, &files, list) {
		if (file->fd == fd)
			break;
	}

	if (file == NULL)
		nyfe_fatal("failed to find file matching fd '%d'", fd);

	LIST_REMOVE(file, list);

	if (close(fd) == -1) {
		if (unlink(file->path) == -1 && errno != ENOENT) {
			printf("WARNING: failed to remove '%s', do not use\n",
			    file->path);
		}
		nyfe_fatal("close failed on '%s': %s", file->path, errno_s);
	}

	free(file->path);
	free(file);
}

/* Returns the file size of the file pointed to by the given file descriptor. */
u_int64_t
nyfe_file_size(int fd)
{
	struct stat	st;

	PRECOND(fd >= 0);

	if (fstat(fd, &st) == -1)
		nyfe_fatal("fstat failed: %s", errno_s);

	return ((u_int64_t)st.st_size);
}

/*
 * Atomically write all wanted data into the file descriptor.
 */
void
nyfe_file_write(int fd, const void *buf, size_t len)
{
	ssize_t		ret;

	PRECOND(fd >= 0);
	PRECOND(buf != NULL);
	PRECOND(len > 0);

	for (;;) {
		ret = write(fd, buf, len);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			nyfe_fatal("write: %s", errno_s);
		}

		if ((size_t)ret != len)
			nyfe_fatal("write: %zd/%zu", ret, len);

		break;
	}
}

/*
 * Atomically read the number of requested bytes from the file descriptor.
 */
size_t
nyfe_file_read(int fd, void *buf, size_t len)
{
	ssize_t		ret;

	PRECOND(fd >= 0);
	PRECOND(buf != NULL);
	PRECOND(len > 0);

	for (;;) {
		ret = read(fd, buf, len);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			nyfe_fatal("read: %s", errno_s);
		}
		break;
	}

	return ((size_t)ret);
}
