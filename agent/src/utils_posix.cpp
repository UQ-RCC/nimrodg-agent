/*
 * Nimrod/G Agent
 * https://github.com/UQ-RCC/nimrodg-agent
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 The University of Queensland
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "utils_posix.hpp"
#ifdef NIMRODG_USE_POSIX

#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>

using namespace nimrod;
using namespace nimrod::posix;

void fd_deleter::operator()(pointer p)
{
	close(p);
}

std::system_error posix::make_errno_exception(int err)
{
	std::error_code ec(err, std::system_category());
	return std::system_error(ec);
}

/* https://stackoverflow.com/a/21952155 */
void posix::set_all_close_on_exec()
{
    struct rlimit  rlim;
    long           max;
    int            fd;

    /* Resource limit? */
#if defined(RLIMIT_NOFILE)
    if (getrlimit(RLIMIT_NOFILE, &rlim) != 0)
        rlim.rlim_max = 0;
#elif defined(RLIMIT_OFILE)
    if (getrlimit(RLIMIT_OFILE, &rlim) != 0)
        rlim.rlim_max = 0;
#else
    /* POSIX: 8 message queues, 20 files, 8 streams */
    rlim.rlim_max = 36;
#endif

    /* Configured limit? */
#if defined(_SC_OPEN_MAX)
    max = sysconf(_SC_OPEN_MAX);
#else
    max = 36L;
#endif

    /* Use the bigger of the two. */
    if ((int)max > (int)rlim.rlim_max)
        fd = max;
    else
        fd = rlim.rlim_max;

    while (fd-->0)
        if (fd != STDIN_FILENO  &&
            fd != STDOUT_FILENO &&
            fd != STDERR_FILENO)
            fcntl(fd, F_SETFD, FD_CLOEXEC);
}

#include <csignal>

/* NB: Deliberately not in posix:: */
void enter_batch_mode() noexcept
{
	/* Everything's set up, now fork() if we need to. */
	pid_t pid = fork();
	if(pid < 0)
	{
		fprintf(stderr, "fork(): %s\n", strerror(errno));
		exit(1);
	}
	else if(pid > 0)
	{
		fprintf(stdout, "%d\n", pid);
		fflush(stdout);
		exit(0);
	}

	/* We're in the child here. */
	fd_ptr devnull(open(NIMRODG_DEVNULL, O_RDWR));
	if(!devnull)
	{
		fprintf(stderr, "open(): %s\n", strerror(errno));
		exit(1);
	}

	/* These guys MUST be closed, otherwise SSH sessions will hang. */
	if(dup2(devnull.get(), STDIN_FILENO) < 0)
	{
		fprintf(stderr, "dup2(): %s\n", strerror(errno));
		exit(1);
	}

	if(dup2(devnull.get(), STDOUT_FILENO) < 0)
	{
		fprintf(stderr, "dup2(): %s\n", strerror(errno));
		exit(1);
	}

	if(dup2(devnull.get(), STDERR_FILENO) < 0)
	{
		fprintf(stderr, "dup2(): %s\n", strerror(errno));
		exit(1);
	}
}

#include <sys/stat.h>
static int statfile(const char *p, uid_t uid, gid_t gid)
{
	struct stat statbuf{};
	memset(&statbuf, 0, sizeof(statbuf));

	if(stat(p, &statbuf) < 0)
		return -1;

	/* EACCES The file or a script interpreter is not a regular file. */
	if(!S_ISREG(statbuf.st_mode))
		return errno = EACCES, -1;

	/* Check permissions, least-specific to most-specific.  */
	if(statbuf.st_mode & S_IXOTH)
		return 0;

	if((statbuf.st_mode & S_IXGRP) && (statbuf.st_gid == gid))
		return 0;

	if((statbuf.st_mode & S_IXUSR) && (statbuf.st_uid == uid))
		return 0;

	/* EACCES Execute permission is denied for the file or a script or ELF interpreter. */
	return errno = EACCES, -1;
}

std::string posix::search_path(const std::string& f)
{
	/* Get PATH. If empty, fall back to _CS_PATH. */
	const char *path = getenv("PATH");
	if(path == nullptr || path[0] == '\0')
	{
		size_t n = confstr(_CS_PATH, nullptr, 0);
		if(n == 0)
			throw make_errno_exception(EINVAL);

		/* If _CS_PATH overflows the stack then something's wrong. */
		char *_path = (char*)alloca(n * sizeof(char));
		if(confstr(_CS_PATH, _path, n))
			throw make_errno_exception(EINVAL);

		path = _path;
	}

	const char *pend = path + strlen(path);

	/* Get the max buffer size. */
	size_t dlen = 0;
	for(const char *o = path, *c = strchr(o, ':'); o < pend; o = c + 1, c = strchr(o, ':'))
	{
		if(c == nullptr)
			c = pend;

		size_t dist = c - o;
		if(dist > dlen)
			dlen = dist;
	}

	size_t flen = f.size() + 1; /* /%s */
	dlen += flen + 1;

	uid_t uid = getuid();
	gid_t gid = getgid();

	std::string buf;
	buf.reserve(dlen);

	for(const char *o = path, *c = strchr(o, ':'); o < pend; o = c + 1, c = strchr(o, ':'))
	{
		if(c == nullptr)
			c = pend;

		size_t dist = c - o;

		buf.clear();
		buf.append(o, dist).append(1, '/').append(f);

		if((statfile(buf.c_str(), uid, gid)) < 0)
			continue;

		return buf;
	}

	throw make_errno_exception(ENOENT);
}

#endif