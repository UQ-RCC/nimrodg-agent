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

std::string posix::get_cspath()
{
	size_t n = confstr(_CS_PATH, nullptr, 0);
	if(n == 0)
		throw make_errno_exception(errno);
	
	std::string storage;
	storage.reserve(n + 1);
	if((n = confstr(_CS_PATH, &storage[0], n)) == 0)
		throw make_errno_exception(errno);
	
	return storage;
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

#include <map>
#include <csignal>

/*
** *Whistles nonchalantly*
** kill -l | sed 's/[0-9]*)//g' | xargs -n1 echo | awk '{ print "{" $0 ", \"" $0 "\"}," }'
*/
const static std::map<int, const char *> s_Sigmap = {
	{SIGHUP, "SIGHUP"},
	{SIGINT, "SIGINT"},
	{SIGQUIT, "SIGQUIT"},
	{SIGILL, "SIGILL"},
	{SIGTRAP, "SIGTRAP"},
	{SIGABRT, "SIGABRT"},
	{SIGBUS, "SIGBUS"},
	{SIGFPE, "SIGFPE"},
	{SIGKILL, "SIGKILL"},
	{SIGUSR1, "SIGUSR1"},
	{SIGSEGV, "SIGSEGV"},
	{SIGUSR2, "SIGUSR2"},
	{SIGPIPE, "SIGPIPE"},
	{SIGALRM, "SIGALRM"},
	{SIGTERM, "SIGTERM"},
	{SIGSTKFLT, "SIGSTKFLT"},
	{SIGCHLD, "SIGCHLD"},
	{SIGCONT, "SIGCONT"},
	{SIGSTOP, "SIGSTOP"},
	{SIGTSTP, "SIGTSTP"},
	{SIGTTIN, "SIGTTIN"},
	{SIGTTOU, "SIGTTOU"},
	{SIGURG, "SIGURG"},
	{SIGXCPU, "SIGXCPU"},
	{SIGXFSZ, "SIGXFSZ"},
	{SIGVTALRM, "SIGVTALRM"},
	{SIGPROF, "SIGPROF"},
	{SIGWINCH, "SIGWINCH"},
	{SIGIO, "SIGIO"},
	{SIGPWR, "SIGPWR"},
	{SIGSYS, "SIGSYS"},
	{SIGRTMIN, "SIGRTMIN"},
	{SIGRTMIN+1, "SIGRTMIN+1"},
	{SIGRTMIN+2, "SIGRTMIN+2"},
	{SIGRTMIN+3, "SIGRTMIN+3"},
	{SIGRTMIN+4, "SIGRTMIN+4"},
	{SIGRTMIN+5, "SIGRTMIN+5"},
	{SIGRTMIN+6, "SIGRTMIN+6"},
	{SIGRTMIN+7, "SIGRTMIN+7"},
	{SIGRTMIN+8, "SIGRTMIN+8"},
	{SIGRTMIN+9, "SIGRTMIN+9"},
	{SIGRTMIN+10, "SIGRTMIN+10"},
	{SIGRTMIN+11, "SIGRTMIN+11"},
	{SIGRTMIN+12, "SIGRTMIN+12"},
	{SIGRTMIN+13, "SIGRTMIN+13"},
	{SIGRTMIN+14, "SIGRTMIN+14"},
	{SIGRTMIN+15, "SIGRTMIN+15"},
	{SIGRTMAX-14, "SIGRTMAX-14"},
	{SIGRTMAX-13, "SIGRTMAX-13"},
	{SIGRTMAX-12, "SIGRTMAX-12"},
	{SIGRTMAX-11, "SIGRTMAX-11"},
	{SIGRTMAX-10, "SIGRTMAX-10"},
	{SIGRTMAX-9, "SIGRTMAX-9"},
	{SIGRTMAX-8, "SIGRTMAX-8"},
	{SIGRTMAX-7, "SIGRTMAX-7"},
	{SIGRTMAX-6, "SIGRTMAX-6"},
	{SIGRTMAX-5, "SIGRTMAX-5"},
	{SIGRTMAX-4, "SIGRTMAX-4"},
	{SIGRTMAX-3, "SIGRTMAX-3"},
	{SIGRTMAX-2, "SIGRTMAX-2"},
	{SIGRTMAX-1, "SIGRTMAX-1"},
	{SIGRTMAX, "SIGRTMAX"},
};

const char *posix::get_signal_string(int signal)
{
    return s_Sigmap.at(signal);
}

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

#endif