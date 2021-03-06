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
#include "process_posix.hpp"
#ifdef NIMRODG_USE_POSIX
#include "utils_posix.hpp"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pwd.h>
#include <cassert>
#include <unordered_map>
#include "log.hpp"


using namespace nimrod;
using namespace nimrod::posix;

/* Defined by POSIX */
extern "C" char **environ;

static int errno2ret(int e)
{
	if(errno == EACCES)
		return 126;
	else if(errno == ENOENT)
		return 127;
	else
		return 1;
}

static void dokill(pid_t pid, int signal) noexcept
{
	if(pid == 0)
		return;

	pid_t grp;
	if(pid < 0)
		grp = -pid;
	else
		grp = getpgid(pid);

	pid_t our_group = getpgrp();
	pid_t target = 0;
	if(grp < 0)
	{
		log::warn("PROCESS", "getpgid(%d) failed with error %d, using PID.", pid, errno);
		log::warn("PROCESS", " %s", strerror(errno));
		target = pid;
	}
	else if(our_group == grp)
	{
		/* If setpgid failed in the child.  */
		target = pid;
	}
	else
	{
		/* We can kill the entire group. */
		target = -grp;
	}

	log::trace("PROCESS", "Calling kill(%d, %d)", target, signal);
	if(::kill(target, signal) < 0)
	{
		log::error("PROCESS", "kill(%d, %d) failed with error %d", target, signal, errno);
		log::error("PROCESS", " %s", strerror(errno));
	}
}

posixprocess::posixprocess(
	const filesystem::path& path,
	const std::vector<std::string>& args,
	const filesystem::path& cwd,
	const environment_map& env,
	iofile out,
	iofile err)
{
	/* Store all the initial stuff */
	m_initial.path = path;
	m_initial.args = args;
	m_initial.cwd = cwd;
	m_initial.env = env;

	/* Build argv */
	std::vector<const char*> argv;
	argv.reserve(args.size());
	for(auto& s : args)
		argv.emplace_back(s.c_str());

	argv.emplace_back(nullptr);

	/*
	** http://pubs.opengroup.org/onlinepubs/009695399/basedefs/xbd_chap08.html
	** If more than one string in a process' environment has the same name,
	** the consequences are undefined.
	*/
	environment_map envs;
	for(char **e = environ; *e != nullptr; ++e)
	{
		/* These strings have the form name=value; names shall not contain the character '='. */
		char *equ = strchr(*e, '=');
		envs[std::string(*e, equ)] = equ + 1;
	}

	/* Overwrite system variables with ours. */
	for(auto& e : env)
		envs[e.first] = e.second;

	/* Now (finally), build the environment pointers */
	std::vector<std::string> envstorage;

	for(auto& e : envs)
		envstorage.emplace_back(fmt::format("{0}={1}", e.first, e.second));

	std::vector<const char *> envp;
	for(auto& e : envstorage)
		envp.emplace_back(const_cast<char * const>(e.c_str()));

	envp.emplace_back(nullptr);

	/* Set variables up so the child has to do as little as possible */
	std::string pathStr = path.u8string();
	std::string cwdStr = cwd.u8string();

	set_all_close_on_exec();
	int outFd = fileno(reinterpret_cast<FILE*>(out));
	int errFd = fileno(reinterpret_cast<FILE*>(err));
	fcntl(outFd, F_SETFD, 0) ;
	fcntl(errFd, F_SETFD, 0);

	/*
	** Let's follow Bash here: http://tldp.org/LDP/abs/html/exitcodes.html
	*/
	if((m_pid = fork()) < 0)
	{
		log::error("PROCESS", "fork() failed with error %d.", errno);
		log::error("PROCESS", "  %s", strerror(errno));
		throw make_errno_exception(errno);
	}

	if(m_pid == 0)
	{
		/*
		** Child. Just do our shit and get out of here quickly.
		**
		** - According to POSIX, we're the only thread running.
		** - set_all_close_on_exec(), should have already been called,
		**   so only std{out,in,err} and our redirects are open.
		*/

		close(STDIN_FILENO);

		/* Move us into our own group, so the agent can kill our entire group. */
		if(setpgid(0, 0) < 0)
		{
			fprintf(stderr, "setpgid(0, 0) failed with error %d: %s\n", errno, strerror(errno));
			_exit(errno2ret(errno));
		}

		/* We're screwed if these fail */
		if(dup2(outFd, STDOUT_FILENO) < 0)
		{
			fprintf(stderr, "stdout dup2(%d, %d) failed with error %d: %s\n", outFd, STDOUT_FILENO, errno, strerror(errno));
			_exit(errno2ret(errno));
		}

		if(outFd != errFd)
			close(outFd);

		if(dup2(errFd, STDERR_FILENO) < 0)
		{
			fprintf(stderr, "stderr dup2() failed with error %d: %s\n", errno, strerror(errno));
			_exit(errno2ret(errno));
		}

		close(errFd);

		//fprintf(stdout, "chdir'ing() to %s\n", cwdStr.c_str());
		if(chdir(cwdStr.c_str()) < 0)
		{
			fprintf(stderr, "chdir() failed with error %d: %s\n", errno, strerror(errno));
			_exit(errno2ret(errno));
		}

		/* Try to execve(), if this fails then _exit() */
		if(execve(pathStr.c_str(), const_cast<char * const*>(argv.data()), const_cast<char * const*>(envp.data())) < 0)
		{
			/* This will be redirected, so just use fprintf() */
			fprintf(stderr, "execve() failed with error %d: %s\n", errno, strerror(errno));
			_exit(errno2ret(errno));
		}

		/* Will never get here */
		std::terminate();
		return;
	}

	log::trace("PROCESS", "Child forked to pid %d", m_pid);

}

static process::process_result make_process_result(pid_t pid, int status)
{
	/* Technically, these aren't our errors */
	std::error_code ec(0, std::system_category());

	/* Exited normally! */
	if(WIFEXITED(status))
		return std::make_pair(WEXITSTATUS(status), ec);

	/* Exited uncleanly. */
	if(WIFSIGNALED(status))
	{
		int signum = WTERMSIG(status);
		log::trace("PROCESS", "Child terminated with %s.", get_signal_string(signum));
		return std::make_pair(128 + signum, ec);
	}

	/*
	** We don't know why it failed, but print the waitpid() status so further
	** examination can be done.
	*/
	log::error("PROCESS", "  Child terminated uncleanly. waitpid() status: %x", status);
	return std::make_pair(0xFFFFFFFF, ec);
}

void posixprocess::on_child_exit(pid_t corpse, int status) noexcept
{
	if(corpse != m_pid)
		return;

	log::trace("PROCESS", "on_child_exit(%d, %d) called", corpse, status);

	/*
	 * If we're here, we either came from (1) a voluntary termination, or from (2) dokill().
	 * If (1), assume the program behaved nicely and has no children left.
	 * If (2), tough shit. The program should pass signals correctly.
	 *
	 * SIGKILL the entire group. If (1), then this won't do anything.
	 *
	 * There is a minor race-condition here, but it's not possible to fix via any
	 * non-root method that I know of.
	 */
	::kill(-corpse, SIGKILL);

	this->m_pid = 0;
	this->m_promise.set_value(make_process_result(corpse, status));
}

posixprocess::~posixprocess() noexcept
{
	/* The process should've been killed properly by now. If it hasn't SIGKILL the entire tree. */
	if(m_pid != 0)
		dokill(m_pid, SIGKILL);
}

const filesystem::path& posixprocess::executable_path() const noexcept
{
	return m_initial.path;
}

const filesystem::path& posixprocess::initial_working_directory() const noexcept
{
	return m_initial.cwd;
}

const process::environment_map& posixprocess::initial_environment_variables() const noexcept
{
	return m_initial.env;
}

const process::environment_map& posixprocess::initial_merged_environment_variables() const noexcept
{
	return m_initial.env_merged;
}

std::future<process::process_result> posixprocess::get_future()
{
	return m_promise.get_future();
}

void posixprocess::kill(bool force) noexcept
{
	return dokill(m_pid.load(), force ? SIGKILL : SIGTERM);
}

filesystem::path posixprocess::get_system_interpreter_impl()
{
	/* Try get the shell from the environment. */
	const char *envShell = getenv("SHELL");
	if(envShell != nullptr && envShell[0] != '\0')
		return getenv("SHELL");

	/* Try from /etc/passwd */
	struct passwd *p;
	if((p = getpwuid(geteuid())))
		return p->pw_shell;

	/* Nothing worked, default to /bin/sh */
	return "/bin/sh";
}


filesystem::path posixprocess::search_path_impl(const std::string& program)
{
	return posix::search_path(program);
}

static_assert(sizeof(int) <= sizeof(process::iofile), "sizeof(int) > sizeof(iofile)");

process::iofile_ptr posixprocess::create_iofile_impl(const filesystem::path& path, bool append)
{
	const char *_path = !path.empty() ? path.c_str() : "/dev/null";
	FILE *f = fopen(_path, append ? "ab" : "wb");
	if(!f)
		throw make_errno_exception(errno);

	return iofile_ptr(f);
}

process::iofile_ptr posixprocess::create_iofile_dup_impl(const filesystem::path& path, bool append, iofile existing)
{
	/* This is significantly easier than on Windows. */
	return create_iofile(path, append);
}

process::iofile_ptr posixprocess::create_iofile_null_impl()
{
	FILE *f = fopen("/dev/null", "wb");
	if(!f)
		throw make_errno_exception(errno);

	return iofile_ptr(f);
}

void posixprocess::delete_iofile_impl(iofile iof)
{
	FILE *f = reinterpret_cast<FILE*>(iof);
	fclose(f);
}

process::string_vector posixprocess::build_shell_args_impl(const std::string& cmdline)
{
	return { get_system_interpreter().u8string(), "-c", cmdline };
}

void posixprocess::reap_impl(size_t numproc, va_list ap)
{
	va_list aap;
	for(pid_t corpse;;)
	{
		int status;
		if((corpse = waitpid(-1, &status, WNOHANG)) < 0)
		{
			if(errno == EINTR)
				continue;

			if(errno == ECHILD)
				break;
		}

		/* No children. */
		if(corpse == 0)
			break;

		/* We have a dead child. */
		va_copy(aap, ap);
		for(size_t i = 0; i < numproc; ++i)
		{
			posixprocess *proc = va_arg(aap, posixprocess*);
			if(proc == nullptr)
				continue;

			proc->on_child_exit(corpse, status);

		}
		va_end(aap);
	}
}

#endif