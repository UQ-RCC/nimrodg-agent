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
#include <cstdarg>
#include "process/process.hpp"

using namespace nimrod;

#if defined(NIMRODG_USE_WIN32API)
#	include "process_win32.hpp"
using process_impl = win32::win32process;
#elif defined(NIMRODG_USE_POSIX)
#	include "process_posix.hpp"
using process_impl = posix::posixprocess;
#else
#	error No process implementation defined
#endif

void process::iofile_deleter::operator()(iofile f)
{
	process_impl::delete_iofile_impl(f);
}

std::unique_ptr<process> process::create_process(const filesystem::path& path, const string_vector& args, const filesystem::path& cwd, const environment_map& env, iofile out, iofile err)
{
	return std::make_unique<process_impl>(path, args, cwd, env, out, err);
}

filesystem::path process::get_system_interpreter()
{
	return process_impl::get_system_interpreter_impl();
}

filesystem::path process::search_path(const std::string& program)
{
	return process_impl::search_path_impl(program);
}

process::string_vector process::build_shell_args(const std::string& cmdline)
{
	return process_impl::build_shell_args_impl(cmdline);
}

process::iofile_ptr process::create_iofile(const filesystem::path& path, bool append)
{
	return process_impl::create_iofile_impl(path, append);
}

process::iofile_ptr process::create_iofile_dup(const filesystem::path& path, bool append, iofile existing)
{
	return process_impl::create_iofile_dup_impl(path, append, existing);
}

process::iofile_ptr process::create_iofile_null()
{
	return process_impl::create_iofile_null_impl();
}

void process::reap(size_t numproc, ...)
{
	va_list ap;
	va_start(ap, numproc);
	try
	{
		process_impl::reap_impl(numproc, ap);
	}
	catch(...)
	{
		va_end(ap);
		throw;
	}
	va_end(ap);
}