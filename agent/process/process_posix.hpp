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
#ifndef _NIMRODG_PROCESS_PROCESS_POSIX_HPP
#define _NIMRODG_PROCESS_PROCESS_POSIX_HPP

#include "config.h"
#ifdef NIMRODG_USE_POSIX

#include <map>
#include <thread>
#include "process/process.hpp"
#include <atomic>
#include <condition_variable>

namespace nimrod {
namespace posix {

class posixprocess : public process
{
public:
	posixprocess(
		const filesystem::path& path,
		const string_vector& args,
		const filesystem::path& cwd,
		const environment_map& env,
		iofile out,
		iofile err
	);

	~posixprocess() noexcept override;

	const filesystem::path& executable_path() const noexcept override;
	const filesystem::path& initial_working_directory() const noexcept override;
	const environment_map& initial_environment_variables() const noexcept override;
	const environment_map& initial_merged_environment_variables() const noexcept override;
	std::future<process_result> get_future() override;
	void kill(bool force) noexcept override;

	static filesystem::path get_system_interpreter_impl();
	static filesystem::path search_path_impl(const std::string& program);
	static string_vector build_shell_args_impl(const std::string& cmdline);
	static iofile_ptr create_iofile_impl(const filesystem::path& path, bool append);
	static iofile_ptr create_iofile_dup_impl(const filesystem::path& path, bool append, iofile existing);
	static iofile_ptr create_iofile_null_impl();
	static void delete_iofile_impl(iofile f);
	static void reap_impl(size_t numproc, va_list ap);
private:

	void on_child_exit(pid_t corpse, int status) noexcept;

	struct
	{
		filesystem::path path;
		string_vector args;
		filesystem::path cwd;
		environment_map env;
		environment_map env_merged;
	} m_initial;

	std::promise<process_result> m_promise;
	std::atomic<pid_t> m_pid;

	friend class process;
};

}
}
#endif

#endif /* _NIMRODG_PROCESS_PROCESS_POSIX_HPP */