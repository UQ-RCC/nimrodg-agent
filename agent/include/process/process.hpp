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
#ifndef _NIMRODG_PROCESS_PROCESS_HPP
#define _NIMRODG_PROCESS_PROCESS_HPP

#include <unordered_map>
#include <memory>
#include <future>
#include <vector>
#include "agent_common.hpp"

namespace nimrod {

class process
{
public:
	using iofile = void*;
	struct iofile_deleter
	{
		using pointer = iofile;
		void operator()(pointer p);
	};
	using iofile_ptr = std::unique_ptr<iofile, iofile_deleter>;

	using process_result = std::pair<int32_t, std::error_code>;

	using string_vector = std::vector<std::string>;
	using environment_map = std::unordered_map<std::string, std::string>;

	virtual const filesystem::path& executable_path() const noexcept = 0;
	virtual const filesystem::path& initial_working_directory() const noexcept = 0;
	virtual const environment_map& initial_environment_variables() const noexcept = 0;
	virtual const environment_map& initial_merged_environment_variables() const noexcept = 0;
	virtual std::future<process_result> get_future() = 0;
	virtual void kill(bool force) noexcept = 0;

	virtual ~process() = default;

	process() = default;
	process(const process&) = delete;
	process(process&&) = default;

	process& operator=(const process&) = delete;
	process& operator=(process&&) = default;

	static std::unique_ptr<process> create_process(
		const filesystem::path& path,
		const string_vector& args,
		const filesystem::path& cwd,
		const environment_map& env,
		iofile out,
		iofile err
	);
	static filesystem::path get_system_interpreter();
	static filesystem::path search_path(const std::string& program);
	static string_vector build_shell_args(const std::string& cmdline);
	static iofile_ptr create_iofile(const filesystem::path& path, bool append);
	static iofile_ptr create_iofile_dup(const filesystem::path& path, bool append, iofile existing);
	static iofile_ptr create_iofile_null();
	static void reap(size_t numproc, ...);
};
}

#endif /* _NIMRODG_PROCESS_PROCESS_HPP */