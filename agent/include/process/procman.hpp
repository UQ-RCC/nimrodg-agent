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
#ifndef _NIMRODG_PROCESS_PROCMAN_HPP
#define _NIMRODG_PROCESS_PROCMAN_HPP

#include <mutex>
#include "agent_common.hpp"
#include "command_result.hpp"
#include "process.hpp"
#include "transfer.hpp"

namespace nimrod {

class procman
{
public:
	struct path_info
	{
		filesystem::path path_job_root;
		filesystem::path path_stdout;
		filesystem::path path_stderr;
		filesystem::path path_working;
		filesystem::path path_tmp;

		std::string uri_base_stor;
		uri_ptr uri_base;
	};

	procman(const job_definition& j, const filesystem::path& work_root, txman *tx);
	~procman();

	const uuid job_uuid() const noexcept;
	const job_definition& job() const noexcept;
	const path_info& paths() const noexcept;
	size_t command_index() const noexcept;
	onerror_command::action_t error_policy() const noexcept;

	size_t num_commands() const noexcept;
	command_result run();

	void report_child_signal();
	void ask_nicely_to_exit();
	void ask_meanly_to_exit();

private:
	using process_ptr = std::unique_ptr<process>;
	using iofile_ptr = process::iofile_ptr;

	command_result run_command(const onerror_command& cmd);
	command_result run_command(const redirect_command& cmd);
	command_result run_command(const copy_command& cmd);
	command_result run_command(const exec_command& cmd);

	job_definition m_job;
	path_info m_paths;
	txman *m_tx;

	size_t m_command_index;
	onerror_command::action_t m_error_policy;

	process_ptr m_process;
	iofile_ptr m_ionull;
	iofile_ptr m_ioout;
	bool m_appendout;
	iofile_ptr m_ioerr;
	bool m_appenderr;
	txman::future_pair m_transfer_info;
	bool m_killflag;

	std::mutex m_mutex;
};

}


#endif /* _NIMRODG_PROCESS_PROCMAN_HPP */