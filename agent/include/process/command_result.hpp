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
#ifndef _NIMRODG_PROCESS_COMMAND_RESULT_HPP
#define _NIMRODG_PROCESS_COMMAND_RESULT_HPP

#include <iosfwd>
#include <system_error>
#include "job_definition.hpp"

namespace nimrod {

struct command_result
{
public:
	enum class result_status
	{
		precondition_failure,
		system_error,
		exception,
		aborted,
		success,
	};

	result_status status() const noexcept;
	size_t index() const noexcept;
	float time() const noexcept;
	int retval() const noexcept;
	const std::string& message() const noexcept;
	int error_code() const noexcept;


	static command_result make_precondition_failure(size_t index, float time, std::string_view msg);
	static command_result make_system_error(size_t index, float time, const std::system_error &err);
	static command_result make_system_error(size_t index, float time, const std::error_code& err);
	static command_result make_system_error(size_t index, float time, std::string_view msg, int err);
	static command_result make_exception(size_t index, float time, const std::exception& e);
	static command_result make_exception(size_t index, float time, std::string_view msg);
	static command_result make_exception(size_t index, float time, std::string_view msg, int retval);
	static command_result make_success(size_t index, float time, int retval);
	static command_result make_abort(size_t index, float time);

	command_result(result_status status, size_t index, float time, int retval, std::string_view message, int error_code);
private:
	result_status m_status;
	size_t m_index;
	float m_time;
	int m_retval;
	std::string m_message;
	int m_error_code;
};

std::ostream& operator<<(std::ostream& os, command_result::result_status s);
std::ostream& operator<<(std::ostream& os, const command_result& res);

}

#endif /* _NIMRODG_PROCESS_COMMAND_RESULT_HPP */