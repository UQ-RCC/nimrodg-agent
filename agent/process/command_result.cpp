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
#include "process/command_result.hpp"

using namespace nimrod;

command_result::command_result(result_status status, size_t index, float time, int retval, std::string_view message, int error_code) :
	m_status(status),
	m_index(index),
	m_time(time),
	m_retval(retval),
	m_message(message),
	m_error_code(error_code)
{}

command_result::result_status command_result::status() const noexcept
{
	return m_status;
}

size_t command_result::index() const noexcept
{
	return m_index;
}

float command_result::time() const noexcept
{
	return m_time;
}

int command_result::retval() const noexcept
{
	return m_retval;
}

const std::string& command_result::message() const noexcept
{
	return m_message;
}

int command_result::error_code() const noexcept
{
	return m_error_code;
}

command_result command_result::make_precondition_failure(size_t index, float time, std::string_view msg)
{
	return command_result(result_status::precondition_failure, index, time, -1, msg, 0);
}

command_result command_result::make_system_error(size_t index, float time, const std::system_error &err)
{
	return make_system_error(index, time, err.what(), err.code().value());
}

command_result command_result::make_system_error(size_t index, float time, const std::error_code& err)
{
	return make_system_error(index, time, err.message(), err.value());
}

command_result command_result::make_system_error(size_t index, float time, std::string_view msg, int err)
{
	return command_result(result_status::system_error, index, time, -1, msg, err);
}

command_result command_result::make_exception(size_t index, float time, const std::exception& e)
{
	return command_result(result_status::exception, index, time, -1, e.what(), 0);
}

command_result command_result::make_exception(size_t index, float time, std::string_view msg)
{
	return make_exception(index, time, msg, -1);
}

command_result command_result::make_exception(size_t index, float time, std::string_view msg, int retval)
{
	return command_result(result_status::exception, index, time, retval, msg, 0);
}

command_result command_result::make_success(size_t index, float time, int retval)
{
	return command_result(result_status::success, index, time, retval, "Success", 0);
}

command_result command_result::make_abort(size_t index, float time)
{
	return command_result(result_status::aborted, index, 0.0f, -1, "Abortion requested", 0);
}

command_result command_result::make_failed(size_t index, float time, int retval)
{
	return command_result(result_status::failed, index, time, retval, "Command returned nonzero", 0);
}

#include <ostream>

std::ostream& nimrod::operator<<(std::ostream& os, command_result::result_status s)
{
	switch(s)
	{
		case command_result::result_status::precondition_failure: return os << "PRECONDITION_FAILURE";
		case command_result::result_status::system_error: return os << "SYSTEM_ERROR";
		case command_result::result_status::exception: return os << "EXCEPTION";
		case command_result::result_status::success: return os << "SUCCESS";
		case command_result::result_status::aborted: return os << "ABORTED";
		case command_result::result_status::failed: return os << "FAILED";
	}

	throw std::domain_error("Oops, you forgot a switch condition");
}

#include <string>
std::ostream& nimrod::operator<<(std::ostream& os, const command_result& res)
{
	os << res.status();
	if(res.status() == command_result::result_status::success)
		os << "(" << res.retval() << ")";
	else if(res.status() == command_result::result_status::system_error)
		os << "(" << res.error_code() << ")";

	return os << ": " << res.message();
}
