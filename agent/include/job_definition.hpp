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
#ifndef _NIMROD_JOB_HPP
#define _NIMROD_JOB_HPP

#include <iosfwd>
#include <vector>
#include <unordered_map>
#include <variant>
#include "uuid.hpp"

namespace nimrod {

enum class command_type { onerror, redirect, copy, exec };

class command
{
protected:
	explicit command(command_type type) noexcept;
public:
	command_type type() const noexcept;
private:
	command_type m_type;
};

class onerror_command : public command
{
public:
	enum class action_t { fail, ignore };

	explicit onerror_command(action_t action) noexcept;

	action_t action() const noexcept;

private:
	action_t m_action;
};

class redirect_command : public command
{
public:
	enum class stream_t { stdout_, stderr_ };

	redirect_command(stream_t stream, bool append, const std::string& file);

	stream_t stream() const noexcept;
	bool append() const noexcept;
	const std::string& file() const noexcept;

private:

	stream_t m_stream;
	bool m_append;
	std::string m_file;
};

class copy_command : public command
{
public:
	enum class context_t { node, root };

	copy_command(context_t src_ctx, const std::string& src_path, context_t dst_ctx, const std::string& dst_path);

	context_t source_context() const noexcept;
	const std::string& source_path() const noexcept;

	context_t dest_context() const noexcept;
	const std::string& dest_path() const noexcept;

private:
	context_t m_source_context;
	std::string m_source_path;

	context_t m_dest_context;
	std::string m_dest_path;
};

class exec_command : public command
{
public:
	using argument_list = std::vector<std::string>;

	exec_command(const std::string& program, const argument_list& args, bool search_path);

	const std::string& program() const noexcept;
	const argument_list& arguments() const noexcept;
	bool search_path() const noexcept;

private:
	std::string m_program;
	argument_list m_arguments;
	bool m_search_path;
};

using _command_union = std::variant<onerror_command, redirect_command, copy_command, exec_command>;

class command_union : public _command_union
{
public:
	using _command_union::_command_union;
	using _command_union::operator=;

	command_union(const command_union&) = default;
	command_union& operator=(const command_union&) = default;

	command_type type() const noexcept;

	template <typename T>
	const T& get() const { return std::get<T>(*this); }
};

class job_definition
{
public:
	using command_vector = std::vector<command_union>;
	using env_map = std::unordered_map<std::string, std::string>;

	job_definition();
	job_definition(const job_definition&) = default;
	job_definition(job_definition&&) = default;
	job_definition(uuid u, size_t index, const std::string& txuri, const std::string& token, const command_vector& commands, const env_map& environment);

	job_definition& operator=(const job_definition&) = default;
	job_definition& operator=(job_definition&&) = default;

	uuid get_uuid() const noexcept;
	uint64_t index() const noexcept;
	const std::string& txuri() const noexcept;
	const std::string& token() const noexcept;
	const command_vector& commands() const noexcept;
	const env_map& environment() const noexcept;

private:
	uuid m_uuid;
	uint64_t m_index;
	std::string m_txuri;
	std::string m_token;
	command_vector m_commands;
	env_map m_environment;
};

std::ostream& operator<<(std::ostream& os, redirect_command::stream_t stream);
std::ostream& operator<<(std::ostream& os, onerror_command::action_t action);
std::ostream& operator<<(std::ostream& os, const command_union& cmd);

}

#endif /* _NIMROD_JOB_HPP */