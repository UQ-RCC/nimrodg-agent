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
#include <ostream>
#include "job_definition.hpp"

using namespace nimrod;

job_definition::job_definition() : job_definition(uuid(), 0, "", command_vector(), env_map()) {}

job_definition::job_definition(uuid u, size_t index, std::string_view txuri, const command_vector& commands, const env_map& environment) :
	m_uuid(u),
	m_index(index),
	m_txuri(txuri),
	m_commands(commands),
	m_environment(environment)
{}

uuid job_definition::get_uuid() const noexcept { return m_uuid; }
uint64_t job_definition::index() const noexcept { return m_index; }
const std::string& job_definition::txuri() const noexcept { return m_txuri; }
const job_definition::command_vector& job_definition::commands() const noexcept { return m_commands; }
const job_definition::env_map& job_definition::environment() const noexcept { return m_environment; }


onerror_command::onerror_command(action_t action) noexcept :
	m_action(action)
{}

onerror_command::action_t onerror_command::action() const noexcept
{
	return m_action;
}

redirect_command::redirect_command(stream_t stream, bool append, std::string_view file) :
	m_stream(stream),
	m_append(append),
	m_file(file)
{}

redirect_command::stream_t redirect_command::stream() const noexcept { return m_stream; }
bool redirect_command::append() const noexcept { return m_append; }
const std::string& redirect_command::file() const noexcept { return m_file; }


copy_command::copy_command(context_t src_ctx, std::string_view src_path, context_t dst_ctx, std::string_view dst_path) :
	m_source_context(src_ctx),
	m_source_path(src_path),
	m_dest_context(dst_ctx),
	m_dest_path(dst_path)
{}

copy_command::context_t copy_command::source_context() const noexcept
{
	return m_source_context;
}

const std::string& copy_command::source_path() const noexcept
{
	return m_source_path;
}

copy_command::context_t copy_command::dest_context() const noexcept
{
	return m_dest_context;
}

const std::string& copy_command::dest_path() const noexcept
{
	return m_dest_path;
}


exec_command::exec_command(std::string_view program, const argument_list& comps, bool search_path) :
	m_program(program),
	m_arguments(comps),
	m_search_path(search_path)
{}

const std::string& exec_command::program() const noexcept
{
	return m_program;
}

const exec_command::argument_list& exec_command::arguments() const noexcept
{
	return m_arguments;
}

bool exec_command::search_path() const noexcept
{
	return m_search_path;
}


command_type command_union::type() const noexcept
{
	return std::visit([](auto&& cmd) { return cmd.type(); }, static_cast<const _command_union&>(*this));
}

std::ostream& nimrod::operator<<(std::ostream& os, redirect_command::stream_t stream)
{
	return os << (stream == redirect_command::stream_t::stderr_ ? "STDERR" : "STDOUT");
}

std::ostream& nimrod::operator<<(std::ostream& os, onerror_command::action_t act)
{
	return os << (act == onerror_command::action_t::fail ? "FAIL" : "IGNORE");
}
