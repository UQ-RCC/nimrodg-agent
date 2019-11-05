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
#include "messages/messages.hpp"

using namespace nimrod;
using namespace nimrod::net;

hello_message::hello_message(nimrod::uuid uuid, std::string_view queue) :
	message_base_type(uuid),
	m_queue(queue)
{}

std::string_view hello_message::queue() const noexcept
{
	return m_queue;
}


init_message::init_message() noexcept :
	base_message<init_message>(nimrod::uuid())
{}

init_message::init_message(nimrod::uuid uuid) noexcept :
	base_message<init_message>(uuid)
{}


lifecontrol_message::lifecontrol_message(nimrod::uuid uuid, operation_t op) :
	base_message<lifecontrol_message>(uuid),
	m_operation(op)
{}

lifecontrol_message::operation_t lifecontrol_message::operation() const noexcept
{
	return m_operation;
}

const char *lifecontrol_message::get_operation_string(operation_t op) noexcept
{
	switch(op)
	{
		case operation_t::cancel: return "cancel";
		case operation_t::terminate: return "terminate";
		default: return "unknown";
	}
}


shutdown_message::shutdown_message(nimrod::uuid agent_uuid, reason_t reason, int signal) noexcept :
	base_message<shutdown_message>(agent_uuid),
	m_reason(reason),
	m_signal(signal)
{}

shutdown_message::reason_t shutdown_message::reason() const noexcept
{
	return m_reason;
}

int shutdown_message::signal() const noexcept
{
	return m_signal;
}

const char *shutdown_message::get_reason_string(reason_t r) noexcept
{
	switch(r)
	{
		case reason_t::host_signal: return "host_signal";
		case reason_t::requested: return "requested";
		default: return "unknown";
	}
}


submit_message::submit_message(nimrod::uuid uuid, const job_definition& job) :
	base_message<submit_message>(uuid),
	m_job(job)
{}

submit_message::submit_message(nimrod::uuid uuid, job_definition&& job) :
	base_message<submit_message>(uuid),
	m_job(std::move(job))
{}


const job_definition& submit_message::job() const noexcept
{
	return m_job;
}



update_message::update_message(nimrod::uuid uuid, nimrod::uuid job_uuid, const command_result& result, action_t action) :
	base_message<update_message>(uuid),
	m_job_uuid(job_uuid),
	m_result(result),
	m_action(action)
{}

nimrod::uuid update_message::job_uuid() const noexcept
{
	return m_job_uuid;
}

const command_result& update_message::result() const noexcept
{
	return m_result;
}

update_message::action_t update_message::action() const noexcept
{
	return m_action;
}
