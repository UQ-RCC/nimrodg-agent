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
#include "agent_common.hpp"

using namespace nimrod;
using namespace nimrod::net;

hello_message::hello_message(nimrod::uuid uuid, nim1::nanotime_t time, std::string_view queue) :
	message_base_type(uuid, time),
	m_queue(queue)
{}

std::string_view hello_message::queue() const noexcept
{
	return m_queue;
}


init_message::init_message() noexcept :
	init_message(nimrod::uuid(), nim1::nanotime_t{0})
{}

init_message::init_message(nimrod::uuid uuid, nim1::nanotime_t time) noexcept :
	message_base_type(uuid, time)
{}


lifecontrol_message::lifecontrol_message(nimrod::uuid uuid, nim1::nanotime_t time, operation_t op) :
	message_base_type(uuid, time),
	m_operation(op)
{}

lifecontrol_message::operation_t lifecontrol_message::operation() const noexcept
{
	return m_operation;
}

shutdown_message::shutdown_message(nimrod::uuid uuid, nim1::nanotime_t time, reason_t reason, int signal) noexcept :
	message_base_type(uuid, time),
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


submit_message::submit_message(nimrod::uuid uuid, nim1::nanotime_t time, const job_definition& job) :
	message_base_type(uuid, time),
	m_job(job)
{}

submit_message::submit_message(nimrod::uuid uuid, nim1::nanotime_t time, job_definition&& job) :
	message_base_type(uuid, time),
	m_job(std::move(job))
{}


const job_definition& submit_message::job() const noexcept
{
	return m_job;
}



update_message::update_message(nimrod::uuid uuid, nim1::nanotime_t time, nimrod::uuid job_uuid, const command_result& result, action_t action) :
	message_base_type(uuid, time),
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

ping_message::ping_message(nimrod::uuid uuid, nim1::nanotime_t time) noexcept :
	message_base_type(uuid, time)
{}

pong_message::pong_message(
	nimrod::uuid uuid,
	nim1::nanotime_t time,
	agent_state_t state
) noexcept :
	message_base_type(uuid, time),
	m_state(state)
{}

agent_state_t pong_message::state() const noexcept
{
	return m_state;
}


log_message::log_message(nimrod::uuid uuid, nim1::nanotime_t time, log::level_t level,
                         const std::string& message) noexcept :
    message_base_type(uuid, time), m_level(level), m_message(message)
{}

log_message::log_message(nimrod::uuid uuid, nim1::nanotime_t time, log::level_t level,
                         std::string&& message) noexcept :
	message_base_type(uuid, time), m_level(level), m_message(std::move(message))
{}

log::level_t log_message::level() const noexcept
{
	return m_level;
}

const std::string& log_message::message() const noexcept
{
	return m_message;
}
