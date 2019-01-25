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

#ifndef _NIMROD_MESSAGES_MESSAGES_HPP
#define _NIMROD_MESSAGES_MESSAGES_HPP

#include "base_message.hpp"
#include "../process/command_result.hpp"

namespace nimrod::net {

class hello_message : public base_message<hello_message>
{
public:
	const static message_type type_value = message_type::agent_hello;

	hello_message(nimrod::uuid uuid, const std::string& queue);
	const std::string& queue() const noexcept;
private:
	std::string m_queue;
};

class init_message : public base_message<init_message>
{
public:
	const static message_type type_value = message_type::agent_init;

	init_message() noexcept;
	explicit init_message(nimrod::uuid uuid) noexcept;
};

class lifecontrol_message : public base_message<lifecontrol_message>
{
public:
	const static message_type type_value = message_type::agent_lifecontrol;

	enum class operation_t { terminate, cancel };
	lifecontrol_message(nimrod::uuid uuid, operation_t op);

	operation_t operation() const noexcept;

	static const char *get_operation_string(operation_t op) noexcept;
private:
	operation_t m_operation;
};


class shutdown_message : public base_message<shutdown_message>
{
public:
	const static message_type type_value = message_type::agent_shutdown;
	enum class reason_t { host_signal, requested };
	shutdown_message(nimrod::uuid agent_uuid, reason_t reason, int signal) noexcept;

	reason_t reason() const noexcept;
	int signal() const noexcept;

	static const char *get_reason_string(reason_t r) noexcept;

private:
	reason_t m_reason;
	int m_signal;
};


class submit_message : public base_message<submit_message>
{
public:
	const static message_type type_value = message_type::agent_submit;
	submit_message(nimrod::uuid uuid, const job_definition& job);
	submit_message(nimrod::uuid uuid, job_definition&& job);

	const job_definition& job() const noexcept;

private:
	job_definition m_job;
};

class update_message : public base_message<update_message>
{
public:
	const static message_type type_value = message_type::agent_update;
	enum class action_t { continue_, stop };

	update_message(nimrod::uuid uuid, nimrod::uuid job_uuid, const command_result& result, action_t action);

	nimrod::uuid job_uuid() const noexcept;
	const command_result& result() const noexcept;
	action_t action() const noexcept;

private:
	nimrod::uuid m_job_uuid;
	command_result m_result;
	action_t m_action;
};

class ping_message : public base_message<ping_message>
{
public:
	const static message_type type_value = message_type::agent_ping;
	using message_base_type::message_base_type;
};

class pong_message : public base_message<pong_message>
{
public:
	const static message_type type_value = message_type::agent_pong;
    using message_base_type::message_base_type;
};

}

#endif /* _NIMROD_MESSAGES_MESSAGES_HPP */