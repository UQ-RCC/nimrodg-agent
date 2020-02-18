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

#include <string_view>
#include <variant>
#include <nim1/time.hpp>
#include <job_definition.hpp>
#include <process/command_result.hpp>
#include "agent_common.hpp"
#include "uuid.hpp"

namespace nimrod::net {

enum {
    PROTOCOL_VERSION = NIMRODG_VERSION_MAJOR
};

enum class message_type_t
{
	agent_init,
	agent_lifecontrol,
	agent_submit,
	agent_hello,
	agent_shutdown,
	agent_update,
	agent_ping,
	agent_pong
};

/*
** An abstract receivable "network message". This can be passed as an event.
*/
template<typename T>
class base_message
{
public:
	using message_base_type = base_message<T>;

	nimrod::uuid				uuid() const noexcept { return m_uuid; }
	constexpr uint32_t         	version() const noexcept { return PROTOCOL_VERSION; }
	constexpr message_type_t	type() const noexcept { return T::type_value; }
	nim1::nanotime_t			time() const noexcept { return m_time; }

protected:
	base_message(nimrod::uuid uuid, nim1::nanotime_t time) noexcept :
		m_uuid(uuid),
		m_time(time)
	{}

	friend class message_container;

private:
	nimrod::uuid m_uuid;
	nim1::nanotime_t m_time;
};



class hello_message : public base_message<hello_message>
{
public:
	constexpr static message_type_t type_value = message_type_t::agent_hello;

	hello_message(nimrod::uuid uuid, nim1::nanotime_t time, std::string_view queue);

	std::string_view queue() const noexcept;

private:
	std::string m_queue;
};

class init_message : public base_message<init_message>
{
public:
	constexpr static message_type_t type_value = message_type_t::agent_init;

	init_message() noexcept;
	explicit init_message(nimrod::uuid uuid, nim1::nanotime_t time) noexcept;
};

class lifecontrol_message : public base_message<lifecontrol_message>
{
public:
	constexpr static message_type_t type_value = message_type_t::agent_lifecontrol;

	enum class operation_t { terminate, cancel };
	lifecontrol_message(nimrod::uuid uuid, nim1::nanotime_t time, operation_t op);

	operation_t operation() const noexcept;
private:
	operation_t m_operation;
};


class shutdown_message : public base_message<shutdown_message>
{
public:
	constexpr static message_type_t type_value = message_type_t::agent_shutdown;

	enum class reason_t { host_signal, requested };
	shutdown_message(nimrod::uuid uuid, nim1::nanotime_t time, reason_t reason, int signal) noexcept;

	reason_t reason() const noexcept;
	int signal() const noexcept;

private:
	reason_t m_reason;
	int m_signal;
};


class submit_message : public base_message<submit_message>
{
public:
	constexpr static message_type_t type_value = message_type_t::agent_submit;

	submit_message(nimrod::uuid uuid, nim1::nanotime_t time, const job_definition& job);
	submit_message(nimrod::uuid uuid, nim1::nanotime_t time, job_definition&& job);

	const job_definition& job() const noexcept;

private:
	job_definition m_job;
};

class update_message : public base_message<update_message>
{
public:
	constexpr static message_type_t type_value = message_type_t::agent_update;

	enum class action_t { continue_, stop };

	update_message(nimrod::uuid uuid, nim1::nanotime_t time, nimrod::uuid job_uuid, const command_result& result, action_t action);

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
	constexpr static message_type_t type_value = message_type_t::agent_ping;

	explicit ping_message(nimrod::uuid uuid, nim1::nanotime_t time) noexcept;
};

class pong_message : public base_message<pong_message>
{
public:
	constexpr static message_type_t type_value = message_type_t::agent_pong;

	explicit pong_message(
		nimrod::uuid	uuid,
		nim1::nanotime_t		time,
		agent_state_t	state
	) noexcept;

	agent_state_t state() const noexcept;
private:
	agent_state_t m_state;
};

template <typename T>
constexpr std::optional<T> from_string(std::string_view s) noexcept = delete;

constexpr std::string_view to_string(message_type_t type)
{
	switch(type)
	{
		case message_type_t::agent_init:		return "agent.init";
		case message_type_t::agent_lifecontrol:	return "agent.lifecontrol";
		case message_type_t::agent_submit:		return "agent.submit";
		case message_type_t::agent_hello:		return "agent.hello";
		case message_type_t::agent_shutdown:	return "agent.shutdown";
		case message_type_t::agent_update:		return "agent.update";
		case message_type_t::agent_ping:		return "agent.ping";
		case message_type_t::agent_pong:		return "agent.pong";
		default: throw std::domain_error("message_type_t");
	}
}

template<>
constexpr std::optional<message_type_t> from_string<message_type_t>(std::string_view s) noexcept
{
	if(s == "agent.init")			return message_type_t::agent_init;
	if(s == "agent.lifecontrol")	return message_type_t::agent_lifecontrol;
	if(s == "agent.submit")			return message_type_t::agent_submit;
	if(s == "agent.hello")			return message_type_t::agent_hello;
	if(s == "agent.shutdown")		return message_type_t::agent_shutdown;
	if(s == "agent.update")			return message_type_t::agent_update;
	if(s == "agent.ping")			return message_type_t::agent_ping;
	if(s == "agent.pong")			return message_type_t::agent_pong;
									return std::optional<message_type_t>();
}



constexpr std::string_view to_string(lifecontrol_message::operation_t op)
{
	switch(op)
	{
		case lifecontrol_message::operation_t::cancel:		return "cancel";
		case lifecontrol_message::operation_t::terminate:	return "terminate";
		default: throw std::domain_error("lifecontrol_message::operation_t");
	}
}

template<>
constexpr std::optional<lifecontrol_message::operation_t> from_string<lifecontrol_message::operation_t>(std::string_view s) noexcept
{
	if(s == "terminate")	return lifecontrol_message::operation_t::terminate;
	if(s == "cancel")		return lifecontrol_message::operation_t::cancel;
							return std::optional<lifecontrol_message::operation_t>();
}




constexpr std::string_view to_string(shutdown_message::reason_t r)
{
	switch(r)
	{
		case shutdown_message::reason_t::host_signal:	return "hostsignal";
		case shutdown_message::reason_t::requested:		return "requested";
		default: throw std::domain_error("shutdown_message::reason_t");
	}
}

template<>
constexpr std::optional<shutdown_message::reason_t> from_string<shutdown_message::reason_t>(std::string_view s) noexcept
{
	if(s == "hostsignal")	return shutdown_message::reason_t::host_signal;
	if(s == "requested")	return shutdown_message::reason_t::requested;
							return std::optional<shutdown_message::reason_t>();
}



constexpr std::string_view to_string(command_type t)
{
	switch(t)
	{
		case command_type::onerror:		return "onerror";
		case command_type::redirect:	return "redirect";
		case command_type::copy:		return "copy";
		case command_type::exec:		return "exec";
		default: throw std::domain_error("command_type");
	}
}

template<>
constexpr std::optional<command_type> from_string<command_type>(std::string_view s) noexcept
{
	if(s == "onerror")	return command_type::onerror;
	if(s == "redirect")	return command_type::redirect;
	if(s == "copy")		return command_type::copy;
	if(s == "exec")		return command_type::exec;
						return std::optional<command_type>();
}


constexpr std::string_view to_string(onerror_command::action_t a)
{
	switch(a)
	{
		case onerror_command::action_t::fail:	return "fail";
		case onerror_command::action_t::ignore:	return "ignore";
		default: throw std::domain_error("onerror_command::action_t");
	}
}

template<>
constexpr std::optional<onerror_command::action_t> from_string<onerror_command::action_t>(std::string_view s) noexcept
{
	if(s == "fail")		return onerror_command::action_t::fail;
	if(s == "ignore")	return onerror_command::action_t::ignore;
						return std::optional<onerror_command::action_t>();
}


constexpr std::string_view to_string(redirect_command::stream_t s)
{
	switch(s)
	{
		case redirect_command::stream_t::stdout_:	return "stdout";
		case redirect_command::stream_t::stderr_:	return "stderr";
		default: throw std::domain_error("redirect_command::stream_t");
	}
}

template<>
constexpr std::optional<redirect_command::stream_t> from_string<redirect_command::stream_t>(std::string_view s) noexcept
{
	if(s == "stdout")	return redirect_command::stream_t::stdout_;
	if(s == "stderr")	return redirect_command::stream_t::stderr_;
						return std::optional<redirect_command::stream_t>();
}

constexpr std::string_view to_string(copy_command::context_t s)
{
	switch(s)
	{
		case copy_command::context_t::node:	return "node";
		case copy_command::context_t::root:	return "root";
		default: throw std::domain_error("copy_command::context_t");
	}
}

template<>
constexpr std::optional<copy_command::context_t> from_string<copy_command::context_t>(std::string_view s) noexcept
{
	if(s == "node")	return copy_command::context_t::node;
	if(s == "root")	return copy_command::context_t::root;
					return std::optional<copy_command::context_t>();
}


constexpr std::string_view to_string(update_message::action_t s)
{
	switch(s)
	{
		case update_message::action_t::continue_:	return "continue";
		case update_message::action_t::stop:		return "stop";
		default: throw std::domain_error("update_message::action_t");
	}
}

template<>
constexpr std::optional<update_message::action_t> from_string<update_message::action_t>(std::string_view s) noexcept
{
	if(s == "continue")	return update_message::action_t::continue_;
	if(s == "stop")		return update_message::action_t::stop;
						return std::optional<update_message::action_t>();
}


constexpr std::string_view to_string(command_result::result_status s)
{
	switch(s)
	{
		case command_result::result_status::success:				return "success";
		case command_result::result_status::precondition_failure:	return "precondition_failure";
		case command_result::result_status::system_error:			return "system_error";
		case command_result::result_status::exception:				return "exception";
		case command_result::result_status::aborted:				return "aborted";
		case command_result::result_status::failed:					return "failed";
		default: throw std::domain_error("command_result::result_status");
	}
}

template<>
constexpr std::optional<command_result::result_status> from_string<command_result::result_status>(std::string_view s) noexcept
{
	if(s == "success")				return command_result::result_status::success;
	if(s == "precondition_failure")	return command_result::result_status::precondition_failure;
	if(s == "system_error")			return command_result::result_status::system_error;
	if(s == "exception")			return command_result::result_status::exception;
	if(s == "aborted")				return command_result::result_status::aborted;
	if(s == "failed")				return command_result::result_status::failed;
									return std::optional<command_result::result_status>();
}


constexpr std::string_view to_string(agent_state_t s)
{
	switch(s)
	{
		case agent_state_t::waiting_for_init:	return "WAITING_FOR_INIT";
		case agent_state_t::idle:				return "IDLE";
		case agent_state_t::in_job:				return "IN_JOB";
		case agent_state_t::stopped:			return "STOPPED";
		default: throw std::domain_error("agent_state_t");
	}
}

template<>
constexpr std::optional<agent_state_t> from_string<agent_state_t>(std::string_view s) noexcept
{
	if(s == "WAITING_FOR_INIT")	return agent_state_t::waiting_for_init;
	if(s == "IDLE")				return agent_state_t::idle;
	if(s == "IN_JOB")			return agent_state_t::in_job;
	if(s == "STOPPED")			return agent_state_t::stopped;
								return std::optional<agent_state_t>();
}


}

#endif /* _NIMROD_MESSAGES_MESSAGES_HPP */
