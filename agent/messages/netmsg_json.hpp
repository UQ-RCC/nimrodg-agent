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
#ifndef _NIMROD_MESSAGES_NETMSG_JSON_HPP
#define _NIMROD_MESSAGES_NETMSG_JSON_HPP

#include "../json.hpp"
#include "netmsg.hpp"

namespace nimrod::net {

template<typename T>
struct enum_serialiser
{
	static T from_json(const nlohmann::json& j)
	{
		std::optional<T> t = nimrod::net::from_string<T>(j.get<std::string_view>());
		if(!t.has_value())
			throw std::domain_error("");

		return t.value();
	}

	static void to_json(nlohmann::json& j, const T& t)
	{
		j = nimrod::net::to_string(t);
	}
};

}

namespace nlohmann {

template<>
struct adl_serializer<nimrod::agent_state_t> :
	nimrod::net::enum_serialiser<nimrod::agent_state_t>{};

template<>
struct adl_serializer<nimrod::command_type> :
	nimrod::net::enum_serialiser<nimrod::command_type>{};

template<>
struct adl_serializer<nimrod::onerror_command::action_t> :
	nimrod::net::enum_serialiser<nimrod::onerror_command::action_t>{};

template<>
struct adl_serializer<nimrod::copy_command::context_t> :
	nimrod::net::enum_serialiser<nimrod::copy_command::context_t>{};

template<>
struct adl_serializer<nimrod::redirect_command::stream_t> :
	nimrod::net::enum_serialiser<nimrod::redirect_command::stream_t>{};

template<>
struct adl_serializer<nimrod::net::message_type_t> :
	nimrod::net::enum_serialiser<nimrod::net::message_type_t>{};

template<>
struct adl_serializer<nimrod::net::lifecontrol_message::operation_t> :
	nimrod::net::enum_serialiser<nimrod::net::lifecontrol_message::operation_t>{};

template<>
struct adl_serializer<nimrod::net::shutdown_message::reason_t> :
	nimrod::net::enum_serialiser<nimrod::net::shutdown_message::reason_t>{};

template<>
struct adl_serializer<nimrod::command_result::result_status> :
	nimrod::net::enum_serialiser<nimrod::command_result::result_status>{};

template<>
struct adl_serializer<nimrod::net::update_message::action_t> :
	nimrod::net::enum_serialiser<nimrod::net::update_message::action_t>{};


template<>
struct adl_serializer<nimrod::uuid>
{
	static nimrod::uuid from_json(const json& j);
	static void to_json(json& j, const nimrod::uuid& msg);
};

template<>
struct adl_serializer<nimrod::onerror_command>
{
	static nimrod::onerror_command from_json(const json& j);
	static void to_json(json& j, const nimrod::onerror_command& cmd);
};

template<>
struct adl_serializer<nimrod::redirect_command>
{
	static nimrod::redirect_command from_json(const json& j);
	static void to_json(json& j, const nimrod::redirect_command& msg);
};

template<>
struct adl_serializer<nimrod::copy_command>
{
	static nimrod::copy_command from_json(const json& j);
	static void to_json(json& j, const nimrod::copy_command& msg);
};

template<>
struct adl_serializer<nimrod::exec_command>
{
	static nimrod::exec_command from_json(const json& j);
	static void to_json(json& j, const nimrod::exec_command& msg);
};

template<>
struct adl_serializer<nimrod::command_union>
{
	static nimrod::command_union from_json(const json& j);
	static void to_json(json& j, const nimrod::command_union& msg);
};

template<>
struct adl_serializer<nimrod::job_definition>
{
	static nimrod::job_definition from_json(const json& j);
	static void to_json(json& j, const nimrod::job_definition& msg);
};

template<>
struct adl_serializer<nimrod::net::hello_message>
{
	static nimrod::net::hello_message from_json(const json& j);
	static void to_json(json& j, const nimrod::net::hello_message& msg);
};

template<>
struct adl_serializer<nimrod::net::init_message>
{
	static nimrod::net::init_message from_json(const json& j);
	static void to_json(json& j, const nimrod::net::init_message& msg);
};


template<>
struct adl_serializer<nimrod::net::lifecontrol_message>
{
	static nimrod::net::lifecontrol_message from_json(const json& j);
	static void to_json(json& j, const nimrod::net::lifecontrol_message& msg);
};

template<>
struct adl_serializer<nimrod::net::shutdown_message>
{
	static nimrod::net::shutdown_message from_json(const json& j);
	static void to_json(json& j, const nimrod::net::shutdown_message& msg);
};

template<>
struct adl_serializer<nimrod::net::submit_message>
{
	static nimrod::net::submit_message from_json(const json& j);
	static void to_json(json& j, const nimrod::net::submit_message& msg);
};


template<>
struct adl_serializer<nimrod::command_result>
{
	static nimrod::command_result from_json(const json& j);
	static void to_json(json& j, const nimrod::command_result& res);
};

template<>
struct adl_serializer<nimrod::net::update_message>
{
	static nimrod::net::update_message from_json(const json& j);
	static void to_json(json& j, const nimrod::net::update_message& msg);
};

template<>
struct adl_serializer<nimrod::net::ping_message>
{
	static nimrod::net::ping_message from_json(const json& j);
	static void to_json(json& j, const nimrod::net::ping_message& msg);
};

template<>
struct adl_serializer<nimrod::net::pong_message>
{
	static nimrod::net::pong_message from_json(const json& j);
	static void to_json(json& j, const nimrod::net::pong_message& msg);
};

template<>
struct adl_serializer<nimrod::net::message_container>
{
	static nimrod::net::message_container from_json(const json& j);
	static void to_json(json& j, const nimrod::net::message_container& msg);
};

}

#endif /* _NIMROD_MESSAGES_NETMSG_JSON_HPP */