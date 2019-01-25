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
#include <cstdint>
#include <sstream>
#include "messages/netmsg.hpp"

using namespace nimrod;
using namespace nimrod::net;

const char *net::get_message_type_string(message_type type) noexcept
{
	switch(type)
	{
		case message_type::agent_init: return "agent.init";
		case message_type::agent_lifecontrol: return "agent.lifecontrol";
		case message_type::agent_query: return "agent.query";
		case message_type::agent_submit: return "agent.submit";
		case message_type::agent_hello: return "agent.hello";
		case message_type::agent_shutdown: return "agent.shutdown";
		case message_type::agent_update: return "agent.update";
		case message_type::agent_ping: return "agent.ping";
		case message_type::agent_pong: return "agent.pong";
	}

	return nullptr;
}

message_type message_container::type() const noexcept
{
	return std::visit([](auto&& m) { return m.type(); }, static_cast<const msg_union&>(*this));
}

nimrod::uuid message_container::uuid() const noexcept
{
	return std::visit([](auto&& msg) { return msg.uuid(); }, static_cast<const msg_union&>(*this));
}
