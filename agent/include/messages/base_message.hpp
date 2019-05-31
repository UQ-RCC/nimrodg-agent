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
#ifndef _NIMROD_MESSAGES_BASE_MESSAGE_HPP
#define _NIMROD_MESSAGES_BASE_MESSAGE_HPP

#include <ostream>
#include <variant>
#include "uuid.hpp"

namespace nimrod::net {

enum class message_type
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

class init_message;
class lifecontrol_message;
class submit_message;
class hello_message;
class shutdown_message;
class update_message;
class ping_message;
class pong_message;

using msg_union = std::variant<
	init_message,
	hello_message,
	lifecontrol_message,
	submit_message,
	shutdown_message,
	update_message,
	ping_message,
	pong_message
>;

class message_container;

const char *get_message_type_string(message_type type) noexcept;

/*
** An abstract receivable "network message". This can be passed as an event.
*/
template <typename T>
class base_message
{
public: 
	using message_base_type = base_message<T>;

	nimrod::uuid uuid() const noexcept { return m_uuid; }

	constexpr message_type type() const noexcept { return T::type_value; }

	const char *type_string() const noexcept { return get_message_type_string(this->type()); }

	explicit base_message(nimrod::uuid uuid) noexcept:
		m_uuid(uuid)
	{}

	friend class message_container;

private:
	nimrod::uuid m_uuid;
};

}
#endif /* _NIMROD_MESSAGES_BASE_MESSAGE_HPP */