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
#ifndef _NIMROD_NETWORK_HPP
#define _NIMROD_NETWORK_HPP

#include "messages.hpp"

namespace nimrod::net {

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

class message_container : public msg_union
{
public:
	using msg_union::msg_union;
	using msg_union::operator=;

	message_type_t	type() const noexcept;
	nimrod::uuid	uuid() const noexcept;

	template <typename T, typename = std::enable_if_t<std::is_base_of_v<base_message<T>, T>>>
	const T& get() const { return std::get<T>(*this); }
};

//static_assert(sizeof(message_container) == sizeof(msg_union), "sizeof(message_container) != sizeof(msg_union)");

message_container message_read(const char *buffer, size_t size);
std::string message_write(const message_container& msg);

std::string_view message_content_type() noexcept;

std::ostream& operator<<(std::ostream& os, const message_container& msg);

}
#endif /* _NIMROD_NETWORK_HPP */