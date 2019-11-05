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
#define FMT_USE_WINDOWS_H 0
#include <fmt/format.h>
#include <fmt/ostream.h>
#include <ostream>

#include "messages/netmsg.hpp"
#include "messages/netmsg_json.hpp"

using namespace nimrod;
using namespace nimrod::net;

std::ostream& nimrod::net::operator<<(std::ostream& os, const message_container& msg)
{

	return std::visit([&os](auto&& m) -> std::ostream& {
		return os << fmt::format("{}({})", m.type_string(), nlohmann::json(m).dump());
	}, static_cast<const msg_union&>(msg));
}

std::ostream& nimrod::operator<<(std::ostream& os, const command_union& cmd)
{
	return os << nlohmann::json(cmd).dump();
}
