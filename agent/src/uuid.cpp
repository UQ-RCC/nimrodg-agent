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
#include <string>
#include <stdexcept>
#include <ostream>
#include <string.h>
#include "uuid.hpp"

using namespace nimrod;

uuid::uuid() noexcept
{
	uuid_generate(m_uuid);
}

uuid::uuid(uuid_t u) noexcept
{
	uuid_copy(m_uuid, u);
}

uuid::uuid(std::string_view s)
{
	if(s.size() != string_length)
		throw std::runtime_error("malformed uuid");

	/* FIXME: Use uuid_parse_range() when (if) it's merged. */
	uuid_string_type buf;
	strncpy(buf, s.data(), std::min(s.size(), string_length));
	buf[string_length] = '\0';

	if(uuid_parse(buf, m_uuid) < 0)
		throw std::runtime_error("malformed uuid");
}

uuid& uuid::operator=(uuid_t u) noexcept
{
	uuid_copy(m_uuid, u);
	return *this;
}

uuid& uuid::operator=(std::string_view s)
{
	this->operator=(uuid(s));
	return *this;
}

std::string uuid::str() const
{
	uuid_string_type out;
	str(out, sizeof(out));
	return out;
}

size_t uuid::str(char *buf, size_t size) const
{
	uuid_string_type out;
	uuid_unparse_lower(m_uuid, out);
	strncpy(buf, out, size);
	if(size < sizeof(uuid_string_type))
		buf[size - 1] = '\0';

	if(size >= sizeof(uuid_string_type))
		return sizeof(uuid_string_type);
	else
		return size;
}

bool uuid::operator==(const uuid& u) const noexcept
{
	return uuid_compare(m_uuid, u.m_uuid) == 0;
}

bool uuid::operator!=(const uuid& u) const noexcept
{
	return !(*this == u);
}

std::ostream& nimrod::operator<<(std::ostream& os, const uuid& u)
{
	uuid::uuid_string_type out;
	u.str(out, sizeof(out));
	return os << out;
}
