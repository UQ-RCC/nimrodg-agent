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
#include <openssl/rand.h>
#include "uuid.hpp"

using namespace nimrod;

uuid::uuid() noexcept
{
	int rc = RAND_bytes(m_uuid, sizeof(m_uuid));
	if(rc != 1)
		RAND_pseudo_bytes(m_uuid, sizeof(m_uuid));
}

uuid::uuid(uuid_t u) noexcept
{
	uuid_copy(m_uuid, u);
}

uuid::uuid(std::string_view s)
{
	if(uuid_parse_range(s.begin(), s.end(), m_uuid) < 0)
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

std::string uuid::str(int flags) const
{
	uuid_string_type out;
	str(out, sizeof(out), flags);
	return out;
}

size_t uuid::str(char *buf, size_t size, int flags) const
{
	char out[string_length + 1];
	size_t len = string_length;

	/* The util-linux patch was rejected, so we have to do it
	 * the slow way. */
	if(flags & UNPARSE_UPPER)
		uuid_unparse_upper(m_uuid, out);
	else
		uuid_unparse_lower(m_uuid, out);

	if(flags & UNPARSE_COMPACT)
	{
		/* Strip the dashes. */
		memmove(out + 23, out + 24, 36 - 24);
		memmove(out + 18, out + 19, 35 - 19);
		memmove(out + 13, out + 14, 34 - 14);
		memmove(out +  8, out +  9, 33 -  9);
		out[32] = '\0';
		len = 32;
	}

	strncpy(buf, out, size);
	if(size < len)
		buf[len - 1] = '\0';

	if(size >= len)
		return len;
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
