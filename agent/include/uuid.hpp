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
#ifndef _NIMROD_UUID_HPP
#define _NIMROD_UUID_HPP

#include "config.h"

#include <iosfwd>
#include <uuid/uuid.h>

namespace nimrod {

struct uuid
{
	constexpr static size_t string_length = 36;
	using uuid_string_type = char[string_length + 1];

	uuid() noexcept;
	explicit uuid(uuid_t u) noexcept;
	uuid(const uuid&) noexcept = default;
	uuid(uuid&&) noexcept = default;
	explicit uuid(std::string_view s);

	uuid& operator=(uuid_t u) noexcept;
	uuid& operator=(const uuid&) noexcept = default;
	uuid& operator=(uuid&&) noexcept = default;
	uuid& operator=(std::string_view s);

	std::string str() const;
	size_t str(char *buf, size_t size) const;

	bool operator==(const uuid& u) const noexcept;
	bool operator!=(const uuid& u) const noexcept;

private:
	uuid_t m_uuid;
};


static_assert(sizeof(uuid) == sizeof(uuid_t), "sizeof(uuid) != sizeof(uuid_t)");

std::ostream& operator<<(std::ostream& os, const uuid& u);

}

#endif /* _NIMROD_UUID_HPP */