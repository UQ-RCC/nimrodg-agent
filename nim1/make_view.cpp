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
#include <amqp.h>

#include <nim1/make_view.hpp>

using namespace nimrod;

std::string_view nim1::make_view(const char *b, const char *e) noexcept
{
	if(b == nullptr || e == nullptr)
		return "";

	return std::string_view(b, static_cast<size_t>(std::distance(b, e)));
}

std::string_view nim1::make_view(const amqp_bytes_t& b) noexcept
{
	return std::string_view(static_cast<const char*>(b.bytes), b.len);
}

std::string_view nim1::make_view(const std::string& s, size_t pos, size_t count)
{
	return std::string_view(s).substr(pos, count);
}