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
#ifndef _NIM1_MAKE_VIEW_HPP
#define _NIM1_MAKE_VIEW_HPP

#include <string_view>

struct amqp_bytes_t_;
typedef struct amqp_bytes_t_ amqp_bytes_t;

namespace nimrod::nim1 {

std::string_view make_view(const char *b, const char *e) noexcept;
std::string_view make_view(const amqp_bytes_t& b) noexcept;
std::string_view make_view(const std::string& s, size_t pos = 0, size_t count = std::string_view::npos);

}

#endif /* _NIM1_MAKE_VIEW_HPP */