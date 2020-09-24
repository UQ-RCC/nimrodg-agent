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
#ifndef _NIM1_TIME_HPP
#define _NIM1_TIME_HPP

#include <ctime>
#include <cstdint>
#include <string_view>

namespace nimrod::nim1 {

typedef struct nanotime_t {
    explicit operator time_t() const noexcept
    { return static_cast<time_t>(v / 1000000000ULL); }

    static nanotime_t from_epoch(time_t t) noexcept
    { return nanotime_t{t * 1000000000ULL}; }

    uint64_t v{0};
} nanotime_t;

nanotime_t current_time() noexcept;

enum class iso8601_format_t {
    basic,
    extended,
    extended_nanosec
};

using iso8601_string_t = char[32];

int to_iso8601(nanotime_t nt, iso8601_format_t fmt, iso8601_string_t iso) noexcept;
int parse_iso8601(const char *s, iso8601_format_t fmt, nanotime_t& nt) noexcept;
int parse_iso8601(std::string_view s, iso8601_format_t fmt, nanotime_t& nt) noexcept;

}

#endif /* _NIM1_TIME_HPP */
