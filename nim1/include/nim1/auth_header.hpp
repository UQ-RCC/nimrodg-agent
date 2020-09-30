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
#ifndef _NIM1_AUTH_HEADER_HPP
#define _NIM1_AUTH_HEADER_HPP

#include <ctime>
#include <string_view>

namespace nimrod::nim1 {

/* Auth header components. */
struct auth_header_t
{
    std::string_view	algorithm;
    std::string_view    credential;
    std::string_view    access_key;
    std::string_view    timestamp;
    std::string_view    nonce;
    std::string_view    appid;
    std::string_view    signed_props;
    std::string_view    signed_headers;
    std::string_view    signature;

    /* Convenience fields, not used for equality. */
    struct tm           _tm{};
    time_t              _time;
    uint64_t            _nonce{};

    bool operator==(const auth_header_t &other) const noexcept;

    static bool parse(std::string_view s, auth_header_t& hdr);
};

}

#endif /* _NIM1_AUTH_HEADER_HPP */
