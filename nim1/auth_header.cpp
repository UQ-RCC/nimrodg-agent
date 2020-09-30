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
#include <regex>
#include <charconv>
#include <nim1/make_view.hpp>
#include <nim1/auth_header.hpp>

using namespace nimrod::nim1;

bool auth_header_t::parse(std::string_view s, auth_header_t& hdr)
{
    /* This is gross, but I'm too tired to care. */
    static const std::regex AUTH_HEADER_PATTERN(
        R"((NIM1-[\w-]+)\s+Credential=(([\w]+)\/((\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z)\/(\d+)\/([\w]+)),\s*SignedProperties=([\w-;]+),\s*SignedHeaders=([\w-;]+),\s+Signature=([a-z0-9]*)$)",
        std::regex_constants::ECMAScript
    );

    std::match_results<std::string_view::const_iterator> m;

    if(!std::regex_match(s.begin(), s.end(), m, AUTH_HEADER_PATTERN))
        return false;

    hdr.algorithm	= make_view(m[ 1].first, m[ 1].second);
    hdr.credential 	= make_view(m[ 2].first, m[ 2].second);
    hdr.access_key 	= make_view(m[ 3].first, m[ 3].second);
    hdr.timestamp   = make_view(m[ 4].first, m[ 4].second);

    if(auto [p, ec] = std::from_chars<int>(m[ 5].first, m[ 5].second, hdr._tm.tm_year, 10); ec != std::errc())
        return false;

    hdr._tm.tm_year -= 1900;

    if(auto [p, ec] = std::from_chars<int>(m[ 6].first, m[ 6].second, hdr._tm.tm_mon, 10); ec != std::errc())
        return false;

    hdr._tm.tm_mon -= 1;

    if(auto [p, ec] = std::from_chars<int>(m[ 7].first, m[ 7].second, hdr._tm.tm_mday, 10); ec != std::errc())
        return false;

    if(auto [p, ec] = std::from_chars<int>(m[ 8].first, m[ 8].second, hdr._tm.tm_hour, 10); ec != std::errc())
        return false;

    if(auto [p, ec] = std::from_chars<int>(m[ 9].first, m[ 9].second, hdr._tm.tm_min, 10); ec != std::errc())
        return false;

    if(auto [p, ec] = std::from_chars<int>(m[10].first, m[10].second, hdr._tm.tm_sec, 10); ec != std::errc())
        return false;

    if(auto [p, ec] = std::from_chars<uint64_t>(m[11].first, m[11].second, hdr._nonce, 10); ec != std::errc())
        return false;

    if((hdr._time = timegm(&hdr._tm)) == static_cast<time_t>(-1))
        return false;

    hdr.nonce          = make_view(m[11].first, m[11].second);
    hdr.appid          = make_view(m[12].first, m[12].second);
    hdr.signed_props   = make_view(m[13].first, m[13].second);
    hdr.signed_headers = make_view(m[14].first, m[14].second);
    hdr.signature      = make_view(m[15].first, m[15].second);

    return true;
}

bool auth_header_t::operator==(const auth_header_t& other) const noexcept
{
    return algorithm      == other.algorithm      &&
           credential     == other.credential     &&
           access_key     == other.access_key     &&
           timestamp      == other.timestamp      &&
           nonce          == other.nonce          &&
           appid          == other.appid          &&
           signed_props   == other.signed_props   &&
           signed_headers == other.signed_headers &&
           signature      == other.signature;
}
