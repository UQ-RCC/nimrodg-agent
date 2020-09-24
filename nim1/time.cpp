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
#include <errno.h>
#include <cstdio>

#include <nim1/time.hpp>

using namespace nimrod;
using namespace nimrod::nim1;

nanotime_t nim1::current_time() noexcept
{
    struct timespec ts{};
    /* Will never fail with these arguments. */
    clock_gettime(CLOCK_REALTIME, &ts);

    return nanotime_t{ts.tv_sec * 1000000000ULL + ts.tv_nsec};
}

int nim1::to_iso8601(nanotime_t nt, iso8601_format_t fmt, iso8601_string_t iso) noexcept
{
    time_t sec = static_cast<time_t>(nt.v / 1000000000ULL);
    uint32_t nsec = static_cast<uint32_t>(nt.v % 1000000000ULL);

    struct tm tm{};
    gmtime_r(&sec, &tm);

    const char *fmts;
    switch(fmt) {
        case iso8601_format_t::basic:
            fmts = "%04d%02d%02dT%02d%02d%02dZ";
            break;
        case iso8601_format_t::extended:
            fmts = "%04d-%02d-%02dT%02d:%02d:%02dZ";
            break;
        case iso8601_format_t::extended_nanosec:
            fmts = "%04d-%02d-%02dT%02d:%02d:%02d.%uZ";
            break;
    }

    return snprintf(iso, sizeof(iso8601_string_t), fmts,
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        nsec
    );
}

int nim1::parse_iso8601(const char *s, iso8601_format_t fmt, nanotime_t& nt) noexcept
{
    struct tm tm{};
    size_t nano = 0;
    const char *fmts;
    int count, r, n;
    time_t t;

    switch(fmt) {
        case iso8601_format_t::basic:
            fmts = "%04d%02d%02dT%02d%02d%02dZ%n";
            count = 6;
            break;
        case iso8601_format_t::extended:
            fmts = "%04d-%02d-%02dT%02d:%02d:%02dZ%n";
            count = 6;
            break;
        case iso8601_format_t::extended_nanosec:
            fmts = "%04d-%02d-%02dT%02d:%02d:%02d.%uZ%n";
            count = 7;
            break;
    }

    r = sscanf(s, fmts,
        &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
        &tm.tm_hour, &tm.tm_min, &tm.tm_sec, &nano, &n);

    if(r < 0)
        return -1;

    if(r != count || s[n] != '\0') {
        errno = EINVAL;
        return -1;
    }

    tm.tm_year -= 1900;
    tm.tm_mon  -= 1;

    if((t = timegm(&tm)) == static_cast<time_t>(-1))
        return -1;

    nt.v = t * 1000000000ULL + nano;

    return 0;
}

int nim1::parse_iso8601(std::string_view s, iso8601_format_t fmt, nanotime_t& nt) noexcept
{
    /*
     * Due to scanf(), s needs to be NULL-terminated.
     * Make it so! A timestamp should easily fit on the stack.
     */
    iso8601_string_t tmp{};
    if(s.size() >= std::extent_v<iso8601_string_t>) {
        errno = EINVAL;
        return -1;
    }

    std::copy(s.begin(), s.end(), tmp);
    return parse_iso8601(tmp, fmt, nt);
}
