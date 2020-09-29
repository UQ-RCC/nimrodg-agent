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

#include <cassert>
#include <system_error>

#include <nim1/lc.hpp>

#include "nim1_ip.hpp"

using namespace nimrod;
using namespace nimrod::nim1;
using namespace nimrod::nim1::lc;

void lc::locale_deleter::operator()(locale_t l) const noexcept { freelocale(l); }

static locale_ptr _posix_locale;

void nim1::lc_init()
{
    if(_posix_locale)
        return;

    _posix_locale.reset(newlocale(LC_ALL_MASK, "POSIX", nullptr));

    if(!_posix_locale)
        throw std::system_error(errno, std::system_category());
}

locale_t lc::locale() noexcept
{
    return _posix_locale.get();
}

int lc::tolower(int c) noexcept
{
    assert(_posix_locale);
    return ::tolower_l(c, _posix_locale.get());
}

int lc::stricmp(const char *_l, const char *_r) noexcept
{
    const unsigned char *l = reinterpret_cast<const unsigned char *>(_l);
    const unsigned char *r = reinterpret_cast<const unsigned char *>(_r);
    for(; *l && *r && (*l == *r || tolower(*l) == tolower(*r)); l++, r++);
    return tolower(*l) - tolower(*r);
}


/* From https://git.musl-libc.org/cgit/musl/tree/src/string/strncmp.c */
int lc::strnicmp(const char *_l, const char *_r, size_t n) noexcept
{
    const unsigned char *l = reinterpret_cast<const unsigned char *>(_l);
    const unsigned char *r = reinterpret_cast<const unsigned char *>(_r);
    if(!n--) return 0;
    for(; *l && *r && n && tolower(*l) == tolower(*r); l++, r++, n--);
    return *l - *r;
}