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
#include <nim1/strbuf.hpp>

using namespace nimrod::nim1;

strbuf::strbuf(std::string *s) noexcept : s_(s) {}

std::streamsize strbuf::xsputn(const char_type *s, std::streamsize n)
{
    if(s_ == nullptr || n < 0)
        return 0;

    s_->append(s, static_cast<size_t>(n));
    return n;
}

/* Not sure if this is right, but it seems to never be called :/ */
strbuf::int_type strbuf::overflow(int_type c)
{
    if(s_ == nullptr)
        return traits_type::eof();

    if(traits_type::eq_int_type(c, traits_type::eof()))
        return 0;

    s_->append(1, static_cast<char>(c));
    return 0;
}
