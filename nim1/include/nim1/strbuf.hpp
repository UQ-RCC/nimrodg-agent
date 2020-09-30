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
#ifndef _NIM1_STRBUF_HPP
#define _NIM1_STRBUF_HPP

#include <streambuf>

namespace nimrod::nim1 {

/*
 * I wanted to call this stringbuf, but that's taken.
 * Can't use std::stringbuf because it doesn't allow direct access
 * to the string.
 */
class strbuf : public std::streambuf
{
public:
    explicit strbuf(std::string *s = nullptr) noexcept;

    std::string *string() const noexcept { return s_; }
    void string(std::string *s) noexcept { s_ = s; }

    std::streamsize  xsputn(const char_type *s, std::streamsize n) override;
    int_type         overflow(int_type c) override;

private:
    std::string *s_;
};

}
#endif /* _NIM1_STRBUF_HPP */
