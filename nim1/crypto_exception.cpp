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
#include <ostream>
#include <openssl/err.h>

#include <nim1/crypto_exception.hpp>

using namespace nimrod;
using namespace nimrod::nim1;

crypto_exception::crypto_exception(unsigned long err, const char *file, int line, const char *data, int flags) noexcept :
    m_err(err),
    m_file(file),
    m_data(data),
    m_lib(nullptr),
    m_reason(nullptr),
    m_func(nullptr),
    m_line(line)
{
    m_reason = ERR_reason_error_string(err);
    m_lib = ERR_lib_error_string(err);
    if((m_func = ERR_func_error_string(err)) == nullptr)
        m_func = "unknown function";

    if((flags & ERR_TXT_STRING) == 0)
        m_data = "";
}

crypto_exception crypto_exception::make_current() noexcept
{
    const char *file, *data;
    int line, flags;
    unsigned long err = ERR_peek_error_line_data(&file, &line, &data, &flags);
    return crypto_exception(err, file, line, data, flags);
}

std::ostream& nim1::operator<<(std::ostream& os, const crypto_exception& e)
{
    return os
        << e.lib()    << ":"
        << e.func()   << ":"
        << e.reason() << ":"
        << e.file()   << ":"
        << e.line()   << ":"
        << e.data();
}
