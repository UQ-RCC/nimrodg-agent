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
#ifndef _NIM1_CRYPTO_EXCEPTION_HPP
#define _NIM1_CRYPTO_EXCEPTION_HPP

#include <exception>
#include <iosfwd>

namespace nimrod::nim1 {

class crypto_exception : public std::exception
{
public:
    crypto_exception(unsigned long err, const char *file, int line, const char *data, int flags) noexcept;
    ~crypto_exception() noexcept override = default;

    const char *what() const noexcept override { return m_reason; }

    const char *file()   const noexcept { return m_file; }
    const char *data()   const noexcept { return m_data; };
    const char *lib()    const noexcept { return m_lib; };
    const char *reason() const noexcept { return m_reason; };
    const char *func()   const noexcept { return m_func; };

    int line() const noexcept { return m_line; }

    static crypto_exception make_current() noexcept;
private:
    unsigned long m_err;
    const char *m_file;
    const char *m_data;
    const char *m_lib;
    const char *m_reason;
    const char *m_func;
    int m_line;
};

std::ostream& operator<<(std::ostream& os, const crypto_exception& e);

}

#endif /* _NIM1_CRYPTO_EXCEPTION_HPP */
