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
#ifndef _NIM1_LC_HPP
#define _NIM1_LC_HPP

#include <clocale>
#include <memory>

#include <nim1/nim1.hpp>

namespace nimrod::nim1::lc {

struct locale_deleter { void operator()(locale_t l) const noexcept; };
using locale_ptr = std::unique_ptr<std::remove_pointer_t<locale_t>, locale_deleter>;

locale_t locale() noexcept;

}

#endif /* _NIM1_LC_HPP */