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
#ifndef _NIM1_NIM1FWD_HPP
#define _NIM1_NIM1FWD_HPP

namespace nimrod::nim1 {

class crypto_exception;
class evpbuf;
class hmacbuf;
class strbuf;

struct auth_header_t;
typedef struct auth_header_t auth_header_t;

struct nanotime_t;
typedef struct nanotime_t nanotime_t;

/* This is opaque. */
struct signature_algorithm_t;
typedef struct signature_algorithm_t signature_algorithm_t;

}

#endif /* _NIM1_NIM1FWD_HPP */
