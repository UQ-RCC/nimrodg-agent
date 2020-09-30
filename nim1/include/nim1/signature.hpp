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
#ifndef _NIM1_SIGNATURE_HPP
#define _NIM1_SIGNATURE_HPP

#include <string_view>
#include <openssl/ossl_typ.h>
#include "nim1fwd.hpp"
#include "auth_header.hpp"

struct amqp_basic_properties_t_;
typedef struct amqp_basic_properties_t_ amqp_basic_properties_t;

namespace nimrod::nim1 {

using namespace std::string_view_literals;

/* Please, please only use this for debugging... */
constexpr static std::string_view nim1_hmac_null    = "NIM1-HMAC-NULL"sv;
constexpr static std::string_view nim1_hmac_sha224  = "NIM1-HMAC-SHA224"sv;
constexpr static std::string_view nim1_hmac_sha256  = "NIM1-HMAC-SHA256"sv;
constexpr static std::string_view nim1_hmac_sha384  = "NIM1-HMAC-SHA384"sv;
constexpr static std::string_view nim1_hmac_sha512  = "NIM1-HMAC-SHA512"sv;
constexpr static std::string_view default_algorithm = nim1_hmac_sha256;

typedef struct signature_algorithm_t
{
	std::string_view name;
	const EVP_MD  *(*proc)();
} signature_algorithm_t;

const signature_algorithm_t *find_signature_algorithm(std::string_view name) noexcept;

auth_header_t build_auth_header(
    std::string& stor,
    const signature_algorithm_t *algorithm,
    std::string_view access_key,
    std::string_view secret_key,
    time_t t,
    uint64_t nonce,
    std::string_view appid,
    const amqp_basic_properties_t *props,
    std::string_view payload
);

bool verify_signature(
    std::string& stor,
    auth_header_t& hdr,
    std::string_view access_key,
    std::string_view secret_key,
    amqp_basic_properties_t *props,
    std::string_view payload
);

}

#endif /* _NIM1_SIGNATURE_HPP */
