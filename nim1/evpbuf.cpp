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
#include "nim1_ip.hpp"
#include <nim1/evpbuf.hpp>
#include <nim1/crypto_exception.hpp>

using namespace nimrod::nim1;

evpbuf::evpbuf(EVP_MD_CTX *ctx) noexcept : ctx_(ctx)
{}

std::streamsize evpbuf::xsputn(const char_type *s, std::streamsize n)
{
    if(ctx_ == nullptr || n < 0)
        return 0;

    if(!EVP_DigestUpdate(ctx_, s, static_cast<size_t>(n)))
        throw crypto_exception::make_current();

    return n;
}

/* Not sure if this is right, but it seems to never be called :/ */
evpbuf::int_type evpbuf::overflow(int_type c)
{
    if(ctx_ == nullptr)
        return traits_type::eof();

    if(traits_type::eq_int_type(c, traits_type::eof()))
        return 0;

    char cc = static_cast<char>(c);
    if(!EVP_DigestUpdate(ctx_, &cc, 1))
        throw crypto_exception::make_current();

    return 0;
}

void evpbuf::reset(const EVP_MD *evp)
{
    if(ctx_ == nullptr)
        return;

    if(!EVP_MD_CTX_reset(ctx_))
        throw crypto_exception::make_current();

    if(!EVP_DigestInit_ex(ctx_, evp, nullptr))
        throw crypto_exception::make_current();
}

void evpbuf::digest(unsigned char *buf, unsigned int *n)
{
    if(!EVP_DigestFinal_ex(ctx_, buf, n))
        throw crypto_exception::make_current();
}

std::string_view evpbuf::hexdigest(char *hd, unsigned int *hd_len)
{
    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned int n = 0;

    this->digest(buf, &n);

    if(hd_len != nullptr)
        *hd_len = n * 2;

    bin2hex(hd, buf, n);
    return std::string_view(hd, n * 2);
}
