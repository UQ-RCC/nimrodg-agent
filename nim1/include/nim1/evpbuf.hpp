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
#ifndef _NIM1_EVPBUF_HPP
#define _NIM1_EVPBUF_HPP

#include <streambuf>
#include <openssl/evp.h>

namespace nimrod::nim1 {

class evpbuf : public std::streambuf
{
public:
    explicit evpbuf(EVP_MD_CTX *ctx = nullptr) noexcept;

    EVP_MD_CTX *ctx() const noexcept { return ctx_; }
    void ctx(EVP_MD_CTX *ctx) noexcept { ctx_ = ctx; }

    std::streamsize  xsputn(const char_type *s, std::streamsize n) override;
    int_type         overflow(int_type c) override;
    void             reset(const EVP_MD *evp);
    void             digest(unsigned char *buf, unsigned int *n);
    std::string_view hexdigest(char *hd, unsigned int *hd_len = nullptr);

private:
    EVP_MD_CTX *ctx_;
};

}

#endif /* _NIM1_EVPBUF_HPP */
