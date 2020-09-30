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
#ifndef _NIM1_IP_HPP
#define _NIM1_IP_HPP

#include <memory>
#include <string_view>
#include <iosfwd>
#include <algorithm>
#include <clocale>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <amqp.h>

namespace nimrod::nim1 {

typedef struct amqp_property_info_s
{
	amqp_flags_t        flag;
	size_t              offset;
	bool                is_bytes;
	std::string_view    name;
} amqp_property_info_t;

extern const std::array<amqp_property_info_t, 13> propinfo;

struct hmac_ctx_deleter { void operator()(HMAC_CTX *ctx) const noexcept; };
using hmac_ctx_ptr = std::unique_ptr<HMAC_CTX, hmac_ctx_deleter>;

struct evp_md_ctx_deleter { void operator()(EVP_MD_CTX *ctx) const noexcept; };
using evp_md_ctx_ptr = std::unique_ptr<EVP_MD_CTX, evp_md_ctx_deleter>;

void lc_init();

std::string_view			bin2hex(char *s, const void *data, size_t n) noexcept;
const amqp_property_info_t	*find_property(std::string_view name) noexcept;
/* Find a table entry using a lowercase key. */
amqp_table_entry_t 			*find_entry_lc(std::string_view key, amqp_table_t *table, int offset);

/* TODO: Pulled from vsclib, need to add as proper dependency. */
template<
	typename V,
	typename CharT = char,
	typename InputIt = const CharT*,
	typename Traits = std::char_traits<CharT>,
	typename ViewT = std::basic_string_view<CharT, Traits>
>
static bool for_each_delim(InputIt begin, InputIt end, CharT delim, V&& proc)
{
	for(InputIt start = begin, next; start != end; start = next)
	{
		if((next = std::find(start, end, delim)))
		{
			if constexpr(std::is_same_v<std::decay_t<std::invoke_result_t<V, ViewT>>, void>)
				proc(ViewT(start, std::distance(start, next)));
			else if(!proc(ViewT(start, std::distance(start, next))))
				return false;

			if(next != end)
				++next;
		}
	}

	return true;
}

template<typename V>
bool for_each_delim(std::string_view input, char delim, V&& proc)
{
	return for_each_delim(input.begin(), input.end(), delim, proc);
}

}

#endif /* _NIM1_IP_HPP */
