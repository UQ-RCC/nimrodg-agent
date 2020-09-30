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
#include <algorithm>
#include <nim1/lc.hpp>
#include <nim1/signature.hpp>
#include <nim1/nim1.hpp>
#include "nim1_ip.hpp"

using namespace std::string_view_literals;
using namespace nimrod;
using namespace nimrod::nim1;

void nim1::init()
{
    nim1::lc_init();
}

/*
 * The list of AMQP Basic Properties that can be used for signing.
 * Make sure these are sorted by code-point in name.
 */
const std::array<amqp_property_info_t, 13> nim1::propinfo = {{
        {AMQP_BASIC_APP_ID_FLAG,           offsetof(amqp_basic_properties_t, app_id),           true,  "app-id"sv},
        {AMQP_BASIC_CLUSTER_ID_FLAG,       offsetof(amqp_basic_properties_t, cluster_id),       true,  "cluster-id"sv},
        {AMQP_BASIC_CONTENT_ENCODING_FLAG, offsetof(amqp_basic_properties_t, content_encoding), true,  "content-encoding"sv},
        {AMQP_BASIC_CONTENT_TYPE_FLAG,     offsetof(amqp_basic_properties_t, content_type),     true,  "content-type"sv},
        {AMQP_BASIC_CORRELATION_ID_FLAG,   offsetof(amqp_basic_properties_t, correlation_id),   true,  "correlation-id"sv},
        {AMQP_BASIC_DELIVERY_MODE_FLAG,    offsetof(amqp_basic_properties_t, delivery_mode),    false, "delivery-mode"sv},
        {AMQP_BASIC_EXPIRATION_FLAG,       offsetof(amqp_basic_properties_t, expiration),       true,  "expiration"sv},
        /* Don't include these, are handled separately. */
        //{AMQP_BASIC_HEADERS_FLAG,          offsetof(amqp_basic_properties_t, headers),          false, "headers"sv},
        {AMQP_BASIC_MESSAGE_ID_FLAG,       offsetof(amqp_basic_properties_t, message_id),       true,  "message-id"sv},
        {AMQP_BASIC_PRIORITY_FLAG,         offsetof(amqp_basic_properties_t, priority),         false, "priority"sv},
        {AMQP_BASIC_REPLY_TO_FLAG,         offsetof(amqp_basic_properties_t, reply_to),         true,  "reply-to"sv},
        {AMQP_BASIC_TIMESTAMP_FLAG,        offsetof(amqp_basic_properties_t, timestamp),        false, "timestamp"sv},
        {AMQP_BASIC_TYPE_FLAG,             offsetof(amqp_basic_properties_t, type),             true,  "type"sv},
        {AMQP_BASIC_USER_ID_FLAG,          offsetof(amqp_basic_properties_t, user_id),          true,  "user-id"sv},
}};

void nim1::hmac_ctx_deleter::operator()(HMAC_CTX *ctx) const noexcept
{ HMAC_CTX_free(ctx); }

void nim1::evp_md_ctx_deleter::operator()(EVP_MD_CTX *ctx) const noexcept
{ EVP_MD_CTX_free(ctx); }

std::string_view nim1::bin2hex(char *s, const void *data, size_t n) noexcept
{
    constexpr static std::string_view characters = "0123456789abcdef"sv;

    char *start = s;
    for(size_t i = 0; i < n; ++i) {
        uint8_t c = reinterpret_cast<const uint8_t*>(data)[i];
        *start++ = characters[(c >> 4) & 0x0F];
        *start++ = characters[(c >> 0) & 0x0F];
    }

    return std::string_view(s, n * 2);
}

const amqp_property_info_t *nim1::find_property(std::string_view name) noexcept
{
    /* Yes, this is a linear search. No, I don't care. */
    for(const amqp_property_info_t& p : propinfo) {
        if(p.name == name)
            return &p;
    }

    return nullptr;
}

amqp_table_entry_t *nim1::find_entry_lc(std::string_view key, amqp_table_t *table, int offset)
{
    amqp_table_entry_t *start = table->entries + offset;
    amqp_table_entry_t *end = start + table->num_entries;

    amqp_table_entry_t *te = std::find_if(start, end, [&key](const amqp_table_entry_t& te) {
        std::string_view _key = make_view(te.key);

        return std::equal(_key.begin(), _key.end(), key.begin(), key.end(), [](char a, char b){
            return lc::tolower(a) == b;
        });
    });

    if(te == end)
        return nullptr;

    return te;
}
