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
#include <sstream>
#include <iterator>
#include "nim1_ip.hpp"
#include <nim1/make_view.hpp>
#include <nim1/time.hpp>
#include <nim1/lc.hpp>
#include <nim1/crypto_exception.hpp>
#include <nim1/evpbuf.hpp>
#include <nim1/hmacbuf.hpp>
#include <nim1/strbuf.hpp>
#include <nim1/signature.hpp>

using namespace std::string_view_literals;
using namespace nimrod;
using namespace nimrod::nim1;

constexpr static std::string_view nim1_ = "NIM1"sv;

constexpr static const signature_algorithm_t signature_algorithms[] = {
    {nim1_hmac_null,   EVP_md_null},
    {nim1_hmac_sha224, EVP_sha224},
    {nim1_hmac_sha256, EVP_sha256},
    {nim1_hmac_sha384, EVP_sha384},
    {nim1_hmac_sha512, EVP_sha512},
};

const signature_algorithm_t *nim1::find_signature_algorithm(std::string_view name) noexcept
{
    for(const signature_algorithm_t& a : signature_algorithms) {
        if(a.name == name)
            return &a;
    }

    return nullptr;
}


/* Call proc() for all the properties we care about. */
template<typename F>
static void for_each_p(const amqp_basic_properties_t *props, F&& proc)
{
    size_t i = 0;
    for(const amqp_property_info_t& p : propinfo) {
        if(p.flag == AMQP_BASIC_HEADERS_FLAG || !(props->_flags & p.flag))
            continue;

        proc(p, i++);
    }
}

/* Call proc() for all the headers we care about (and are utf8). */
template<typename F>
static void for_each_h(const amqp_basic_properties_t *props, F&& proc)
{
    if(!(props->_flags & AMQP_BASIC_HEADERS_FLAG))
        return;

    for(int i = 0; i < props->headers.num_entries; ++i) {
        amqp_table_entry_t *t = props->headers.entries + i;

        if(t->value.kind != AMQP_FIELD_KIND_UTF8)
            continue;

        proc(t, i);
    }
}

/* Append canonical properties in the default order. */
static std::ostream& append_canonical_properties(std::ostream& os, const amqp_basic_properties_t *props)
{
    /* k_1:v_1\nk_2:v_2\n...k_n:v_n\n */
    for_each_p(props, [&os, props](const amqp_property_info_t& p, size_t i) {
        void *ptr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(props) + p.offset);

        os << p.name << ":"; /* p.name should already be lowercase */

        if(p.is_bytes)
            os << make_view(*reinterpret_cast<amqp_bytes_t*>(ptr));
        else if(p.flag == AMQP_BASIC_DELIVERY_MODE_FLAG || p.flag == AMQP_BASIC_PRIORITY_FLAG)
            os << static_cast<int>(*reinterpret_cast<uint8_t*>(ptr));
        else if(p.flag == AMQP_BASIC_TIMESTAMP_FLAG)
            os << *reinterpret_cast<uint64_t*>(ptr);

        os << "\n";
    });

    return os;
}

static std::ostream& append_signed_properties(std::ostream& os, const amqp_basic_properties_t *props)
{
    /* k_1;k_2;...;k_n */
    size_t kcount = 0;
    for_each_p(props, [&kcount](const amqp_property_info_t& p, size_t i) {
        ++kcount;
    });

    for_each_p(props, [kcount, &os](const amqp_property_info_t& p, size_t i) {
        os << p.name; /* p.name should already be lowercase */
        if(i != (kcount - 1))
            os << ";";
    });

    return os;
}

static std::ostream& append_canonical_headers(std::ostream& os, const amqp_basic_properties_t *props)
{
    /* k_1:v_1\nk_2:v_2\n...k_n:v_n\n */
    for_each_h(props, [&os](const amqp_table_entry_t *t, size_t i) {
        std::string_view key = make_view(t->key);
        std::transform(key.begin(), key.end(), std::ostream_iterator<char>(os), lc::tolower);
        os << ":" << make_view(t->value.value.bytes) << "\n";
    });
    return os;
}

static std::ostream& append_signed_headers(std::ostream& os, const amqp_basic_properties_t *props)
{
    /* k_1;k_2;...;k_n */
    size_t kcount = 0;
    for_each_h(props, [&kcount](const amqp_table_entry_t *t, size_t i) {
        ++kcount;
    });

    for_each_h(props, [&os, kcount](const amqp_table_entry_t *t, size_t i) {
        std::string_view key = make_view(t->key);
        std::transform(key.begin(), key.end(), std::ostream_iterator<char>(os), lc::tolower);
        if(i != (kcount - 1))
            os << ";";
    });

    return os;
}

static std::string_view make_view(const std::string& s, std::pair<size_t, size_t> range)
{
    return nim1::make_view(s.data() + range.first, s.data() + range.second);
}

auth_header_t nim1::build_auth_header(
    std::string& stor,
    const signature_algorithm_t *algorithm,
    std::string_view access_key,
    std::string_view secret_key,
    time_t t,
    uint64_t nonce,
    std::string_view appid,
    const amqp_basic_properties_t *props,
    std::string_view payload
)
{
    if(algorithm == nullptr)
        throw std::system_error(EINVAL, std::system_category());

    const EVP_MD *evp = algorithm->proc();

    /* Signing key */
    unsigned char skey[EVP_MAX_MD_SIZE];
    unsigned int slen;
    /* Temp storage for hex digests. */
    unsigned int hashlen;
    char _currhash[EVP_MAX_MD_SIZE * 2];
    iso8601_string_t _timestamp;

    hmac_ctx_ptr hmac(HMAC_CTX_new());
    if(!hmac)
        throw crypto_exception::make_current();

    evp_md_ctx_ptr md(EVP_MD_CTX_new());
    if(!md)
        throw crypto_exception::make_current();

    if(to_iso8601(nanotime_t::from_epoch(t), iso8601_format_t::basic, _timestamp) < 0)
        throw std::system_error(errno, std::system_category());

    std::string_view timestamp = _timestamp;

    /* iostreams are fun to abuse. */
    evpbuf evpio(md.get());
    hmacbuf hmacio(hmac.get());
    std::ostream os(&hmacio);

    /* Derive the signing key */
    {
        /* HMAC(HMAC(HMAC("NIM1" + secret, "YYYYMMDDTHHMMSSZ"), nonce), app_id) */
        unsigned char buf[EVP_MAX_MD_SIZE];

        /* The secret key should fit in skey. */
        if(secret_key.size() > sizeof(skey) - nim1_.size())
            throw std::system_error(ERANGE, std::system_category());

        std::copy(nim1_.begin(), nim1_.end(), skey);
        std::copy(secret_key.begin(), secret_key.end(), skey + nim1_.size());
        slen = static_cast<unsigned int>(secret_key.size() + nim1_.size());

        hmacio.reset(evp, skey, slen);
        os << timestamp << std::flush;
        hmacio.digest(buf, &slen);

        hmacio.reset(evp, buf, slen);
        os << nonce << std::flush;
        hmacio.digest(buf, &slen);

        hmacio.reset(evp, buf, slen);
        os << appid << std::flush;
        hmacio.digest(skey, &slen);
    }


    /* Hash the payload. */
    os.rdbuf(&evpio);
    evpio.reset(evp);
    os << payload << std::flush;
    evpio.hexdigest(_currhash, &hashlen);

    /* Build & hash the canonical request. */
    evpio.reset(evp);
    append_canonical_properties(os, props) << "\n";
    append_signed_properties(os, props)    << "\n";
    append_canonical_headers(os, props)    << "\n";
    append_signed_headers(os, props)       << "\n";
    os << std::string_view(_currhash, hashlen) << std::flush;
    evpio.hexdigest(_currhash, &hashlen);


    /* Build and HMAC the string-to-sign */
    os.rdbuf(&hmacio);
    hmacio.reset(evp, skey, slen);
    os << algorithm->name << "\n"
       << timestamp << "\n"
       << timestamp << "/" << nonce << "/" << appid << "\n"
       << std::string_view(_currhash, hashlen)
       << std::flush;
    hmacio.hexdigest(_currhash, &hashlen);

    nim1::strbuf strio(&stor);
    os.rdbuf(&strio);

    {
        /* This is messy, but it's efficient and it works. */
        auth_header_t hdr;
        stor.clear();

        /* The string may dynamically resize, so only store indices. */
        std::pair<size_t, size_t> range_algo;
        std::pair<size_t, size_t> range_cred;
        std::pair<size_t, size_t> range_access_key;
        std::pair<size_t, size_t> range_timestamp;
        std::pair<size_t, size_t> range_nonce;
        std::pair<size_t, size_t> range_appid;
        std::pair<size_t, size_t> range_signed_props;
        std::pair<size_t, size_t> range_signed_headers;
        std::pair<size_t, size_t> range_signature;

        /* Finally, build the header. */
        range_algo.first = stor.size();
        os << algorithm->name << std::flush;
        range_algo.second = stor.size();
        os << " Credential=" << std::flush;

        range_cred.first = stor.size();

        range_access_key.first = stor.size();
        os << access_key << std::flush;
        range_access_key.second = stor.size();

        os << "/" << std::flush;
        range_timestamp.first = stor.size();
        os << timestamp << std::flush;
        range_timestamp.second = stor.size();
        os << "/" << std::flush;
        range_nonce.first = stor.size();
        os << nonce << std::flush;
        range_nonce.second = stor.size();
        os << "/" << std::flush;
        range_appid.first = stor.size();
        os << appid << std::flush;
        range_appid.second = stor.size();
        range_cred.second = stor.size();

        hdr.credential = nim1::make_view(hdr.access_key.begin(), hdr.appid.end());

        os << ", SignedProperties=" << std::flush;
        range_signed_props.first = stor.size();
        append_signed_properties(os, props) << std::flush;
        range_signed_props.second = stor.size();
        os << ", SignedHeaders=" << std::flush;
        range_signed_headers.first = stor.size();
        append_signed_headers(os,props) << std::flush;
        range_signed_headers.second = stor.size();

        os << ", Signature=" << std::flush;
        range_signature.first = stor.size();
        os << std::string_view(_currhash, hashlen) << std::flush;
        range_signature.second = stor.size();

        hdr.algorithm      = ::make_view(stor, range_algo);
        hdr.credential     = ::make_view(stor, range_cred);
        hdr.access_key     = ::make_view(stor, range_access_key);
        hdr.timestamp      = ::make_view(stor, range_timestamp);
        hdr.nonce          = ::make_view(stor, range_nonce);
        hdr.appid          = ::make_view(stor, range_appid);
        hdr.signed_props   = ::make_view(stor, range_signed_props);
        hdr.signed_headers = ::make_view(stor, range_signed_headers);
        hdr.signature      = ::make_view(stor, range_signature);

        return hdr;
    }
}

static bool build_basic_properties(
    const auth_header_t *hdr,
    const amqp_basic_properties_t *inprops,
    amqp_basic_properties_t *outprops
) noexcept
{
    nanotime_t ts;

    *outprops = *inprops;
    outprops->_flags = 0;

    /* Only flag the specified ones. Bail if unknown ones are specified. */
    if(!for_each_delim(hdr->signed_props, ';', [&outprops](std::string_view hdr) {
        if(const amqp_property_info_t *p = find_property(hdr))
            return outprops->_flags |= p->flag, true;
        else
            return false;
    }))
        return false;

    /* No headers, we're done. */
    if((inprops->_flags & AMQP_BASIC_HEADERS_FLAG) == 0 || inprops->headers.num_entries == 0)
        return true;

    outprops->_flags |= AMQP_BASIC_HEADERS_FLAG;

    /*
     * Sort the table entries based on the order provided in the header.
     * This is fine to do in-place.
     */
    int i = 0;
    if(!for_each_delim(hdr->signed_headers, ';', [&i, &outprops](std::string_view key) {
        amqp_table_entry_t *te = find_entry_lc(key, &outprops->headers, i);
        if(te == nullptr)
            return false;

        std::swap(*te, outprops->headers.entries[i++]);
        return true;
    }))
        return false;

    outprops->headers.num_entries = i;
    return true;
}

bool nim1::verify_signature(
    std::string& stor,
    auth_header_t& hdr,
    std::string_view access_key,
    std::string_view secret_key,
    amqp_basic_properties_t *props,
    std::string_view payload
)
{
    return verify_signature(stor, nullptr, hdr, access_key, secret_key, props, payload);
}

bool nim1::verify_signature(
    std::string& stor,
    const signature_algorithm_t *algorithm,
    auth_header_t& hdr,
    std::string_view access_key,
    std::string_view secret_key,
    amqp_basic_properties_t *props,
    std::string_view payload
)
{
    amqp_table_entry_t *te;
    std::string_view header;
    amqp_basic_properties_t nprops;

    if(!(props->_flags & AMQP_BASIC_HEADERS_FLAG))
        return false; /* No headers */

    /* Find the authorization header. */
    if((te = find_entry_lc("authorization", &props->headers, 0)) == nullptr)
        return false;

    if(te->value.kind != AMQP_FIELD_KIND_UTF8)
        return false;

    header = make_view(te->value.value.bytes);

    if(!auth_header_t::parse(header, hdr))
        return false;

    /* If no algorithm given, use the one from the header. */
    if(algorithm == nullptr)
        algorithm = find_signature_algorithm(hdr.algorithm);

    if(algorithm == nullptr)
        return false;

    /* Check the message is using the same algorithm as we are. */
    if(algorithm->name != hdr.algorithm)
        return false;

    /*
     * Build an amqp_basic_properties_t with all unnecessary data stripped.
     * This may reorder the headers, but that doesn't matter.
     */
    if(!build_basic_properties(&hdr, props, &nprops))
        return false;

    return hdr == build_auth_header(stor, algorithm,
        access_key, secret_key,
        hdr._time, hdr._nonce, hdr.appid,
        &nprops, payload
    );
}
