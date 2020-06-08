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
#ifndef _AGENT_FWD_HPP
#define _AGENT_FWD_HPP

/* Forward Declarations */
#include <cstdio>
#include <memory>

/* I hate this, but our CI environment (GCC 7.2.0) doesn't like <filesystem> */
#if defined(_MSC_VER)
#	include <filesystem>
#	include <experimental/filesystem>
namespace nimrod { namespace filesystem = std::experimental::filesystem; }
#elif defined(__GNUC__)
#	if __GNUC__ >= 8
#		include <filesystem>
namespace nimrod { namespace filesystem = std::filesystem; }
#	else
#		include <experimental/filesystem>
namespace nimrod { namespace filesystem = std::experimental::filesystem; }
#	endif
#endif

#include "config.h"

#include <openssl/ossl_typ.h>

/* <uriparser/Uri.h> */
struct UriUriStructA;
typedef struct UriUriStructA UriUriA;

struct UriQueryListStructA;
typedef struct UriQueryListStructA UriQueryListA;

/* <curl/curl.h> */
typedef void CURL;
typedef void CURLM;
struct curl_slist;

/* <amqp.h> */
struct amqp_socket_t_;
typedef struct amqp_socket_t_ amqp_socket_t;

struct amqp_bytes_t_;
typedef struct amqp_bytes_t_ amqp_bytes_t;

struct amqp_connection_state_t_;
typedef struct amqp_connection_state_t_ *amqp_connection_state_t;

#include <nim1/nim1fwd.hpp>

namespace nimrod
{

struct deleter_uri { void operator()(UriUriA *uri) const noexcept; };
using uri_ptr = std::unique_ptr<UriUriA, deleter_uri>;

struct deleter_x509_store { void operator()(X509_STORE *ptr) const noexcept; };
using x509_store_ptr = std::unique_ptr<X509_STORE, deleter_x509_store>;

struct deleter_amqp_conn { void operator()(amqp_connection_state_t conn) const noexcept; };
using amqp_conn_ptr = std::unique_ptr<amqp_connection_state_t_, deleter_amqp_conn>;

struct deleter_cstdio { void operator()(FILE *f) const noexcept; };
using cstdio_ptr = std::unique_ptr<FILE, deleter_cstdio>;
using file_ptr = cstdio_ptr;

struct deleter_curl_multi { void operator()(CURLM *m) const noexcept; };
using curl_multi_ptr = std::unique_ptr<CURLM, deleter_curl_multi>;

enum class agent_state_t { waiting_for_init, idle, in_job, stopped };

class agent;
}

#endif /* _AGENT_FWD_HPP */