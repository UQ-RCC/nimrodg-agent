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
#ifndef _NIMROD_AMQP_EXCEPTION_HPP
#define _NIMROD_AMQP_EXCEPTION_HPP

#include <exception>
#include <string>

struct amqp_rpc_reply_t_;
typedef struct amqp_rpc_reply_t_ amqp_rpc_reply_t;

struct amqp_channel_close_t_;
typedef struct amqp_channel_close_t_ amqp_channel_close_t;

struct amqp_connection_close_t_;
typedef struct amqp_connection_close_t_ amqp_connection_close_t;

namespace nimrod
{

class amqp_exception : public std::exception
{
public:
	enum class error_type_t { none, library, connection, channel };

	amqp_exception(const amqp_exception&) = default;
	amqp_exception(amqp_exception&&) = default;

	amqp_exception& operator=(const amqp_exception&) = default;
	amqp_exception& operator=(amqp_exception&&) = default;

	const std::string& reply() const noexcept { return m_reply; }
	int code() const noexcept { return m_code; }
	error_type_t error_type() const noexcept { return m_error_type; }
	uint16_t class_id() const noexcept { return m_class_id; }
	uint16_t method_id() const noexcept { return m_method_id; }

	const char *what() const noexcept override { return m_reply.c_str(); }

	static amqp_exception from_rpc_reply(const amqp_rpc_reply_t& r);
	static amqp_exception from_channel_close(const amqp_channel_close_t& c);
	static amqp_exception from_connection_close(const amqp_connection_close_t& c);

	static void throw_if_bad(const amqp_rpc_reply_t& r);

private:
	amqp_exception(std::string_view reply, int code, error_type_t type, uint16_t c, uint16_t m);

	std::string m_reply;
	int m_code;
	error_type_t m_error_type;
	uint16_t m_class_id;
	uint16_t m_method_id;
};

std::ostream& operator<<(std::ostream& os, const amqp_exception& e);

}
#endif /* _NIMROD_AMQP_EXCEPTION_HPP */
