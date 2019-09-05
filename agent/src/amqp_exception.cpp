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
#include "agent_common.hpp"
#include "amqp_exception.hpp"
#include <amqp.h>

using namespace nimrod;

const char *amqp_exception::what() const noexcept { return m_reply.c_str(); }

const std::string& amqp_exception::reply() const noexcept { return m_reply; }

int amqp_exception::code() const noexcept { return m_code; }

amqp_exception::error_type_t amqp_exception::error_type() const noexcept { return m_error_type; }

uint16_t amqp_exception::class_id() const noexcept { return m_class_id; }

uint16_t amqp_exception::method_id() const noexcept { return m_method_id; }

bool amqp_exception::is_timeout() const noexcept { return m_error_type == error_type_t::library && m_code == AMQP_STATUS_TIMEOUT; }

amqp_exception amqp_exception::from_rpc_reply(const amqp_rpc_reply_t& r)
{
	/* Ref: https://github.com/akalend/amqpcpp/blob/master/src/AMQPException.cpp */
	if(r.reply_type == AMQP_RESPONSE_LIBRARY_EXCEPTION)
	{
		return amqp_exception(
			r.library_error ? amqp_error_string2(r.library_error) : "end-of-stream",
			r.library_error,
			error_type_t::library,
			0,
			0
		);
	}

	if(r.reply_type == AMQP_RESPONSE_SERVER_EXCEPTION)
	{
		if(r.reply.id == AMQP_CONNECTION_CLOSE_METHOD)
			return from_connection_close(*reinterpret_cast<amqp_connection_close_t*>(r.reply.decoded));
		else if(r.reply.id == AMQP_CHANNEL_CLOSE_METHOD)
			return from_channel_close(*reinterpret_cast<amqp_channel_close_t*>(r.reply.decoded));
	}

	throw std::runtime_error("invalid amqp rpc result reply type");
}

amqp_exception amqp_exception::from_channel_close(const amqp_channel_close_t& info)
{
	return amqp_exception(
		amqp_bytes_to_string(info.reply_text),
		info.reply_code,
		error_type_t::channel,
		info.class_id,
		info.method_id
	);
}

amqp_exception amqp_exception::from_connection_close(const amqp_connection_close_t& info)
{
	return amqp_exception(
		amqp_bytes_to_string(info.reply_text),
		info.reply_code,
		error_type_t::connection,
		info.class_id,
		info.method_id
	);
}

void amqp_exception::throw_if_bad(const amqp_rpc_reply_t& r)
{
	if(r.reply_type != AMQP_RESPONSE_NORMAL)
		throw from_rpc_reply(r);
}

amqp_exception::amqp_exception(std::string&& reply, int code, error_type_t type, uint16_t c, uint16_t m) :
	m_reply(std::move(reply)),
	m_code(code),
	m_error_type(type),
	m_class_id(c),
	m_method_id(m)
{}

std::ostream& nimrod::operator<<(std::ostream& os, const amqp_exception& e)
{
	if(e.error_type() == amqp_exception::error_type_t::library)
	{
		os << "AMQP Library Error " << e.code() << ": " << e.reply();
	}
	else
	{
		os << "AMQP " << (e.error_type() == amqp_exception::error_type_t::channel ? "Channel" : "Connection") << " Error "
			<< "(code=" << e.code() << ", class=" << e.class_id() << ", method=" << e.method_id() << "): " << e.reply();
	}

	return os;
}
