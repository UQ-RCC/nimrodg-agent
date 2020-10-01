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

#include <cinttypes>
#include <nim1/make_view.hpp>
#include <nim1/time.hpp>
#include <nim1/signature.hpp>
#include "log.hpp"
#include "agent_common.hpp"
#include "amqp_consumer.hpp"

using namespace std::string_view_literals;

using namespace nimrod;

/* Application Id. */
constexpr static std::string_view appid = "nimrod"sv;

static constexpr amqp_bytes_t make_bytes(std::string_view s) noexcept
{
	return amqp_bytes_t{ s.size(), const_cast<char*>(s.data()) };
}

/* For struct timeval */
#if defined(_WIN32)
#	include <winsock2.h>
#else
#	include <sys/time.h>
#endif

static struct timeval *build_timeout(float timeout, struct timeval *tv) noexcept
{
	if(timeout > 0)
	{
		tv->tv_sec = static_cast<long>(timeout);
		tv->tv_usec = static_cast<long>((timeout - tv->tv_sec) * 1000000);
		return tv;
	}

	return nullptr;
}

amqp_consumer::~amqp_consumer() noexcept
{
	if(m_connection != nullptr)
		amqp_channel_close(m_connection, m_channel, AMQP_REPLY_SUCCESS);
}


amqp_consumer::amqp_consumer(
	amqp_connection_state_t conn,
	amqp_channel_t channel,
	std::string_view user,
	std::string_view routing_key,
	std::string_view direct,
	std::string_view access_key,
	std::string_view secret_key,
	const nim1::signature_algorithm_t *signing_algorithm
) :
	m_connection(conn),
	m_channel(channel),
	m_user(user),
	m_routing_key(routing_key),
	m_direct(direct),
	m_access_key(access_key),
	m_secret_key(secret_key),
	m_signing_algorithm(signing_algorithm),
	m_last_delivery_tag(0)
{
	try
	{
		(void)amqp_channel_open(conn, channel);
		amqp_exception::throw_if_bad(conn);

		(void)amqp_confirm_select(conn, channel);
		amqp_exception::throw_if_bad(conn);

		amqp_queue_declare_ok_t *declare_ok = amqp_queue_declare(
			conn,
			channel,
			amqp_empty_bytes,	/* Let the server generate a name */
			0,					/* Active */
			0,					/* Non-durable */
			1,					/* Exclusive */
			1,					/* Auto-Delete */
			amqp_empty_table
		);
		amqp_exception::throw_if_bad(conn);

		assert(declare_ok != nullptr);

		m_queue_name = nim1::make_view(declare_ok->queue);
		amqp_bytes_t queue_bytes = make_bytes(m_queue_name);

		(void)amqp_queue_bind(
			conn,
			channel,
			queue_bytes,
			make_bytes(m_direct),
			queue_bytes,
			amqp_empty_table
		);
		amqp_exception::throw_if_bad(conn);

		/* Say that we want our messages asynchronously */
		(void)amqp_basic_consume(
			conn,
			channel,
			queue_bytes,
			amqp_empty_bytes,
			0,
			0,
			0,
			amqp_empty_table
		);
		amqp_exception::throw_if_bad(conn);
	}
	catch(...)
	{
		/* This is all we need to do, everything else should be auto-deleted. */
		amqp_channel_close(conn, channel, AMQP_INTERNAL_ERROR);
		throw;
	}
}

std::future<amqp_consumer::send_result_t> amqp_consumer::send_message(net::message_container&& msg, bool ack)
{
    msgstate state;
    state.message  = std::move(msg);
    state.need_ack = ack;
    state.state    = send_result_t::none;

	/* Keep this lock outside, we don't want the message begin sent until we've retrieved the future. */
	std::lock_guard<std::mutex> lock(m_map_mutex);
	auto future = state.promise.get_future();
	m_send_queue.push(std::move(state));
	return future;
}

std::future<net::message_container> amqp_consumer::get_message()
{
	std::lock_guard<std::mutex> l(m_recv_mutex);

	/* If we have held messages, just grab one. */
	if(!m_recv_promises.empty())
	{
		std::promise<net::message_container> p = std::move(m_recv_promises.front());
		m_recv_promises.pop_front();
		return p.get_future();
	}

	/* If there's no messages, create a new promise */
	m_recv_empty.emplace_back();
	return m_recv_empty.back().get_future();
}

std::string_view amqp_consumer::queue_name() const noexcept
{
	return m_queue_name;
}

static amqp_table_entry_t make_te(std::string_view key, std::string_view value) noexcept
{
    amqp_table_entry_t te{};
    te.key = make_bytes(key);
    te.value.kind = AMQP_FIELD_KIND_UTF8;
    te.value.value.bytes = make_bytes(value);
    return te;
}

void amqp_consumer::write_message(const net::message_container& msg)
{
	std::string s = net::message_write(msg);

	nim1::nanotime_t msgtime = msg.time();
	nim1::nanotime_t sendtime = nim1::current_time();

	nim1::iso8601_string_t sendstring;
	to_iso8601(sendtime, nim1::iso8601_format_t::extended_nanosec, sendstring);

	// https://github.com/alanxz/rabbitmq-c/blob/master/examples/amqp_sendstring.c
	amqp_basic_properties_t props;
	memset(&props, 0, sizeof(props));

	props._flags			= AMQP_BASIC_DELIVERY_MODE_FLAG
							| AMQP_BASIC_CONTENT_TYPE_FLAG
							| AMQP_BASIC_CONTENT_ENCODING_FLAG
							| AMQP_BASIC_TYPE_FLAG
							| AMQP_BASIC_TIMESTAMP_FLAG
							| AMQP_BASIC_USER_ID_FLAG
							| AMQP_BASIC_APP_ID_FLAG
							| AMQP_BASIC_MESSAGE_ID_FLAG
							| AMQP_BASIC_HEADERS_FLAG
							;

	props.delivery_mode		= 2;
	props.content_type		= make_bytes(net::message_content_type()); /* Same as HTTP "Content-Type" */
	props.content_encoding	= make_bytes("identity"); /* Same as HTTP "Content-Encoding" */
	props.type				= make_bytes(net::to_string(msg.type()));
	props.timestamp			= static_cast<uint64_t>(static_cast<time_t>(msgtime)); /* AMQP assumes this is in seconds. */
	props.user_id			= make_bytes(m_user);
	props.app_id			= make_bytes(appid);

	uuid u;
	uuid::uuid_string_type uuid_string;
	u.str(uuid_string, sizeof(uuid_string));

	props.message_id = make_bytes(std::string_view(uuid_string, uuid::string_length));

	/* Make sure these are sorted by code-point (if the keys were lowercase) */
	std::array<amqp_table_entry_t, 3> headers = {
		make_te("User-Agent",        g_compile_info.agent.user_agent),
		make_te("X-NimrodG-Sent-At", sendstring),
		/* Except this one, this one doesn't get sorted. */
		make_te("Authorization",     "")
	};

	/* The -1 is so build_auth_header() doesn't know about "Authorization". */
	props.headers.num_entries = headers.size() - 1;
	props.headers.entries     = headers.data();

	nim1::auth_header_t authhdr = nim1::build_auth_header(
		m_authhdr,
		m_signing_algorithm,
		m_access_key, m_secret_key, static_cast<time_t>(msgtime), 0, appid, &props, s
	);

	headers[props.headers.num_entries++] = make_te("Authorization", m_authhdr);

	int ret = amqp_basic_publish(
		m_connection,
		m_channel,
		make_bytes(m_direct),
		make_bytes(m_routing_key),
		1,	/* Mandatory */
		0,	/* Not immediate */
		&props,
		make_bytes(s)
	);

	assert(ret == 0);
	(void)ret;
}

void amqp_consumer::onactivity()
{
	read_proc();

	/* Try to send any pending messages. */
	{
		std::lock_guard<std::mutex> lock(m_map_mutex);

		while(!m_send_queue.empty())
		{
			auto u = std::move(m_send_queue.front());
			m_send_queue.pop();
			write_message(u.message);
			if(!u.need_ack)
				u.promise.set_value(send_result_t::ack);

			m_messages.emplace_back(std::move(u));
		}
	}
}

int amqp_consumer::getsockfd()
{
	return amqp_get_sockfd(m_connection);
}

static bool verify_message(const amqp_basic_properties_t *props, const nim1::auth_header_t& hdr, const net::message_container& msg)
{
	if(!(props->_flags & AMQP_BASIC_TIMESTAMP_FLAG))
		return false;

	if(props->timestamp != hdr._time)
		return false;

	if(props->timestamp != static_cast<time_t>(msg.time()))
		return false;

	if(!(props->_flags & AMQP_BASIC_APP_ID_FLAG))
		return false;

	if(nim1::make_view(props->app_id) != hdr.appid)
		return false;

	if(hdr.appid != appid)
		return false;

	return true;
}

/*
** Read a network message from the broker.
**
** This should *only* be used immediately after receiving a AMQP_BASIC_DELIVER_METHOD frame.
**
** Returns:
** -  1 on AMQP error
** -  0 on success
** - -1 if the backend couldn't parse the message
*/
int amqp_consumer::read_message(net::message_container& msg)
{
	amqp_message_t _msg;
	amqp_rpc_reply_t ret = amqp_read_message(m_connection, m_channel, &_msg, 0);

	if(ret.reply_type != AMQP_RESPONSE_NORMAL)
	{
		log::error("AMQPC", "Error reading message: %s", amqp_exception::from_rpc_reply(ret));
		return 1;
	}

	if(!(_msg.properties._flags & AMQP_BASIC_APP_ID_FLAG) || appid != nim1::make_view(_msg.properties.app_id))
		return 1;

	if(!(_msg.properties._flags & AMQP_BASIC_MESSAGE_ID_FLAG))
		return 1;

	uuid_t uuid;
	std::string_view uuids = nim1::make_view(_msg.properties.message_id);
	if(uuid_parse_range(uuids.begin(), uuids.end(), uuid) < 0)
		return 1;

	if(!(_msg.properties._flags & AMQP_BASIC_CONTENT_TYPE_FLAG))
		return 1;

	/* FIXME: Absolutely disgusting. */
	if("application/json; charset=UTF-8"sv != nim1::make_view(_msg.properties.content_type))
		return 1;

	if(!(_msg.properties._flags & AMQP_BASIC_TIMESTAMP_FLAG))
		return 1;

	nim1::auth_header_t hdr;
	if(!nim1::verify_signature(m_authhdr, m_signing_algorithm, hdr, m_access_key, m_secret_key, &_msg.properties, nim1::make_view(_msg.body)))
	{
		log::error("AMQPC", "Invalid message signature");
		return 1;
	}

	try
	{
		msg = net::message_read(reinterpret_cast<char*>(_msg.body.bytes), _msg.body.len);
	}
	catch(...)
	{
		log::error("AMQPC", "Error parsing network message.");
		amqp_destroy_message(&_msg);
		return -1;
	}

	if(!verify_message(&_msg.properties, hdr, msg))
	{
		log::error("AMQPC", "Message verification failed");
		return 1;
	}

	amqp_destroy_message(&_msg);
	return 0;
}

void amqp_consumer::read_proc()
{
	amqp_maybe_release_buffers(m_connection);

	struct timeval time{};
	struct timeval *tv = build_timeout(0.1f, &time);

	// TODO: This properly
	amqp_frame_t frame;
	int waitStat = amqp_simple_wait_frame_noblock(m_connection, &frame, tv);

	// waitStat has been seen as AMQP_STATUS_SSL_ERROR
	if(waitStat == AMQP_STATUS_TIMEOUT)
	{
		//log::debug("AMQPC", "amqp_simple_wait_frame() failed (timeout)");
		return;
	}

	if(waitStat != AMQP_STATUS_OK)
	{
		log::debug("AMQPC", "amqp_simple_wait_frame() failed, %s", amqp_error_string2(waitStat));
		return;
	}

	//log::debug("AMQPC", "frame_type = %s", amqp_constant_name(frame.frame_type));

	if(frame.frame_type == AMQP_FRAME_METHOD)
	{
		log::trace("AMQPC", "Received %s frame.", amqp_method_name(frame.payload.method.id));

		switch(frame.payload.method.id)
		{
			case AMQP_BASIC_ACK_METHOD:
			{
				amqp_basic_ack_t *ack = reinterpret_cast<amqp_basic_ack_t*>(frame.payload.method.decoded);

				/* Ignore old tags */
				if(ack->delivery_tag <= m_last_delivery_tag)
				{
					log::trace("AMQPC", "Ignoring basic.ack with old delivery tag %" PRIu64, ack->delivery_tag);
					break;
				}

				m_last_delivery_tag = ack->delivery_tag;

				/* Ack the oldest message (is there any other way to do this?) */
				std::lock_guard<std::mutex> lock(m_map_mutex);
				auto it = m_messages.begin();
				if(it == m_messages.end())
				{
					log::trace("AMQPC", "Rogue basic.ack, delivery tag %" PRIu64, ack->delivery_tag);
					break;
				}

				log::trace("AMQPC", "Message with delivery tag %" PRIu64, ack->delivery_tag);

				if(it->state != send_result_t::returned && it->need_ack)
				{
					it->promise.set_value(send_result_t::ack);
				}
				m_messages.erase(it);
				break;
			}
			case AMQP_BASIC_RETURN_METHOD:
			{
				//amqp_basic_return_t *ret = reinterpret_cast<amqp_basic_return_t*>(frame.payload.method.decoded);

				std::lock_guard<std::mutex> lock(m_map_mutex);
				auto it = m_messages.begin();
				if(it == m_messages.end())
				{
					log::trace("AMQPC", "Rogue basic.return");
					break;
				}

				it->state = send_result_t::returned;
				if(it->need_ack)
					it->promise.set_value(send_result_t::returned);
				/* Don't erase it, we're expecting an ack */
				//m_messages.erase(it);
				break;
			}
			case AMQP_BASIC_DELIVER_METHOD:
			{
				amqp_basic_deliver_t *del = reinterpret_cast<amqp_basic_deliver_t*>(frame.payload.method.decoded);

				net::message_container msg;
				int rstat = read_message(msg);
				if(rstat == 0)
				{
					std::lock_guard<std::mutex> l(m_recv_mutex);

					/* If we've got people waiting for a message, give it to them. */
					if(!m_recv_empty.empty())
					{
						m_recv_empty.front().set_value(std::move(msg));
						m_recv_empty.pop_front();
					}
					/* Otherwise, enqueue it. */
					else
					{
						m_recv_promises.emplace_back();
						m_recv_promises.back().set_value(std::move(msg));
					}

					// TODO: ERROR CHECK
					amqp_basic_ack(m_connection, frame.channel, del->delivery_tag, 0);
					// Good for testing:
					//amqp_basic_ack(m_connection, frame.channel, del->delivery_tag, 0);
				}
				else if(rstat < 0)
				{
					/* Invalid message payload, reject it. */
					// TODO: ERROR CHECK
					amqp_basic_reject(m_connection, frame.channel, del->delivery_tag, 0);

					// TODO: Will have to create a custom "NO" message, saying "I don't understand what you're telling me!"
					// If I receive 3 of these, die (or something).
				}
				break;
			}
			case AMQP_CHANNEL_CLOSE_METHOD:
				throw amqp_exception::from_channel_close(*reinterpret_cast<amqp_channel_close_t*>(frame.payload.method.decoded));
			case AMQP_CONNECTION_CLOSE_METHOD:
				throw amqp_exception::from_connection_close(*reinterpret_cast<amqp_connection_close_t*>(frame.payload.method.decoded));
			default:
				break;
		}
	}
}

void amqp_consumer::clear_waiting()
{
	m_recv_empty.clear();
}

