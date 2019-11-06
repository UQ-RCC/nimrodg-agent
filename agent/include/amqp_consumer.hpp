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
#ifndef _NIMRODG_AGENT_AGENT_HPP
#define _NIMRODG_AGENT_AGENT_HPP

#include <cstdint>
#include <vector>
#include <list>
#include <map>
#include <queue>
#include <future>
#include <string_view>
#include "threading.hpp"
#include <amqp.h>
#include "amqp_exception.hpp"
#include "messages/netmsg.hpp"

namespace nimrod {
class amqp_consumer
{
public:
	enum class send_result_t { none, ack, returned };

	amqp_consumer(
		amqp_connection_state_t conn,
		amqp_channel_t channel,
		std::string_view user,
		std::string_view routing_key,
		std::string_view direct
	);
	amqp_consumer(const amqp_consumer&) = delete;
	amqp_consumer(amqp_consumer&&) noexcept = delete;
	~amqp_consumer() noexcept;

	amqp_consumer& operator=(const amqp_consumer&) = delete;
	amqp_consumer& operator=(amqp_consumer&&) noexcept = delete;

	std::future<send_result_t> send_message(const net::message_container& msg, bool ack = false);
	std::future<net::message_container> get_message();

	std::string_view queue_name() const noexcept;

	void onactivity();

	int getsockfd();

	/*
	** Break any outstanding promises for messages.
	*/
	void clear_waiting();
private:

	void write_message(const net::message_container& msg);

	void read_proc();

	amqp_connection_state_t m_connection;
	amqp_channel_t m_channel;

	std::string_view m_user;
	std::string_view m_routing_key;
	std::string_view m_direct;

	std::string m_queue_name;

	struct msgstate
	{
		net::message_container message;
		bool need_ack;
		/* TODO: Move these into a shared pool and have m_messages store a pointer */
		std::promise<send_result_t> promise;
		send_result_t state;
	};

	/* Mutex on m_send_queue */
	std::mutex m_map_mutex;
	using queue_t = std::queue<msgstate>;
	queue_t m_send_queue;

	std::list<msgstate> m_messages;

	/* Mutex on m_recv_promises and m_recv_empty. */
	std::mutex m_recv_mutex;
	/* Storing messages that no one's asked for yet. */
	std::list<std::promise<net::message_container>> m_recv_promises;
	/* Stores promises that expect a message. */
	std::list<std::promise<net::message_container>> m_recv_empty;

	uint64_t m_last_delivery_tag;
};

}
#endif /* _NIMRODG_AGENT_AGENT_HPP */
