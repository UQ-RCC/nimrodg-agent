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
#ifndef _NIMROD_AGENT_HPP
#define _NIMROD_AGENT_HPP

#include <utility>
#include <variant>
#include <fmt/printf.h>
#include <unordered_map>
#include "uuid.hpp"
#include "event.hpp"
#include "blockingconcurrentqueue.h"
#include "amqp_consumer.hpp"
#include "process/procman.hpp"
#include "agent_common.hpp"
#include "transfer.hpp"
#include "rearmable_event.hpp"

namespace nimrod {

using event_variant = std::variant<
	interrupt_event,
	amqp_error_event,
	network_message,
	child_event,
	watchdog_event,
	message_event
>;

using event_union = event_variant;

class agent
{
public:

	agent(uuid uu, const filesystem::path& workRoot, const string_map_t& env);

	void submit_event(const event_union& evt);
	void submit_event(event_union&& evt);

	template <typename... Args>
	void log_message(log::level_t level, const char *label, const std::string& fmt, Args&&... args)
	{
		return submit_event(message_event(level, label, fmt::sprintf(fmt, args...)));
	}

	void log_message(log::level_t level, const char *label, const std::string& msg)
	{
		return log_message(level, label, "%s", msg);
	}

	void run();
	void set_amqp(amqp_consumer *amqp, txman *tx);

	nimrod::uuid get_uuid() const noexcept;

	agent_state_t state() const noexcept;

	bool nohup() const noexcept;
	void nohup(bool b) noexcept;

private:
	using queue = moodycamel::BlockingConcurrentQueue<event_union>;
	using send_future = std::future<amqp_consumer::send_result_t>;

	send_future send_message(net::message_container&& msg, bool ack = false);
	send_future send_shutdown_requested(bool ack = false);
	send_future send_shutdown_signal(int signal, bool ack = false);
	send_future send_update(const uuid& job_uuid, const command_result& res, net::update_message::action_t action, bool ack = false);
	send_future send_pong();

	void state(agent_state_t s) noexcept;

	bool operator()(const interrupt_event& evt);
	bool operator()(const amqp_error_event& evt);
	bool operator()(const network_message& msg);
	bool operator()(const child_event& msg);
	bool operator()(const watchdog_event& msg);
	bool operator()(const message_event& msg);

	void run_next_job();

	void _enqueue(event_union&& evt);

	agent_state_t m_state;
	bool m_nohup;
	amqp_consumer *m_amqp;
	txman *m_tx;
	queue m_queue;
	const filesystem::path m_work_root;

	uuid m_uuid;

	string_map_t m_environment;

	std::unique_ptr<procman> m_procman;
	std::future<void> m_proctask;

	bool _rev_pred();
	void _rev_proc(rearmable_event_result);
	rearmable_event_e m_termevent;
	std::atomic_bool m_proc_terminated;

	/* Defer an interrupt event */
	using deferred_event = std::variant<std::monostate, event_union>;
	void defer_event(const event_union& evt);
	deferred_event m_deferred_event;

	class visitor;
	friend class visitor;
};

std::ostream& operator<<(std::ostream& os, agent_state_t s);

}

#endif /* _NIMROD_AGENT_HPP */
