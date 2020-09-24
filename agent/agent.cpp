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

#include "config.h"

#include <vector>
#include <unordered_map>
#include <csignal>
#include "agent.hpp"
#include "agent_common.hpp"
#include "log.hpp"

using namespace nimrod;

agent::agent(uuid uu, const filesystem::path& workRoot, const string_map_t& env) :
	m_state(agent_state_t::waiting_for_init),
	m_nohup(false),
	m_amqp(nullptr),
	m_tx(nullptr),
	m_work_root(workRoot),
	m_uuid(uu),
	m_environment(env),
	m_termevent(std::bind(&agent::_rev_pred, this), std::bind(&agent::_rev_proc, this, std::placeholders::_1))
{}

void agent::submit_event(const event_union& evt)
{
	event_union u(evt);
	_enqueue(std::move(u));
}

void agent::submit_event(event_union&& evt)
{
	_enqueue(std::move(evt));
}

void agent::_enqueue(event_union&& evt)
{
	m_queue.enqueue(std::move(evt));
}

void agent::run()
{
	constexpr size_t event_cache_size = 32;
	event_union events[event_cache_size];

	for(;;)
	{
		size_t num = m_queue.wait_dequeue_bulk(events, event_cache_size);
		for(size_t i = 0; i < num; ++i)
		{
			bool exit = std::visit([this](auto&& evt) { return (*this)(evt); }, events[i]);
			if(exit)
				return;
		}
	}
}

void agent::set_amqp(amqp_consumer *amqp, txman *tx)
{
	m_amqp = amqp;
	m_tx = tx;
}

nimrod::uuid agent::get_uuid() const noexcept
{
	return m_uuid;
}

agent_state_t agent::state() const noexcept
{
	return m_state;
}

bool agent::nohup() const noexcept
{
	return m_nohup;
}

void agent::nohup(bool b) noexcept
{
	m_nohup = b;
}

bool agent::operator()(const interrupt_event& evt)
{
	/* Terminate request, just die. */
	if(evt.interrupt() == interrupt_event::interrupt_t::terminate)
		return true;

	assert(evt.interrupt() == interrupt_event::interrupt_t::interrupt);

#if !defined(SIGCHLD)
#	define SIGCHLD 18
#endif

#if !defined(SIGHUP)
#	define SIGHUP 1
#endif
	if(evt.signal() == SIGCHLD)
	{
		if(m_state != agent_state_t::in_job)
		{
			log::warn("AGENT", "Received child interrupt outside of job. Wut?");
		}
		m_procman->report_child_signal();
		return false;
	}

	if(evt.signal() == SIGHUP && this->nohup())
	{
		log::info("AGENT", "Ignoring Hangup...");
		return false;
	}

	switch(m_state)
	{
		case agent_state_t::in_job:
			if(!std::get_if<std::monostate>(&m_deferred_event))
			{
				/* Already have an interrupt, ignore. */
				return false;
			}
			this->defer_event(evt);
			m_procman->ask_meanly_to_exit();
			/* The child update processor will re-raise us once the process has been terminated. */
			return false;
		case agent_state_t::idle:
		case agent_state_t::waiting_for_init:
			send_shutdown_signal(evt.signal()).wait();
			break;
		case agent_state_t::stopped:
			return true; /* Should never happen, but whatever. */
	}

	this->state(agent_state_t::stopped);
	return true;
}

bool agent::operator()(const amqp_error_event& evt)
{
	/* Fatal network error, attempt cleanup. */
	if(m_state == agent_state_t::in_job)
	{
		this->defer_event(evt);
		m_procman->ask_meanly_to_exit();
		/* The child update processor will re-raise us once the process has been terminated. */
		return false;
	}

	this->state(agent_state_t::stopped);
	return true;
}

static bool is_valid_for_state(agent_state_t state, const net::message_type_t type)
{
	if(state == agent_state_t::stopped)
		return false;

	switch(type)
	{
		/* agent.hello, agent.shutdown, and agent.pong are outgoing messages */
		case net::message_type_t::agent_hello:
		case net::message_type_t::agent_shutdown:
		case net::message_type_t::agent_pong:
			return false;

		/* agent.lifecontrol is always valid. */
		case net::message_type_t::agent_lifecontrol:
			return true;

		case net::message_type_t::agent_ping:
			return true;

		default:
			break;
	}

	/* Now do state-specific checks */
	switch(state)
	{
		case agent_state_t::waiting_for_init:
			return type == net::message_type_t::agent_init;

		case agent_state_t::idle:
			return type == net::message_type_t::agent_submit;

		case agent_state_t::in_job:
			return false;

		default:
			break;
	}

	return false;
}

void agent::state(agent_state_t s) noexcept
{
	agent_state_t old = m_state;
	m_state = s;

	log::trace("AGENT", "State change from %s -> %s.", net::to_string(old), net::to_string(s));
}

bool agent::operator()(const network_message& _msg)
{
	using namespace nimrod::net;

	const message_container& msg = _msg.message();

	if(msg.uuid() != this->get_uuid())
	{
		log::warn("AGENT", "Rejecting message, has foreign UUID, rejecting...");
		return false;
	}

	if(!is_valid_for_state(m_state, msg.type()))
	{
		log::warn("AGENT", "Rejecting message, not valid for state, rejecting...");
		return false;
	}

	if(msg.type() == message_type_t::agent_ping)
	{
		this->send_pong();
		return false;
	}

	if(m_state == agent_state_t::waiting_for_init)
	{
		if(msg.type() == message_type_t::agent_init)
		{
			//auto& init = msg.get<init_message>();
			/* For future reference, any initialisation should go here. */
			this->state(agent_state_t::idle);
			return false;
		}
		else if(msg.type() == message_type_t::agent_lifecontrol)
		{
			/* This MUST be a termination, so just die. */
			return true;
		}
		else
		{
			throw std::logic_error("Bad state");
		}
	}
	else if(m_state == agent_state_t::idle)
	{
		if(msg.type() == message_type_t::agent_lifecontrol)
		{
			if(const lifecontrol_message& lf = msg.get<lifecontrol_message>(); lf.operation() == lifecontrol_message::operation_t::terminate)
			{
				send_shutdown_requested().wait();
				this->state(agent_state_t::stopped);
				return true;
			}
		}
		else if(msg.type() == message_type_t::agent_submit)
		{
			assert(m_state == agent_state_t::idle);

			auto& sub = msg.get<submit_message>();
			try
			{
				m_procman = std::make_unique<procman>(m_uuid, sub.job(), m_work_root, m_environment, m_tx);
			}
			catch(std::exception& e)
			{
				log::error("AGENT", "Interpreter initialisation failed: %s", e.what());
				this->send_update(sub.job().get_uuid(), command_result::make_precondition_failure(0, 0.0f, e.what()), update_message::action_t::stop);
				this->state(agent_state_t::idle);
				return false;
			}

			run_next_job();
		}
	}
	else if(m_state == agent_state_t::in_job)
	{
		if(msg.type() == message_type_t::agent_lifecontrol)
		{
			/*
			** If we've received a lifecontrol when we're in a job, defer the event
			** and kill the interpreter. The interpreter will submit a child event.
			**
			** If an event is deferred, the child handler will switch the state to idle
			** and re-raise the event.
			*/
			auto& lf = msg.get<lifecontrol_message>();
			this->defer_event(_msg);
			switch(lf.operation())
			{
				case lifecontrol_message::operation_t::cancel:
					log::info("AGENT", "Premature termination requested...");
					m_procman->ask_nicely_to_exit();
					m_proc_terminated = false;
					if(!m_termevent)
					{
						log::info("AGENT", "Watchdog inactive, rearming...");
						using namespace std::chrono_literals;
						m_termevent.rearm(5s);
					}
					else
					{
						log::info("AGENT", "Watchdog active, not rearming...");
					}
					return false;

				case lifecontrol_message::operation_t::terminate:
					/* Force quit job */
					m_termevent.abort();
					m_procman->ask_meanly_to_exit();
					return false;
			}
		}
		else
		{
			throw std::logic_error("Bad state");
		}
	}

	return false;
}

bool agent::_rev_pred()
{
	return m_proc_terminated;
}

void agent::_rev_proc(rearmable_event_result result)
{
	/* Don't do anything if we're successful or were aborted. */
	if(result == rearmable_event_result::success || result == rearmable_event_result::aborted)
		return;

	log::info("WATCH", "Watchdog timeout...");
	this->submit_event(watchdog_event());
}

void agent::run_next_job()
{
	if(m_procman->command_index() < m_procman->num_commands())
	{
		m_proctask = std::async(std::launch::async, [this]() { this->submit_event(child_event(m_procman->run())); });
		this->state(agent_state_t::in_job);
	}
	else
	{
		m_procman = nullptr;
		this->state(agent_state_t::idle);
	}
}

bool agent::operator()(const child_event& evt)
{
	using action_t = net::update_message::action_t;

	auto& result = evt.result();

	/* Cancel any pending force-exits. */
	m_proc_terminated = true;
	m_termevent.notify();

	log::error("AGENT", "Received child status update...");
	log::error("AGENT", "[%u] %s", result.index(), result);

	/* We've been asked to prematurely stop. There will be an event that's deferred, so raise it. */
	if(auto p = std::get_if<event_union>(&m_deferred_event))
	{
		command_result ares = command_result::make_abort(result.index(), result.time());
		this->send_update(m_procman->job_uuid(), ares, action_t::stop).wait();

		/* Reset to idle and re-raise the event. */
		m_procman = nullptr;
		this->state(agent_state_t::idle);
		std::visit([this](const auto& e) { this->submit_event(e); }, *p);
		m_deferred_event = std::monostate();
		return false;
	}

	/* This should never happen, but handle it just in case. */
	if(m_state != agent_state_t::in_job)
	{
		log::error("AGENT", "Invalid state for child update. Attempting to recover...");
		log::error("AGENT", "  If this happens often, please report this to the developers.");
		m_procman = nullptr;
		return false;
	}

	/*
	** First, check for a precondition failure. This is fatal, it means that the
	** master has sent a bad job.
	*/
	if(result.status() == command_result::result_status::precondition_failure)
	{
		log::error("AGENT", "[%u] Precondition failure, aborting job...", result.index());
		this->send_update(m_procman->job_uuid(), result, action_t::stop).get();
		m_procman = nullptr;
		this->state(agent_state_t::idle);
		return false;
	}

	action_t nextAction = result.index() < (m_procman->num_commands() - 1) ? action_t::continue_ : action_t::stop;

	/*
	** Anything that's not a precondition failure can safely be ignored.
	*/
	if(m_procman->error_policy() == onerror_command::action_t::ignore)
	{
		log::error("JOB", "[%u] Error policy is %s, ignoring result...", result.index(), m_procman->error_policy());
		this->send_update(m_procman->job_uuid(), result, nextAction).get();
		run_next_job();
		return false;
	}

	/* If the command was executed successfully, check it's return value and fail on nonzero. */
	if(result.status() == command_result::result_status::success && result.retval() == 0)
	{
		this->send_update(m_procman->job_uuid(), result, nextAction).get();
		run_next_job();
		return false;
	}

	/* Here we can abort the job if there's an error. */
	this->send_update(m_procman->job_uuid(), result, action_t::stop).get();
	m_procman = nullptr;
	this->state(agent_state_t::idle);
	return false;
}

bool agent::operator()(const watchdog_event& evt)
{
	log::info("AGENT", "Watchdog timeout, killing interpreter...");
	/* We timed out, force kill. */
	m_procman->ask_meanly_to_exit();
	return false;
}

bool agent::operator()(const message_event& evt)
{
	log::manual(evt.level(), evt.label().c_str(), "%s", evt.message());
	return false;
}

agent::send_future agent::send_message(net::message_container&& msg, bool ack)
{
	assert(m_amqp);
	return m_amqp->send_message(std::move(msg), ack);
}

agent::send_future agent::send_shutdown_requested(bool ack)
{
	return send_message(net::shutdown_message(this->m_uuid, net::shutdown_message::reason_t::requested, -1), ack);
}

agent::send_future agent::send_shutdown_signal(int signal, bool ack)
{
	return send_message(net::shutdown_message(this->m_uuid, net::shutdown_message::reason_t::host_signal, signal), ack);
}

agent::send_future agent::send_update(const uuid& job_uuid, const command_result& res, net::update_message::action_t action, bool ack)
{
	return send_message(net::update_message(this->m_uuid, job_uuid, res, action), ack);
}

agent::send_future agent::send_pong()
{
	return send_message(net::pong_message(this->m_uuid));
}

void agent::defer_event(const event_union& evt)
{
	m_deferred_event = evt;
}