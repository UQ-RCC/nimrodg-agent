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
#ifndef _NIMROD_EVENT_HPP
#define _NIMROD_EVENT_HPP

#include "messages/netmsg.hpp"
#include "process/procman.hpp"
#include "amqp_exception.hpp"
#include "log.hpp"

namespace nimrod {

enum class event_type_t
{
	none,
	system_interrupt,
	amqp_error,
	network_message,
	child_update,
	watchdog_timeout,
	message
};

/*
** An abstract "event". Events are sent to the agent for processing.
*/
class event
{
public:
	event(const event&) noexcept = default;
	event(event&&) noexcept = default;

	event& operator=(const event&) noexcept = default;
	event& operator=(event&&) noexcept = default;

	event_type_t type() const noexcept;
protected:
	explicit event(event_type_t type) noexcept;

private:
	event_type_t m_type;
};

/*
** The system has raised an interrupt.
** i.e. SIGINT, SIGTERM, SIGBREAK
**
** For the sake of simplicity, SIGBREAK is treated as SIGINT.
**
** SIGINT = interrupt_t::interrupt
** SIGTERM = interrupt_t::terminate
*/
class interrupt_event : public event
{
public:
	enum class interrupt_t { interrupt, terminate };

	interrupt_event() noexcept;
	interrupt_event(interrupt_t type, int signal) noexcept;

	interrupt_t interrupt() const noexcept;
	int signal() const noexcept;
private:
	interrupt_t m_type;
	int m_signal;
};

class amqp_error_event : public event
{
public:
	explicit amqp_error_event(const amqp_exception& ex);

	const amqp_exception& exception() const noexcept;
private:
	amqp_exception m_exception;
};

class network_message : public event
{
public:
	using msgtype = net::message_container;

	explicit network_message(const msgtype& msg);
	explicit network_message(msgtype&& msg);

	const msgtype& message() const noexcept;

private:
	msgtype m_msg;
};

class child_event : public event
{
public:
	explicit child_event(const command_result& res);

	const command_result& result() const noexcept;
private:
	command_result m_result;
};

class watchdog_event : public event
{
public:
	watchdog_event() noexcept;
};

class message_event : public event
{
public:
	message_event(log::level_t level, const std::string& label, const std::string& s);
	message_event(log::level_t level, std::string&& label, std::string&& s) noexcept;

	log::level_t level() const noexcept;
	const std::string& label() const noexcept;
	const std::string& message() const noexcept;

private:
	log::level_t m_level;
	std::string m_label;
	std::string m_message;
};

}
#endif /* _NIMROD_EVENT_HPP */
