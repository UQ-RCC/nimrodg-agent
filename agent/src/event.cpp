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
#include <csignal>
#include "event.hpp"

using namespace nimrod;

event::event(event_type_t type) noexcept :
	m_type(type)
{}

interrupt_event::interrupt_event() noexcept :
	interrupt_event(interrupt_t::terminate, SIGTERM)
{}

interrupt_event::interrupt_event(interrupt_t type, int signal) noexcept :
	event(event_type_t::system_interrupt),
	m_type(type),
	m_signal(signal)
{}

interrupt_event::interrupt_t interrupt_event::interrupt() const noexcept
{
	return m_type;
}

int interrupt_event::signal() const noexcept
{
	return m_signal;
}

amqp_error_event::amqp_error_event(const amqp_exception& ex) :
	event(event_type_t::amqp_error),
	m_exception(ex)
{}

const amqp_exception& amqp_error_event::exception() const noexcept
{
	return m_exception;
}


network_message::network_message(const msgtype& msg) :
	event(event_type_t::network_message),
	m_msg(msg)
{}

network_message::network_message(msgtype&& msg) :
	event(event_type_t::network_message),
	m_msg(std::move(msg))
{}

const network_message::msgtype& network_message::message() const noexcept
{
	return m_msg;
}

child_event::child_event(const command_result& res) :
	event(event_type_t::child_update),
	m_result(res)
{}

const command_result& child_event::result() const noexcept
{
	return m_result;
}

watchdog_event::watchdog_event() noexcept :
	event(event_type_t::watchdog_timeout)
{}

message_event::message_event(log::level_t level, const std::string& label, const std::string& s) :
	event(event_type_t::message),
	m_level(level),
	m_label(label),
	m_message(s)
{}

message_event::message_event(log::level_t level, std::string&& label, std::string&& s) noexcept :
	event(event_type_t::message),
	m_level(level),
	m_label(std::move(label)),
	m_message(std::move(s))
{}

log::level_t message_event::level() const noexcept
{
	return m_level;
}

const std::string& message_event::label() const noexcept
{
	return m_label;
}

const std::string& message_event::message() const noexcept
{
	return m_message;
}