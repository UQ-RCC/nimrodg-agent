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
#include "messages/netmsg_json.hpp"

using namespace nimrod;
using namespace nimrod::net;

uuid nlohmann::adl_serializer<uuid>::from_json(const json& j)
{
	return uuid(j.get<std::string>());
}

void nlohmann::adl_serializer<uuid>::to_json(json& j, const uuid& u)
{
	uuid::uuid_string_type out;
	u.str(out, sizeof(out));
	j = out;
}

command_type nlohmann::adl_serializer<command_type>::from_json(const json& j)
{
	std::string t = j.get<std::string>();

	if(t == "onerror")
		return command_type::onerror;
	else if(t == "redirect")
		return command_type::redirect;
	else if(t == "copy")
		return command_type::copy;
	else if(t == "exec")
		return command_type::exec;

	throw std::domain_error("Invalid value for command_type");
}

void nlohmann::adl_serializer<command_type>::to_json(json& j, const command_type& t)
{
	switch(t)
	{
		case command_type::onerror: j = "onerror"; break;
		case command_type::redirect: j = "redirect"; break;
		case command_type::copy: j = "copy"; break;
		case command_type::exec: j = "exec"; break;
		default: throw std::domain_error("Invalid value for command_type");
	}
}

command_union nlohmann::adl_serializer<command_union>::from_json(const json& j)
{
	command_type type = j.at("type").get<command_type>();
	switch(type)
	{
		case command_type::onerror:
			return nlohmann::adl_serializer<onerror_command>::from_json(j);
		case command_type::redirect:
			return nlohmann::adl_serializer<redirect_command>::from_json(j);
		case command_type::copy:
			return nlohmann::adl_serializer<copy_command>::from_json(j);
		case command_type::exec:
			return nlohmann::adl_serializer<exec_command>::from_json(j);
	}

	throw std::domain_error("Invalid value for command_type");
}

void nlohmann::adl_serializer<command_union>::to_json(json& j, const command_union& u)
{
	/* This is absolutely disgusting. I love it! */
	std::visit([&j](auto&& cmd) { nlohmann::adl_serializer<typename std::decay<decltype(cmd)>::type>::to_json(j, cmd); }, static_cast<const _command_union&>(u));
}

onerror_command::action_t nlohmann::adl_serializer<onerror_command::action_t>::from_json(const json& j)
{
	std::string a = j.get<std::string>();

	if(a == "fail")
		return onerror_command::action_t::fail;
	else if(a == "ignore")
		return onerror_command::action_t::ignore;

	throw std::domain_error("Invalid value for onerror_command::action_t");
}

void nlohmann::adl_serializer<onerror_command::action_t>::to_json(json& j, const onerror_command::action_t& a)
{
	switch(a)
	{
		case onerror_command::action_t::fail: j = "fail"; break;
		case onerror_command::action_t::ignore: j = "ignore"; break;
		default: throw std::domain_error("Invalid value for onerror_command::action_t");
	}
}

onerror_command nlohmann::adl_serializer<onerror_command>::from_json(const json& j)
{
	return onerror_command(j.at("action").get<onerror_command::action_t>());
}

void nlohmann::adl_serializer<onerror_command>::to_json(json& j, const onerror_command& cmd)
{
	j = { {"type", cmd.type() },  { "action", cmd.action() } };
}

redirect_command::stream_t nlohmann::adl_serializer<redirect_command::stream_t>::from_json(const json& j)
{
	std::string s = j.get<std::string>();

	if(s == "stdout")
		return redirect_command::stream_t::stdout_;
	else if(s == "stderr")
		return redirect_command::stream_t::stderr_;

	throw std::domain_error("Invalid value for redirect_command::stream_t");
}

void nlohmann::adl_serializer<redirect_command::stream_t>::to_json(json& j, const nimrod::redirect_command::stream_t& stream)
{
	switch(stream) {
		case redirect_command::stream_t::stderr_: j = "stderr"; break;
		case redirect_command::stream_t::stdout_: j = "stdout"; break;
		default: throw std::domain_error("Invalid value for redirect_command::stream_t");
	}
}

redirect_command nlohmann::adl_serializer<redirect_command>::from_json(const json& j)
{
	return redirect_command(
		j.at("stream").get<redirect_command::stream_t>(),
		j.at("append").get<bool>(),
		j.at("file").get<std::string>()
	);
}

void nlohmann::adl_serializer<redirect_command>::to_json(json& j, const redirect_command& cmd)
{
	j = { { "stream", cmd.stream() },{ "append", cmd.append() }, { "file", cmd.file() } };
}



copy_command::context_t nlohmann::adl_serializer<copy_command::context_t>::from_json(const json& j)
{
	std::string t = j.get<std::string>();

	if(t == "node")
		return copy_command::context_t::node;
	else if(t == "root")
		return copy_command::context_t::root;

	throw std::domain_error("Invalid value for copy_command::context_t");
}

void nlohmann::adl_serializer<copy_command::context_t>::to_json(json& j, const copy_command::context_t& t)
{
	switch(t)
	{
		case copy_command::context_t::node: j = "node"; break;
		case copy_command::context_t::root: j = "root"; break;
		default: throw std::domain_error("Invalid value for copy_command::context_t");
	}
}

copy_command nlohmann::adl_serializer<copy_command>::from_json(const json& j)
{
	return copy_command(
		j.at("source_context").get<copy_command::context_t>(),
		j.at("source_path").get<std::string>(),
		j.at("destination_context").get<copy_command::context_t>(),
		j.at("destination_path").get<std::string>()
	);
}

void nlohmann::adl_serializer<copy_command>::to_json(json& j, const copy_command& cmd)
{
	j = {
		{"type", cmd.type()},
		{"source_context", cmd.source_context()},
		{"source_path", cmd.source_path()},
		{"destination_context", cmd.dest_context()},
		{"destination_path", cmd.dest_path()}
	};
}




exec_command nlohmann::adl_serializer<exec_command>::from_json(const json& j)
{
	return exec_command(
		j.at("program").get<std::string>(),
		j.at("arguments").get<exec_command::argument_list>(),
		j.at("search_path").get<bool>()
	);
}

void nlohmann::adl_serializer<exec_command>::to_json(json& j, const exec_command& cmd)
{
	j = { { "type", cmd.type() }, {"search_path", cmd.search_path()}, { "program", cmd.program() },  { "arguments", cmd.arguments() } };
}


job_definition nlohmann::adl_serializer<job_definition>::from_json(const json& j)
{
	return job_definition(
		j.at("uuid").get<nimrod::uuid>(),
		j.at("index").get<uint64_t>(),
		j.at("txuri").get<std::string>(),
		j.at("token").get<std::string>(),
		j.at("commands").get<job_definition::command_vector>(),
		j.at("environment").get<job_definition::env_map>()
	);
}

void nlohmann::adl_serializer<job_definition>::to_json(json& j, const job_definition& job)
{
	j = { { "uuid", job.get_uuid() }, { "index", job.index() }, { "txuri", job.txuri() }, { "token", job.token() }, { "environment", job.environment() }, {"commands", job.commands()} };
}

message_type nlohmann::adl_serializer<message_type>::from_json(const json& j)
{
	std::string t = j.get<std::string>();

	if(t == "agent.init") return message_type::agent_init;
	else if(t == "agent.lifecontrol") return message_type::agent_lifecontrol;
	else if(t == "agent.submit") return message_type::agent_submit;
	else if(t == "agent.hello") return message_type::agent_hello;
	else if(t == "agent.shutdown") return message_type::agent_shutdown;
	else if(t == "agent.update") return message_type::agent_update;
	else if(t == "agent.ping") return message_type::agent_ping;
	else if(t == "agent.pong") return message_type::agent_pong;

	throw std::domain_error("Invalid value for message_type");
}

void nlohmann::adl_serializer<message_type>::to_json(json& j, const message_type& type)
{
	/* I'm deliberately not using net::get_message_type_string() here. */
	switch(type)
	{
		case message_type::agent_init: j = "agent.init"; break;
		case message_type::agent_lifecontrol: j = "agent.lifecontrol"; break;
		case message_type::agent_submit: j = "agent.submit"; break;
		case message_type::agent_hello: j = "agent.hello"; break;
		case message_type::agent_shutdown: j = "agent.shutdown"; break;
		case message_type::agent_update: j = "agent.update"; break;
		case message_type::agent_ping: j = "agent.ping"; break;
		case message_type::agent_pong: j = "agent.pong"; break;
		default: throw std::domain_error("Invalid value for message_type");
	}
}

hello_message nlohmann::adl_serializer<hello_message>::from_json(const json& j)
{
	return nimrod::net::hello_message(j.at("uuid").get<uuid>(), j.at("queue").get<std::string>());
}

void nlohmann::adl_serializer<hello_message>::to_json(json& j, const hello_message& msg)
{
	j = json{ { "uuid", msg.uuid() },{ "type", msg.type() },{ "queue", msg.queue() } };
}

init_message nlohmann::adl_serializer<init_message>::from_json(const json& j)
{
	return nimrod::net::init_message(j.at("uuid").get<nimrod::uuid>());
}

void nlohmann::adl_serializer<init_message>::to_json(json& j, const init_message& msg)
{
	j = json{ { "uuid", msg.uuid() },{ "type", msg.type() } };
}





shutdown_message::reason_t nlohmann::adl_serializer<shutdown_message::reason_t>::from_json(const json& j)
{
	std::string v = j.get<std::string>();

	if(v == "hostsignal")
		return shutdown_message::reason_t::host_signal;
	else if(v == "requested")
		return shutdown_message::reason_t::requested;

	throw std::domain_error("Invalid value for shutdown_message::reason_t");
}

void nlohmann::adl_serializer<shutdown_message::reason_t>::to_json(json& j, const shutdown_message::reason_t& r)
{
	switch(r)
	{
		case shutdown_message::reason_t::host_signal:
			j = "hostsignal";
			break;
		case shutdown_message::reason_t::requested:
			j = "requested";
			break;
		default:
			throw std::domain_error("Invalid value for shutdown_message::reason_t");
	}
}

shutdown_message nlohmann::adl_serializer<shutdown_message>::from_json(const json& j)
{
	return nimrod::net::shutdown_message(j.at("uuid").get<uuid>(), j.at("reason").get<shutdown_message::reason_t>(), j.at("signal").get<int>());
}

void nlohmann::adl_serializer<shutdown_message>::to_json(json& j, const shutdown_message& msg)
{
	j = json{ { "uuid", msg.uuid() },{ "type", msg.type() },{ "reason", msg.reason() },{ "signal", msg.signal() } };
}

submit_message nlohmann::adl_serializer<submit_message>::from_json(const json& j)
{
	return nimrod::net::submit_message(j.at("uuid").get<uuid>(), j.at("job").get<job_definition>());
}

void nlohmann::adl_serializer<submit_message>::to_json(json& j, const submit_message& msg)
{
	j = json{ {"uuid", msg.uuid()}, { "type", msg.type() }, {"job", msg.job()} };
}


command_result::result_status nlohmann::adl_serializer<command_result::result_status>::from_json(const json& j)
{
	std::string s = j.get<std::string>();

	if(s == "success") return command_result::result_status::success;
	if(s == "precondition_failure") return command_result::result_status::precondition_failure;
	if(s == "system_error") return command_result::result_status::system_error;
	if(s == "exception") return command_result::result_status::exception;
	if(s == "aborted") return command_result::result_status::aborted;

	throw std::domain_error("Invalid value for command_result::result_status");
}

void nlohmann::adl_serializer<command_result::result_status>::to_json(json& j, command_result::result_status s)
{
	switch(s)
	{
		case command_result::result_status::success: j = "success"; break;
		case command_result::result_status::precondition_failure: j = "precondition_failure"; break;
		case command_result::result_status::system_error: j = "system_error"; break;
		case command_result::result_status::exception: j = "exception"; break;
		case command_result::result_status::aborted: j = "aborted"; break;
		default: throw std::domain_error("Invalid value for command_result::result_status");
	}
}

command_result nlohmann::adl_serializer<command_result>::from_json(const json& j)
{
	return command_result(
		j.at("status").get<command_result::result_status>(),
		j.at("index").get<size_t>(),
		j.at("time").get<float>(),
		j.at("retval").get<int>(),
		j.at("message").get<std::string>(),
		std::error_code(j.at("error_code").get<int>(), std::system_category())
	);
}



update_message::action_t nlohmann::adl_serializer<update_message::action_t>::from_json(const json& j)
{
	std::string s = j.get<std::string>();

	if(s == "continue") return update_message::action_t::continue_;
	if(s == "stop") return update_message::action_t::stop;

	throw std::domain_error("Invalid value for update_message::action_t");
}

void nlohmann::adl_serializer<update_message::action_t>::to_json(json& j, update_message::action_t s)
{
	switch(s)
	{
		case update_message::action_t::continue_: j = "continue"; break;
		case update_message::action_t::stop: j = "stop"; break;
		default: throw std::domain_error("Invalid value for update_message::action_t");
	}
}

void nlohmann::adl_serializer<command_result>::to_json(json& j, const command_result& res)
{
	j = json{
		{ "status", res.status() },
		{ "index", res.index() },
		{ "message", res.message() },
		{ "retval", res.retval() },
		{ "error_code", res.error_code().value() },
		{ "time", res.time() }
	};
}

update_message nlohmann::adl_serializer<update_message>::from_json(const json& j)
{
	return nimrod::net::update_message(
		j.at("uuid").get<uuid>(),
		j.at("job_uuid").get<uuid>(),
		j.at("result").get<command_result>(),
		j.at("action").get<update_message::action_t>()
	);
}

void nlohmann::adl_serializer<update_message>::to_json(json& j, const update_message& msg)
{
	j = json{
		{ "uuid", msg.uuid() },
		{ "type", msg.type() },
		{ "job_uuid", msg.job_uuid() },
		{ "command_result", msg.result() },
		{ "action", msg.action() }
	};
}


lifecontrol_message::operation_t nlohmann::adl_serializer<lifecontrol_message::operation_t>::from_json(const json& j)
{
	std::string v = j.get<std::string>();

	if(v == "terminate") return lifecontrol_message::operation_t::terminate;
	else if(v == "cancel") return lifecontrol_message::operation_t::cancel;
	else throw std::domain_error("Invalid value for lifecontrol_message::operation_t");
}

void nlohmann::adl_serializer<lifecontrol_message::operation_t>::to_json(json& j, const lifecontrol_message::operation_t& op)
{
	switch(op)
	{
		case lifecontrol_message::operation_t::terminate: j = "terminate"; break;
		case lifecontrol_message::operation_t::cancel: j = "cancel"; break;
		default: throw std::domain_error("Invalid value for lifecontrol_message::operation_t");
	}
}


lifecontrol_message nlohmann::adl_serializer<lifecontrol_message>::from_json(const json& j)
{
	return nimrod::net::lifecontrol_message(j.at("uuid").get<uuid>(), j.at("operation").get<lifecontrol_message::operation_t>());
}

void nlohmann::adl_serializer<lifecontrol_message>::to_json(json& j, const lifecontrol_message& msg)
{
	j = json{ { "uuid", msg.uuid() },{ "type", msg.type() },{ "operation", msg.operation() } };
}

ping_message nlohmann::adl_serializer<ping_message>::from_json(const json& j)
{
	return nimrod::net::ping_message(j.at("uuid").get<uuid>());
}

void nlohmann::adl_serializer<ping_message>::to_json(json& j, const ping_message& msg)
{
	j = json{ { "uuid", msg.uuid() }, { "type", msg.type() } };
}

pong_message nlohmann::adl_serializer<pong_message>::from_json(const json& j)
{
	return nimrod::net::pong_message(j.at("uuid").get<uuid>());
}

void nlohmann::adl_serializer<pong_message>::to_json(json& j, const pong_message& msg)
{
	j = json{ { "uuid", msg.uuid() }, { "type", msg.type() }, { "stats", json::object() } };
}

message_container nlohmann::adl_serializer<message_container>::from_json(const json& j)
{
	message_type t = j.at("type").get<message_type>();

	switch(t)
	{
		case message_type::agent_hello: return adl_serializer<hello_message>::from_json(j);
		case message_type::agent_init: return adl_serializer<init_message>::from_json(j);
		case message_type::agent_lifecontrol: return adl_serializer<lifecontrol_message>::from_json(j);
		case message_type::agent_submit: return adl_serializer<submit_message>::from_json(j);
		case message_type::agent_shutdown: return adl_serializer<shutdown_message>::from_json(j);
		case message_type::agent_update: return adl_serializer<update_message>::from_json(j);
		case message_type::agent_ping: return adl_serializer<ping_message>::from_json(j);
		case message_type::agent_pong: return adl_serializer<pong_message>::from_json(j);
	}

	throw std::domain_error("Invalid value for message_type");
}

void nlohmann::adl_serializer<message_container>::to_json(json& j, const message_container& msg)
{
	return std::visit([&j](auto&& m) { return nlohmann::adl_serializer<std::decay_t<decltype(m)>>::to_json(j, m); }, static_cast<const msg_union&>(msg));
}

message_container net::message_read(const char *buffer, size_t size)
{
	return nlohmann::json::parse(buffer, buffer + size).get<message_container>();
}

std::string net::message_write(const net::message_container& msg)
{
	return static_cast<nlohmann::json>(msg).dump();
}

std::string_view net::message_content_type() noexcept
{
	return "application/json; charset=utf-8";
}
