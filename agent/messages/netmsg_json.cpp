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
#include "agent_common.hpp"

using namespace nimrod;
using namespace nimrod::net;

uuid nlohmann::adl_serializer<uuid>::from_json(const json& j)
{
	return uuid(j.get<std::string_view>());
}

void nlohmann::adl_serializer<uuid>::to_json(json& j, const uuid& u)
{
	uuid::uuid_string_type out;
	u.str(out, sizeof(out));
	j = out;
}

nim1::nanotime_t nlohmann::adl_serializer<nim1::nanotime_t>::from_json(const json& j)
{
	nim1::nanotime_t nt;
	if(parse_iso8601(j.get<std::string>().c_str(), nim1::iso8601_format_t::extended_nanosec, nt) < 0)
		throw std::runtime_error("invalid timestamp");

	return nt;
}

void nlohmann::adl_serializer<nim1::nanotime_t>::to_json(json& j, const nim1::nanotime_t& nt)
{
	nim1::iso8601_string_t iso;
	to_iso8601(nt, nim1::iso8601_format_t::extended_nanosec, iso);
	j = std::string(iso);
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
	std::visit([&j](auto&& cmd) {
		nlohmann::adl_serializer<std::decay_t<decltype(cmd)>>::to_json(j, cmd);
	}, static_cast<const _command_union&>(u));
}

onerror_command nlohmann::adl_serializer<onerror_command>::from_json(const json& j)
{
	return onerror_command(j.at("action").get<onerror_command::action_t>());
}

void nlohmann::adl_serializer<onerror_command>::to_json(json& j, const onerror_command& cmd)
{
    j = {
        {"type",   cmd.type()},
        {"action", cmd.action()}
    };
}

redirect_command nlohmann::adl_serializer<redirect_command>::from_json(const json& j)
{
	return redirect_command(
		j.at("stream").get<redirect_command::stream_t>(),
		j.at("append").get<bool>(),
		j.at("file").get<std::string_view>()
	);
}

void nlohmann::adl_serializer<redirect_command>::to_json(json& j, const redirect_command& cmd)
{
    j = {
        {"stream", cmd.stream()},
        {"append", cmd.append()},
        {"file",   cmd.file()}
    };
}

copy_command nlohmann::adl_serializer<copy_command>::from_json(const json& j)
{
    return copy_command(
        j.at("source_context").get<copy_command::context_t>(),
        j.at("source_path").get<std::string_view>(),
        j.at("destination_context").get<copy_command::context_t>(),
        j.at("destination_path").get<std::string_view>()
    );
}

void nlohmann::adl_serializer<copy_command>::to_json(json& j, const copy_command& cmd)
{
    j = {
        {"type",                cmd.type()},
        {"source_context",      cmd.source_context()},
        {"source_path",         cmd.source_path()},
        {"destination_context", cmd.dest_context()},
        {"destination_path",    cmd.dest_path()}
    };
}




exec_command nlohmann::adl_serializer<exec_command>::from_json(const json& j)
{
	return exec_command(
		j.at("program").get<std::string_view>(),
		j.at("arguments").get<exec_command::argument_list>(),
		j.at("search_path").get<bool>()
	);
}

void nlohmann::adl_serializer<exec_command>::to_json(json& j, const exec_command& cmd)
{
    j = {
        {"type",        cmd.type()},
        {"search_path", cmd.search_path()},
        {"program",     cmd.program()},
        {"arguments",   cmd.arguments()}
    };
}


job_definition nlohmann::adl_serializer<job_definition>::from_json(const json& j)
{
	return job_definition(
		j.at("uuid").get<nimrod::uuid>(),
		j.at("index").get<uint64_t>(),
		j.at("txuri").get<std::string_view>(),
		j.at("token").get<std::string_view>(),
		j.at("commands").get<job_definition::command_vector>(),
		j.at("environment").get<job_definition::env_map>()
	);
}

void nlohmann::adl_serializer<job_definition>::to_json(json& j, const job_definition& job)
{
    j = {
        {"uuid",        job.get_uuid()},
        {"index",       job.index()},
        {"txuri",       job.txuri()},
        {"token",       job.token()},
        {"environment", job.environment()},
        {"commands",    job.commands()}
    };
}


static uint32_t ensure_version(const nlohmann::json& j)
{
	uint32_t version = 1;

	/* Version 1 had no version field. */
	if(auto it = j.find("version"); it != j.end())
		version = it->get<uint32_t>();

	if(version != net::PROTOCOL_VERSION)
		throw std::runtime_error("mismatched protocol version");

	return version;
}


hello_message nlohmann::adl_serializer<hello_message>::from_json(const json& j)
{
	ensure_version(j);
	return nimrod::net::hello_message(
		j.at("uuid").get<uuid>(),
		j.at("timestamp").get<nim1::nanotime_t>(),
		j.at("queue").get<std::string_view>()
	);
}

void nlohmann::adl_serializer<hello_message>::to_json(json& j, const hello_message& msg)
{
    j = {
        {"uuid",    msg.uuid()},
        {"version", msg.version()},
        {"type",    msg.type()},
        {"timestamp", msg.time()},
        {"queue",   msg.queue()}
    };
}

init_message nlohmann::adl_serializer<init_message>::from_json(const json& j)
{
    ensure_version(j);
	return nimrod::net::init_message(
		j.at("uuid").get<nimrod::uuid>(),
		j.at("timestamp").get<nim1::nanotime_t>()
	);
}

void nlohmann::adl_serializer<init_message>::to_json(json& j, const init_message& msg)
{
    j = {
        {"uuid",    msg.uuid()},
        {"version", msg.version()},
        {"type",    msg.type()},
        {"timestamp", msg.time()},
    };
}


shutdown_message nlohmann::adl_serializer<shutdown_message>::from_json(const json& j)
{
	ensure_version(j);
	return nimrod::net::shutdown_message(
		j.at("uuid").get<uuid>(),
		j.at("timestamp").get<nim1::nanotime_t>(),
		j.at("reason").get<shutdown_message::reason_t>(),
		j.at("signal").get<int>()
	);
}

void nlohmann::adl_serializer<shutdown_message>::to_json(json& j, const shutdown_message& msg)
{
    j = {
        {"uuid",    msg.uuid()},
        {"version", msg.version()},
        {"timestamp", msg.time()},
        {"type",    msg.type()},
        {"reason",  msg.reason()},
        {"signal",  msg.signal()}
    };
}

submit_message nlohmann::adl_serializer<submit_message>::from_json(const json& j)
{
    ensure_version(j);
	return nimrod::net::submit_message(
		j.at("uuid").get<uuid>(),
		j.at("timestamp").get<nim1::nanotime_t>(),
		j.at("job").get<job_definition>()
	);
}

void nlohmann::adl_serializer<submit_message>::to_json(json& j, const submit_message& msg)
{
    j = {
        {"uuid",    msg.uuid()},
        {"version", msg.version()},
        {"type",    msg.type()},
        {"timestamp", msg.time()},
        {"job",     msg.job()}
    };
}

command_result nlohmann::adl_serializer<command_result>::from_json(const json& j)
{
	return command_result(
		j.at("status").get<command_result::result_status>(),
		j.at("index").get<size_t>(),
		j.at("time").get<float>(),
		j.at("retval").get<int>(),
		j.at("message").get<std::string_view>(),
		j.at("error_code").get<int>()
	);
}

void nlohmann::adl_serializer<command_result>::to_json(json& j, const command_result& res)
{
    j = {
        {"status",     res.status()},
        {"index",      res.index()},
        {"message",    res.message()},
        {"retval",     res.retval()},
        {"error_code", res.error_code()},
        {"time",       res.time()}
	};
}

update_message nlohmann::adl_serializer<update_message>::from_json(const json& j)
{
	ensure_version(j);
	return nimrod::net::update_message(
		j.at("uuid").get<uuid>(),
		j.at("timestamp").get<nim1::nanotime_t>(),
		j.at("job_uuid").get<uuid>(),
		j.at("result").get<command_result>(),
		j.at("action").get<update_message::action_t>()
	);
}

void nlohmann::adl_serializer<update_message>::to_json(json& j, const update_message& msg)
{
    j = {
        {"uuid",           msg.uuid()},
        {"version",        msg.version()},
        {"type",           msg.type()},
        {"timestamp",      msg.time()},
        {"job_uuid",       msg.job_uuid()},
        {"command_result", msg.result()},
        {"action",         msg.action()}
    };
}

lifecontrol_message nlohmann::adl_serializer<lifecontrol_message>::from_json(const json& j)
{
	ensure_version(j);
	return nimrod::net::lifecontrol_message(
		j.at("uuid").get<uuid>(),
		j.at("timestamp").get<nim1::nanotime_t>(),
		j.at("operation").get<lifecontrol_message::operation_t>()
	);
}

void nlohmann::adl_serializer<lifecontrol_message>::to_json(json& j, const lifecontrol_message& msg)
{
    j = {
        {"uuid",      msg.uuid()},
        {"version",   msg.version()},
        {"type",      msg.type()},
        {"timestamp", msg.time()},
        {"operation", msg.operation()}
    };
}

ping_message nlohmann::adl_serializer<ping_message>::from_json(const json& j)
{
    ensure_version(j);
	return nimrod::net::ping_message(
		j.at("uuid").get<uuid>(),
		j.at("timestamp").get<nim1::nanotime_t>()
	);
}

void nlohmann::adl_serializer<ping_message>::to_json(json& j, const ping_message& msg)
{
    j = {
        {"uuid",    msg.uuid()},
        {"version", msg.version()},
        {"type",    msg.type()},
        {"timestamp", msg.time()}
    };
}

pong_message nlohmann::adl_serializer<pong_message>::from_json(const json& j)
{
	ensure_version(j);
	return nimrod::net::pong_message(
		j.at("uuid").get<uuid>(),
		j.at("timestamp").get<nim1::nanotime_t>(),
		j.at("state").get<agent_state_t>()
	);
}

void nlohmann::adl_serializer<pong_message>::to_json(json& j, const pong_message& msg)
{
    j = {
        {"uuid",    msg.uuid()},
        {"version", msg.version()},
        {"type",    msg.type()},
        {"timestamp", msg.time()},
        {"state",   msg.state()},
    };
}

message_container nlohmann::adl_serializer<message_container>::from_json(const json& j)
{
	message_type_t t = j.at("type").get<message_type_t>();

	switch(t)
	{
		case message_type_t::agent_hello: return adl_serializer<hello_message>::from_json(j);
		case message_type_t::agent_init: return adl_serializer<init_message>::from_json(j);
		case message_type_t::agent_lifecontrol: return adl_serializer<lifecontrol_message>::from_json(j);
		case message_type_t::agent_submit: return adl_serializer<submit_message>::from_json(j);
		case message_type_t::agent_shutdown: return adl_serializer<shutdown_message>::from_json(j);
		case message_type_t::agent_update: return adl_serializer<update_message>::from_json(j);
		case message_type_t::agent_ping: return adl_serializer<ping_message>::from_json(j);
		case message_type_t::agent_pong: return adl_serializer<pong_message>::from_json(j);
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
