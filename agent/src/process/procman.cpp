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
#include <uriparser/Uri.h>
#include <algorithm>
#include "log.hpp"
#include "process/procman.hpp"

using namespace nimrod;

procman::procman(const uuid& agent_uuid, const job_definition& j, const filesystem::path& work_root, const string_map_t& environment, txman *tx) :
	m_agent_uuid(agent_uuid),
	m_job(j),
	m_paths(),
	m_tx(tx),
	m_command_index(0),
	m_error_policy(onerror_command::action_t::fail),
	m_process(nullptr),
	m_ionull(process::create_iofile_null()),
	m_ioout(nullptr),
	m_appendout(false),
	m_ioerr(nullptr),
	m_appenderr(false),
	m_transfer_info(txman::default_future_pair())
{
	m_paths.path_job_root = work_root / j.get_uuid().str();
	m_paths.path_working = m_paths.path_job_root / "working";
	m_paths.path_tmp = m_paths.path_job_root / "tmp";
	m_paths.path_default_intepreter = process::get_system_interpreter();
	if(m_paths.path_default_intepreter.empty())
		throw std::runtime_error("Unable to determine the default interpreter");

	m_paths.uri_base_stor = j.txuri();
	if(!(m_paths.uri_base = parse_uri(m_paths.uri_base_stor)))
		throw std::runtime_error("Invalid transfer URI");

	fixup_uri(m_paths.uri_base.get());

	filesystem::create_directories(m_paths.path_working);
	filesystem::create_directories(m_paths.path_tmp);


	m_environment.reserve(environment.size() + m_job.environment().size() + 6);
	for(const auto& it : environment)
		m_environment.insert(it);

	for(const auto& it : m_job.environment())
		m_environment.insert(it);

#if defined(NIMRODG_USE_POSIX)
	m_environment["TMPDIR"] = m_paths.path_tmp;
#elif defined(NIMRODG_USE_WIN32API)
	m_environment["TEMP"] = m_paths.path_tmp;
	m_environment["TMP"] = m_paths.path_tmp;
#endif
	m_environment["NIMROD_AGENT_UUID"] = m_agent_uuid.str();
	m_environment["NIMROD_AGENT_VERSION"] = g_compile_info.agent.version;
	m_environment["NIMROD_AGENT_PLATFORM"] = g_compile_info.agent.platform;
	m_environment["NIMROD_AGENT_USER_AGENT"] = g_compile_info.agent.user_agent;
}

procman::~procman()
{
	this->ask_meanly_to_exit();
	std::error_code ec;
	filesystem::remove_all(m_paths.path_job_root, ec);
	if(ec)
		report_filesystem_error("JOB", m_paths.path_job_root, ec);
}

const uuid procman::job_uuid() const noexcept
{
	return m_job.get_uuid();
}

const job_definition& procman::job() const noexcept
{
	return m_job;
}

const procman::path_info& procman::paths() const noexcept
{
	return m_paths;
}

size_t procman::command_index() const noexcept
{
	return m_command_index;
}

onerror_command::action_t procman::error_policy() const noexcept
{
	return m_error_policy;
}

size_t procman::num_commands() const noexcept
{
	return m_job.commands().size();
}

command_result procman::run()
{
	if(m_command_index >= m_job.commands().size())
		throw std::out_of_range("Out of jobs");

	command_union cmd = m_job.commands()[m_command_index];

	log::info("JOB", "[%u] Executing command %s", m_command_index, cmd);

	try
	{
		command_result res = std::visit([this](auto&& c) -> command_result { return this->run_command(c); }, static_cast<const _command_union&>(cmd));

		log::info("JOB", "[%u] Command execution status: %d", m_command_index++, res.retval());
		return res;
	}
	catch(const std::system_error& err)
	{
		return command_result::make_system_error(m_command_index++, 0.0f, err);
	}
	catch(const std::exception& e)
	{
		return command_result::make_exception(m_command_index++, 0.0f, e);
	}
	catch(...)
	{
		return command_result::make_exception(m_command_index++, 0.0f, "Unknown exception");
	}
}

command_result procman::run_command(const onerror_command& cmd)
{
	/* Don't need to lock anything here. */
	log::info("JOB", "[%u] Setting error policy to %s", m_command_index, cmd.action());
	m_error_policy = cmd.action();
	return command_result::make_success(m_command_index, 0.0f, 0);
}

command_result procman::run_command(const redirect_command& cmd)
{
	std::lock_guard<std::mutex> lock(m_mutex);
	const std::string& _file = cmd.file();

	iofile_ptr iof;
	bool append;

	if(_file.empty())
	{
		iof = nullptr;
		append = false;
		log::info("JOB", "[%u] Disabling redirection for %s", m_command_index, cmd.stream());
	}
	else
	{
		filesystem::path file = resolve_path(m_paths.path_working, cmd.file());
		process::iofile existing = cmd.stream() == redirect_command::stream_t::stdout_ ? m_ioerr.get() : m_ioout.get();
		iof = process::create_iofile_dup(file, cmd.append(), existing);
		append = cmd.append();
		log::info("JOB", "[%u] Redirecting %s to %s", m_command_index, cmd.stream(), file);
	}

	if(cmd.stream() == redirect_command::stream_t::stdout_)
	{
		m_ioout = std::move(iof);
		m_appendout = append;
	}
	else
	{
		m_ioerr = std::move(iof);
		m_appenderr = append;
	}

	return command_result::make_success(m_command_index, 0.0f, 0);
}

static void print_copy(size_t index, const char *desc, const UriUriA *srcUri, const filesystem::path& dstPath)
{
	log::trace("JOB", "[%u] Performing %s:", index, desc);
	log::trace("JOB", "[%u]    URI: %s", index, uri_to_string(srcUri));
	log::trace("JOB", "[%u]   Path: %s", index, dstPath);
}

/*
 * "Inject" the base URI's query and fragment into the given one and invoke the
 * given function with it. Avoids a malloc.
 */
template <typename V>
static auto run_with_injected_uri(const UriUriA *base, UriUriA *uri, V&& proc)
{
	UriTextRangeA old_query = uri->query;
	UriTextRangeA old_fragment = uri->fragment;
	try
	{
		uri->query = base->query;
		uri->fragment = base->fragment;

		auto ret = proc(uri);
		uri->query = old_query;
		uri->fragment = old_fragment;
		return ret;
	}
	catch(...)
	{
		uri->query = old_query;
		uri->fragment = old_fragment;
		throw;
	}
}

command_result procman::run_command(const copy_command& cmd)
{
	using context_t = copy_command::context_t;

	std::unique_lock lock(m_mutex);

	const char *token = m_job.token().c_str();

	if(cmd.dest_context() == context_t::node && cmd.source_context() == context_t::node)
	{
		filesystem::path srcPath = resolve_path(m_paths.path_working, cmd.source_path());
		filesystem::path dstPath = resolve_path(m_paths.path_working, cmd.dest_path());

		/* Pick your poison. */
		{
			std::string uristring = path_to_uristring(srcPath.u8string());
			if(uristring.empty())
				return command_result::make_exception(m_command_index, 0.0f, "Path->URI conversion failed.");

			uri_ptr srcUri = parse_uri(uristring);
			if(!srcUri)
				return command_result::make_precondition_failure(m_command_index, 0.0f, "parse_uri() failed on uristring.");

			print_copy(m_command_index, "LOCAL COPY", srcUri.get(), dstPath);
			m_transfer_info = m_tx->do_transfer(tx::operation_t::get, srcUri.get(), dstPath, token);
		}
	}
	else if(cmd.dest_context() == context_t::node && cmd.source_context() == context_t::root)
	{
		filesystem::path path = resolve_path(m_paths.path_working, cmd.dest_path());
		uri_ptr uri = resolve_uri(m_paths.uri_base.get(), cmd.source_path());
		if(!uri)
			return command_result::make_exception(m_command_index, 0.0f, "Malformed source URI.");

		print_copy(m_command_index, "REMOTE GET", uri.get(), path);
		m_transfer_info = run_with_injected_uri(m_paths.uri_base.get(), uri.get(), [this, &path, &token](const UriUriA *uri){
			return m_tx->do_transfer(tx::operation_t::get, uri, path, token);
		});
	}
	else if(cmd.dest_context() == context_t::root && cmd.source_context() == context_t::node)
	{
		filesystem::path path = resolve_path(m_paths.path_working, cmd.source_path());
		uri_ptr uri = resolve_uri(m_paths.uri_base.get(), cmd.dest_path());
		if(!uri)
			return command_result::make_exception(m_command_index, 0.0f, "Malformed destination URI.");

		print_copy(m_command_index, "REMOTE PUT", uri.get(), path);
		m_transfer_info = run_with_injected_uri(m_paths.uri_base.get(), uri.get(), [this, &path, &token](const UriUriA *uri){
			return m_tx->do_transfer(tx::operation_t::put, uri, path, token);
		});
	}
	else
	{
		/* No, I am not doing a root->root copy. */
		return command_result::make_exception(m_command_index, 0.0f, "root->root copy not supported.");
	}

	try
	{
		auto start = std::chrono::system_clock::now();

		tx::result_type ret;
		{
			lock.unlock();
			ret = m_transfer_info.second.get();
			lock.lock();
		}

		auto end = std::chrono::system_clock::now();

		std::chrono::duration<float> timeDiff = end - start;

		switch(ret.first)
		{
			case tx::error_type::none:
				return command_result::make_success(m_command_index, timeDiff.count(), 0);
			case tx::error_type::transfer:
			case tx::error_type::backend:
			case tx::error_type::argument:
				return command_result::make_exception(m_command_index, timeDiff.count(), ret.second.second, ret.second.first);
			case tx::error_type::system:
				return command_result::make_system_error(m_command_index, timeDiff.count(), std::system_error(ret.second.first, std::system_category(), ret.second.second));
			default:
				return command_result::make_precondition_failure(m_command_index, timeDiff.count(), "Internal agent error. Unhandled enumeration value for transfer_backend::error_type");

		}
	}
	catch(const std::exception& e)
	{
		return command_result::make_exception(m_command_index, 0.0f, e.what());
	}
}

command_result procman::run_command(const exec_command& cmd)
{
	std::unique_lock<std::mutex> lock(m_mutex);
	auto& components = cmd.arguments();

	if(cmd.arguments().size() < 1)
	{
		log::error("JOB", "[%u] Command must have at least 1 argument. Failing job...", m_command_index);
		return command_result::make_precondition_failure(m_command_index, 0.0f, "Command argument count < 1");
	}

	filesystem::path prog;
	process::string_vector args;

	if(cmd.program().empty())
	{
		/* No program? Dump everything to the default shell. */
		log::trace("JOB", "[%u] Program empty, using system interpreter...", m_command_index);
		prog = m_paths.path_default_intepreter;
		log::trace("JOB", "[%u] Found system interpreter at %s", m_command_index, prog);

		if(cmd.arguments().size() != 1)
		{
			log::error("JOB", "[%u] Shell commands must have exactly 1 argument. Failing job...", m_command_index);
			return command_result::make_precondition_failure(m_command_index, 0.0f, "Command argument count < 1");
		}
		/*
		** TODO: Make this take the interpreter as an argument and vary the args based on that.
		** This will allow multiple shells, to be used (cmd.exe, powershell.exe, etc.)
		*/
		args = process::build_shell_args(cmd.arguments()[0]);
	}
	else
	{
		/*
		** If we want to search the path, only do it if the program doesn't have a parent path, i.e. is just an executable name.
		**
		** "./echo"		DON'T SEARCH
		** "/bin/echo"	DON'T SEARCH
		** "../../echo"	DON'T SEARCH
		** "echo"		SEARCH
		*/
		prog = cmd.program();
		if(cmd.search_path() && !prog.has_parent_path())
			prog = process::search_path(cmd.program());

		log::trace("JOB", "[%u] Resolved program to %s", m_command_index, prog);

		args.reserve(components.size());

		/* Deal with argv0 */
		if(components[0].empty())
			args.push_back(prog.u8string());
		else
			args.push_back(components[0]);

		args.insert(args.end(), components.begin() + 1, components.end());
	}

	log::trace("JOB", "[%u] Command arguments: %s", m_command_index, nimrod::join(args.begin(), args.end(), true));
	m_process = process::create_process(
		prog,
		args,
		m_paths.path_working,
		m_environment,
		m_ioout ? m_ioout.get() : m_ionull.get(),
		m_ioerr ? m_ioerr.get() : m_ionull.get()
	);

	auto start = std::chrono::system_clock::now();
	try
	{
		/* NB: The process is guaranteed to have been spawned here. */
		process::process_result ret;
		{
			lock.unlock();
			ret = m_process->get_future().get();
			lock.lock();
		}
		m_process = nullptr;
		auto end = std::chrono::system_clock::now();

		std::chrono::duration<float> timeDiff = end - start;

		if(ret.second)
			return command_result::make_system_error(m_command_index, timeDiff.count(), ret.second);
		else
			return command_result::make_success(m_command_index, timeDiff.count(), ret.first);
	}
	catch(const std::future_error& e)
	{
		auto end = std::chrono::system_clock::now();
		std::chrono::duration<float> timeDiff = end - start;
		return command_result::make_exception(m_command_index, timeDiff.count(), e.what());
	}
}

void procman::report_child_signal()
{
	std::lock_guard<std::mutex> lock(m_mutex);
	if(m_process)
		process::reap(1, m_process.get());
	else
		process::reap(0);
}

void procman::ask_nicely_to_exit()
{
	std::lock_guard<std::mutex> lock(m_mutex);
	m_tx->cancel(m_transfer_info);
	if(m_process != nullptr)
		m_process->kill(false);
}

void procman::ask_meanly_to_exit()
{
	std::lock_guard<std::mutex> lock(m_mutex);
	m_tx->cancel(m_transfer_info);
	if(m_process != nullptr)
		m_process->kill(true);
}
