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
#include "log.hpp"
#include <memory>
#include <atomic>
#include <iostream>
#include <sstream>
#include <fstream>

#include <uriparser/Uri.h>
#include <amqp.h>
#include <curl/curl.h>
#include <config.h>

#include <nim1/nim1.hpp>

#include "agent_common.hpp"
#include "amqp_consumer.hpp"
#include "agent.hpp"

#include "transfer/curl_backend.hpp"

using namespace nimrod;

/*
** Get an AMQP message and pass it to the agent.
**
** This uses amqp_consumer::get_message(), and will wait on a message.
** To interrupt it, set done == true, and call amqp::clear_waiting().
*/
static void dispatchProc(amqp_consumer& amqp, std::atomic_bool& done, agent& a)
{
	log::info("AMQPD", "AMQP Message Dispatcher, starting up...");
	while(!done)
	{
		try
		{
			network_message msg(amqp.get_message().get());
			a.submit_event(std::move(msg));
		}
		catch(amqp_exception& e)
		{
			log::error("AMQPD", "Error retrieving message: %s", e);
		}
		catch(std::future_error& e)
		{
			log::trace("AMQPD", "Caught future error: %s.", e.what());
			break;
		}
		catch(std::exception& e)
		{
			log::error("AMQPD", "Caught exception: %s", e.what());
			break;
		}
	}
	log::info("AMQPD", "This is AMQP Message Dispatcher, signing off...");
}

int main(int argc, char **argv)
{
	int argStatus;
	settings s;

	nim1::init();

	if(!parse_program_arguments(argc, argv, argStatus, std::cout, std::cerr, s))
		return argStatus;

	if(s.batch)
	{
#if defined(NIMRODG_USE_POSIX)
		void enter_batch_mode() noexcept;
		enter_batch_mode();
#else
		log::error("AGENT", "Batch mode not supported on non-POSIX systems.");
		return 1;
#endif
	}

	filesystem::path workRoot(s.work_root);
	std::error_code errc = nimrod::create_directories(s.work_root);
	if(errc)
	{
		report_filesystem_error("AGENT", workRoot, errc);
		return 1;
	}

	/* Handle output redirection. */
	std::ofstream rstream;

	auto workroot_cleanup_proc = [&s, &rstream, &workRoot]() {
		/* So we can delete it on Windows. */
		if(s.output == settings::output_t::workroot)
			rstream.close();

		nimrod::remove_all(workRoot);
	};

	auto workroot_cleaner = make_protector(workroot_cleanup_proc);

	switch(s.output)
	{
		case settings::output_t::console:
			break;
		case settings::output_t::off:
			rstream.open(NIMRODG_DEVNULL, std::ios::binary);
			break;
		case settings::output_t::workroot:
			rstream.open(workRoot / "output.txt", std::ios::binary);
			break;
	}

	if(!rstream && s.output != settings::output_t::console)
	{
		log::error("AGENT", "Error configuring redirects, exiting...");
		return 1;
	}

	if(rstream.is_open())
	{
		std::cout.rdbuf(rstream.rdbuf());
		std::cerr.rdbuf(rstream.rdbuf());
		std::clog.rdbuf(rstream.rdbuf());
	}

	/* FIXME: I need to redo the platform code. */
#if defined(NIMRODG_USE_POSIX)
	int fnullify(FILE *f);
	if(fnullify(stdin) < 0)
	{
		log::error("AGENT", "Unable to nullify stdin, please fix your system.");
		log::error("AGENT", "%s", strerror(errno));
		return 1;
	}
#endif

	log::info("AGENT", "%s starting up...", g_compile_info.agent.description);
	log::info("AGENT", "UUID: %s", s.uuid);
	log::info("AGENT", "Work Root %s...", workRoot);

	agent ag(s.uuid, workRoot, s.environment);
	ag.nohup(s.nohup);
	if(!init_console_handlers(&ag))
		return 1;

	init_openssl();

	/* Initialise cURL. Don't use CURL_GLOBAL_ALL, we're already initialising OpenSSL. */
	if(CURLcode err = curl_global_init(CURL_GLOBAL_WIN32))
	{
		log::error("AGENT", "curl_global_init() failed with error %d: %s", static_cast<int>(err), curl_easy_strerror(err));
		return 1;
	}

	auto curl_deinit = make_protector(curl_global_cleanup);

	/* Load the CA certs. These are used for the File Server as well. */
	x509_store_ptr castore = load_ca_store(s.ca_path, s.ca_encoding);

	/* Delete the cert. */
	if(!s.ca_no_delete && !s.ca_path.empty())
	{
		filesystem::path capath(s.ca_path);
		if(!remove(capath, errc))
			report_filesystem_error("AGENT", capath, errc);
	}

	if(!castore)
		return 1;

	dump_ca_store(castore);

	curl_multi_ptr curlm(curl_multi_init());
	if(!curlm)
	{
		log::error("AGENT", "curl_multi_init() failed.");
		return 1;
	}

	txman txm(s.uuid, curlm.get(), castore.get(), !s.ssl_no_verify_peer, !s.ssl_no_verify_hostname);

	amqp_conn_ptr conn(amqp_new_connection());
	if(!conn)
	{
		log::error("AGENT", "Error creating AMQP connection.");
		log::debug("AGENT", "  amqp_new_connection() returned NULL.");
		return 1;
	}

	amqp_socket_t *socket = create_socket(s, conn.get(), castore.get());
	if(socket == nullptr)
		return 1;

	/* If we've reached here, start doing agenty things. */
	std::atomic_bool exit_amqp(false);
	try
	{
		amqp_consumer amqp(conn.get(), 1, s.amqp_user, s.amqp_routing_key, s.amqp_direct_exchange, s.access_key, s.secret_key, s.signing_algorithm);

		ag.set_amqp(&amqp, &txm);

		/* Spin off the network worker (networker?). */
		std::thread qt([&curlm, &amqp, &ag, &exit_amqp]()
		{
			log::info("NET", "Network Thread, starting up...");

			void ttt(nimrod::amqp_consumer& amqp, CURLM *mh);

			try
			{
				while(!exit_amqp)
					ttt(amqp, curlm.get());
			}
			catch(amqp_exception& e)
			{
				log::error("NET", "%s", e);
				ag.submit_event(amqp_error_event(e));
			}

			/* Will kill the dispatcher thread. */
			amqp.clear_waiting();
			log::info("NET", "Network Thread, signing off...");
		});

		/* Send the broker "hello" */
		log::trace("AGENT", "Sending broker hello. UUID is %s", ag.get_uuid());
		auto f = amqp.send_message(net::hello_message(ag.get_uuid(), nim1::current_time(), amqp.queue_name()), true);
		f.wait();

		auto res = f.get();
		if(res == amqp_consumer::send_result_t::returned)
		{
			log::error("AGENT", "Broker returned message, no master active. Exiting...");
			exit_amqp = true;
			qt.join();
			goto dead;
		}

		assert(res == amqp_consumer::send_result_t::ack);

		std::thread dd([&amqp, &exit_amqp, &ag]() { dispatchProc(amqp, exit_amqp, ag); });

		ag.run();
		log::info("AGENT", "Main processor terminated, waiting for AMQP to exit...");
		exit_amqp = true;
		qt.join();
		dd.join();
	}
	catch(amqp_exception& e)
	{
		log::error("AGENT", "%s", e);
	}

dead:
	log::info("AGENT", "%s signing off...", g_compile_info.agent.description);
	amqp_connection_close(conn.get(), AMQP_REPLY_SUCCESS);
	return 0;
}
