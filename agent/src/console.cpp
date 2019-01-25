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
#include "log.hpp"
#include "agent_common.hpp"
#include "agent.hpp"

using namespace nimrod;

#if defined(NIMRODG_USE_WIN32API)
#include "utils_win32.hpp"

static agent *s_pAgent;

static interrupt_event _interrupt(interrupt_event::interrupt_t::interrupt, SIGINT);
static interrupt_event _terminate(interrupt_event::interrupt_t::terminate, SIGINT);

static BOOL WINAPI win32_console_handler(DWORD dwCtrlType)
{
	/* This is executed in a different thread, so be careful. */
	switch(dwCtrlType)
	{
		case CTRL_C_EVENT:
			/* SIGINT */
			s_pAgent->log_message(log::level_t::info, "CONSOLE", "Got CTRL+C, sending interrupt...");
			s_pAgent->submit_event(_interrupt);
			return TRUE;
		case CTRL_BREAK_EVENT:
		case CTRL_CLOSE_EVENT:
			/* SIGTERM */
			s_pAgent->log_message(log::level_t::info, "CONSOLE", "Got CTRL+BREAK, sending termination...");
			s_pAgent->submit_event(_terminate);
			return TRUE;
	}

	return FALSE;
}

bool nimrod::init_console_handlers(agent *a)
{
	/*
	** Install a console control handler. This will only work if we're running
	** with /SUBSYSTEM:CONSOLE subsystem. If using /SUBSYSTEM:WINDOWS, it'd be best
	** to get a proper Win32 TranslateMessage()/DispatchMessage() loop going and handling
	** WM_CLOSE and friends.
	*/

	s_pAgent = a; /* Eww */
	log::info("AGENT", "Registering Win32 console handler...");
	if(SetConsoleCtrlHandler(win32_console_handler, TRUE) == FALSE)
	{
		DWORD dwError = GetLastError();
		log::error("AGENT", "Error registering console handler.");
		log::debug("AGENT", "  SetConsoleCtrlHandler() returned FALSE, GetLastError() = %d", dwError);
		log::error("AGENT", "  %s", win32::get_win32_error_message(dwError));
		return false;
	}

	return true;
}
#elif defined(NIMRODG_USE_POSIX)
#include "utils_posix.hpp"
#include <string.h>
static agent *s_pAgent;


bool nimrod::init_console_handlers(agent *a)
{
	s_pAgent = a;

	struct sigaction new_action;
	memset(&new_action, 0, sizeof(new_action));

	/* Can't use sa_sigaction here, we may not always be on Linux */
	new_action.sa_handler = [](int signum)
	{
		s_pAgent->log_message(log::level_t::info, "CONSOLE", "Caught %s", posix::get_signal_string(signum));
		switch(signum)
		{
			case SIGHUP:
			case SIGINT:
			case SIGTERM:
			case SIGCHLD:
				s_pAgent->submit_event(interrupt_event(interrupt_event::interrupt_t::interrupt, signum));
				break;
			default:
				std::terminate();
				break;
		}
	};

	new_action.sa_flags = 0;
	sigemptyset(&new_action.sa_mask);
	sigaddset(&new_action.sa_mask, SIGTERM);
	sigaddset(&new_action.sa_mask, SIGINT);
	sigaddset(&new_action.sa_mask, SIGCHLD);
	sigaddset(&new_action.sa_mask, SIGHUP);
	new_action.sa_restorer = nullptr;

	auto sigaction_verbose = [](int s, struct sigaction *sa){
		log::info("AGENT", "  %s...", posix::get_signal_string(s));
		if(sigaction(s, sa, nullptr) < 0)
		{
			log::error("AGENT", "Error registering console handler for %s.", posix::get_signal_string(s));
			log::debug("AGENT", "  sigaction() returned < 0, errno = %d", errno);
			log::error("AGENT", "  %s.", strerror(errno));
			return false;
		}
		return true;
	};

	log::info("AGENT", "Registering POSIX signal handlers...");

	if(!sigaction_verbose(SIGINT, &new_action))
		return false;

	if(!sigaction_verbose(SIGTERM, &new_action))
		return false;

	if(!sigaction_verbose(SIGCHLD, &new_action))
		return false;

	if(!sigaction_verbose(SIGHUP, &new_action))
		return false;

	return true;
}
#else
#	error No Console API defined
#endif
