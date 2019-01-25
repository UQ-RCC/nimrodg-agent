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
#define __STDC_FORMAT_MACROS
#include <cinttypes>
#include <cstdio>

#include <fmt/ostream.h>
#include "threading.hpp"
#include "log.hpp"

#define XSTR(a) STR(a)
#define STR(a) #a

#define COMPONENT_STRING_SIZE 7
#define COMPONENT_STRING_SIZE_AS_STRING XSTR(COMPONENT_STRING_SIZE)

using namespace nimrod;

void log::vmanual(level_t level, const char *component, const char *fmt, fmt::printf_args args)
{
	static std::mutex logLock;

	/* http://stackoverflow.com/a/8438730/21475 */
	static thread_local int threadMarker;

	FILE *stream = stderr;
	const char *sLevel = "UNKWN";

	switch(level)
	{
		case level_t::error:
			sLevel = "ERROR";
			stream = stderr;
			break;
		case level_t::warn:
			sLevel = "WARN";
			stream = stdout;
			break;
		case level_t::info:
			sLevel = "INFO";
			stream = stdout;
			break;
		case level_t::debug:
			sLevel = "DEBUG";
			stream = stdout;
			break;
		case level_t::trace:
			sLevel = "TRACE";
			stream = stdout;
			break;
	}

	{
		std::lock_guard<std::mutex> lock(logLock);
		fprintf(
			stream,
			"%" COMPONENT_STRING_SIZE_AS_STRING "." COMPONENT_STRING_SIZE_AS_STRING "s [%" PRIxPTR "] [%5s] ",
			component,
			reinterpret_cast<uintptr_t>(&threadMarker),
			sLevel
		);

		fmt::vfprintf(stream, fmt, args);
		fmt::print(stream, "\n");
	}
}
