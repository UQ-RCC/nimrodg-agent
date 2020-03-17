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
#include <iostream>
#include <mutex>

#include <fmt/ostream.h>
#include "log.hpp"

using namespace nimrod;

void log::vmanual(level_t level, const char *component, const char *fmt, fmt::printf_args args)
{
	static std::mutex logLock;

	/* http://stackoverflow.com/a/8438730/21475 */
	static thread_local int threadMarker;

	/* NB: Using iostreams so output is redirected when in batch mode. */
	std::ostream *stream = &std::cerr;

	const char *sLevel = "UNKWN";

	switch(level)
	{
		case level_t::error:
			sLevel = "ERROR";
			stream = &std::cerr;
			break;
		case level_t::warn:
			sLevel = "WARN";
			stream = &std::cout;
			break;
		case level_t::info:
			sLevel = "INFO";
			stream = &std::cout;
			break;
		case level_t::debug:
			sLevel = "DEBUG";
			stream = &std::cout;
			break;
		case level_t::trace:
			sLevel = "TRACE";
			stream = &std::cout;
			break;
	}

	{
		std::lock_guard<std::mutex> lock(logLock);
		fmt::fprintf(
			*stream,
			"%7.7s [%" PRIxPTR "] [%5s] ",
			component,
			reinterpret_cast<uintptr_t>(&threadMarker),
			sLevel
		);

		fmt::vfprintf(*stream, fmt, args);
		fmt::print(*stream, "\n");
	}
}
