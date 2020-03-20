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
#ifndef _NIMROD_LOG_HPP
#define _NIMROD_LOG_HPP

#include "config.h"

#if defined(_WIN32)
#	ifndef FMT_USE_WINDOWS_H
#		define FMT_USE_WINDOWS_H 0
#	endif
#endif

#include <fmt/printf.h>

namespace nimrod::log {

enum class level_t { trace, debug, info, warn, error };

void vmanual(level_t level, const char *component, const char *fmt, fmt::printf_args args);

template<typename... Args>
void manual(level_t level, const char *component, const char *fmt, Args&&... args)
{
	return vmanual(level, component, fmt, fmt::make_printf_args(args...));
}

template<typename... Args>
void trace(const char *component, const char *fmt, Args&&... args)
{
	return manual(level_t::trace, component, fmt, std::forward<Args&&>(args)...);
}

template<typename... Args>
void debug(const char *component, const char *fmt, Args&&... args)
{
	return manual(level_t::debug, component, fmt, std::forward<Args&&>(args)...);
}

template<typename... Args>
void info(const char *component, const char *fmt, Args&&... args)
{
	return manual(level_t::info, component, fmt, std::forward<Args&&>(args)...);
}

template<typename... Args>
void warn(const char *component, const char *fmt, Args&&... args)
{
	return manual(level_t::warn, component, fmt, std::forward<Args&&>(args)...);
}

template<typename... Args>
void error(const char *component, const char *fmt, Args&&... args)
{
	return manual(level_t::error, component, fmt, std::forward<Args&&>(args)...);
}

}
#endif /* _NIMROD_LOG_HPP */
