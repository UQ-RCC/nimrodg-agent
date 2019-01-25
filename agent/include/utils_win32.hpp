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
#ifndef _NIMRODG_UTILS_WIN32_HPP
#define _NIMRODG_UTILS_WIN32_HPP

#include "config.h"
#ifdef NIMRODG_USE_WIN32API

#include <string>
#include <map>
#include <vector>
#include <type_traits>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

namespace nimrod {
namespace win32 {

struct handle_deleter { void operator()(HANDLE h); };
using handle_ptr = std::unique_ptr<std::remove_pointer_t<HANDLE>, handle_deleter>;

/* Make an exception from a Win32 error code. */
std::system_error make_win32_exception(DWORD dwErr);

/* Convert a UTF-8 std::string to a Win32 Wide Char string. */
std::wstring to_win_wchar(const std::string& s);

/* Convert a Win32 WCHAR string into a UTF-8 std::string. */
std::string from_win_wchar(const std::wstring& ws);

/* FormatMessageW() to a string. */
std::string get_win32_error_message(DWORD dwErr);


/* Used to sort the environment block. */
struct wcs_lexicographical_less
{
	bool operator()(const std::wstring& a, const std::wstring& b) const noexcept;
};

using wenvironment_map = std::map<std::wstring, std::wstring, wcs_lexicographical_less>;

/* Extract the environment variables and parse them into a map. */
wenvironment_map create_environment_map(LPWCH envBlock);

/* Extract the current environment and dump them into a map. */
wenvironment_map create_environment_map_from_system(void);

/*
** Create the environment block.
** This is:
** XXXX=YYYY\0
** XXXX=YYYY\0
** XXXX=YYYY\0\0
**
** The variables should be lexicographically sorted.
*/
std::vector<wchar_t> create_environment_block(const wenvironment_map& env);

std::wstring build_win32w_cmdline(const std::vector<std::string>& args);

void ArgvQuote(const std::wstring& Argument, std::wstring& CommandLine, bool Force);

}
}

#endif /* NIMRODG_USE_WIN32API */
#endif /* _NIMRODG_UTILS_WIN32_HPP */
