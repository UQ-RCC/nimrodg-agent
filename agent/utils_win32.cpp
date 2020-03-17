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

#include "utils_win32.hpp"
#ifdef NIMRODG_USE_WIN32API

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <memory>

using namespace nimrod;

void win32::handle_deleter::operator()(HANDLE h)
{
	if(h != INVALID_HANDLE_VALUE)
		CloseHandle(h);
}

std::system_error win32::make_win32_exception(DWORD dwErr)
{
	std::error_code ec(dwErr, std::system_category());
	throw std::system_error(ec);
}

std::wstring win32::to_win_wchar(const std::string& s)
{
	if(s.empty())
		return L"";

	/* Get the required size. */
	int x = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);

	if(x == 0)
		throw make_win32_exception(GetLastError());

	/* Get the string. */
	std::vector<wchar_t> ws(x);
	x = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), ws.data(), static_cast<int>(ws.size()));

	if(x == 0)
		throw make_win32_exception(GetLastError());

	return std::wstring(ws.begin(), ws.end());
}

std::string win32::from_win_wchar(const std::wstring& ws)
{
	if(ws.empty())
		return "";

	int x = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), static_cast<int>(ws.size()), nullptr, 0, nullptr, nullptr);
	if(x == 0)
		throw make_win32_exception(GetLastError());

	std::vector<char> s(x);
	x = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), static_cast<int>(ws.size()), s.data(), static_cast<int>(s.size()), nullptr, nullptr);

	if(x == 0)
		throw make_win32_exception(GetLastError());

	return std::string(s.begin(), s.end());
}


std::string win32::get_win32_error_message(DWORD dwErr)
{
	LPWSTR buffer;
	DWORD oshite = FormatMessageW(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
		nullptr,
		dwErr,
		0,
		reinterpret_cast<LPWSTR>(&buffer), 0,
		nullptr);

	if(oshite == FALSE)
	{
		return "Cannot retrieve error message, FormatMessageW() failed.";
	}

	std::unique_ptr<WCHAR, decltype(LocalFree)*> lp(buffer, &LocalFree);

	std::wstring ws(buffer);
	ws.erase(ws.find_last_not_of(L" \n\r\t") + 1);
	return from_win_wchar(ws);
}




bool win32::wcs_lexicographical_less::operator()(const std::wstring& a, const std::wstring& b) const noexcept
{
	return _wcsicmp(a.c_str(), b.c_str()) < 0;
}


/* Extract the environment variables and parse them into a map. */
win32::wenvironment_map win32::create_environment_map(LPWCH envBlock)
{
	wenvironment_map envs;

	for(PWCH env = envBlock; *env != L'\0'; )
	{
		size_t len = wcslen(env);
		PWCH equals = wcsstr(env, L"=");
		std::wstring key(env, equals);
		envs[key] = std::wstring(equals + 1, env + len);
		env += len + 1;
	}

	return envs;
}

using wenv_ptr = std::unique_ptr<WCHAR, decltype(FreeEnvironmentStringsW)*>;
win32::wenvironment_map win32::create_environment_map_from_system()
{
	wenv_ptr wenv(GetEnvironmentStringsW(), &FreeEnvironmentStringsW);

	return create_environment_map(wenv.get());
}



std::vector<wchar_t> win32::create_environment_block(const wenvironment_map& env)
{
	std::vector<wchar_t> eb;

	for(auto& e : env)
	{
		eb.insert(eb.end(), e.first.begin(), e.first.end());
		eb.push_back(L'=');
		eb.insert(eb.end(), e.second.begin(), e.second.end());
		eb.push_back(L'\0');
	}
	eb.push_back(L'\0');
	return eb;
}

std::wstring win32::build_win32w_cmdline(const std::vector<std::string>& args)
{
	std::wstring cmdline;

	for(auto& arg : args)
	{
		if(!cmdline.empty())
			cmdline.append(L" ");
		std::wstring warg = to_win_wchar(arg);
		ArgvQuote(warg, cmdline, false);
	}

	return cmdline;
}


//https://blogs.msdn.microsoft.com/twistylittlepassagesallalike/2011/04/23/everyone-quotes-command-line-arguments-the-wrong-way/
void win32::ArgvQuote(const std::wstring& Argument, std::wstring& CommandLine, bool Force)

/*++

Routine Description:

This routine appends the given argument to a command line such
that CommandLineToArgvW will return the argument string unchanged.
Arguments in a command line should be separated by spaces; this
function does not add these spaces.

Arguments:

Argument - Supplies the argument to encode.

CommandLine - Supplies the command line to which we append the encoded argument string.

Force - Supplies an indication of whether we should quote
the argument even if it does not contain any characters that would
ordinarily require quoting.

Return Value:

None.

Environment:

Arbitrary.

--*/

{
	//
	// Unless we're told otherwise, don't quote unless we actually
	// need to do so --- hopefully avoid problems if programs won't
	// parse quotes properly
	//

	if(Force == false &&
		Argument.empty() == false &&
		Argument.find_first_of(L" \t\n\v\"") == Argument.npos)
	{
		CommandLine.append(Argument);
	}
	else
	{
		CommandLine.push_back(L'"');

		for(auto It = Argument.begin(); ; ++It)
		{
			unsigned NumberBackslashes = 0;

			while(It != Argument.end() && *It == L'\\')
			{
				++It;
				++NumberBackslashes;
			}

			if(It == Argument.end())
			{

				//
				// Escape all backslashes, but let the terminating
				// double quotation mark we add below be interpreted
				// as a metacharacter.
				//

				CommandLine.append(NumberBackslashes * 2, L'\\');
				break;
			}
			else if(*It == L'"')
			{

				//
				// Escape all backslashes and the following
				// double quotation mark.
				//

				CommandLine.append(NumberBackslashes * 2 + 1, L'\\');
				CommandLine.push_back(*It);
			}
			else
			{

				//
				// Backslashes aren't special here.
				//

				CommandLine.append(NumberBackslashes, L'\\');
				CommandLine.push_back(*It);
			}
		}

		CommandLine.push_back(L'"');
	}
}
#endif