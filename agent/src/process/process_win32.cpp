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
#include "process_win32.hpp"
#ifdef NIMRODG_USE_WIN32API
#include <shellapi.h>
#include <cassert>
#include "log.hpp"

/* For NTSTATUS, we're not actually using any symbols from here. */
#include <winternl.h>

using namespace nimrod;
using namespace nimrod::win32;

/* Attempt 1: Post a WM_QUIT to the main thread. */
static bool killByWmQuit(LPPROCESS_INFORMATION pi) noexcept
{
	return PostThreadMessageW(pi->dwThreadId, WM_QUIT, 0, 0) != 0;
}

/* Attempt 2: Post a WM_CLOSE to the main thread. */
static bool killByWmClose(LPPROCESS_INFORMATION pi) noexcept
{
	return PostThreadMessageW(pi->dwThreadId, WM_CLOSE, 0, 0) != 0;
}

/* Attempt 3: TerminateProcess() */
static bool killByTerminateProcess(LPPROCESS_INFORMATION pi) noexcept
{
	return TerminateProcess(pi->hProcess, 0xFFFFFFFF) != 0;
}

/* Attempt 4: NtTerminateProcess() */
static bool killByNtTerminateProcess(LPPROCESS_INFORMATION pi) noexcept
{
	using NTTERMINATEPROCESS = NTSTATUS(WINAPI *)(HANDLE, NTSTATUS);
	HMODULE hNtDll = GetModuleHandleW(L"ntdll");
	if(hNtDll == nullptr)
		return false;

	NTTERMINATEPROCESS NtTerminateProcess = reinterpret_cast<NTTERMINATEPROCESS>(GetProcAddress(hNtDll, "NtTerminateProcess"));
	if(NtTerminateProcess == nullptr)
		return false;

#ifndef STATUS_SUCCESS
#	define STATUS_SUCCESS 0x00000000
#endif
	/* NTSTATUS Codes: https://msdn.microsoft.com/en-au/library/cc704588.aspx */
	return NtTerminateProcess(pi->hProcess, STATUS_CONTROL_C_EXIT) == STATUS_SUCCESS;
}

using KILLPROC = bool(*)(LPPROCESS_INFORMATION);

static KILLPROC s_KillProcs[] = {
	killByWmClose,
	killByWmQuit,
	killByTerminateProcess,
	killByNtTerminateProcess
};

static constexpr size_t s_NumKillProcs = sizeof(s_KillProcs) / sizeof(s_KillProcs[0]);

/*
** Try to kill the process, starting off gentle, and gradually getting to
** "oi ntoskrnl, can you kill this pls?"
*/

static int trykill(LPPROCESS_INFORMATION pi, float timeout) noexcept
{
	DWORD dwWait = static_cast<DWORD>((timeout * 1000));

	/* First see if it's already dead. */
	if(WaitForSingleObject(pi->hProcess, 0) == WAIT_OBJECT_0)
		return 0;

	size_t i;
	for(i = 0; i < s_NumKillProcs; ++i)
	{
		if(!s_KillProcs[i](pi))
			continue;

		DWORD dwResult = WaitForSingleObject(pi->hProcess, dwWait);
		if(dwResult == WAIT_OBJECT_0)
			break;
	}

	if(i == s_NumKillProcs)
	{
		/*
		** All methods failed. Process is probably hung on a driver IO request
		** or something like that. Not much we can do.
		*/
		return -1;
	}

	return 0;
}


void win32::process_information_deleter::operator()(LPPROCESS_INFORMATION pi)
{
	CloseHandle(pi->hThread);
	CloseHandle(pi->hProcess);
}

static void setup_appending(HANDLE h, bool append)
{
	/* This only makes sense on actual files. */
	if(GetFileType(h) != FILE_TYPE_DISK)
		return;

	/* If appending, seek to EOF. */
	if(append)
	{
		if(SetFilePointer(h, 0, nullptr, FILE_END) == INVALID_SET_FILE_POINTER)
			throw make_win32_exception(GetLastError());
		return;
	}

	/* If not, rewind and truncate. */
	if(SetFilePointer(h, 0, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
		throw make_win32_exception(GetLastError());

	if(!SetEndOfFile(h))
		throw make_win32_exception(GetLastError());
}

win32process::win32process(
	const filesystem::path& path,
	const std::vector<std::string>& args,
	const filesystem::path& cwd,
	const environment_map& env,
	iofile out,
	iofile err)
{
	/* Store all the initial stuff */
	m_initial.path = path;
	m_initial.args = args;
	m_initial.cwd = cwd;
	m_initial.env = env;

	/* Build a Win32 command line from the arguments */
	m_cmdline = build_win32w_cmdline(args);

	/* Convert the environment map into Win32 Wide Strings */
	wenvironment_map wenv;
	for(auto& e : env)
		wenv[to_win_wchar(e.first)] = to_win_wchar(e.second);

	/* Get our environment variables. */
	m_envmap = create_environment_map_from_system();

	/* Merge then with our specified ones. */
	m_envmap.insert(wenv.begin(), wenv.end());

	/* Convert our merged environment variables back to UTF-8 */
	for(auto& e : m_envmap)
		m_initial.env_merged[from_win_wchar(e.first)] = from_win_wchar(e.second);

	/* Build the environment block. */
	m_envblock = create_environment_block(m_envmap);

	STARTUPINFOW si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = INVALID_HANDLE_VALUE;
	si.hStdOutput = out;
	si.hStdError = err;

	/* CreateProcessW() needs a mutable cmdline. */
	std::vector<wchar_t> cpws_stupid_mutable_cmdline(m_cmdline.begin(), m_cmdline.end());
	cpws_stupid_mutable_cmdline.push_back(L'\0');

	/*
	** From MSDN: CREATE_NO_WINDOW
	** The process is a console application that is being run without a console window. Therefore, the console
	** handle for the application is not set.
	**
	** This flag is ignored if the application is not a console application, or if it is used with either
	** CREATE_NEW_CONSOLE or DETACHED_PROCESS.
	*/
	if(!CreateProcessW(
		path.c_str(),
		cpws_stupid_mutable_cmdline.data(),
		nullptr,
		nullptr,
		TRUE,
		CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | /*CREATE_NO_WINDOW | */ NORMAL_PRIORITY_CLASS /* | CREATE_NEW_CONSOLE*/,
		m_envblock.data(),
		cwd.c_str(),
		&si,
		&m_pi
	))
	{
		DWORD dwErr = GetLastError();
		log::error("PROCESS", "CreateProcessW() failed with error %d.", dwErr);
		log::error("PROCESS", "  %s", get_win32_error_message(dwErr));
		throw make_win32_exception(dwErr);
	}

	m_process_information.reset(&m_pi);

	/* Start the process. */
	if(ResumeThread(m_pi.hThread) == 0xFFFFFFFF)
		throw make_win32_exception(GetLastError());

	m_waitthread = std::thread([this]() {
		if(WaitForSingleObject(this->m_pi.hProcess, INFINITE) != WAIT_OBJECT_0)
		{
			DWORD dwErr = GetLastError();
			log::error("PROCESS", "WaitForSingleObject() failed with error %d.", dwErr);
			log::error("PROCESS", "  %s", get_win32_error_message(dwErr));
			return this->m_promise.set_value(std::make_pair(0xFFFFFFFF, std::error_code(dwErr, std::system_category())));
		}

		DWORD dwResult;
		if(!GetExitCodeProcess(this->m_pi.hProcess, &dwResult))
		{
			DWORD dwErr = GetLastError();
			log::error("PROCESS", "GetExitCodeProcess() failed with error %d.", dwErr);
			log::error("PROCESS", "  %s", get_win32_error_message(dwErr));
			return this->m_promise.set_value(std::make_pair(0xFFFFFFFF, std::error_code(dwErr, std::system_category())));
		}

		return this->m_promise.set_value(std::make_pair(dwResult, std::error_code(ERROR_SUCCESS, std::system_category())));
	});
}

win32process::~win32process() noexcept
{
	killByNtTerminateProcess(m_process_information.get());
	m_waitthread.join();
	/* NB: The handle is valid until here, even after the process has died. */
	m_process_information.reset();
}

const filesystem::path& win32process::executable_path() const noexcept
{
	return m_initial.path;
}

const filesystem::path& win32process::initial_working_directory() const noexcept
{
	return m_initial.cwd;
}

const process::environment_map& win32process::initial_environment_variables() const noexcept
{
	return m_initial.env;
}

const process::environment_map& win32process::initial_merged_environment_variables() const noexcept
{
	return m_initial.env_merged;
}

std::future<win32process::process_result> win32process::get_future()
{
	return m_promise.get_future();
}

void win32process::kill(bool force) noexcept
{
	if(force)
		killByNtTerminateProcess(m_process_information.get());
	else
		killByWmClose(m_process_information.get());
}

void win32process::reap_impl(size_t numproc, va_list ap)
{
	/* We don't have signals. */
}

filesystem::path win32process::get_system_interpreter_impl()
{
	DWORD x = GetEnvironmentVariableW(L"ComSpec", nullptr, 0);
	if(x == 0)
		return "";

	std::vector<wchar_t> ws(x);

	GetEnvironmentVariableW(L"ComSpec", ws.data(), x);

	return from_win_wchar(std::wstring(ws.begin(), ws.end()));
}

filesystem::path win32process::search_path_impl(const std::string& program)
{
	std::wstring wp = to_win_wchar(program);
	DWORD x = SearchPathW(nullptr, wp.c_str(), L".exe", 0, nullptr, nullptr);
	if(x == 0)
		throw make_win32_exception(GetLastError());

	std::vector<wchar_t> path(x);

	x = SearchPathW(nullptr, wp.c_str(), L".exe", x, path.data(), nullptr);
	if(x == 0)
		throw make_win32_exception(GetLastError());

	return from_win_wchar(std::wstring(path.begin(), path.end()));
}

process::string_vector win32process::build_shell_args_impl(const std::string& cmdline)
{
	return { get_system_interpreter().u8string(), "/C", cmdline };
}

process::iofile_ptr win32process::create_iofile_impl(const filesystem::path& path, bool append)
{
	SECURITY_ATTRIBUTES sa;
	ZeroMemory(&sa, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = nullptr;
	sa.bInheritHandle = TRUE;

	handle_ptr hFile(CreateFileW(
		path.c_str(),
		FILE_GENERIC_WRITE,
		FILE_SHARE_READ,
		&sa,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	));

	if(hFile.get() == INVALID_HANDLE_VALUE)
		throw make_win32_exception(GetLastError());

	setup_appending(hFile.get(), append);

	return iofile_ptr(hFile.release());
}

process::iofile_ptr win32process::create_iofile_dup_impl(const filesystem::path& path, bool append, iofile existing)
{
	SECURITY_ATTRIBUTES sa;
	ZeroMemory(&sa, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = nullptr;
	sa.bInheritHandle = TRUE;

	const wchar_t *_path = !path.empty() ? path.c_str() : L"NUL";

	/* Open stderr in "query mode" in case they refer to the same file. */
	handle_ptr hStdErr(CreateFileW(_path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
	if(hStdErr.get() == INVALID_HANDLE_VALUE)
	{
		DWORD dwErr = GetLastError();
		if(dwErr != ERROR_FILE_NOT_FOUND)
			throw make_win32_exception(dwErr);

		/* If the file doesn't exist, create it and get outta here. */
		hStdErr.reset(CreateFileW(_path, FILE_GENERIC_WRITE, FILE_SHARE_READ, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));

		if(hStdErr.get() == INVALID_HANDLE_VALUE)
			throw make_win32_exception(dwErr);

		return iofile_ptr(hStdErr.release());
	}

	HANDLE hStdOut = existing;

	/*
	** Both files exist and are opened.
	** If the files are both on-disk files, see if they're the same object.
	*/
	DWORD outType = GetFileType(hStdOut);
	DWORD errType = GetFileType(hStdErr.get());
	if(hStdOut != INVALID_HANDLE_VALUE && hStdOut != nullptr && outType == errType && outType == FILE_TYPE_DISK)
	{
		BY_HANDLE_FILE_INFORMATION outInfo;
		ZeroMemory(&outInfo, sizeof(outInfo));
		if(!GetFileInformationByHandle(hStdOut, &outInfo))
			throw make_win32_exception(GetLastError());

		BY_HANDLE_FILE_INFORMATION errInfo;
		ZeroMemory(&errInfo, sizeof(errInfo));
		if(!GetFileInformationByHandle(hStdErr.get(), &errInfo))
			throw make_win32_exception(GetLastError());

		uint64_t outIndex = (static_cast<uint64_t>(outInfo.nFileIndexHigh) << 32) | outInfo.nFileIndexLow;
		uint64_t errIndex = (static_cast<uint64_t>(errInfo.nFileIndexHigh) << 32) | errInfo.nFileIndexLow;
		if(outInfo.dwVolumeSerialNumber == errInfo.dwVolumeSerialNumber && outIndex == errIndex)
		{
			/* They both reference the same file, duplicate the handle. */
			HANDLE hThis = GetCurrentProcess();
			HANDLE hOut = nullptr;
			if(!DuplicateHandle(hThis, hStdOut, hThis, &hOut, 0, TRUE, DUPLICATE_SAME_ACCESS))
				throw make_win32_exception(GetLastError());

			return iofile_ptr(hOut);
		}
	}

	/* They reference different files (or are different types). Reopen the stderr in exclusive mode. */
	hStdErr.reset(ReOpenFile(hStdErr.get(), FILE_GENERIC_WRITE, FILE_SHARE_READ, 0));
	if(hStdErr.get() == INVALID_HANDLE_VALUE)
		throw make_win32_exception(GetLastError());

	/* ReOpenFile()'d handles aren't inheritable. Make it so. */
	if(!SetHandleInformation(hStdErr.get(), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
		throw make_win32_exception(GetLastError());

	return iofile_ptr(hStdErr.release());
}

process::iofile_ptr win32process::create_iofile_null_impl()
{
	return iofile_ptr(INVALID_HANDLE_VALUE);

	SECURITY_ATTRIBUTES sa;
	ZeroMemory(&sa, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = nullptr;
	sa.bInheritHandle = TRUE;

	HANDLE hNul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ, &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if(hNul == INVALID_HANDLE_VALUE)
		throw make_win32_exception(GetLastError());

	return iofile_ptr(hNul);
}

void win32process::delete_iofile_impl(iofile f)
{
	if(f == nullptr)
		return;

	return handle_deleter().operator()(f);
}

#endif