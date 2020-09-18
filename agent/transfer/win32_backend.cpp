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
#include "config.h"
#if defined(NIMRODG_USE_WIN32API)
#include "agent_common.hpp"
#include "win32_backend.hpp"

using namespace nimrod;
using namespace nimrod::tx;
using namespace nimrod::win32;

win32_backend::win32_backend(txman& tx, result_proc proc) :
	transfer_backend(tx, proc),
	m_state(state_t::ready),
	m_stopflag(false)
{}

void win32_backend::do_transfer(tx::operation_t op, const UriUriA *uri, const filesystem::path& path)
{
	if(m_state != state_t::ready)
		throw std::logic_error("Invalid state transition");

	if(uri == nullptr)
		return this->set_error(error_type::argument, -1, "Invalid URI");

	if(path.empty())
		return this->set_error(error_type::argument, -1, "Invalid path");

	std::string pathstring = uristring_to_path(uri_to_string(uri));
	if(pathstring.empty())
		return this->set_error(error_type::argument, -1, "Invalid path");

	std::wstring src = win32::to_win_wchar(pathstring);
	std::wstring dest = path.c_str();

	if(op == tx::operation_t::put)
		src.swap(dest);

	//fprintf(stderr, "source = %ls, dest = %ls\n", src.c_str(), dest.c_str());
	std::thread([this, src, dest]() {
		m_state = state_t::busy;

		BOOL cflag = false;
		DWORD dwErr = ERROR_SUCCESS;
		if(!CopyFileExW(src.c_str(), dest.c_str(), cpr_stub, this, &cflag, 0))
			dwErr = GetLastError();

		m_state = state_t::ready;
		this->set_result(std::make_pair(
			dwErr == ERROR_SUCCESS ? error_type::none : error_type::system,
			std::make_pair(dwErr, win32::get_win32_error_message(dwErr))
		));
	}).detach();
}

void win32_backend::cancel()
{
	if(m_state != state_t::busy)
		return;

	m_stopflag.store(true);
}

DWORD CALLBACK win32_backend::cpr_proc(
	LARGE_INTEGER TotalFileSize,
	LARGE_INTEGER TotalBytesTransferred,
	LARGE_INTEGER StreamSize,
	LARGE_INTEGER StreamBytesTransferred,
	DWORD dwStreamNumber,
	DWORD dwCallbackReason,
	HANDLE hSourceFile,
	HANDLE hDestinationFile)
{
	bool exp = true;
	if(m_stopflag.compare_exchange_strong(exp, false))
		return PROGRESS_CANCEL;
	else
		return PROGRESS_CONTINUE;
}

DWORD CALLBACK win32_backend::cpr_stub(
	LARGE_INTEGER TotalFileSize,
	LARGE_INTEGER TotalBytesTransferred,
	LARGE_INTEGER StreamSize,
	LARGE_INTEGER StreamBytesTransferred,
	DWORD dwStreamNumber,
	DWORD dwCallbackReason,
	HANDLE hSourceFile,
	HANDLE hDestinationFile,
	LPVOID lpData)
{
	return reinterpret_cast<win32_backend*>(lpData)->cpr_proc(
		TotalFileSize,
		TotalBytesTransferred,
		StreamSize,
		StreamBytesTransferred,
		dwStreamNumber,
		dwCallbackReason,
		hSourceFile,
		hDestinationFile
	);
}

#endif