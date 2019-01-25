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
#ifndef _TRANSFER_WIN32_BACKEND_HPP
#define _TRANSFER_WIN32_BACKEND_HPP

#include "config.h"

#if defined(NIMRODG_USE_WIN32API)
#include "transfer_backend.hpp"
#include "utils_win32.hpp"

namespace nimrod::win32 {

class win32_backend : public tx::transfer_backend
{
private:
	enum class state_t { ready, busy, waiting_to_stop };

public:
	win32_backend(txman& tx, tx::result_proc proc);

	void get(const UriUriA *uri, const filesystem::path& path, const char *token) override;
	void put(const UriUriA *uri, const filesystem::path& path, const char *token) override;

	void cancel() override;

private:
	void doit(const UriUriA *uri, const filesystem::path& path, const char *token, bool put);

	DWORD CALLBACK cpr_proc(
		LARGE_INTEGER TotalFileSize,
		LARGE_INTEGER TotalBytesTransferred,
		LARGE_INTEGER StreamSize,
		LARGE_INTEGER StreamBytesTransferred,
		DWORD dwStreamNumber,
		DWORD dwCallbackReason,
		HANDLE hSourceFile,
		HANDLE hDestinationFile
	);

	static DWORD CALLBACK cpr_stub(
		LARGE_INTEGER TotalFileSize,
		LARGE_INTEGER TotalBytesTransferred,
		LARGE_INTEGER StreamSize,
		LARGE_INTEGER StreamBytesTransferred,
		DWORD dwStreamNumber,
		DWORD dwCallbackReason,
		HANDLE hSourceFile,
		HANDLE hDestinationFile,
		LPVOID lpData
	);

	state_t m_state;
	std::atomic_bool m_stopflag;
};

}

#endif
#endif /* _TRANSFER_WIN32_BACKEND_HPP */
