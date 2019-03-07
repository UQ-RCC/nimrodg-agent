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
#ifndef _TRANSFER_CURL_BACKEND_HPP
#define _TRANSFER_CURL_BACKEND_HPP

#include "log.hpp"
#include "transfer_backend.hpp"
#include <cstdio>
#include <curl/curl.h>
#include <uriparser/Uri.h>
#include <mutex>

namespace nimrod::tx {

class curl_backend : public transfer_backend
{
private:
	enum class state_t
	{
		ready,
		in_get,
		in_put
	};

public:
	curl_backend(txman& tx, result_proc proc, CURLM *mh, X509_STORE *x509, bool verifyPeer, bool verifyHost);

	void get(const Ugit riUriA *uri, const filesystem::path& path, const char *token) override;
	void put(const UriUriA *uri, const filesystem::path& path, const char *token) override;
	void cancel() override;

	void _handle_message(CURLMsg *msg);
private:

	struct deleter_curl { void operator()(CURL *c) const; };
	using curl_ptr = std::unique_ptr<CURL, deleter_curl>;

	struct deleter_curl_slist { void operator()(struct curl_slist *l) const; };
	using curl_slist_ptr = std::unique_ptr<struct curl_slist, deleter_curl_slist>;

	void doit(const UriUriA *uri, const filesystem::path& path, const char *token, state_t state);

	size_t write_proc(char *ptr, size_t size, size_t nmemb) noexcept;
	size_t read_proc(char *ptr, size_t size, size_t nmemb) noexcept;
	int xferinfo_proc(curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) noexcept;

	std::atomic<state_t> m_state;
	std::atomic_bool m_cancelflag;

	CURLM *m_mh;
	curl_ptr m_context;
	curl_slist_ptr m_headers;
	file_ptr m_file;
	std::string m_uristring;

	std::recursive_mutex m_mutex;
};
}
#endif /* _TRANSFER_CURL_BACKEND_HPP */