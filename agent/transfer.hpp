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
#ifndef _TRANSFER_HPP
#define _TRANSFER_HPP

#include <future>
#include <array>
#include <unordered_map>

namespace nimrod {

class txman;

namespace tx {

enum class error_type
{
	/* No error */
	none,
	/* A transfer error, such as HTTP 403/404, etc. */
	transfer,
	/* An error with the transfer backend, such as cURL. */
	backend,
	/* An error with the arguments -- invalid path, etc. */
	argument,
	/* System error. */
	system
};

enum class operation_t { get, put };

using transfer_id_type = size_t;
using result_type = std::pair<error_type, std::pair<int, std::string>>;
using future_type = std::future<result_type>;
using promise_type = std::promise<result_type>;

class transfer_backend;

}

class txman
{
public:
	using backend_ptr = std::unique_ptr<tx::transfer_backend>;
	using future_pair = std::pair<size_t, tx::future_type>;

	txman(nimrod::uuid uuid, CURLM *mh, X509_STORE *x509, bool verifyPeer, bool verifyHost);

	virtual ~txman() = default;
	txman(const txman&) = delete;
	txman(txman&&) = delete;

	txman& operator=(const txman&) = delete;
	txman& operator=(txman&&) = delete;

	static future_pair default_future_pair() { return std::make_pair(0, tx::future_type()); }

	future_pair do_transfer(tx::operation_t op, const UriUriA *uri, const filesystem::path& path);

	void cancel(size_t id);
	void cancel(const future_pair& fp);

	nimrod::uuid uuid() const noexcept;

private:
	constexpr static size_t max_backends = 16;

	void result_handler(tx::transfer_backend *tx, tx::result_type&& res);

	static future_pair make_error(size_t id, tx::error_type err, int ret, const char *msg);

	struct backend_pool
	{
		std::vector<backend_ptr> instances;
		std::vector<tx::transfer_backend*> free;
	};

	struct scheme_entry
	{
		const char *scheme;
		backend_pool *pool;
	};

	struct ops_data
	{
		tx::transfer_backend *tx;
		tx::promise_type promise;
		backend_pool *pool;
	};

	size_t m_next_id;
	std::unordered_map<tx::transfer_id_type, ops_data> m_ops;
	std::array<backend_pool, max_backends> m_backends;
	std::array<scheme_entry, max_backends> m_schemes;

	nimrod::uuid m_uuid;
};

}

#endif /* _TRANSFER_HPP */