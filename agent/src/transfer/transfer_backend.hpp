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
#ifndef _TRANSFER_TRANSFER_BACKEND_HPP
#define _TRANSFER_TRANSFER_BACKEND_HPP

#include "agent_fwd.hpp"
#include "transfer.hpp"
#include <tuple>

namespace nimrod {

namespace tx {

using result_proc = void(txman::*)(transfer_backend *self, result_type&& res);

class transfer_backend
{
public:

	virtual ~transfer_backend() = default;
	transfer_backend(const transfer_backend&) = delete;
	transfer_backend(transfer_backend&&) = delete;

	transfer_backend& operator=(const transfer_backend&) = delete;
	transfer_backend& operator=(transfer_backend&&) = delete;

	virtual void get(const UriUriA *uri, const filesystem::path& path, const char *token) = 0;
	virtual void put(const UriUriA *uri, const filesystem::path& path, const char *token) = 0;

	virtual void cancel() = 0;

protected:
	transfer_backend(txman& tx, result_proc proc);

	void set_result(result_type&& res);
	void set_error(error_type err, int ret, const char *msg);
	nimrod::uuid uuid() const noexcept;
	const char *uuid_string() const noexcept;
private:
	txman& m_tx;
	result_proc m_proc;

	friend class txman;
};
}
}

#endif /* _TRANSFER_TRANSFER_BACKEND_HPP */