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
#include "agent_common.hpp"
#include "transfer_backend.hpp"
#include "curl_backend.hpp"

using namespace nimrod;
using namespace nimrod::tx;

#if defined(NIMRODG_USE_WIN32API)
#	include "win32_backend.hpp"
using local_backend_type = win32::win32_backend;
#elif defined(NIMRODG_USE_POSIX)
#	include "posix_backend.hpp"
using local_backend_type = posix::posix_backend;
#else
#	error No local transfer backend defined
#endif

template <typename... Args>
static txman::backend_ptr create_local_backend(Args&&... args)
{
	return std::make_unique<local_backend_type>(std::forward<Args>(args)...);
}

transfer_backend::transfer_backend(txman& tx, result_proc proc) :
	m_tx(tx),
	m_proc(proc)
{}

void transfer_backend::set_result(result_type&& res)
{
	return (m_tx.*m_proc)(this, std::move(res));
}

void transfer_backend::set_error(error_type err, int ret, const char *msg)
{
	return set_result(std::make_pair(err, std::make_pair(-1, msg)));
}

void transfer_backend::set_errno(int err)
{
	return this->set_error(error_type::system, err, strerror(errno));
}

nimrod::uuid transfer_backend::uuid() const noexcept
{
	return m_tx.uuid();
}

txman::txman(nimrod::uuid uuid, CURLM *mh, X509_STORE *x509, bool verifyPeer, bool verifyHost) :
	m_next_id(1),
	m_uuid(uuid)
{

	auto add_instance = [](backend_pool *pool, backend_ptr&& ptr) {
		pool->free.push_back(pool->instances.emplace_back(std::move(ptr)).get());
	};

	/*
	** Only one instance for now. In the far distant future when
	** concurrent transfers are supported, this should be configurable.
	*/
	backend_pool *curlPool = &m_backends[0];
	add_instance(curlPool, std::make_unique<curl_backend>(*this, &txman::result_handler, mh, x509, verifyPeer, verifyHost));

	backend_pool *localPool = &m_backends[1];
	add_instance(localPool, create_local_backend(*this, &txman::result_handler));

	for(auto& s : m_schemes)
		s = { .scheme = nullptr, .pool = nullptr };

	m_schemes[0] = { "http",	curlPool };		/* cURL, native */
	m_schemes[1] = { "https",	curlPool };		/* cURL, native */
	m_schemes[2] = { "ftp",		curlPool };		/* cURL, native */
	m_schemes[3] = { "ftps",	curlPool };		/* cURL, native */
	m_schemes[4] = { "tftp",	curlPool };		/* cURL, native */
	m_schemes[5] = { "gopher",	curlPool };		/* cURL, native */
	m_schemes[6] = { "scp",		curlPool };		/* cURL, native */
	m_schemes[7] = { "sftp",	curlPool };		/* cURL, native */
	m_schemes[8] = { "file",	localPool };	/* POSIX: Use Splice, Win32: Use CopyFileExW */
}


void txman::cancel(size_t id)
{
	if(auto it = m_ops.find(id); it != m_ops.end())
		it->second.tx->cancel();
}

void txman::cancel(const future_pair& fp)
{
	return this->cancel(fp.first);
}

nimrod::uuid txman::uuid() const noexcept
{
	return m_uuid;
}

txman::future_pair txman::do_transfer(tx::operation_t op, const UriUriA *uri, const filesystem::path& path)
{
	if(!uri || !uri->scheme.first || !uri->scheme.afterLast || uri->scheme.first > uri->scheme.afterLast)
		return make_error(0, tx::error_type::argument, -1, "Invalid or NULL URI");

	ptrdiff_t len = reinterpret_cast<uintptr_t>(uri->scheme.afterLast) - reinterpret_cast<uintptr_t>(uri->scheme.first);

	auto se = std::find_if(m_schemes.begin(), m_schemes.end(), [uri, len](const scheme_entry& e) {
		if(e.scheme == nullptr)
			return false;

		return c_strnicmp(uri->scheme.first, e.scheme, static_cast<size_t>(len)) == 0;
	});

	if(se == m_schemes.end())
		return make_error(0, tx::error_type::argument, -1, "Unrecognised URI scheme");

	if(se->pool == nullptr)
		return make_error(0, tx::error_type::backend, -1, "No backend for scheme");

	if(se->pool->free.empty())
		return make_error(0, tx::error_type::backend, -1, "Out of transfer providers");

	transfer_backend *b = se->pool->free.back();

	size_t id = m_next_id++;
	ops_data ops;
	ops.tx = b;
	ops.promise = promise_type();
	ops.pool = se->pool;

	auto it2 = m_ops.emplace(std::make_pair(id, std::move(ops))).first;
	se->pool->free.pop_back();

	txman::future_pair ret = std::make_pair(id, it2->second.promise.get_future());

	/* Do this last, as it may fail immediately and undo what we've just done. */
	b->do_transfer(op, uri, path);
	return ret;
}

void txman::result_handler(transfer_backend *tx, result_type&& res)
{
	/* Do a linear search, I don't want to maintain multiple maps. */
	auto fp = std::find_if(m_ops.begin(), m_ops.end(), [tx](const auto& p) {
		return p.second.tx == tx;
	});

	if(fp == m_ops.end())
	{
		/* Umm, what? */
		return;
	}

	fp->second.pool->free.push_back(tx);
	fp->second.promise.set_value(std::move(res));
	m_ops.erase(fp);
}

txman::future_pair txman::make_error(size_t id, error_type err, int ret, const char *msg)
{
	promise_type p;
	p.set_value(std::make_pair(err, std::make_pair(-1, msg)));
	return std::make_pair(0, p.get_future());
}
