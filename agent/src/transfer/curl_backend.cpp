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

/*
** cURL goes here.
*/
#include <uriparser/Uri.h>
#include "agent_common.hpp"
#include "curl_backend.hpp"

using namespace nimrod;
using namespace nimrod::tx;

/*
** NB:
** The curl_multi_add_handle() calls will never fail -- I've satisfied their preconditions.
*/


void nimrod::deleter_curl_multi::operator()(CURLM *m) const noexcept
{
	curl_multi_cleanup(m);
}

void tx::deleter_curl::operator()(CURL *c) const noexcept
{
	curl_easy_cleanup(c);
}

void tx::deleter_curl_slist::operator()(struct curl_slist *l) const noexcept
{
	curl_slist_free_all(l);
}

curl_backend::curl_backend(txman& tx, result_proc proc, CURLM *mh, X509_STORE *x509, bool verifyPeer, bool verifyHost) :
	transfer_backend(tx, proc),
	m_state(state_t::ready),
	m_cancelflag(false),
	m_mh(mh),
	m_context(curl_easy_init())
{
	if(!m_context)
		throw std::bad_alloc();

	int nwrite = snprintf(m_uuid_header.data(), m_uuid_header.size(), "%s: %s", http_header_key_uuid, tx.uuid_string());
	assert(nwrite == 58);

	curl_easy_setopt(m_context.get(), CURLOPT_VERBOSE, 1);
	curl_easy_setopt(m_context.get(), CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(m_context.get(), CURLOPT_CAINFO, nullptr);
	curl_easy_setopt(m_context.get(), CURLOPT_CAPATH, nullptr);
	curl_easy_setopt(m_context.get(), CURLOPT_SSL_VERIFYPEER, static_cast<long>(verifyPeer));
	curl_easy_setopt(m_context.get(), CURLOPT_SSL_VERIFYHOST, verifyHost ? 2 : 0);
	curl_easy_setopt(m_context.get(), CURLOPT_SSL_CTX_DATA, x509);
	curl_easy_setopt(m_context.get(), CURLOPT_SSL_CTX_FUNCTION, static_cast<curl_ssl_ctx_callback>([](CURL *curl, void *ctx, void *parm){
		set_ssl_store(reinterpret_cast<SSL_CTX*>(ctx), static_cast<X509_STORE*>(parm));
		return CURLE_OK;
	}));

	/* For SSH, allow both key auth and password. The password can be specified in the URI. Caveat emptor. */
	curl_easy_setopt(m_context.get(), CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_PASSWORD | CURLSSH_AUTH_PUBLICKEY);

	curl_easy_setopt(m_context.get(), CURLOPT_READDATA, this);
	curl_easy_setopt(m_context.get(), CURLOPT_READFUNCTION, static_cast<curl_read_callback>([](char *ptr, size_t size, size_t nmemb, void *user){
		return reinterpret_cast<curl_backend*>(user)->read_proc(ptr, size, nmemb);
	}));

	curl_easy_setopt(m_context.get(), CURLOPT_WRITEDATA, this);
	curl_easy_setopt(m_context.get(), CURLOPT_WRITEFUNCTION, static_cast<curl_write_callback>([](char *ptr, size_t size, size_t nmemb, void *user){
		return reinterpret_cast<curl_backend*>(user)->write_proc(ptr, size, nmemb);
	}));

	curl_easy_setopt(m_context.get(), CURLOPT_NOPROGRESS, 0);
	curl_easy_setopt(m_context.get(), CURLOPT_XFERINFOFUNCTION, static_cast<curl_xferinfo_callback>([](void *clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow){
		return reinterpret_cast<curl_backend*>(clientp)->xferinfo_proc(dltotal, dlnow, ultotal, ulnow);
	}));
	curl_easy_setopt(m_context.get(), CURLOPT_XFERINFODATA, this);

	curl_easy_setopt(m_context.get(), CURLOPT_PRIVATE, this);

	curl_easy_setopt(m_context.get(), CURLOPT_USERAGENT, NIMRODG_USER_AGENT);
}

static long get_curl_proto(CURL *curl) noexcept
{
	/*
	** There's a bit of screwy going on here. Sometimes CURLINFO_PROTOCOL is correct.
	** Sometimes it's 0. Same with CURLINFO_SCHEME.
	**
	** Try protocol, then try scheme. If all else fails, rip it out of the URI ourselves.
	*/
	long proto = 0;
	if(curl_easy_getinfo(curl, CURLINFO_PROTOCOL, &proto) != CURLE_OK)
		proto = 0;

	if(proto != 0)
		return proto;

	char *scheme = nullptr;
	if(curl_easy_getinfo(curl, CURLINFO_SCHEME, &scheme) != CURLE_OK)
		scheme = nullptr;

	if(scheme != nullptr)
	{
		/* Give me a scheme > 16 bytes. */
		char buf[16];

		strncpy(buf, scheme, sizeof(buf));
		buf[sizeof(buf) - 1] = '\0';

		if(!c_stricmp(buf, "http"))
			return CURLPROTO_HTTP;
		else if(!c_stricmp(buf, "https"))
			return CURLPROTO_HTTPS;
		else if(!c_stricmp(buf, "file"))
			return CURLPROTO_FILE;
		else if(!c_stricmp(buf, "ftp"))
			return CURLPROTO_FTP;
		else if(!c_stricmp(buf, "ftps"))
			return CURLPROTO_FTPS;
		else if(!c_stricmp(buf, "tftp"))
			return CURLPROTO_TFTP;
		else if(!c_stricmp(buf, "gopher"))
			return CURLPROTO_GOPHER;
		else if(!c_stricmp(buf, "sftp"))
			return CURLPROTO_SFTP;
		else if(!c_stricmp(buf, "scp"))
			return CURLPROTO_SCP;
	}

	char *url = nullptr;
	if(curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url) != CURLE_OK)
		return 0;

	char *end = strchr(url, ':');
	if(end == nullptr)
		return 0;

	size_t len = static_cast<size_t>(std::distance(url, end));

	if(!c_strnicmp(url, "http", len))
		return CURLPROTO_HTTP;
	else if(!c_strnicmp(url, "https", len))
		return CURLPROTO_HTTPS;
	else if(!c_strnicmp(url, "file", len))
		return CURLPROTO_FILE;
	else if(!c_strnicmp(url, "ftp", len))
		return CURLPROTO_FTP;
	else if(!c_strnicmp(url, "ftps", len))
		return CURLPROTO_FTPS;
	else if(!c_strnicmp(url, "tftp", len))
		return CURLPROTO_TFTP;
	else if(!c_strnicmp(url, "gopher", len))
		return CURLPROTO_GOPHER;
	else if(!c_strnicmp(url, "sftp", len))
		return CURLPROTO_SFTP;
	else if(!c_strnicmp(url, "scp", len))
		return CURLPROTO_SCP;

	return 0;
}

void curl_backend::_handle_message(CURLMsg *msg)
{
	std::lock_guard<std::recursive_mutex> lock(m_mutex);

	const char *errmsg = curl_easy_strerror(msg->data.result);

	if(msg->data.result == CURLE_OK)
	{
		long proto = get_curl_proto(m_context.get());
		if(proto == CURLPROTO_HTTP || proto == CURLPROTO_HTTPS)
		{
			long result = 0;
			curl_easy_getinfo(m_context.get(), CURLINFO_RESPONSE_CODE, &result);

			auto httpp = std::make_pair(static_cast<int>(result), fmt::format("HTTP Response {0}", result));

			if(result != 200 && result != 201 && result != 204)
				this->set_result(std::make_pair(error_type::transfer, httpp));
			else
				this->set_result(std::make_pair(error_type::none, httpp));
		}
		else if(proto == CURLPROTO_FTP || proto == CURLPROTO_FTPS)
		{
			long result = 0;
			curl_easy_getinfo(m_context.get(), CURLINFO_RESPONSE_CODE, &result);

			auto ftpp = std::make_pair(static_cast<int>(result), fmt::format("FTP Response {0}", result));

			/* https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes */
			if(result >= 200 && result < 300)
				this->set_result(std::make_pair(error_type::none, ftpp));
			else
				this->set_result(std::make_pair(error_type::transfer, ftpp));
		}
		else
		{
			this->set_result(std::make_pair(error_type::none, std::make_pair(0, "Success")));
		}
	}
	else
	{
		this->set_result(std::make_pair(error_type::backend, std::make_pair(-msg->data.result, errmsg)));
	}

	/* This is called on the network thread, it's safe to use this here. */
	curl_multi_remove_handle(m_mh, m_context.get());
	m_file.reset(nullptr);
	m_state = state_t::ready;
	m_cancelflag = false;
}

struct uri_query_list_deleter
{
	using pointer = UriQueryListA*;
	void operator()(pointer p) noexcept { uriFreeQueryListA(p); }
};
using uri_query_list_ptr = std::unique_ptr<UriQueryListA*, uri_query_list_deleter>;

static CURLcode apply_query_curlopts(CURL *ctx, const UriUriA *uri) noexcept
{
	if(uri->query.first == uri->query.afterLast)
		return CURLE_OK;

	UriQueryListA *_qlist = nullptr;
	int urierr = uriDissectQueryMallocA(&_qlist, nullptr, uri->query.first, uri->query.afterLast);
	if(urierr == URI_ERROR_MALLOC)
		return CURLE_OUT_OF_MEMORY;
	else if(urierr != URI_SUCCESS)
		return CURLE_URL_MALFORMAT;

	uri_query_list_ptr qlist(_qlist);

	struct
	{
		const char *ssh_private_keyfile;
		const char *ssh_host_public_key_md5;
		const char *keypasswd;
	} values = {
		.ssh_private_keyfile = NIMRODG_DEVNULL,
		.ssh_host_public_key_md5 = "00000000000000000000000000000000",
		.keypasswd = nullptr
	};

	for(UriQueryListA *e = qlist.get(); e != nullptr; e = e->next)
	{
		if(c_stricmp("nimrod_ssh_private_keyfile", e->key) == 0)
		{
			values.ssh_private_keyfile = e->value;
		}
		else if(c_stricmp("nimrod_ssh_host_public_key_md5", e->key) == 0)
		{
			if(strlen(e->value) == 32)
				values.ssh_host_public_key_md5 = e->value;
		}
		else if(c_stricmp("nimrod_keypasswd", e->key) == 0)
		{
			values.keypasswd = e->value;
		}
	}

	CURLcode ret;
	if((ret = curl_easy_setopt(ctx, CURLOPT_SSH_PRIVATE_KEYFILE, values.ssh_private_keyfile)) != CURLE_OK)
		return ret;

	if((ret = curl_easy_setopt(ctx, CURLOPT_SSH_HOST_PUBLIC_KEY_MD5, values.ssh_host_public_key_md5)) != CURLE_OK)
		return ret;

	if((ret = curl_easy_setopt(ctx, CURLOPT_KEYPASSWD, values.keypasswd)) != CURLE_OK)
		return ret;

	return CURLE_OK;
}

void curl_backend::doit(const UriUriA *uri, const filesystem::path& path, const char *token, state_t state)
{
	std::lock_guard<std::recursive_mutex> lock(m_mutex);

	if(m_state != state_t::ready)
		throw std::logic_error("Invalid state transition");

	if(uri == nullptr)
		return this->set_error(error_type::argument, -1, "Invalid URI");

	if(path.empty())
		return this->set_error(error_type::argument, -1, "Invalid path");

	if(token == nullptr)
		token = "";

	CURLcode cerr = apply_query_curlopts(m_context.get(), uri);
	if(cerr != CURLE_OK)
		return this->set_error(error_type::backend, static_cast<int>(cerr), curl_easy_strerror(cerr));

	m_uristring = uri_to_string(uri);
	curl_easy_setopt(m_context.get(), CURLOPT_URL, m_uristring.c_str());

	/* For HTTP, we only support basic auth. */
	curl_easy_setopt(m_context.get(), CURLOPT_HTTPAUTH, CURLAUTH_BASIC | CURLAUTH_ONLY);

	/* For HTTP, create our identification headers. */
	m_headers.reset();
	{
		std::string tokhdr = "X-NimrodG-File-Auth-Token: ";
		tokhdr.append(token);

		curl_slist *list = nullptr;
		if(!(list = curl_slist_append(list, tokhdr.c_str())))
			throw std::bad_alloc();

		if(!(list = curl_slist_append(list, m_uuid_header.data())))
			throw std::bad_alloc();

		m_headers.reset(list);
		curl_easy_setopt(m_context.get(), CURLOPT_HTTPHEADER, m_headers.get());
	}

	if(state == state_t::in_get)
	{
		curl_easy_setopt(m_context.get(), CURLOPT_UPLOAD, 0L);
		m_file.reset(xfopen(path, "wb"));
	}
	else if(state == state_t::in_put)
	{
		curl_easy_setopt(m_context.get(), CURLOPT_UPLOAD, 1L);

		{ /* I know this is a race condition, but I don't care anymore. */
			auto stats = filesystem::status(path);
			auto perms = stats.permissions();
			if(perms != filesystem::perms::unknown)
				curl_easy_setopt(m_context.get(), CURLOPT_NEW_FILE_PERMS, static_cast<long>(perms) & 0777);
			else
				curl_easy_setopt(m_context.get(), CURLOPT_NEW_FILE_PERMS, 0644);

			/* For SCP */
			uintmax_t size = filesystem::file_size(path);
			curl_easy_setopt(m_context.get(), CURLOPT_INFILESIZE, static_cast<long>(size));
			curl_easy_setopt(m_context.get(), CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(size));
		}
		m_file.reset(xfopen(path, "rb"));
	}

	if(!m_file)
		return this->set_error(error_type::system, errno, strerror(errno));

	curl_multi_add_handle(m_mh, m_context.get());

	m_state = state;
}

void curl_backend::get(const UriUriA *uri, const filesystem::path& path, const char *token)
{
	return doit(uri, path, token, state_t::in_get);
}

void curl_backend::put(const UriUriA *uri, const filesystem::path& path, const char *token)
{
	return doit(uri, path, token, state_t::in_put);
}

size_t curl_backend::write_proc(char *ptr, size_t size, size_t nmemb) noexcept
{
	/* If we're here from a PUT, the server's probably sent an error page. Ignore it. */
	if(m_state == state_t::in_put)
		return size * nmemb;
	return fwrite(ptr, size, nmemb, m_file.get());
}

size_t curl_backend::read_proc(char *ptr, size_t size, size_t nmemb) noexcept
{
	//assert(m_state == state_t::in_get);
	return fread(ptr, size, nmemb, m_file.get());
}

int curl_backend::xferinfo_proc(curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) noexcept
{
	if(m_cancelflag)
		return -1;
	return 0;
}

void curl_backend::cancel()
{
	std::lock_guard<std::recursive_mutex> lock(m_mutex);
	if(m_state != state_t::in_get && m_state != state_t::in_put)
		return;

	m_cancelflag = true;
}
