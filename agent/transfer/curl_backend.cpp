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
#include <sys/stat.h>
#include "agent_common.hpp"
#include "curl_backend.hpp"

using namespace nimrod;
using namespace nimrod::tx;

/*
** NB:
** The curl_multi_add_handle() calls will never fail -- I've satisfied their preconditions.
*/

struct uri_query_list_deleter
{
	using pointer = UriQueryListA*;
	void operator()(pointer p) noexcept { uriFreeQueryListA(p); }
};
using uri_query_list_ptr = std::unique_ptr<UriQueryListA*, uri_query_list_deleter>;

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

	curl_easy_setopt(m_context.get(), CURLOPT_USERAGENT, g_compile_info.agent.user_agent);
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

void curl_backend::set_curl_error(CURLcode cerr)
{
	return this->set_error(error_type::backend, static_cast<int>(cerr), curl_easy_strerror(cerr));
}

static UriQueryListA *strip_nimrod_parameters(UriQueryListA *qlist) noexcept
{
	UriQueryListA *nqlist = nullptr;
	for(UriQueryListA *e = qlist, *prev = nullptr; e != nullptr;)
	{
		if(strstr(e->key, "nimrod_") != e->key)
		{
			if(nqlist == nullptr)
				nqlist = e;

			prev = e;
			e = e->next;
			continue;
		}

		if(prev)
			prev->next = e->next;

		UriQueryListA *olde = e;

		e = e->next;
		prev = e;

		/* FIXME: Memory managers */
		free(const_cast<char*>(olde->key));
		free(const_cast<char*>(olde->value));
		free(olde);
	}

	return nqlist;
}

static CURLcode apply_nimrod_parameters(CURL *ctx, UriQueryListA *qlist) noexcept
{
	struct
	{
		const char *ssh_private_keyfile;
		const char *ssh_host_public_key_md5;
		const char *keypasswd;
	} values = {
		/* NB: Must be something, otherwise it'll try $HOME/.ssh/id_rsa */
		.ssh_private_keyfile = NIMRODG_DEVNULL,
		.ssh_host_public_key_md5 = nullptr,
		.keypasswd = nullptr
	};

	for(UriQueryListA *e = qlist; e != nullptr; e = e->next)
	{
		if(strcmp("nimrod_ssh_private_keyfile", e->key) == 0)
		{
			values.ssh_private_keyfile = e->value;
		}
		else if(strcmp("nimrod_ssh_host_public_key_md5", e->key) == 0)
		{
			if(strlen(e->value) == 32)
				values.ssh_host_public_key_md5 = e->value;
		}
		else if(strcmp("nimrod_keypasswd", e->key) == 0)
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

static CURLcode apply_curl_options(CURL *ctx, const UriUriA *uri)
{
	uri_query_list_ptr qlist;
	if(uri->query.first != uri->query.afterLast)
	{
		UriQueryListA *_qlist = nullptr;
		int urierr = uriDissectQueryMallocA(&_qlist, nullptr, uri->query.first, uri->query.afterLast);
		if(urierr == URI_ERROR_MALLOC)
			return CURLE_OUT_OF_MEMORY;
		else if(urierr != URI_SUCCESS)
			return CURLE_URL_MALFORMAT;

		qlist.reset(_qlist);
	}

	CURLcode cerr;
	if((cerr = apply_nimrod_parameters(ctx, qlist.get())) != CURLE_OK)
		return cerr;

	/*
	 * Strip the nimrod_* parameters from the list.
	 * Any of the above values are now invalid, cURL should have copied them.
	 */
	qlist.reset(strip_nimrod_parameters(qlist.release()));

	/* Create the new query string (if any). */
	std::string newquery = uri_query_list_to_string(qlist.get());

	/* "Copy" the uri and patch our new query string into it. */
	UriUriA newuri = *uri;
	newuri.query.first = newquery.data();
	newuri.query.afterLast = newquery.data() + newquery.size();

	/* Give cURL our sanitised URL. */
	std::string uristring = uri_to_string(&newuri);
	return curl_easy_setopt(ctx, CURLOPT_URL, uristring.c_str());
}

#define TEMPLATE_UUID "00000000-0000-0000-0000-000000000000"
#define TEMPLATE_UUID_HEADER NIMRODG_HTTP_HEADER_UUID ": " TEMPLATE_UUID
static_assert(sizeof(TEMPLATE_UUID) == nimrod::uuid::string_length + 1);

static CURLcode apply_curl_http(CURL *ctx, const char *token, curl_slist_ptr& headers, const nimrod::uuid& uuid)
{
	CURLcode cerr;

	/* For HTTP, we only support basic auth. */
	if((cerr = curl_easy_setopt(ctx, CURLOPT_HTTPAUTH, CURLAUTH_BASIC | CURLAUTH_ONLY)) != CURLE_OK)
		return cerr;

	/* For HTTP, create our identification headers. */
	headers.reset();

	if(token != nullptr)
	{
		char buf[4096];
		if(snprintf(buf, 4096, NIMRODG_HTTP_HEADER_TOKEN ": %s", token) >= 4096)
			throw std::range_error("Token too long");

		curl_slist *list = curl_slist_append(nullptr, buf);
		if(list == nullptr)
			return CURLE_OUT_OF_MEMORY;

		headers.reset(list);
	}

	{
		char buf[] = TEMPLATE_UUID_HEADER;
		uuid.str(buf + sizeof(TEMPLATE_UUID_HEADER) - sizeof(TEMPLATE_UUID), sizeof(TEMPLATE_UUID));

		curl_slist *list = curl_slist_append(headers.get(), buf);
		if(list == nullptr)
			return CURLE_OUT_OF_MEMORY;

		if(!headers)
			headers.reset(list);
	}

	if((cerr = curl_easy_setopt(ctx, CURLOPT_HTTPHEADER, headers.get())) != CURLE_OK)
		headers.reset();

	return cerr;
}

static CURLcode apply_curl_stat(CURL *ctx, struct stat *stat)
{
	if(stat == nullptr)
		return curl_easy_setopt(ctx, CURLOPT_UPLOAD, 0L);

	CURLcode cerr;
	if((cerr = curl_easy_setopt(ctx, CURLOPT_UPLOAD, 1L)) != CURLE_OK)
		return cerr;

	if((cerr = curl_easy_setopt(ctx, CURLOPT_NEW_FILE_PERMS, static_cast<long>(stat->st_mode & 0777))) != CURLE_OK)
		return cerr;

	if((cerr = curl_easy_setopt(ctx, CURLOPT_INFILESIZE, static_cast<long>(stat->st_size))) != CURLE_OK)
		return cerr;

	if((cerr = curl_easy_setopt(ctx, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(stat->st_size))) != CURLE_OK)
		return cerr;

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

	CURLcode cerr;

	/* Apply nimrod_* parameters and set the URL. */
	if((cerr = apply_curl_options(m_context.get(), uri)) != CURLE_OK)
		return this->set_curl_error(cerr);

	/* Apply HTTP options. These can be done independently. */
	if((cerr = apply_curl_http(m_context.get(), token, m_headers, this->uuid())))
		return this->set_curl_error(cerr);

	m_file.reset(xfopen(path, state == state_t::in_get ? "wb" : "rb"));
	if(!m_file)
		return this->set_errno(errno);

	struct stat *stat = nullptr;
	struct stat _stat{};
	if(state == state_t::in_put)
	{
		if(fstat(fileno(m_file.get()), &_stat) < 0)
			return this->set_errno(errno);
		stat = &_stat;
	}

	if((cerr = apply_curl_stat(m_context.get(), stat)) != CURLE_OK)
		return this->set_curl_error(cerr);

	curl_multi_add_handle(m_mh, m_context.get());

	m_state = state;
}

void curl_backend::do_transfer(operation_t op, const UriUriA *uri, const filesystem::path& path, const char *token)
{
	return doit(uri, path, token, op == operation_t::get ? state_t::in_get : state_t::in_put);
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
	if(m_cancelflag)
		return CURL_READFUNC_ABORT;

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
