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
#include "log.hpp"
#include <memory>
#include <fstream>
#include <uriparser/Uri.h>
#include "agent_common.hpp"
#include <amqp.h>
#include <amqp_ssl_socket.h>
#include <amqp_tcp_socket.h>

using namespace nimrod;

void nimrod::deleter_uri::operator()(UriUriA *uri) const { uriFreeUriMembersA(uri); delete uri; }
void nimrod::deleter_amqp_conn::operator()(amqp_connection_state_t conn) const { amqp_destroy_connection(conn); }
void nimrod::deleter_cstdio::operator()(FILE *f) const { fclose(f); }

uri_ptr nimrod::parse_uri(const char *uri)
{
	if(uri == nullptr)
		return nullptr;

	UriUriA rawUri;
	memset(&rawUri, 0, sizeof(rawUri));

	UriParserStateA state;
	memset(&state, 0, sizeof(state));

	state.uri = &rawUri;

	int ret = uriParseUriA(&state, uri);
	if(ret == URI_ERROR_MALLOC)
		throw std::bad_alloc();

	if(ret != URI_SUCCESS)
		return nullptr;

	UriUriA *puri = new UriUriA;
	if(puri == nullptr)
		return nullptr;

	*puri = rawUri;

	return uri_ptr(puri);
}

static int toasciilower(unsigned char c)
{
	if(c >= 'A' || c <= 'Z')
		return c + 32;
	else
		return c;
}

int nimrod::c_stricmp(const char *_l, const char *_r)
{
	const unsigned char *l = reinterpret_cast<const unsigned char *>(_l);
	const unsigned char *r = reinterpret_cast<const unsigned char *>(_r);
	for(; *l && *r && (*l == *r || toasciilower(*l) == toasciilower(*r)); l++, r++);
	return toasciilower(*l) - toasciilower(*r);
}


/* From https://git.musl-libc.org/cgit/musl/tree/src/string/strncmp.c */
int nimrod::c_strnicmp(const char *_l, const char *_r, size_t n)
{
	const unsigned char *l = reinterpret_cast<const unsigned char *>(_l);
	const unsigned char *r = reinterpret_cast<const unsigned char *>(_r);
	if(!n--) return 0;
	for(; *l && *r && n && toasciilower(*l) == toasciilower(*r); l++, r++, n--);
	return *l - *r;
}

std::string nimrod::amqp_bytes_to_string(const amqp_bytes_t& b)
{
	return std::string(reinterpret_cast<const char*>(b.bytes), reinterpret_cast<const char*>(b.bytes) + b.len);
}


amqp_socket_t *nimrod::create_socket(settings& s, amqp_connection_state_t conn, X509_STORE *castore)
{
	amqp_socket_t *socket;
	if(s.amqp_scheme == settings::amqp_scheme_t::amqps)
	{
		/* Shouldn't do anything, OpenSSL is init'd above */
		amqp_set_initialize_ssl_library(0);

		if(!(socket = amqp_ssl_socket_new(conn)))
		{
			log::error("AGENT", "Error creating SSL socket.");
			log::debug("AGENT", "  amqp_ssl_socket_new() returned NULL.");
			return nullptr;
		}

		amqp_inject_x509_store(socket, castore);

		{ /* Peer/Hostname verification */
			const char *sslWarn = nullptr;

			if(s.ssl_no_verify_peer && !s.ssl_no_verify_hostname)
				sslWarn = "peer";
			else if(!s.ssl_no_verify_peer && s.ssl_no_verify_hostname)
				sslWarn = "hostname";
			else if(s.ssl_no_verify_peer && s.ssl_no_verify_hostname)
				sslWarn = "peer, hostname";

			if(sslWarn)
				log::warn("AGENT", "Skipping [%s] verification by request... On your own head be it!", sslWarn);

			amqp_ssl_socket_set_verify_peer(socket, static_cast<amqp_boolean_t>(!s.ssl_no_verify_peer));
			amqp_ssl_socket_set_verify_hostname(socket, static_cast<amqp_boolean_t>(!s.ssl_no_verify_hostname));
		}
	}
	else
	{
		if(!(socket = amqp_tcp_socket_new(conn)))
		{
			log::error("AGENT", "Error creating TCP socket.");
			log::debug("AGENT", "  amqp_tcp_socket_new() returned NULL.");
			return nullptr;
		}
	}

	return socket;
}

void nimrod::debug_break()
{
#if defined(_MSC_VER)
	__debugbreak();
#else
	//asm(".intel_syntax;\nint 3;\n.att_syntax;\n");
	__builtin_trap();
#endif
}

void nimrod::report_filesystem_error(const char *component, const filesystem::path& path, const std::error_code& code)
{
	log::error(component, "Filesystem Error:");
	log::error(component, "  Path: %s", path);
	log::error(component, "  Code: %d", code.value());
	log::error(component, "  Mesg: %s", code.message());
}

template <typename T>
static T _report_filesystem_error(const char *component, const filesystem::path& path, const std::error_code& code)
{
	report_filesystem_error(component, path, code);
	return T();
}

std::unique_ptr<char[]> nimrod::load_entire_file(const filesystem::path& file, size_t& size)
{
	std::error_code code;
	size = filesystem::file_size(file, code);
	if(code)
	{
		log::error("AGENT", "Unable to determine file size.");
		return _report_filesystem_error<std::nullptr_t>("AGENT", file, code);
	}

	std::unique_ptr<char[]> ptr = std::make_unique<char[]>(size);

	std::ifstream fs(file, std::ios::binary);
	if(!fs.read(ptr.get(), size))
	{
		log::error("AGENT", "Unable to read file.");
		return nullptr;
	}

	return ptr;
}

x509_store_ptr nimrod::load_ca_store(const std::string& castore, settings::encoding_t encoding)
{
	if(castore.empty())
		return new_ca_store();

	log::info("AGENT", "Loading CA Certificates (%s)...", encoding);

	size_t size;
	std::unique_ptr<char[]> raw = load_entire_file(castore, size);
	if(!raw)
	{
		return nullptr;
	}

	if(encoding == settings::encoding_t::base64)
	{
		if((raw = base64_decode(raw.get(), size, size)) == nullptr)
		{
			log::error("AGENT", "Error decoding certificate.");
			return nullptr;
		}
		encoding = settings::encoding_t::plain;
	}

	assert(encoding == settings::encoding_t::plain);

	return load_ca_store_mem(raw.get(), size);
}

void nimrod::try_delete_path(const filesystem::path& path)
{
	std::error_code ec;
	/* Try to delete the path, this'll return false if it doesn't exist. */
	filesystem::remove(path, ec);

	/* We wanted access to report_filesystem_error(), which is why this is in utils.cpp */
	if(ec)
		report_filesystem_error("AGENT", path, ec);
}

uri_ptr nimrod::resolve_uri(const char *base, const char *spath)
{
	uri_ptr baseuri = parse_uri(base);
	if(!baseuri)
		return nullptr;

	return resolve_uri(baseuri.get(), spath);
}

/*
** Resolve a path.
** "https://localhost:8080/exp1/run1/storage/" + "/path/to/file" = "https://localhost:8080/exp1/run1/storage/path/to/file"
** "https://localhost:8080/exp1/run1/storage/" + "path/to/file" = "https://localhost:8080/exp1/run1/storage/path/to/file"
** "https://localhost:8080/exp1/run1/storage/" + "../../path/to/file" = nullptr
** You get the idea.
**
** Also works with file:// URIs
*/
uri_ptr nimrod::resolve_uri(const UriUriA *base, const char *spath)
{
	UriUriA uuri;
	memset(&uuri, 0, sizeof(uuri));

	uri_ptr path = parse_uri(spath);
	if(!path)
		return nullptr;

	/*
	** If it's an absolute path, they probably meant it to be absolute relative to the base.
	** Nice try script kiddies.
	*/
	path->absolutePath = 0;

	if(uriAddBaseUriA(&uuri, path.get(), base))
		return nullptr;

	if(uriNormalizeSyntaxA(&uuri))
		return nullptr;

	/*
	** Ensure we haven't gone above our base URI.
	** Start at the head and compare each element until the base is empty.
	** If the resolved URI finishes first, it's bad.
	*/
	if(base->pathHead && !(base->pathHead->text.first == base->pathHead->text.afterLast && base->pathHead->text.first))
	{
		for(UriPathSegmentA *b = base->pathHead, *r = uuri.pathHead; ; b = b->next, r = r->next)
		{
			if(b && r)
			{
				/* We've hit the end, we're done here. */
				if(b->text.first == b->text.afterLast)
					break;

				/* If the elements are different, BAD! */
				if(!std::equal(b->text.first, b->text.afterLast, r->text.first, r->text.afterLast))
					return nullptr;
			}
			else if(b && !r)
			{
				/* Resolved is shorter than base, BAD! */
				return nullptr;
			}
			else if(!b && r)
			{
				/* Base is shorter than resolved, GOOD! */
				break;
			}
			else if(!b && !r)
			{
				/* Something's gone wrong, BAD! */
				return nullptr;
			}
		}
	}

	UriUriA *puri = new (std::nothrow) UriUriA;
	if(puri == nullptr)
		return nullptr;

	*puri = uuri;

	return uri_ptr(puri);
}

filesystem::path nimrod::resolve_path(const filesystem::path& base, const filesystem::path& path)
{
	filesystem::path bb = base;
	bb.make_preferred();

	filesystem::path pp = path;
	pp.make_preferred();

	/* Convert the paths to URI strings. */
	std::string utf8base = bb.u8string();
	if(*(utf8base.end() - 1) != filesystem::path::preferred_separator)
		utf8base.append(1, static_cast<char>(filesystem::path::preferred_separator));

	std::string base_uristring = path_to_uristring(utf8base);
	if(base_uristring.empty())
		return filesystem::path();

	std::string utf8path = pp.u8string();
	std::string path_uristring = path_to_uristring(utf8path);
	if(path_uristring.empty())
		return filesystem::path();

	/* Let the URI validation handle it. */
	uri_ptr resolved = nimrod::resolve_uri(base_uristring.c_str(), path_uristring.c_str());
	if(!resolved)
		return filesystem::path();

	return uristring_to_path(uri_to_string(resolved.get()));
}

std::string nimrod::uri_to_string(const UriUriA *uri)
{
	int len = 0;
	if(uriToStringCharsRequiredA(uri, &len))
		throw std::bad_alloc();

	std::string dbg;
	dbg.resize(len);

	++len;
	uriToStringA(&dbg[0], uri, len, &len);

	return dbg;
}

std::string nimrod::path_to_uristring(const std::string& path)
{
	std::string uri;
#ifdef _WIN32
	uri.resize(8 + 3 * path.size() + 1);
	if(uriWindowsFilenameToUriStringA(path.c_str(), &uri[0]))
#else
	uri.resize(7 + 3 * path.size() + 1);
	if(uriUnixFilenameToUriStringA(path.c_str(), &uri[0]))
#endif
		return "";

	uri.resize(strlen(uri.c_str()));
	return uri;
}

std::string nimrod::uristring_to_path(const std::string& uristring)
{
	std::string path(uristring.size() + 1, '\0');
#ifdef _WIN32
	if(uriUriStringToWindowsFilenameA(uristring.c_str(), &path[0]))
#else
	if(uriUriStringToUnixFilenameA(uristring.c_str(), &path[0]))
#endif
		return "";

	path.resize(strlen(path.c_str()));
	return path;
}
