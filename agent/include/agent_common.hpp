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
** Agent master include file.
** Try to keep external libraries (especially boost) out of this.
** C++ STL is fine.
*/

#ifndef _NIMROD_AGENT_COMMON_HPP
#define _NIMROD_AGENT_COMMON_HPP

#include <memory>
#include <ostream>
#include <istream>
#include <sstream>
#include <iomanip>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include "config.h"
#include "uuid.hpp"

#include "agent_fwd.hpp"

namespace nimrod {

struct settings
{
	enum class amqp_scheme_t { amqp, amqps };
	enum class encoding_t { plain, base64 };
	enum class output_t { console, off, workroot };

	settings();

	nimrod::uuid		uuid;
	std::string			work_root;

	std::string			amqp_raw_uri;
	uri_ptr				amqp_uri;
	amqp_scheme_t		amqp_scheme;
	std::string_view	amqp_sscheme;
	std::string			amqp_host;
	uint16_t			amqp_port;
	std::string			amqp_user;
	std::string			amqp_pass;
	std::string			amqp_vhost;
	std::string			amqp_routing_key;
	std::string			amqp_direct_exchange;

	bool				ssl_no_verify_peer;
	bool				ssl_no_verify_hostname;

	std::string			ca_path;
	encoding_t			ca_encoding;
	bool				ca_no_delete;

	bool				batch;
	output_t			output;
	bool				nohup;

	std::unordered_map<std::string, std::string> environment;
};


/* utils.cpp */

/*
** Parse a URI using the embedded uriparser library.
**
** If the URI is valid and was parsed successfully, returns a pointer
** to the UriUriA structure. If uri is nullptr or parsing failed, this returns nullptr.
*/
uri_ptr parse_uri(std::string_view uri);
bool fixup_uri(UriUriA *uri);

int c_stricmp(const char *l, const char *r);
int c_strnicmp(const char *_l, const char *_r, size_t n);

FILE *xfopen(const filesystem::path& path, const char *mode) noexcept;

std::string_view make_view(const char *b, const char *e) noexcept;

/*
** Convert an amqp_bytes_t structure to a C++ string.
*/
std::string amqp_bytes_to_string(const amqp_bytes_t& b);

amqp_socket_t *create_socket(settings& s, amqp_connection_state_t conn, X509_STORE *castore);
void debug_break();
void report_filesystem_error(const char *component, const filesystem::path& path, const std::error_code& code);
std::unique_ptr<char[]> load_entire_file(const filesystem::path& file, size_t& size);

x509_store_ptr load_ca_store(const std::string& castore, settings::encoding_t encoding);
uri_ptr resolve_uri(std::string_view base, std::string_view path);
uri_ptr resolve_uri(const UriUriA *base, std::string_view path);
filesystem::path resolve_path(const filesystem::path& base, const filesystem::path& path);
std::string uri_to_string(const UriUriA *uri);
std::string uri_query_list_to_string(const UriQueryListA *qlist);
std::string path_to_uristring(const std::string& path);
std::string uristring_to_path(const std::string& uristring);

/* Actual noexcept versions of std::filesystem functions. */
std::error_code create_directories(const filesystem::path& p) noexcept;
std::error_code remove_all(const filesystem::path& p) noexcept;


std::ostream& operator<<(std::ostream& os, settings::encoding_t enc);

/* ssl.cpp */
void init_openssl();
x509_store_ptr new_ca_store();
x509_store_ptr load_ca_store_mem(const char *data, size_t size);
void dump_ca_store(const x509_store_ptr& castore);
void set_ssl_store(SSL_CTX *ctx, X509_STORE *st);
std::unique_ptr<char[]> base64_decode(const char *data, size_t inSize, size_t& outSize);

/* console.cpp */
bool init_console_handlers(agent *a);

/* settings.cpp */
bool parse_program_arguments(int argc, char **argv, int& status, std::ostream& out, std::ostream& err, settings& s);

template <typename InputIt, typename Ot>
Ot& join(Ot& os, InputIt begin, InputIt end, bool quote = true)
{
	os << "[";
	for(;begin < end; ++begin)
	{
		if(quote)
			os << std::quoted(*begin);
		else
			os << *begin;

		if(begin != (end - 1))
			os << ", ";
	}
	return os << "]", os;
}

template <typename InputIt>
std::string join(InputIt begin, InputIt end, bool quote = true)
{
	std::ostringstream ss;
	join(ss, begin, end, quote);
	return ss.str();
}

/* Abuse std::unique_ptr to handle static cleanups. */
template <typename D>
auto make_protector(D& deleter)
{
	using ptr_type = std::unique_ptr<D, void(*)(D*)>;
	return ptr_type(&deleter, [](D* d) { (*d)(); });
}

}

#include "amqp_exception.hpp"

#endif /* _NIMROD_AGENT_COMMON_HPP */
