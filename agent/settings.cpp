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
#	define WIN32_LEAN_AND_MEAN
#endif

#include <fmt/format.h>
#include <uriparser/Uri.h>
#include <fstream>
#include <optional>
#include <iostream>
#include <config.h>
#include <nim1/make_view.hpp>
#include "json.hpp"
#include "agent_common.hpp"
#include "uuid.hpp"
#include "parg/parg.h"

enum
{
	ARGDEF_VERSION					= 'v',
	ARGDEF_PLATFORM					= 'p',
	ARGDEF_USERAGENT				= 'u',
	ARGDEF_HELP						= 'h',
	ARGDEF_CONFIG					= 'c',
	ARGDEF_UUID						= 300,
	ARGDEF_WORKROOT,
	ARGDEF_AMQP_URI,
	ARGDEF_AMQP_ROUTING_KEY,
	ARGDEF_AMQP_DIRECT_EXCHANGE,
	ARGDEF_NO_VERIFY_PEER,
	ARGDEF_NO_VERIFY_HOST,
	ARGDEF_CACERT,
	ARGDEF_CAENC,
	ARGDEF_NO_CA_DELETE,
	ARGDEF_BATCH,
	ARGDEF_OUTPUT,
	ARGDEF_NOHUP,
	ARGDEF_SECRET_KEY,
};

static struct parg_option argdefs[] = {
	{ "version",				PARG_NOARG,		nullptr, ARGDEF_VERSION },
	{ "platform",				PARG_NOARG,		nullptr, ARGDEF_PLATFORM },
	{ "user-agent",				PARG_NOARG,		nullptr, ARGDEF_USERAGENT },
	{ "help",					PARG_NOARG,		nullptr, ARGDEF_HELP },
	{ "uuid",					PARG_REQARG,	nullptr, ARGDEF_UUID },
	{ "config",					PARG_REQARG,	nullptr, ARGDEF_CONFIG },
	{ "work-root",				PARG_REQARG,	nullptr, ARGDEF_WORKROOT },
	{ "amqp-uri",				PARG_REQARG,	nullptr, ARGDEF_AMQP_URI },
	{ "amqp-routing-key",		PARG_REQARG,	nullptr, ARGDEF_AMQP_ROUTING_KEY },
	{ "amqp-direct-exchange",	PARG_REQARG,	nullptr, ARGDEF_AMQP_DIRECT_EXCHANGE },
	{ "no-verify-peer",			PARG_NOARG,		nullptr, ARGDEF_NO_VERIFY_PEER },
	{ "no-verify-host",			PARG_NOARG,		nullptr, ARGDEF_NO_VERIFY_HOST },
	{ "cacert",					PARG_REQARG,	nullptr, ARGDEF_CACERT },
	{ "caenc",					PARG_REQARG,	nullptr, ARGDEF_CAENC },
	{ "no-ca-delete",			PARG_NOARG,		nullptr, ARGDEF_NO_CA_DELETE },
	{ "batch",					PARG_NOARG,		nullptr, ARGDEF_BATCH },
	{ "output",					PARG_REQARG,	nullptr, ARGDEF_OUTPUT },
	{ "nohup",					PARG_NOARG,		nullptr, ARGDEF_NOHUP },
	{ "secret-key",				PARG_REQARG,	nullptr, ARGDEF_SECRET_KEY },
	{ nullptr, 0, nullptr, 0 }
};

static const char *USAGE_OPTIONS =
"  -v, --version\n"
"                          Display version string\n"
"  -p, --platform\n"
"                          Display platform string\n"
"  -u, --user-agent\n"
"                          Display HTTP user agent\n"
"  -h, --help\n"
"                          Display help message\n"
"  -c, --config=PATH\n"
"                          Path to a configuration file.\n"
"                          - Any arguments already provided will be overridden.\n"
"                          - Any subsequent arguments will override the configuration values.\n"
"  --uuid=UUID\n"
"                          The UUID of the agent. If omitted, use a random one\n"
"  --work-root=PATH\n"
"                          Change directory to PATH if specified\n"
"  --amqp-uri=URI\n"
"                          The URI of the AMQP broker\n"
"  --amqp-routing-key=KEY\n"
"                          The routing key to use to contact the Nimrod master. Defaults to \"iamthemaster\"\n"
"  --amqp-direct-exchange=NAME\n"
"                          The name of the direct exchange to use. Defaults to \"amqp.direct\"\n"
"  --no-verify-peer\n"
"                          Disable peer verification\n"
"  --no-verify-host\n"
"                          Disable hostname verification\n"
"  --cacert=PATH\n"
"                          Path to the CA certificate\n"
"  --caenc={plain,base64}\n"
"                          Encoding of the CA certificate specified by --cacert\n"
"                          - plain  = The certificate is a base64-encoded PEM certificate\n"
"                          - base64 = The certificate is a base64-encoded, base64-encoded PEM certificate\n"
"                          The double-encoding is used to account for the RFC7468 headers\n"
"  --no-ca-delete\n"
"                          Don't delete the CA certificate after reading\n"
"  --batch\n"
"                          Enter batch mode. Implies --nohup and --output=workroot\n"
"                          - Upon start, the agent fork()'s and prints the child PID and a newline character\n"
"                            to stdout before exiting\n"
"                          - The --output flag may be given to change the behaviour, but will be ignored if\n"
"                            it is set to \"console\"\n"
"                          - This is only supported on POSIX systems\n"
"  --output={console,off,workroot}\n"
"                          Set stdout/stderr redirection mode\n"
"                          - console  = Use the attached console's stdout/stderr\n"
"                          - off      = Disable stdout/stderr\n"
"                          - workroot = Redirect everything to a file called output.txt in the work root\n"
"  --nohup\n"
"                          Ignore SIGHUP. Ignored on non-POSIX systems.\n"
"  --secret-key\n"
"                          Secret Key.\n"
;

using namespace nimrod;

static int usage(int val, std::ostream& s, const char *argv0)
{
	s << "Usage: " << filesystem::path(argv0).filename() << " [OPTIONS]\nOptions:\n";
	s << USAGE_OPTIONS;
	return val;
}

static int parseerror(int val, std::ostream& s, const char *argv0, const char *msg)
{
	s << "Error parsing arguments: " << msg << std::endl;
	return usage(val, s, argv0);
}

static int atoi(std::string_view v)
{
	char *buf = (char*)alloca((v.size() + 1) * sizeof(char));
	memcpy(buf, v.data(), v.size());
	buf[v.size()] = '\0';

	return ::atoi(buf);
}

static bool validate_uri(std::ostream& out, std::ostream& err, settings& s)
{
	uri_ptr& uri = s.amqp_uri;

	{ /* Scheme */
		s.amqp_sscheme = nim1::make_view(uri->scheme.first, uri->scheme.afterLast);
		if(s.amqp_sscheme.empty())
			   return out << "URI Scheme cannot be empty. Must be one of [amqp, amqps]." << std::endl, false;

		if(s.amqp_sscheme == "amqp")
			s.amqp_scheme = settings::amqp_scheme_t::amqp;
		else if(s.amqp_sscheme == "amqps")
			s.amqp_scheme = settings::amqp_scheme_t::amqps;
		else
			return out << "Invalid URI Scheme. Must be one of [amqp, amqps]." << std::endl, false;
	}

	{ /* Host */
		if(!uri->hostText.first || !uri->hostText.afterLast || (uri->hostText.first == uri->hostText.afterLast))
			return out << "Host cannot be empty." << std::endl, false;

		s.amqp_host = std::string(uri->hostText.first, uri->hostText.afterLast);
	}

	{ /* Port */
		std::string_view sport = nim1::make_view(uri->portText.first, uri->portText.afterLast);

		/* No port specified? Use defaults. */
		if(sport.empty())
		{
			if(s.amqp_scheme == settings::amqp_scheme_t::amqp)
				s.amqp_port = 5672;
			else
				s.amqp_port = 5671;
		}
		else
		{
			int port = atoi(sport);
			if(port <= 0 || port > 65535)
				return out << "Port must be in the range [1, 65535]." << std::endl, false;

			s.amqp_port = static_cast<uint16_t>(port);
		}
	}

	{ /* User/Pass */
		/* Don't do NULL checks here, allow it. */
		std::string_view user = nim1::make_view(uri->userInfo.first, uri->userInfo.afterLast);

		size_t colonPos = user.find(':', 0);

		if(colonPos == std::string::npos)
		{
			s.amqp_user = user;
		}
		else
		{
			s.amqp_user = user.substr(0, colonPos);
			s.amqp_pass = user.substr(colonPos + 1, std::string::npos);
		}
	}

	{ /* VHost */
		/* NB: Things like nim%2Frod will be split into nim/rod. This is intentional. */
		size_t nreq = 0;
		for(UriPathSegmentA *seg = uri->pathHead; seg; seg = seg->next)
			nreq += std::distance(seg->text.first, seg->text.afterLast) + 1;

		s.amqp_vhost.reserve(nreq);

		for(UriPathSegmentA *seg = uri->pathHead; seg; seg = seg->next)
		{
			s.amqp_vhost.insert(s.amqp_vhost.end(), seg->text.first, seg->text.afterLast);
			s.amqp_vhost.push_back('/');
		}
		if(uri->pathHead)
			s.amqp_vhost.pop_back();
		s.amqp_vhost.push_back('\0');
	}

	return true;
}

static bool parse_encoding(std::string_view s, settings::encoding_t& enc)
{
	if(s == "plain")
		return enc = settings::encoding_t::plain, true;
	else if(s == "base64")
		return enc = settings::encoding_t::base64, true;

	return false;
}

std::ostream& nimrod::operator<<(std::ostream& os, settings::encoding_t enc)
{
	if(enc == settings::encoding_t::plain)
		return os << "plain";
	else if(enc == settings::encoding_t::base64)
		return os << "base64";
	else
		return os.setstate(std::ios_base::failbit), os;
}

static bool parse_output(std::string_view s, settings::output_t& out)
{
	if(s == "console")
		return out = settings::output_t::console, true;
	else if(s == "off")
		return out = settings::output_t::off, true;
	else if(s == "workroot")
		return out = settings::output_t::workroot, true;

	return false;
}

struct tmpargs
{
	using sopt_t = std::optional<std::string>;
	using bopt_t = std::optional<bool>;
	using smap_t = std::unordered_map<std::string, std::string>;

	sopt_t	uuid;
	sopt_t  work_root;
	sopt_t	amqp_uri;
	sopt_t	amqp_routing_key;
	sopt_t	amqp_direct_exchange;
	bopt_t	no_verify_peer;
	bopt_t	no_verify_host;
	sopt_t	ca_cert;
	sopt_t	ca_encoding;
	bopt_t	ca_no_delete;
	bopt_t	batch;
	sopt_t	output;
	bopt_t	nohup;
	sopt_t	secret_key;
	smap_t	environment;
};

template<typename T>
int get_json_value(const nlohmann::json& j, std::string_view key, nlohmann::json::value_t type, std::optional<T>& opt)
{
	auto it = j.find(key);
	if(it == j.end())
		return 1;

	if(it->type() != type)
		return -1;

	opt = it->get<T>();
	return 0;
}

static int load_config_file(tmpargs& s, std::istream& is, std::ostream& err)
{
	nlohmann::json j;
	try
	{
		j = nlohmann::json::parse(is);
	}
	catch(const nlohmann::detail::exception& e)
	{
		err << e.what() << std::endl;
		return 1;
	}

	/*
	 * NB: Using find() instead of[] to avoid copies.
	 * Also, a key not existing is not an error. A key of the wrong type is.
	 */
	using jv_t = nlohmann::json::value_t;

	if(get_json_value(j, "uuid", jv_t::string, s.uuid) < 0)
		return -1;

	if(get_json_value(j, "work_root", jv_t::string, s.work_root) < 0)
		return -1;

	if(auto it = j.find("amqp"); it != j.end())
	{
		if(!it->is_object())
			return -1;

		if(get_json_value(*it, "uri", jv_t::string, s.amqp_uri) < 0)
			return -1;

		if(get_json_value(*it, "routing_key", jv_t::string, s.amqp_routing_key) < 0)
			return -1;

		if(get_json_value(*it, "direct_exchange", jv_t::string, s.amqp_direct_exchange) < 0)
			return -1;
	}

	if(get_json_value(j, "no_verify_peer", jv_t::boolean, s.no_verify_peer) < 0)
		return -1;

	if(get_json_value(j, "no_verify_host", jv_t::boolean, s.no_verify_host) < 0)
		return -1;

	if(auto it = j.find("ca"); it != j.end())
	{
		if(!it->is_object())
			return -1;

		if(get_json_value(*it, "cert", jv_t::string, s.ca_cert) < 0)
			return -1;

		if(get_json_value(*it, "encoding", jv_t::string, s.ca_encoding) < 0)
			return -1;

		if(get_json_value(*it, "no_delete", jv_t::boolean, s.ca_no_delete) < 0)
			return -1;
	}

	if(get_json_value(j, "batch", jv_t::boolean, s.batch) < 0)
		return -1;

	if(get_json_value(j, "output", jv_t::string, s.output) < 0)
		return -1;

	if(get_json_value(j, "nohup", jv_t::boolean, s.nohup) < 0)
		return -1;

	if(get_json_value(j, "secret_key", jv_t::string, s.secret_key) < 0)
		return -1;

	if(auto it = j.find("environment"); it != j.end())
	{
		if(!it->is_object())
			return -1;

		for(const auto& env : it->items())
		{
			if(!env.value().is_string())
				return -1;

			s.environment[env.key()] = env.value();
		}
	}

	return 0;
}

#include <curl/curl.h>
static void dump_version(std::ostream& out)
{
	curl_version_info_data *d = curl_version_info(CURLVERSION_NOW);
	out << "nimrodg-agent " << g_compile_info.version.agent << " (" << g_compile_info.agent.platform << ")";
	/* curl does a better job of this than we do. */
	out << " " << d->ssl_version;

	out << " librabbitmq/" << g_compile_info.version.rabbitmq_c;
	out << " libcurl/" << g_compile_info.version.curl;

	if(d->libssh_version != nullptr)
		out << " " << d->libssh_version;

	if(d->nghttp2_version != nullptr)
		out << " nghttp2/" << d->nghttp2_version;

	if(d->libz_version != nullptr)
		out << " zlib/" << d->libz_version;

	if(d->ares != nullptr)
		out << " c-ares/" << d->ares;

	out << " uriparser/" << g_compile_info.version.uriparser;
	out << " libuuid/" << g_compile_info.version.libuuid;
	out << std::endl;
	out << "User-Agent: " << g_compile_info.agent.user_agent << std::endl;
	out << "Commit: " << g_compile_info.git.sha1 << std::endl;

	if(d->protocols != nullptr)
	{
		out << "Protocols:";
		for(const char * const *p = d->protocols; *p; ++p)
			out << " " << *p;
		out << std::endl;
	}
}

bool nimrod::parse_program_arguments(int argc, char **argv, int& status, std::ostream& out, std::ostream& err, settings& s)
{
	parg_state ps{};
	parg_init(&ps);

	tmpargs tmp{};
	for(int c; (c = parg_getopt_long(&ps, argc, argv, "vpuhc:", argdefs, nullptr)) != -1; )
	{
		switch(c)
		{
			case ARGDEF_VERSION:
			{
				dump_version(out);
				status = 0;
				return false;
			}
			case ARGDEF_PLATFORM:
				out << g_compile_info.agent.platform << std::endl;
				status = 0;
				return false;

			case ARGDEF_USERAGENT:
				out << g_compile_info.agent.user_agent << std::endl;
				status = 0;
				return false;

			case ARGDEF_HELP:
				status = usage(0, out, argv[0]);
				return false;

			case ARGDEF_CONFIG:
			{
				std::string_view sv = ps.optarg;
				if(sv == "-")
				{
					status = load_config_file(tmp, std::cin, err);
				}
				else
				{
					std::ifstream f(ps.optarg, std::ios::in | std::ios::binary);
					if(!f)
					{
						err << "Unable to open configuration file." << std::endl;
						return false;
					}

					status = load_config_file(tmp, f, err);
				}

				if(status != 0)
				{
					if(status < 0)
						err << "Malformed configuration file." << std::endl;
					return false;
				}
				break;
			}
			case ARGDEF_UUID:
				tmp.uuid = ps.optarg;
				break;

			case ARGDEF_WORKROOT:
				tmp.work_root = ps.optarg;
				break;

			case ARGDEF_AMQP_URI:
				tmp.amqp_uri = ps.optarg;
				break;

			case ARGDEF_AMQP_ROUTING_KEY:
				tmp.amqp_routing_key = ps.optarg;
				break;

			case ARGDEF_AMQP_DIRECT_EXCHANGE:
				tmp.amqp_direct_exchange = ps.optarg;
				break;

			case ARGDEF_NO_VERIFY_PEER:
				tmp.no_verify_peer = true;
				break;

			case ARGDEF_NO_VERIFY_HOST:
				tmp.no_verify_host = true;
				break;

			case ARGDEF_CACERT:
				tmp.ca_cert = ps.optarg;
				break;

			case ARGDEF_CAENC:
				tmp.ca_encoding = ps.optarg;
				break;

			case ARGDEF_NO_CA_DELETE:
				tmp.ca_no_delete = true;
				break;

			case ARGDEF_BATCH:
				tmp.batch = true;
				break;

			case ARGDEF_OUTPUT:
				tmp.output = ps.optarg;
				break;

			case ARGDEF_NOHUP:
				tmp.nohup = true;
				break;

			case ARGDEF_SECRET_KEY:
				tmp.secret_key = ps.optarg;
				break;

			case '?':
			default:
				status = usage(2, out, argv[0]);
				return false;
		}
	}


	/* This is technically the only required argument. */
	if(!tmp.amqp_uri)
	{
		status = parseerror(2, out, argv[0], "Option --amqp-uri is required.");
		return false;
	}

	s = settings();

	if(tmp.uuid)
	{
		uuid_t _uuid;

		if(uuid_parse(tmp.uuid->c_str(), _uuid) < 0)
		{
			status = parseerror(2, out, argv[0], "Malformed UUID");
			return false;
		}

		s.uuid = _uuid;
		s.uuid_string = std::move(tmp.uuid.value());
	}

	if(!tmp.work_root)
		s.work_root = filesystem::temp_directory_path() / "nimrodg-agent" / s.uuid_string;
	else
		s.work_root = tmp.work_root.value();

	s.amqp_raw_uri = tmp.amqp_uri.value();
	{ /* Validate the AMQP URI */
		if(!(s.amqp_uri = parse_uri(s.amqp_raw_uri)))
		{
			status = parseerror(2, out, argv[0], "Malformed URI.");
			return false;
		}

		if(!validate_uri(out, err, s))
		{
			status = 2;
			return false;
		}
	}

	s.amqp_routing_key = tmp.amqp_routing_key.value_or("iamthemaster");
	s.amqp_direct_exchange = tmp.amqp_direct_exchange.value_or("amq.direct");

	s.ssl_no_verify_peer = tmp.no_verify_peer.value_or(false);
	s.ssl_no_verify_hostname = tmp.no_verify_host.value_or(false);

	s.ca_path = tmp.ca_cert.value_or("");

	if(!tmp.ca_encoding)
	{
		s.ca_encoding = settings::encoding_t::plain;
	}
	else if(!parse_encoding(tmp.ca_encoding.value(), s.ca_encoding))
	{
		status = usage(2, out, argv[0]);
		return false;
	}

	s.ca_no_delete = tmp.ca_no_delete.value_or(false);
	s.batch = tmp.batch.value_or(false);

	if(!tmp.output)
	{
		s.output = settings::output_t::console;
	}
	else if(!parse_output(tmp.output.value(), s.output))
	{
		status = usage(2, out, argv[0]);
		return false;
	}

	s.nohup = tmp.nohup.value_or(false);

	s.secret_key = std::move(tmp.secret_key.value_or(""));

	if(s.batch)
	{
		s.nohup = true;
		if(s.output == settings::output_t::console)
			s.output = settings::output_t::workroot;
	}

	s.environment = std::move(tmp.environment);
	return true;
}

settings::settings() :
	uuid(),
	uuid_string(uuid.str()),
	work_root(""),
	amqp_raw_uri(""),
	amqp_uri(nullptr),
	amqp_scheme(amqp_scheme_t::amqp),
	amqp_sscheme(""),
	amqp_host(""),
	amqp_port(0),
	amqp_user(""),
	amqp_pass(""),
	amqp_vhost(""),
	amqp_routing_key(""),
	amqp_direct_exchange(""),
	ssl_no_verify_peer(false),
	ssl_no_verify_hostname(false),
	ca_path(""),
	ca_encoding(encoding_t::plain),
	ca_no_delete(false),
	batch(false),
	output(output_t::console),
	nohup(false),
	secret_key("")
{}