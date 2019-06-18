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
#include "agent_common.hpp"
#include "uuid.hpp"
#include "parg/parg.h"

#define ARGDEF_VERSION					'v'
#define ARGDEF_PLATFORM					'p'
#define ARGDEF_USERAGENT				'u'
#define ARGDEF_HELP						'h'
#define ARGDEF_NO_CA_DELETE				300
#define ARGDEF_NO_VERIFY_PEER			301
#define ARGDEF_NO_VERIFY_HOST			302
#define ARGDEF_CACERT					303
#define ARGDEF_CAENC					304
#define ARGDEF_WORKROOT					305
#define ARGDEF_BATCH					306
#define ARGDEF_OUTPUT					307
#define ARGDEF_NOHUP					308
#define ARGDEF_UUID						309
#define ARGDEF_AMQPURI					310
#define ARGDEF_AMQP_ROUTING_KEY			311
#define ARGDEF_AMQP_FANOUT_EXCHANGE		312
#define ARGDEF_AMQP_DIRECT_EXCHANGE		313

static struct parg_option argdefs[] = {
	{ "version",				PARG_NOARG,		nullptr, ARGDEF_VERSION },
	{ "platform",				PARG_NOARG,		nullptr, ARGDEF_PLATFORM },
	{ "user-agent",				PARG_NOARG,		nullptr, ARGDEF_USERAGENT },
	{ "help",					PARG_NOARG,		nullptr, ARGDEF_HELP },
	{ "cacert",					PARG_REQARG,	nullptr, ARGDEF_CACERT },
	{ "caenc",					PARG_REQARG,	nullptr, ARGDEF_CAENC },
	{ "no-ca-delete",			PARG_NOARG,		nullptr, ARGDEF_NO_CA_DELETE },
	{ "no-verify-peer",			PARG_NOARG,		nullptr, ARGDEF_NO_VERIFY_PEER },
	{ "no-verify-host",			PARG_NOARG,		nullptr, ARGDEF_NO_VERIFY_HOST },
	{ "work-root",				PARG_REQARG,	nullptr, ARGDEF_WORKROOT },
	{ "batch",					PARG_NOARG,		nullptr, ARGDEF_BATCH },
	{ "output",					PARG_REQARG,	nullptr, ARGDEF_OUTPUT },
	{ "nohup",					PARG_NOARG,		nullptr, ARGDEF_NOHUP },
	{ "uuid",					PARG_REQARG,	nullptr, ARGDEF_UUID },
	{ "amqp-uri",				PARG_REQARG,	nullptr, ARGDEF_AMQPURI },
	{ "amqp-routing-key",		PARG_REQARG,	nullptr, ARGDEF_AMQP_ROUTING_KEY },
	{ "amqp-fanout-exchange",	PARG_REQARG,	nullptr, ARGDEF_AMQP_FANOUT_EXCHANGE },
	{ "amqp-direct-exchange",	PARG_REQARG,	nullptr, ARGDEF_AMQP_DIRECT_EXCHANGE },
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
"  --cacert=PATH\n"
"                          Path to the CA certificate\n"
"  --caenc={plain,base64}\n"
"                          Encoding of the CA certificate specified by --cacert\n"
"                          - plain  = The certificate is a base64-encoded PEM certificate\n"
"                          - base64 = The certificate is a base64-encoded, base64-encoded PEM certificate\n"
"                          The double-encoding is used to account for the RFC7468 headers\n"
"  --no-ca-delete\n"
"                          Don't delete the CA certificate after reading\n"
"  --no-verify-peer\n"
"                          Disable peer verification\n"
"  --no-verify-host\n"
"                          Disable hostname verification\n"
"  --uuid=UUID\n"
"                          The UUID of the agent. If omitted, use a random one\n"
"  --work-root=PATH\n"
"                          Change directory to PATH if specified\n"
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
"  --amqp-uri=URI\n"
"                          The URI of the AMQP broker\n"
"  --amqp-routing-key=KEY\n"
"                          The routing key to use to contact the Nimrod master. Defaults to \"iamthemaster\"\n"
"  --amqp-fanout-exchange=NAME\n"
"                          The name of the fanout exchange to use. Defaults to \"amqp.fanout\"\n"
"  --amqp-direct-exchange=NAME\n"
"                          The name of the direct exchange to use. Defaults to \"amqp.direct\"\n"
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

static bool validate_uri(std::ostream& out, std::ostream& err, settings& s)
{
	uri_ptr& uri = s.amqp_uri;

	{ /* Scheme */
		s.amqp_sscheme = std::string(uri->scheme.first, uri->scheme.afterLast);

		if(!uri->scheme.first || !uri->scheme.afterLast || s.amqp_sscheme.empty())
		{
			out << "URI Scheme cannot be empty. Must be one of [amqp, amqps]." << std::endl;
			return false;
		}

		if(s.amqp_sscheme == "amqp")
			s.amqp_scheme = settings::amqp_scheme_t::amqp;
		else if(s.amqp_sscheme == "amqps")
			s.amqp_scheme = settings::amqp_scheme_t::amqps;
		else
			return out << "Invalid URI Scheme. Must be one of [amqp, amqps]." << std::endl, false;
	}

	{ /* Host */
		s.amqp_host = std::string(uri->hostText.first, uri->hostText.afterLast);
		if(!uri->hostText.first || !uri->hostText.afterLast || s.amqp_host.empty())
			return out << "Host cannot be empty." << std::endl, false;
	}

	{ /* Port */

		/* No port specified? Use defaults. */
		if(!uri->portText.first || !uri->portText.afterLast)
		{
			if(s.amqp_scheme == settings::amqp_scheme_t::amqp)
				s.amqp_port = 5672;
			else
				s.amqp_port = 5671;
		}
		else
		{
			std::string sport = std::string(uri->portText.first, uri->portText.afterLast);

			int port = atoi(sport.c_str());
			if(port <= 0 || port > 65535)
			{
				out << "Port must be in the range [1, 65535]." << std::endl;
				return false;
			}

			s.amqp_port = static_cast<uint16_t>(port);
		}
	}

	{ /* User/Pass */
		/* Don't do NULL checks here, allow it. */
		std::string user(uri->userInfo.first, uri->userInfo.afterLast);

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
		std::vector<char> vhost;
		for(UriPathSegmentA *seg = uri->pathHead; seg; seg = seg->next)
		{
			vhost.insert(vhost.end(), seg->text.first, seg->text.afterLast);
			vhost.push_back('/');
		}
		if(uri->pathHead)
			vhost.pop_back();
		vhost.push_back('\0');
		s.amqp_vhost = vhost.data();
	}

	return true;
}

static filesystem::path build_default_workdir(uuid& uu)
{
	return filesystem::temp_directory_path() / fmt::format("nimrodg-agent-{}", uu.str());
}

static bool parse_encoding(const char *s, settings::encoding_t& enc)
{
	if(!strcmp(s, "plain"))
		return enc = settings::encoding_t::plain, true;
	else if(!strcmp(s, "base64"))
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

static bool parse_output(const char *s, settings::output_t& out)
{
	if(!strcmp(s, "console"))
		return out = settings::output_t::console, true;
	else if(!strcmp(s, "off"))
		return out = settings::output_t::off, true;
	else if(!strcmp(s, "workroot"))
		return out = settings::output_t::workroot, true;

	return false;
}

bool nimrod::parse_program_arguments(int argc, char **argv, int& status, std::ostream& out, std::ostream& err, settings& s)
{
	parg_state ps;
	parg_init(&ps);

	bool have_uri = false;
	bool have_key = false;
	bool have_fanout = false;
	bool have_direct = false;

	s = settings();

	for(int c; (c = parg_getopt_long(&ps, argc, argv, "vpuh", argdefs, nullptr)) != -1; )
	{
		switch(c)
		{
			case ARGDEF_VERSION:
				out << g_compile_info.description << std::endl;
				status = 0;
				return false;

			case ARGDEF_PLATFORM:
				out << g_compile_info.platform_string << std::endl;
				status = 0;
				return false;

			case ARGDEF_USERAGENT:
				out << g_compile_info.user_agent << std::endl;
				status = 0;
				return false;

			case ARGDEF_HELP:
				status = usage(0, out, argv[0]);
				return false;

			case ARGDEF_NO_CA_DELETE:
				s.ca_no_delete = true;
				break;

			case ARGDEF_NO_VERIFY_PEER:
				s.ssl_no_verify_peer = true;
				break;

			case ARGDEF_NO_VERIFY_HOST:
				s.ssl_no_verify_hostname = true;
				break;

			case ARGDEF_CACERT:
				s.ca_path = ps.optarg;
				break;

			case ARGDEF_CAENC:
				if(!parse_encoding(ps.optarg, s.ca_encoding))
				{
					status = usage(2, out, argv[0]);
					return false;
				}
				break;

			case ARGDEF_WORKROOT:
				s.work_root = ps.optarg;
				break;

			case ARGDEF_BATCH:
				s.batch = true;
				break;

			case ARGDEF_OUTPUT:
				if(!parse_output(ps.optarg, s.output))
				{
					status = usage(2, out, argv[0]);
					return false;
				}
				break;

			case ARGDEF_NOHUP:
				s.nohup = true;
				break;

			case ARGDEF_AMQPURI:
				s.amqp_raw_uri = ps.optarg;
				have_uri = true;
				break;

			case ARGDEF_AMQP_ROUTING_KEY:
				s.amqp_routing_key = ps.optarg;
				have_key = true;
				break;

			case ARGDEF_AMQP_FANOUT_EXCHANGE:
				s.amqp_fanout_exchange = ps.optarg;
				have_fanout = true;
				break;

			case ARGDEF_AMQP_DIRECT_EXCHANGE:
				s.amqp_direct_exchange = ps.optarg;
				have_direct = true;
				break;

			case ARGDEF_UUID:
			{
				uuid_t _uuid;
				if(uuid_parse(ps.optarg, _uuid) < 0)
				{
					status = parseerror(2, out, argv[0], "Malformed UUID");
					return false;
				}

				s.uuid = _uuid;
				break;
			}

			case '?':
			default:
				status = usage(2, out, argv[0]);
				return false;
		}
	}

	if(!have_uri)
	{
		status = parseerror(2, out, argv[0], "Option --amqp-uri is required.");
		return false;
	}

	if(!have_key)
		s.amqp_routing_key = "iamthemaster";

	if(!have_fanout)
		s.amqp_fanout_exchange = "amq.fanout";

	if(!have_direct)
		s.amqp_direct_exchange = "amq.direct";

	{ /* Validate the AMQP URI */
		if(!(s.amqp_uri = parse_uri(s.amqp_raw_uri.c_str())))
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


	/*
	** If no work-root was specified, regenerate the default
	** one with our new UUID.
	*/
	if(s.work_root.empty())
		s.work_root = build_default_workdir(s.uuid).string();

	if(s.batch)
	{
		s.nohup = true;
		if(s.output == settings::output_t::console)
			s.output = settings::output_t::workroot;
	}
	return true;
}

settings::settings() :
	ca_path(""),
	ca_encoding(encoding_t::plain),
	ca_no_delete(false),
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
	amqp_fanout_exchange(""),
	amqp_direct_exchange(""),
	ssl_no_verify_peer(false),
	ssl_no_verify_hostname(false),
	uuid(),
	work_root(""),
	batch(false),
	output(output_t::console),
	nohup(false)
{}