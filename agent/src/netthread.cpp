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
#include "log.hpp"

#if defined(NIMRODG_USE_WIN32API)
#	define WIN32_LEAN_AND_MEAN
#	include <winsock2.h>
#elif defined(NIMRODG_USE_POSIX)
#	include <sys/select.h>
#else
#	error shit
#endif

#include <curl/curl.h>
#include "amqp_consumer.hpp"
#include "transfer/curl_backend.hpp"

/* Network thread. Handles AMQP and cURL. */
void ttt(nimrod::amqp_consumer& amqp, CURLM *mh)
{
	fd_set readfds, writefds, exceptfds;

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);

	/* Add our cURL sockets. */
	bool docurl = false;
	int maxfd = -1;
	/* NB: Will never fail. */
	curl_multi_fdset(mh, &readfds, &writefds, &exceptfds, &maxfd);

	if(maxfd == -1)
		docurl = true;

	/* Add the AMQP socket. */
	int amqpfd = amqp.getsockfd();
	if(amqpfd >= 0)
	{
		FD_SET(amqpfd, &readfds);
		FD_SET(amqpfd, &writefds);
	}

	if(amqpfd > maxfd)
		maxfd = amqpfd;

	struct timeval to = {
		.tv_sec = 1,
		.tv_usec = 0
	};

	int rv = select(maxfd + 1, &readfds, &writefds, &exceptfds, &to);
	if(rv < 0)
		return;
	else if(rv == 0)
		return;

	int amqcount = 0;
	if(FD_ISSET(amqpfd, &readfds))
	{
		FD_CLR(amqpfd, &readfds);
		++amqcount;
	}

	if(FD_ISSET(amqpfd, &writefds))
	{
		FD_CLR(amqpfd, &writefds);
		++amqcount;
	}

	if(amqcount)
	{
		/* AMQP activity */
		amqp.onactivity();
	}

	if(docurl || rv - amqcount > 0)
	{
		/* cURL activity */
		int nh;
		CURLMcode merr;
		while((merr = curl_multi_perform(mh, &nh)) == CURLM_CALL_MULTI_PERFORM)
			;

		int nmsg = 0;
		CURLMsg *msg;
		while((msg = curl_multi_info_read(mh, &nmsg)))
		{
			if(msg->msg != CURLMSG_DONE)
				continue;

			nimrod::tx::curl_backend *backend;
			curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &backend);
			backend->_handle_message(msg);
		}
	}
}