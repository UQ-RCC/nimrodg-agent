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
#if defined(NIMRODG_USE_POSIX)
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include "agent_common.hpp"
#include "posix_backend.hpp"

using namespace nimrod;
using namespace nimrod::tx;
using namespace nimrod::posix;

#if !defined(__linux__)
#	error This is actually a Linux implementation.
#endif

static int copyfile(int fdin, int fdout, const struct stat *instats, std::atomic_bool& stopflag) noexcept
{
	struct stat stats;
	int pipefd[2];

	if(instats == nullptr)
	{
		if(fstat(fdin, &stats) < 0)
			return errno;
	}
	else
	{
		stats = *instats;
	}

	if(pipe2(pipefd, O_CLOEXEC))
		return errno;

	fd_ptr _fd0(pipefd[0]);
	fd_ptr _fd1(pipefd[1]);

	/* http://yarchive.net/comp/linux/splice.html */

	for(size_t left = stats.st_size;;)
	{
		if(stopflag)
			return EINTR;

		ssize_t nr = splice(fdin, nullptr, pipefd[1], nullptr, left, 0);
		if(nr == 0)
			break;
		else if(nr < 0)
			return errno;
		
		left -= nr;

		do
		{
			if(stopflag)
				return EINTR;

			ssize_t ret = splice(pipefd[0], nullptr, fdout, nullptr, nr, 0);
			if(ret <= 0)
				return errno;

			nr -= ret;
		}
		while(nr);
	}

	return 0;
}

posix_backend::posix_backend(txman& tx, result_proc proc) :
	transfer_backend(tx, proc),
	m_state(state_t::ready),
	m_stopflag(false)
{}

void posix_backend::do_transfer(tx::operation_t op, const UriUriA *uri, const filesystem::path& path)
{
	if(m_state != state_t::ready)
		throw std::logic_error("Invalid state transition");

	if(uri == nullptr)
		return this->set_error(error_type::argument, -1, "Invalid URI");

	if(path.empty())
		return this->set_error(error_type::argument, -1, "Invalid path");

	std::string src = uristring_to_path(uri_to_string(uri));
	if(src.empty())
		return this->set_error(error_type::argument, -1, "Invalid path");

	std::string dest = path.c_str();

	if(op == tx::operation_t::put)
		src.swap(dest);

	//fprintf(stderr, "source = %s, dest = %s\n", src.c_str(), dest.c_str());

	/* Open the files here to catch errors early. */
	fd_ptr infd(open(src.c_str(), O_RDONLY | O_CLOEXEC));
	if(!infd)
		return this->set_errno(errno);

	struct stat instats;
	if(fstat(infd.get(), &instats))
		return this->set_errno(errno);

	fd_ptr outfd(open(dest.c_str(), O_WRONLY | O_CREAT | O_NOCTTY | O_TRUNC, instats.st_mode & 0777));
	if(!outfd)
		return this->set_errno(errno);

	std::thread([this, instats](fd_ptr infd, fd_ptr outfd) {
		m_state = state_t::busy;

		int err = copyfile(infd.get(), outfd.get(), &instats, m_stopflag);
		m_state = state_t::ready;

		this->set_result(std::make_pair(
			err == 0 ? error_type::none : error_type::system,
			std::make_pair(err, strerror(err))
		));
	}, std::move(infd), std::move(outfd)).detach();
}

void posix_backend::cancel()
{
	if(m_state != state_t::busy)
		return;

	m_stopflag.store(true);
}

#endif