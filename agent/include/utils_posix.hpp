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
#ifndef _NIMRODG_UTILS_POSIX_HPP
#define _NIMRODG_UTILS_POSIX_HPP

#include "config.h"
#ifdef NIMRODG_USE_POSIX

#include <system_error>
#include <memory>

namespace nimrod {
namespace posix {

struct file_desc
{
	file_desc() : _desc(-1) {}
	file_desc(int fd) : _desc(fd) {}
	file_desc(std::nullptr_t) : _desc(-1) {}

	operator int() { return _desc; }

	bool operator==(const file_desc &other) const { return _desc == other._desc; }
	bool operator!=(const file_desc &other) const { return _desc != other._desc; }
	bool operator==(std::nullptr_t) const { return _desc == -1; }
	bool operator!=(std::nullptr_t) const { return _desc != -1; }

	int _desc;
};

struct fd_deleter
{
	using pointer = file_desc;
	void operator()(pointer p);
};

using fd_ptr = std::unique_ptr<int, fd_deleter>;

std::system_error make_errno_exception(int err);
std::string get_cspath();
void set_all_close_on_exec();
const char *get_signal_string(int signal);

}
}

#endif /* NIMRODG_USE_POSIX */
#endif /* _NIMRODG_UTILS_POSIX_HPP */
