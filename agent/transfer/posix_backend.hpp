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
#ifndef _TRANSFER_POSIX_BACKEND_HPP
#define _TRANSFER_POSIX_BACKEND_HPP

#include "config.h"
#if defined(NIMRODG_USE_POSIX)
#include "transfer_backend.hpp"
#include "utils_posix.hpp"

namespace nimrod::posix {

class posix_backend : public tx::transfer_backend
{
private:
	enum class state_t
	{
		ready,
		busy,
		waiting_to_stop
	};

public:
	posix_backend(txman& tx, tx::result_proc proc);

	void do_transfer(tx::operation_t op, const UriUriA *uri, const filesystem::path& path) override;
	void cancel() override;

private:

	state_t m_state;
	std::atomic_bool m_stopflag;
};

}

#endif
#endif /*_TRANSFER_POSIX_BACKEND_HPP */