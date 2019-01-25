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
#ifndef _NIMRODG_AGENT_THREADING_HPP
#define _NIMRODG_AGENT_THREADING_HPP

#if defined(__MINGW32__)
/* https://github.com/meganz/mingw-std-threads */
#	include "mingw.mutex.h"
#	include "mingw.thread.h"
#else
#	include <thread>
#	include <mutex>
#endif

#endif /* _NIRMODG_AGENT_THREADING_HPP */
