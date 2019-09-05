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
#ifndef _REARMABLE_EVENT_HPP
#define _REARMABLE_EVENT_HPP

#include <chrono>
#include <atomic>
#include <utility>
#include <thread>
#include <condition_variable>
#include <functional>

enum class rearmable_event_result
{
	success,
	aborted,
	timed_out
};

template<class Predicate, class Proc>
class rearmable_event
{
public:
	using result_type = rearmable_event_result;

	rearmable_event(Predicate predicate, Proc proc) noexcept :
		m_predicate(predicate),
		m_proc(proc),
		m_active(false)
	{}

	~rearmable_event()
	{
		abort();

		if(m_thread.joinable())
			m_thread.join();
	}

	rearmable_event(const rearmable_event&) = delete;
	rearmable_event(rearmable_event&&) = delete;
	rearmable_event& operator=(const rearmable_event&) = delete;
	rearmable_event& operator=(rearmable_event&&) = delete;

	// https://stackoverflow.com/a/45740494

	template<class Rep, class Period>
	bool rearm(const std::chrono::duration<Rep, Period>& rel_time)
	{
		bool exp = false;
		if(m_active.compare_exchange_strong(exp, true))
		{
			if(m_thread.joinable())
				m_thread.join();

			/* Lock the mutex so the thread doesn't start. */
			std::unique_lock<std::mutex> lk(m_startmutex);
			m_abort = false;
			m_startflag = false;
			//fprintf(stderr, "Starting thread...\n");
			m_thread = std::thread([this, &rel_time](){ return this->thread_proc(rel_time); });

			//fprintf(stderr, "Waiting for thread to ping...\n");

			m_startcv.wait(lk, [this](){ return static_cast<bool>(m_startflag); });
			//fprintf(stderr, "Thread pinged...\n");
			return true;
		}

		return false;
	}

	operator bool() const noexcept { return m_active; }

	void abort() noexcept
	{
		bool exp = false;
		if(m_abort.compare_exchange_strong(exp, true))
			m_cv.notify_all();
	}

	void notify() noexcept { m_cv.notify_all(); }

private:

	template<class Rep, class Period>
	void thread_proc(const std::chrono::duration<Rep, Period>& rel_time)
	{
		using namespace std::chrono_literals;

		bool _abort = false;
		bool _pred = false;
		bool _started = false;

		auto pred = [this, &_abort, &_pred, &_started]() {
			/*
			** This is done here to make sure rearm() doesn't return until we've entered the wait.
			** wait_for() will check the predicate first thing, so abuse this behaviour.
			*/
			if(!_started)
			{
				std::lock_guard<std::mutex> lk(m_startmutex);
				bool exp = false;
				if(m_startflag.compare_exchange_strong(exp, true))
					m_startcv.notify_all();

				_started = true;
			}

			_abort = m_abort;
			_pred = m_predicate();
			return _abort || _pred;
		};

		std::unique_lock<std::mutex> lk(m_mutex);

		result_type result;
		if(m_cv.wait_for(lk, rel_time, pred))
		{
			if(_abort)
				result = result_type::aborted;
			else if(_pred)
				result = result_type::success;
			else
				std::terminate(); /* Will never happen. */
		}
		else
		{
			result = result_type::timed_out;
		}

		try
		{
			m_proc(result);
		}
		catch(...)
		{
			m_active = false;
			m_abort = false;
			throw;
		}

		m_active = false;
		m_abort = false;
	}

	const Predicate m_predicate;
	const Proc m_proc;
	std::atomic_bool m_active;
	std::atomic_bool m_abort;
	std::thread m_thread;
	std::condition_variable m_cv;
	std::mutex m_mutex;

	std::mutex m_startmutex;
	std::condition_variable m_startcv;
	std::atomic_bool m_startflag;
};

using rearmable_event_e = rearmable_event<std::function<bool()>, std::function<void(rearmable_event_result)>>;

#endif /* _REARMABLE_EVENT_HPP */