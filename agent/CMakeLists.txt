project(agent)

enable_language(C CXX)

if(NOT WIN32)
	set(THREADS_PREFER_PTHREAD_FLAG ON)
	find_package(Threads REQUIRED)
endif()

find_package(OpenSSL 2.0.0 REQUIRED)
find_package(LibSSH2 1.8.0 REQUIRED)
find_package(CURL 7.64.0 REQUIRED)

include(CheckIncludeFiles)
check_include_file("unistd.h" HAVE_UNISTD_H)
check_include_file("windows.h" HAVE_WINDOWS_H)

if(HAVE_WINDOWS_H)
	set(NIMRODG_USE_WIN32API 1)
	set(NIMRODG_USE_POSIX 0)
elseif(HAVE_UNISTD_H)
	set(NIMRODG_USE_WIN32API 0)
	set(NIMRODG_USE_POSIX 1)
else()
	set(NIMRODG_USE_WIN32API 0)
	set(NIMRODG_USE_POSIX 0)
endif()

get_git_head_revision(GIT_REFSPEC GIT_SHA1)
git_describe(GIT_DESCRIBE)
git_local_changes(GIT_LOCAL_CHANGES)

if(NOT NIMRODG_PLATFORM_STRING)
	message(FATAL_ERROR "No platform string provided")
endif()

set(AGENT_GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/include")
set(AGENT_GENERATED_SRC_DIR "${CMAKE_CURRENT_BINARY_DIR}/src")

configure_file("${PROJECT_SOURCE_DIR}/include/config.h.in" "${AGENT_GENERATED_INCLUDE_DIR}/config.h")
configure_file("${PROJECT_SOURCE_DIR}/src/config.cpp.in" "${AGENT_GENERATED_SRC_DIR}/config.cpp")

set(MESSAGE_FILES
	./include/messages/base_message.hpp

	./include/messages/netmsg.hpp
	./src/messages/netmsg.cpp

	./src/messages/formatters.cpp

	./include/messages/messages.hpp
	./src/messages/messages.cpp

	./include/messages/netmsg_json.hpp
	./src/messages/netmsg_json.cpp
)
source_group("Network Messages" FILES ${MESSAGE_FILES})

set(PROCESS_FILES
	./include/process/command_result.hpp
	./src/process/command_result.cpp

	./include/process/procman.hpp
	./src/process/procman.cpp

	./include/process/process.hpp
	./src/process/process.cpp

	./src/process/process_win32.cpp
	./src/process/process_win32.hpp

	./src/process/process_posix.cpp
	./src/process/process_posix.hpp
)
source_group("Process" FILES ${PROCESS_FILES})

set(PARG_FILES
	./src/parg/parg.c
	./src/parg/parg.h
)
source_group("parg" FILES ${PARG_FILES})

set(TRANSFER_FILES
	./include/transfer.hpp

	./src/transfer/transfer_backend.hpp
	./src/transfer/transfer_backend.cpp

	./src/transfer/curl_backend.hpp
	./src/transfer/curl_backend.cpp

	./src/transfer/win32_backend.hpp
	./src/transfer/win32_backend.cpp

	./src/transfer/posix_backend.hpp
	./src/transfer/posix_backend.cpp
)
source_group("Transfer" FILES ${TRANSFER_FILES})

set(AGENT_FILES
	./include/config.h.in
	${AGENT_GENERATED_INCLUDE_DIR}/config.h
	./src/config.cpp.in
	${AGENT_GENERATED_SRC_DIR}/config.cpp

	../concurrentqueue/concurrentqueue.h
	../concurrentqueue/blockingconcurrentqueue.h

	./include/json.hpp

	./include/agent_common.hpp
	./include/agent_fwd.hpp

	./include/amqp_exception.hpp
	./src/amqp_exception.cpp

	./include/log.hpp
	./src/log.cpp

	./include/amqp_consumer.hpp
	./src/amqp_consumer.cpp

	./include/event.hpp
	./src/event.cpp

	./include/rearmable_event.hpp

	./src/main.cpp
	./src/settings.cpp
	./src/utils.cpp
	./src/ssl.cpp
	./src/console.cpp
	./src/netthread.cpp

	./include/agent.hpp
	./src/agent.cpp

	./include/uuid.hpp
	./src/uuid.cpp

	./include/job_definition.hpp
	./src/job_definition.cpp

	./include/utils_win32.hpp
	./src/utils_win32.cpp

	./include/utils_posix.hpp
	./src/utils_posix.cpp
)

add_executable(agent
	${AGENT_FILES}
	${MESSAGE_FILES}
	${PROCESS_FILES}
	${PARG_FILES}
	${TRANSFER_FILES}
)

set_property(TARGET agent PROPERTY C_STANDARD 11)
set_property(TARGET agent PROPERTY CXX_STANDARD 17)
set_property(TARGET agent PROPERTY CXX_STANDARD_REQUIRED ON)

target_include_directories(agent PRIVATE "include")
target_include_directories(agent PRIVATE "../concurrentqueue")
target_include_directories(agent PUBLIC ${AGENT_GENERATED_INCLUDE_DIR})

target_link_libraries(agent Threads::Threads)
target_link_libraries(agent fmt-header-only)
target_link_libraries(agent uuid)
target_link_libraries(agent uriparser)
target_link_libraries(agent rabbitmq-static)


target_include_directories(agent PRIVATE ${CURL_INCLUDE_DIRS})
target_link_libraries(agent ${CURL_LIBRARIES})

target_include_directories(agent PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(agent ${OPENSSL_LIBRARIES})

target_link_libraries(agent ${LIBSSH2_LIBRARY})

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
	target_link_libraries(agent stdc++fs)
endif()

if(MSVC)
	target_compile_definitions(agent PRIVATE _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS)
endif()
