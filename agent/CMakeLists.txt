project(agent)

enable_language(C CXX)

if(NOT WIN32)
	set(THREADS_PREFER_PTHREAD_FLAG ON)
	find_package(Threads REQUIRED)
endif()

find_package(OpenSSL 2.0.0 REQUIRED)
find_package(LibSSH2 1.8.0 REQUIRED)

find_package(CURL 7.64.0 REQUIRED REQUIRED COMPONENTS HTTP HTTPS SSL FTPS GOPHER SCP SFTP TFTP)
target_link_libraries(CURL::libcurl INTERFACE ${LIBSSH2_LIBRARY})


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

if(GIT_DESCRIBE MATCHES "-NOTFOUND$")
	set(GIT_DESCRIBE "UNKNOWN")
endif()

if(GIT_LOCAL_CHANGES MATCHES "DIRTY")
	set(GIT_DESCRIBE "${GIT_DESCRIBE}-${GIT_LOCAL_CHANGES}")
	set(GIT_DIRTY 1)
else()
	set(GIT_DIRTY 0)
endif()

get_target_property(URIPARSER_VERSION_STRING uriparser VERSION)
get_target_property(UUID_VERSION_STRING      uuid      VERSION)

if(NOT NIMRODG_PLATFORM_STRING)
	message(FATAL_ERROR "No platform string provided")
endif()

configure_file("${PROJECT_SOURCE_DIR}/config.h.in" "${CMAKE_CURRENT_BINARY_DIR}/config.h")
configure_file("${PROJECT_SOURCE_DIR}/config.cpp.in" "${CMAKE_CURRENT_BINARY_DIR}/config.cpp")

set(MESSAGE_FILES
	./messages/netmsg.hpp
	./messages/netmsg.cpp

	./messages/formatters.cpp

	./messages/messages.hpp
	./messages/messages.cpp

	./messages/netmsg_json.hpp
	./messages/netmsg_json.cpp
)
source_group("Network Messages" FILES ${MESSAGE_FILES})

set(PROCESS_FILES
	./process/command_result.hpp
	./process/command_result.cpp

	./process/procman.hpp
	./process/procman.cpp

	./process/process.hpp
	./process/process.cpp

	./process/process_win32.cpp
	./process/process_win32.hpp

	./process/process_posix.cpp
	./process/process_posix.hpp
)
source_group("Process" FILES ${PROCESS_FILES})

set(PARG_FILES
	./parg/parg.c
	./parg/parg.h
)
source_group("parg" FILES ${PARG_FILES})

set(TRANSFER_FILES
	./transfer.hpp

	./transfer/transfer_backend.hpp
	./transfer/transfer_backend.cpp

	./transfer/curl_backend.hpp
	./transfer/curl_backend.cpp

	./transfer/win32_backend.hpp
	./transfer/win32_backend.cpp

	./transfer/posix_backend.hpp
	./transfer/posix_backend.cpp
)
source_group("Transfer" FILES ${TRANSFER_FILES})

set(AGENT_FILES
	./config.h.in
	${CMAKE_CURRENT_BINARY_DIR}/config.h
	./config.cpp.in
	${CMAKE_CURRENT_BINARY_DIR}/config.cpp

	../concurrentqueue/concurrentqueue.h
	../concurrentqueue/blockingconcurrentqueue.h

	./json.hpp

	./agent_common.hpp
	./agent_fwd.hpp

	./amqp_exception.hpp
	./amqp_exception.cpp

	./log.hpp
	./log.cpp

	./amqp_consumer.hpp
	./amqp_consumer.cpp

	./event.hpp
	./event.cpp

	./rearmable_event.hpp

	./main.cpp
	./settings.cpp
	./utils.cpp
	./ssl.cpp
	./console.cpp
	./netthread.cpp

	./agent.hpp
	./agent.cpp

	./uuid.hpp
	./uuid.cpp

	./job_definition.hpp
	./job_definition.cpp

	./utils_win32.hpp
	./utils_win32.cpp

	./utils_posix.hpp
	./utils_posix.cpp
)

add_executable(agent
	${AGENT_FILES}
	${MESSAGE_FILES}
	${PROCESS_FILES}
	${PARG_FILES}
	${TRANSFER_FILES}
)

set_target_properties(agent PROPERTIES
	C_STANDARD 11
	CXX_STANDARD 17
	CXX_STANDARD_REQUIRED ON
)

target_include_directories(agent
	PRIVATE "." "../concurrentqueue"
	PUBLIC ${CMAKE_CURRENT_BINARY_DIR}
)

target_link_libraries(agent
	fmt-header-only
	uuid
	uriparser
	rabbitmq-c2
	CURL::libcurl
)

if(NOT WIN32)
	target_link_libraries(agent Threads::Threads)
endif()


# Mainly for Windows, but doesn't hurt on others
target_compile_definitions(agent PRIVATE
		-DCURL_STATICLIB
		-DAMQP_STATIC
)

# Add -lstdc++fs on GCC/Clang
if(NOT MINGW AND (CMAKE_CXX_COMPILER_ID MATCHES "GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang"))
	target_link_libraries(agent stdc++fs)
endif()

if(MSVC)
	target_compile_definitions(agent PRIVATE _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS)
endif()

