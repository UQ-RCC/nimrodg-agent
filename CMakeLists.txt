cmake_minimum_required(VERSION 3.13)
project(nimrodg-agent)

enable_language(C CXX)

include(CheckIPOSupported)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
include(GetGitRevisionDescription)

set(OPENSSL_USE_STATIC_LIBS ON CACHE BOOL "" FORCE)

function(add_uriparser)
	set(BUILD_SHARED_LIBS		OFF CACHE BOOL "" FORCE)
	set(URIPARSER_BUILD_DOCS	OFF CACHE BOOL "" FORCE)
	set(URIPARSER_BUILD_TESTS	OFF CACHE BOOL "" FORCE)
	set(URIPARSER_BUILD_TOOLS	OFF CACHE BOOL "" FORCE)
	set(URIPARSER_BUILD_CHAR	ON CACHE BOOL "" FORCE)
	set(URIPARSER_BUILD_WCHAR_T	OFF CACHE BOOL "" FORCE)
	add_subdirectory(uriparser)


	# Absolutely disgusting
	set(XXXX ${CMAKE_CURRENT_SOURCE_DIR})
	set(CMAKE_CURRENT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/uriparser)
	git_describe(URIPARSER_VERSION_STRING)
	string(REGEX REPLACE "^uriparser-([0-9]\\.[0-9]\\.[0-9])" "\\1" URIPARSER_VERSION_STRING ${URIPARSER_VERSION_STRING})
	set(CMAKE_CURRENT_SOURCE_DIR ${XXXX})
	unset(XXXX)
	set_target_properties(uriparser PROPERTIES VERSION ${URIPARSER_VERSION_STRING})
endfunction(add_uriparser)

function(add_rabbitmqc)
	set(REGENERATE_AMQP_FRAMING	OFF	CACHE BOOL "" FORCE)
	set(BUILD_SHARED_LIBS		OFF	CACHE BOOL "" FORCE)
	set(BUILD_STATIC_LIBS		ON	CACHE BOOL "" FORCE)
	set(BUILD_EXAMPLES			OFF	CACHE BOOL "" FORCE)
	set(BUILD_TOOLS				OFF	CACHE BOOL "" FORCE)
	set(BUILD_TOOLS_DOCS		OFF	CACHE BOOL "" FORCE)
	set(BUILD_TESTS				OFF	CACHE BOOL "" FORCE)
	set(BUILD_API_DOCS			OFF	CACHE BOOL "" FORCE)
	set(ENABLE_SSL_SUPPORT		ON	CACHE BOOL "" FORCE)
	set(ENABLE_THREAD_SAFETY	ON	CACHE BOOL "" FORCE)
	add_subdirectory(rabbitmq-c)

	# Hack to workaround the new install()
	add_library(rabbitmq-c2 INTERFACE)
	target_include_directories(rabbitmq-c2 INTERFACE rabbitmq-c/librabbitmq)
	target_link_libraries(rabbitmq-c2 INTERFACE rabbitmq-static)
endfunction(add_rabbitmqc)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# If we're building with MSVC, use /MTd and /MT instead of /MDd and /MD
if(MSVC)
	set(CompilerFlags
		CMAKE_CXX_FLAGS
		CMAKE_CXX_FLAGS_DEBUG
		CMAKE_CXX_FLAGS_RELEASE
		CMAKE_CXX_FLAGS_RELWITHDEBINFO
		CMAKE_CXX_FLAGS_MINSIZEREL
		CMAKE_C_FLAGS
		CMAKE_C_FLAGS_DEBUG
		CMAKE_C_FLAGS_RELEASE
		CMAKE_C_FLAGS_RELWITHDEBINFO
		CMAKE_C_FLAGS_MINSIZEREL
	)

	foreach(CompilerFlag ${CompilerFlags})
		string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
	endforeach()
endif()

function(add_libuuid)
	# Hack in a CMake-ified libuuid
	# find ./util-linux/libuuid/src -type f -name "*.[cChH]" | sort -u
	add_library(uuid STATIC
			./util-linux/libuuid/src/clear.c
			./util-linux/libuuid/src/compare.c
			./util-linux/libuuid/src/copy.c
			./util-linux/libuuid/src/isnull.c
			./util-linux/libuuid/src/pack.c
			./util-linux/libuuid/src/parse.c
			./util-linux/libuuid/src/predefined.c
			./util-linux/libuuid/src/unpack.c
			./util-linux/libuuid/src/unparse.c
			./util-linux/libuuid/src/uuidd.h
			./util-linux/libuuid/src/uuid.h
			./util-linux/libuuid/src/uuidP.h
			./util-linux/libuuid/src/uuid_time.c

			# NB: Excluding these.
			# gen_uuid.c requires special configuration, where we're just
			# using OpenSSL.
			# test_uuid.c has nothing to do with us.
			#./util-linux/libuuid/src/gen_uuid.c
			#./util-linux/libuuid/src/test_uuid.c
	)

	target_include_directories(uuid PUBLIC ./util-linux/libuuid/src)

	set(XXXX ${CMAKE_CURRENT_SOURCE_DIR})
	set(CMAKE_CURRENT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/util-linux)
	git_describe(LIBUUID_VERSION_STRING)
	set(CMAKE_CURRENT_SOURCE_DIR ${XXXX})
	unset(XXXX)

	set_target_properties(uuid PROPERTIES VERSION ${LIBUUID_VERSION_STRING})
endfunction()

if(NOT NIMRODG_PLATFORM_STRING)
	if(MSVC)
		if(${CMAKE_SIZEOF_VOID_P} EQUAL 4)
			set(NIMRODG_PLATFORM_STRING "i686-pc-windows-msvc")
		elseif(${CMAKE_SIZEOF_VOID_P} EQUAL 8)
			set(NIMRODG_PLATFORM_STRING "x86_64-pc-windows-msvc")
		endif()
	endif()
endif()

if(NOT NIMRODG_OUTPUT_DIRECTORY)
    set(NIMRODG_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin")
endif()

# Persist everything to the cache
set(NIMRODG_PLATFORM_STRING  ${NIMRODG_PLATFORM_STRING}  CACHE STRING "Agent Platform String"   FORCE)
set(NIMRODG_OUTPUT_DIRECTORY ${NIMRODG_OUTPUT_DIRECTORY} CACHE STRING "Agent Install Directory" FORCE)

add_uriparser()
add_rabbitmqc()
add_libuuid()
add_subdirectory(fmt)
add_subdirectory(nim1)
add_subdirectory(agent)


option(USE_LTO "Use LTO" OFF)
if(USE_LTO)
	check_ipo_supported(RESULT IPO_SUPPORTED LANGUAGES C CXX)
	if(NOT IPO_SUPPORTED)
		message(STATUS "LTO not supported, disabling...")
		set(USE_LTO OFF)
	endif()
endif()

message(STATUS "LTO Active: ${USE_LTO}")

set_target_properties(agent PROPERTIES
    OUTPUT_NAME                 agent-${NIMRODG_PLATFORM_STRING}
    RUNTIME_OUTPUT_DIRECTORY    ${NIMRODG_OUTPUT_DIRECTORY}
)

if(NOT CMAKE_BUILD_TYPE MATCHES Debug AND USE_LTO)
	set_target_properties(agent PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()
