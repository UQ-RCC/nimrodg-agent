cmake_minimum_required(VERSION 3.13)
project(nimrodg-agent)

enable_language(C CXX)

include(CheckIPOSupported)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
include(GetGitRevisionDescription)

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
	add_subdirectory(rabbitmq-c EXCLUDE_FROM_ALL)

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

add_rabbitmqc()

add_subdirectory(fmt)
add_subdirectory(libuuid)
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
