cmake_minimum_Required(VERSION 3.3)
project(nimrodg-agent)

enable_language(C CXX)

set(OPENSSL_USE_STATIC_LIBS ON CACHE BOOL "" FORCE)

function(add_uriparser)
	set(URIPARSER_BUILD_URIPARSE	OFF CACHE BOOL "" FORCE)
	add_subdirectory(uriparser)
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
	#target_compile_definitions(amqp-cpp PUBLIC AMQPP_STATIC_LIB)
	#target_include_directories(rabbitmq INTERFACE "./rabbitmq-c/librabbitmq")
	target_include_directories(rabbitmq-static INTERFACE "./rabbitmq-c/librabbitmq")
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

option(NIMRODG_PLATFORM_STRING "Agent Platform String" "")

if(NOT ${NIMRODG_PLATFORM_STRING})
	if(MSVC)
		if(${CMAKE_SIZEOF_VOID_P} EQUAL 4)
			set(NIMRODG_PLATFORM_STRING "i686-pc-windows-msvc")
		elseif(${CMAKE_SIZEOF_VOID_P} EQUAL 8)
			set(NIMRODG_PLATFORM_STRING "x86_64-pc-windows-msvc")
		endif()
	endif()
endif()

add_uriparser()
add_rabbitmqc()
add_subdirectory(uuid)
add_subdirectory(fmt)
add_subdirectory(agent)
