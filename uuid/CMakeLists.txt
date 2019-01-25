cmake_minimum_required(VERSION 2.8)
project(uuid)

enable_language(C)

find_package(OpenSSL 2.0.0 REQUIRED)

set(UUID_HEADERS
	./include/uuid/uuid.h
)

set(UUID_SOURCES
	./src/clear.c
	./src/compare.c
	./src/copy.c
	./src/gen_uuid.c
	./src/isnull.c
	./src/pack.c
	./src/parse.c
	./src/unpack.c
	./src/unparse.c
	./src/uuid_time.c
	
	./src/uuidP.h
)

add_library(uuid STATIC
	${UUID_SOURCES}
	${UUID_HEADERS}
)

target_include_directories(uuid PUBLIC "include")
target_include_directories(uuid PRIVATE ".")
target_include_directories(uuid PRIVATE ${OPENSSL_INCLUDE_DIR})

target_link_libraries(uuid ${OPENSSL_LIBRARIES})