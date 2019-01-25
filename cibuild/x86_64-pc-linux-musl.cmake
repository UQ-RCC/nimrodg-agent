set(CMAKE_SYSTEM_NAME Linux)

set(CMAKE_C_COMPILER /opt/x-tools/x86_64-pc-linux-musl/bin/x86_64-pc-linux-musl-gcc)
set(CMAKE_CXX_COMPILER /opt/x-tools/x86_64-pc-linux-musl/bin/x86_64-pc-linux-musl-g++)
set(CMAKE_FIND_ROOT_PATH /opt/x-tools/x86_64-pc-linux-musl)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static -mindirect-branch=thunk" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static -mindirect-branch=thunk" CACHE STRING "" FORCE)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++" CACHE STRING "" FORCE)

# We're static, not stupid. We'll work.
set(CMAKE_CROSSCOMPILING_EMULATOR "sh" CACHE STRING "" FORCE)
set(NIMRODG_PLATFORM_STRING "x86_64-pc-linux-musl" CACHE STRING "" FORCE)
