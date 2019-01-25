set(CMAKE_SYSTEM_NAME Linux)

set(tuple armv8-rpi3-linux-gnueabihf)
set(base /opt/x-tools/${tuple})

set(CMAKE_C_COMPILER ${base}/bin/${tuple}-gcc)
set(CMAKE_CXX_COMPILER ${base}/bin/${tuple}-g++)
set(CMAKE_FIND_ROOT_PATH /${base})

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++" CACHE STRING "" FORCE)

set(NIMRODG_PLATFORM_STRING ${tuple} CACHE STRING "" FORCE)
set(HAVE_POLL_FINE_EXITCODE 0)