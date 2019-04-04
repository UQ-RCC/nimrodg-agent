#!/bin/sh
set -e

PLATFORMS="x86_64-pc-linux-musl i686-pc-linux-musl armv6-rpi-linux-gnueabi armv8-rpi3-linux-gnueabihf"
#PLATFORMS=x86_64-pc-linux-musl
#PLATFORMS=armv6-rpi-linux-gnueabi

STARTCWD=$PWD

for p in ${PLATFORMS}; do
    mkdir -p "${p}"
    cd ${p}

    export PREFIX=$PWD/prefix
    export CC=/opt/x-tools/${p}/bin/${p}-gcc
    export CXX=/opt/x-tools/${p}/bin/${p}-g++
    export STRIP=/opt/x-tools/${p}/bin/${p}-strip

    ../../buildprefix.sh
    export PKG_CONFIG_PATH=${PREFIX}/lib/pkgconfig

    echo "PREFIX=${PREFIX}"
    echo "PKG_CONFIG_PATH=${PKG_CONFIG_PATH}"

    mkdir -p agent-build && cd agent-build
    cmake \
        -DCMAKE_INSTALL_PREFIX=${PREFIX} \
        -DCMAKE_TOOLCHAIN_FILE=${STARTCWD}/../cibuild/${p}.cmake \
        -DBUILD_SHARED_LIBS=Off \
        -DCMAKE_BUILD_TYPE=MinSizeRel \
        -DNIMRODG_PLATFORM_STRING=${p} \
        ${STARTCWD}/..
    make -j agent
    ${STRIP} -s ../agent-build/agent/agent
    cp ../agent-build/agent/agent ${STARTCWD}/agent-${p}-$(git describe)
    cd ${STARTCWD}
done