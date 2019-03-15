#!/bin/sh
set -e

if [ -z "$PREFIX" ]; then
    echo "\$PREFIX not set"
    exit 2
fi

if [ -z "$LIBRESSL_VERSION" ]; then
    LIBRESSL_VERSION=2.9.0
fi

if [ -z "$LIBSSH2_VERSION" ]; then
    LIBSSH2_VERSION=1.8.0
fi

if [ -z "$CURL_VERSION" ]; then
    CURL_VERSION=7.64.0
fi

#export DEBUG_FLAGS=--enable-debug
export PKG_CONFIG_PATH=${PREFIX}/lib/pkgconfig
mkdir -p ${PKG_CONFIG_PATH}

STARTCWD=$PWD

##
# LibreSSL
##
if [ ! -f "libressl-${LIBRESSL_VERSION}.tar.gz" ]; then
    wget https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL_VERSION}.tar.gz
fi

tar -xf "libressl-${LIBRESSL_VERSION}.tar.gz"

mkdir -p libressl-build
cd libressl-build
    ../libressl-${LIBRESSL_VERSION}/configure --disable-asm --enable-shared=no --enable-static=yes --prefix=${PREFIX}
    make -j
    make install
cd ${STARTCWD}

##
# libssh2
##
if [ ! -f "libssh2-${LIBSSH2_VERSION}.tar.gz" ]; then
    wget https://www.libssh2.org/download/libssh2-${LIBSSH2_VERSION}.tar.gz
fi

tar -xf "libssh2-${LIBSSH2_VERSION}.tar.gz"

mkdir -p libssh2-build
cd libssh2-build
    ../libssh2-${LIBSSH2_VERSION}/configure ${DEBUG_FLAGS} \
        --prefix=${PREFIX} \
        --disable-shared \
        --enable-static \
        --disable-rpath \
        --with-openssl \
        --without-libz \
        --disable-examples-build
    make -j
    make install
cd ${STARTCWD}

##
# cURL
##
if [ ! -f "curl-${CURL_VERSION}.tar.xz" ]; then
    wget https://curl.haxx.se/download/curl-${CURL_VERSION}.tar.xz
fi

tar -xf "curl-${CURL_VERSION}.tar.xz"

mkdir -p curl-build
cd curl-build
    ../curl-${CURL_VERSION}/configure ${DEBUG_FLAGS} \
        --prefix=${PREFIX} \
        --disable-shared \
        --enable-static \
        --disable-ares \
        --disable-rt \
        --enable-http \
        --enable-ftp \
        --disable-file \
        --disable-ldap \
        --disable-ldaps \
        --disable-rtsp \
        --disable-proxy \
        --disable-dict \
        --disable-telnet \
        --disable-tftp \
        --disable-pop3 \
        --disable-imap \
        --disable-smb \
        --disable-smtp \
        --enable-gopher \
        --enable-ipv6 \
        --disable-openssl-auto-load-config \
        --disable-cookies \
        --disable-threaded-resolver \
        --without-brotli \
        --without-ca-bundle \
        --without-ca-path \
        --without-libpsl \
        --with-libssh2 \
        --without-libidn \
        --without-libidn2 \
        --without-zlib
    make -j
    make install
cd ${STARTCWD}


# cmake -DCMAKE_INSTALL_PREFIX=$PWD/../prefix -DBUILD_SHARED_LIBS=OFF -DNIMRODG_PLATFORM_STRING="x86_64-pc-linux-gnu" ~/Documents/Coding/nimrodg-agent/

