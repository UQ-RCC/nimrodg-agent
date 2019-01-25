# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

#.rst:
# FindOpenSSL
# -----------
#
# Find the OpenSSL encryption library.
# Or rather, find the local copy of OpenSSL/LibreSSL.
#
# Imported Targets
# ^^^^^^^^^^^^^^^^
#
# This module defines the following :prop_tgt:`IMPORTED` targets:
#
# ``OpenSSL::SSL``
#   The OpenSSL ``ssl`` library, if found.
# ``OpenSSL::Crypto``
#   The OpenSSL ``crypto`` library, if found.
#
# Result Variables
# ^^^^^^^^^^^^^^^^
#
# This module will set the following variables in your project:
#
# ``OPENSSL_FOUND``
#   System has the OpenSSL library.
# ``OPENSSL_INCLUDE_DIR``
#   The OpenSSL include directory.
# ``OPENSSL_CRYPTO_LIBRARY``
#   The OpenSSL crypto library.
# ``OPENSSL_SSL_LIBRARY``
#   The OpenSSL SSL library.
# ``OPENSSL_LIBRARIES``
#   All OpenSSL libraries.
# ``OPENSSL_VERSION``
#   This is set to ``$major.$minor.$revision$patch`` (e.g. ``0.9.8s``).
#
# Hints
# ^^^^^
#
# Set ``OPENSSL_ROOT_DIR`` to the root directory of an OpenSSL installation.
# Set ``OPENSSL_USE_STATIC_LIBS`` to ``TRUE`` to look for static libraries.
# Set ``OPENSSL_MSVC_STATIC_RT`` set ``TRUE`` to choose the MT version of the lib.

set(OPENSSL_FOUND TRUE)

set(OPENSSL_CRYPTO_LIBRARY crypto)
set(OPENSSL_SSL_LIBRARY ssl)

set(OPENSSL_LIBRARIES ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})

add_library(OpenSSL::SSL ALIAS ${OPENSSL_SSL_LIBRARY})
add_library(OpenSSL::Crypto ALIAS ${OPENSSL_CRYPTO_LIBRARY})

get_target_property(OPENSSL_INCLUDE_DIR ${OPENSSL_SSL_LIBRARY} SOURCE_DIR)
set(OPENSSL_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR}/../include)

set(OPENSSL_VERSION "2.0.0")
