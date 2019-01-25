/*
 * Nimrod/G Agent
 * https://github.com/UQ-RCC/nimrodg-agent
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 The University of Queensland
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Put everything OpenSSL/LibreSSL-related in here. The headers do screwy things with windows.h */
#include "log.hpp"
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include "agent_common.hpp"

using namespace nimrod;

void nimrod::deleter_x509_store::operator()(X509_STORE *v) const { X509_STORE_free(v); }

template <typename T>
static T report_openssl_error(unsigned long err)
{
	char errBuffer[256];
	ERR_error_string_n(err, errBuffer, sizeof(errBuffer));
	log::error("OpenSSL", "%s", errBuffer);
	return T();
}

template <typename T>
static T report_openssl_error()
{
	return report_openssl_error<T>(ERR_get_error());
}

void nimrod::init_openssl()
{
	log::info("AGENT", "Initialising " OPENSSL_VERSION_TEXT "...");
	SSL_library_init();
	OpenSSL_add_ssl_algorithms();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ERR_load_crypto_strings();
}

void nimrod::dump_ca_store(const x509_store_ptr& castore)
{
	/* For Reference: (X509_OBJECT**)castore.get()->objs->stack.data */
	log::info("AGENT", "Loaded %d certificate(s)...", castore->objs->stack.num);

	{ /* Print certificate list (trace) */
		X509_OBJECT **store = reinterpret_cast<X509_OBJECT**>(castore->objs->stack.data);
		for(int i = 0; i < castore->objs->stack.num; ++i)
		{
			if(store[i]->type == X509_LU_X509)
			{
				X509 *x509 = store[i]->data.x509;
				log::trace("AGENT", "  [%d] %s", i, x509->name);
			}
		}
	}
}

x509_store_ptr nimrod::new_ca_store()
{
	x509_store_ptr store(X509_STORE_new());
	if(!store)
		return report_openssl_error<x509_store_ptr>();

	return store;
}

x509_store_ptr nimrod::load_ca_store_mem(const char *data, size_t size)
{
	ERR_clear_error();

	x509_store_ptr store = new_ca_store();
	if(!store)
		return store;

	if(size >= std::numeric_limits<int>::max())
	{
		log::error("AGENT", "Certificate store too big.");
		return nullptr;
	}

	if(X509_STORE_load_mem(store.get(), const_cast<char*>(data), static_cast<int>(size)) != 1)
		return report_openssl_error<x509_store_ptr>();

	return store;
}

void nimrod::set_ssl_store(SSL_CTX *ctx, X509_STORE *st)
{
	SSL_CTX_set_cert_store(ctx, st);

	/* SSL_CTX_set_cert_store() doesn't add a reference, so do it here. */
	CRYPTO_add(&ctx->references, 1, CRYPTO_LOCK_X509_STORE);
}

void nimrod::amqp_inject_x509_store(amqp_socket_t *socket, X509_STORE *ctx)
{
	if(ctx == nullptr)
		return;

	/* Yes, this is a hack. No, I don't care. */
	struct hack
	{
		const struct amqp_socket_class_t *klass;
		SSL_CTX *ctx;
	};

	struct hack *h = reinterpret_cast<struct hack*>(socket);

	set_ssl_store(h->ctx, ctx);
}

static size_t base64_get_decoded_length(const char *data, size_t size)
{
	if((size % 4) != 0)
		return 0;

	size_t padding;
	if(data[size - 1] != '=')
		padding = 0;
	else if(data[size - 2] == '=')
		padding = 2;
	else
		padding = 1;

	return ((size * 3) / 4) - padding;
}

std::unique_ptr<char[]> nimrod::base64_decode(const char *data, size_t inSize, size_t& outSize)
{
	/* OpenSSL */
	if(inSize >= std::numeric_limits<int>::max())
		return nullptr;

	outSize = base64_get_decoded_length(data, inSize);
	if(outSize == 0)
		return nullptr;

	std::unique_ptr<char[]> ptr = std::make_unique<char[]>(outSize);

	using bio_chain_ptr = std::unique_ptr<BIO, decltype(BIO_free_all)*>;

	BIO *_bio = BIO_new_mem_buf(const_cast<char*>(data), static_cast<int>(inSize));
	if(_bio == nullptr)
		return nullptr;

	bio_chain_ptr bio(_bio, [](BIO *b) { if(b) BIO_free_all(b); });

	BIO *b64 = BIO_new(BIO_f_base64());
	if(b64 == nullptr)
		return nullptr;

	BIO_push(b64, bio.get());
	(void)bio.release();
	bio.reset(b64);

	BIO_set_flags(bio.get(), BIO_FLAGS_BASE64_NO_NL);
	int len = BIO_read(bio.get(), ptr.get(), static_cast<int>(inSize));
	/* If this is wrong, we're not a full base64 string. */
	if(len != outSize)
		return nullptr;

	return ptr;
}

/* Temporary work-around for LibreSSL */
//extern "C" void SSL_COMP_free_compression_methods(void) {}
//extern "C" int FIPS_mode_set(int ONOFF) { return 0; }
