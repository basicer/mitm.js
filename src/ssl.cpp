#include <algorithm>
#include <format>

#include <emscripten/bind.h>
#include <emscripten/val.h>

#include "mbedtls/bignum.h"
#include "mbedtls/build_info.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

#include <stdio.h>
#include <string.h>

#include "main.hpp"
#include "ssl.hpp"

using namespace emscripten;

std::string cert_to_into(const mbedtls_x509_crt *cert) {
	char output_buf[14096];
	memset(output_buf, 0, 14096);
	CHECK(mbedtls_x509_crt_info(&output_buf[0], 14096, "", cert), "INFO");
	return std::string(&output_buf[0]);
}

int SSL::ssl_write(void *ctx, const unsigned char *data, size_t size) {
	SSL *ssl = static_cast<SSL *>(ctx);
	ssl->onwrite(typed_memory_view(size, (uint8_t *)data));
	return size;
}

int SSL::ssl_read(void *ctx, unsigned char *buf, size_t len) {
	SSL *ssl = static_cast<SSL *>(ctx);
	size_t avail = ssl->buffer.size();
	size_t amt = std::min(len, avail);
	if (avail == 0) {
		return MBEDTLS_ERR_SSL_WANT_READ;
	}
	for (int i = 0; i < amt; ++i) {
		buf[i] = ssl->buffer.front();
		ssl->buffer.pop_front();
	}
	return amt;
}

int SSL::ssl_sni(void *ctx, mbedtls_ssl_context *sslctx, const unsigned char *buf, size_t len) {
	SSL *ssl = static_cast<SSL *>(ctx);
	mbedtls_x509_crt *fake;
	std::string sni((char *)buf, len);
	if (!ssl->mitm->certs.contains(sni)) {
		std::string cert = ssl->mitm->getFakeCertificate(std::string("CN=") + sni);
		fake = &ssl->mitm->certs[sni];
		mbedtls_x509_crt_init(fake);
		CHECK(mbedtls_x509_crt_parse(fake, (const uint8_t *)cert.c_str(), cert.length() + 1), "LOAD FAKE");
	} else {
		fake = &ssl->mitm->certs[sni];
	}

	mbedtls_ssl_set_hs_own_cert(sslctx, NULL, NULL);
	CHECK(mbedtls_ssl_set_hs_own_cert(sslctx, fake, &ssl->mitm->pk), "Hs OWN CERT");
	mbedtls_ssl_set_hs_ca_chain(sslctx, fake->next, NULL);
	return 0;
}

static void my_debug(void *ctx, int level, const char *file, int line, const char *str) {
	((void)level);
	mbedtls_fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
	fflush((FILE *)ctx);
}

SSL::SSL(std::shared_ptr<MITM> mitm) :
		mitm(mitm) {
	mbedtls_ssl_init(&ctx);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&mitm->cacert);

	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &mitm->ctr_drbg);
	mbedtls_ssl_conf_dbg(&conf, my_debug, stderr);
	mbedtls_debug_set_threshold(mitm->log_level);

	CHECK(mbedtls_ssl_config_defaults(&conf,
				  MBEDTLS_SSL_IS_SERVER,
				  MBEDTLS_SSL_TRANSPORT_STREAM,
				  MBEDTLS_SSL_PRESET_DEFAULT),
			"CONF");

	mbedtls_ssl_conf_sni(&conf, ssl_sni, this);
	mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
	CHECK(mbedtls_ssl_conf_own_cert(&conf, &srvcert, &mitm->pk), "OWN CERT");
	CHECK(mbedtls_ssl_setup(&ctx, &conf), "SETUP");

	CHECK(mbedtls_ssl_session_reset(&ctx), "RESET");
	mbedtls_ssl_set_bio(&ctx, this, ssl_write, ssl_read, NULL);
}

SSL::~SSL() {
	mitm.reset();
}

int SSL::packetIn(std::string data) {
	for (char c : data) {
		buffer.push_back(c);
	}

	int ret;
	while ((ret = mbedtls_ssl_handshake(&ctx)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret);
			char error_buf[100];
			mbedtls_strerror(ret, error_buf, 100);
			printf("ERROR: %s\n", error_buf);
			return -2;
		}
		return -1;
	}

	std::string datao;
	datao.resize(1024 << 2);
	int read;
	while (true) {
		read = mbedtls_ssl_read(&ctx, (uint8_t *)datao.data(), data.capacity());
		if (read < 0) {
			return read;
		}
		datao.resize(read);
		if (ondata != val::undefined()) {
			ondata(typed_memory_view(datao.size(), (uint8_t *)datao.data()));
		}
	}
	return read;
}

int SSL::dataIn(std::string data) {
	int wrote = 0;
	uint8_t *ptr = (uint8_t *)data.data();
	while (wrote < data.length()) {
		int r = mbedtls_ssl_write(&ctx, ptr, data.length() - wrote);
		if (r < 0) {
			mbedtls_printf(" failed\n  !Write interuped %d\n\n", r);
			char error_buf[100];
			mbedtls_strerror(r, error_buf, 100);
			printf("ERROR: %s\n", error_buf);
			return r;
		}
		wrote += r;
		ptr += r;
	}
	return wrote;
}

val SSL::getInfo() {
	val result = val::object();
	int id = mbedtls_ssl_get_ciphersuite_id_from_ssl(&ctx);
	const mbedtls_ssl_ciphersuite_t *cs = mbedtls_ssl_ciphersuite_from_id(id);

	result.set("version", val::u8string(mbedtls_ssl_get_version(&ctx)));
	result.set("ciphersuite", val::u8string(mbedtls_ssl_ciphersuite_get_name(cs)));
	result.set("clientcert", cert_to_into(mbedtls_ssl_get_peer_cert(&ctx)));
	return result;
}

void SSL::close() {
	CHECK(mbedtls_ssl_close_notify(&ctx), "CLOSE");
}