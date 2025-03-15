#pragma once

#include <deque>
#include <map>
#include <memory>
#include <string>

#include <emscripten/bind.h>
#include <emscripten/val.h>

#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

class MITM;

class SSL {
	friend class MITM;

public:
	SSL(std::shared_ptr<MITM> mitm);
	~SSL();
	void setPacketOutCallback(emscripten::val cb) { onwrite = cb; }
	void setDataOutCallback(emscripten::val cb) { ondata = cb; }

	int packetIn(std::string data);
	int dataIn(std::string data);
	emscripten::val getInfo();

	void close();

private:
	emscripten::val onwrite;
	emscripten::val ondata;

	mbedtls_ssl_context ctx;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt srvcert;

	std::shared_ptr<MITM> mitm;
	std::deque<uint8_t> buffer;

	static int ssl_write(void *ctx, const unsigned char *data, size_t size);
	static int ssl_read(void *ctx, unsigned char *buf, size_t len);
	static int ssl_sni(void *ctx, mbedtls_ssl_context *ssl, const unsigned char *buf, size_t len);
};