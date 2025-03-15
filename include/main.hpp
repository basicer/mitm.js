#pragma once

#include <deque>
#include <map>
#include <memory>
#include <string>

#include <emscripten/bind.h>
#include <emscripten/val.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"

#define CHECK(return_value, message)                                      \
	if ((return_value) < 0) {                                             \
		char error_buf[100];                                              \
		mbedtls_strerror((return_value), error_buf, 100);                 \
		printf("ERROR: %s (%d): %s\n", message, return_value, error_buf); \
		exit(1);                                                          \
	}

class SSL;

class MITM : public std::enable_shared_from_this<MITM> {
public:
	friend class SSL;
	MITM();
	~MITM();

	std::string getPrivateKey();
	std::string getPublicKey();
	std::string getCACertificate();
	bool setCACertificate(std::string pem);

	bool hasPrivateKey() { return mbedtls_pk_get_type(&pk) != MBEDTLS_PK_NONE; }

	void generateRSAPrivateKey();
	void generateECCPrivateKey();

	bool setPrivateKey(std::string pem);
	std::string getFakeCertificate(std::string cn);

	int getLogLevel() const { return log_level; }
	void setLogLevel(int level) { log_level = level; }

	std::shared_ptr<SSL> ssl();

private:
	int log_level = 0;
	;
	void seed();
	std::map<std::string, mbedtls_x509_crt> certs;

	mbedtls_pk_context pk;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_x509_crt cacert;
};