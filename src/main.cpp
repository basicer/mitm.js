#include <format>

#include <emscripten.h>
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

#include "main.hpp"
#include "ssl.hpp"

using namespace emscripten;

#define KEY_SIZE 2048
//#define KEY_SIZE 1024
#define EXPONENT 65537

static int jsrand(void *data, unsigned char *output, size_t len, size_t *olen) {
	return mbedtls_psa_external_get_random(NULL, output, len, olen);
}

MITM::MITM() {
	int ok = psa_crypto_init();
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	mbedtls_pk_init(&pk);
	seed();
}

MITM::~MITM() {
	mbedtls_pk_free(&pk);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
}

class MPI {
public:
	MPI() {
		mbedtls_mpi_init(&V);
	}
	~MPI() {
		mbedtls_mpi_free(&V);
	}

	operator mbedtls_mpi *() { return &V; }

private:
	mbedtls_mpi V;
};

void MITM::seed() {
	const char *pers = "mitm.js";
	mbedtls_entropy_add_source(&entropy, jsrand, NULL, 0, MBEDTLS_ENTROPY_SOURCE_STRONG);
	CHECK(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
				  (const unsigned char *)pers,
				  strlen(pers)),
			"SEED");
}

std::string MITM::getCACertificate() {
	//mbedtls_x509_crt cacert;
	//mbedtls_x509_crt_init(&cacert);

	mbedtls_x509write_cert crt;
	mbedtls_x509write_crt_init(&crt);

	MPI serial;
	CHECK(mbedtls_x509write_crt_set_serial_raw(&crt, (unsigned char *)"012345", 6), "serial");

	CHECK(mbedtls_pk_check_pair(&pk, &pk, mbedtls_ctr_drbg_random, &ctr_drbg), "PK=");

	mbedtls_x509write_crt_set_subject_key(&crt, &pk);
	CHECK(mbedtls_x509write_crt_set_subject_name(&crt, "CN=<CACERT>,O=MITM,C=US"), "SKN");

	mbedtls_x509write_crt_set_issuer_key(&crt, &pk);
	CHECK(mbedtls_x509write_crt_set_issuer_name(&crt, "CN=<CACERT>,O=MITM,C=US"), "IKN");

	mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
	mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);

	CHECK(mbedtls_x509write_crt_set_validity(&crt, "20010101000000", "20301231235959"), "VAL");
	CHECK(mbedtls_x509write_crt_set_subject_name(&crt, "CN=<CACERT>,O=MITM,C=US"), "SN");
	CHECK(mbedtls_x509write_crt_set_basic_constraints(&crt, 1, -1), "SBC");

	mbedtls_x509write_crt_set_subject_key_identifier(&crt);
	mbedtls_x509write_crt_set_authority_key_identifier(&crt);

	//mbedtls_x509write_

	unsigned char output_buf[14096];
	unsigned char *output_start;
	size_t len = 0;

	memset(output_buf, 0, 14096);
	CHECK(mbedtls_x509write_crt_pem(&crt, &output_buf[0], 14096, mbedtls_ctr_drbg_random, &ctr_drbg), "write");
	//CHECK(mbedtls_x509write_crt_der(&crt, output_buf, 14096, mbedtls_ctr_drbg_random, &ctr_drbg), "DER");

	CHECK(mbedtls_x509_crt_parse(&cacert, output_buf, strlen((char *)output_buf) + 1), "CERT");

	return std::string((char *)&output_buf[0]);
}

std::string MITM::getFakeCertificate(std::string cn) {
	//mbedtls_x509_crt cacert;
	//mbedtls_x509_crt_init(&cacert);

	mbedtls_x509write_cert crt;
	mbedtls_x509write_crt_init(&crt);

	MPI serial;
	CHECK(mbedtls_x509write_crt_set_serial_raw(&crt, (unsigned char *)"012345", 6), "serial");

	CHECK(mbedtls_pk_check_pair(&pk, &pk, mbedtls_ctr_drbg_random, &ctr_drbg), "PK=");

	mbedtls_x509write_crt_set_subject_key(&crt, &pk);
	CHECK(mbedtls_x509write_crt_set_subject_name(&crt, cn.c_str()), "SKN");

	mbedtls_x509write_crt_set_issuer_key(&crt, &pk);
	CHECK(mbedtls_x509write_crt_set_issuer_name(&crt, "CN=<CACERT>,O=MITM,C=US"), "IKN");

	mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
	mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);

	CHECK(mbedtls_x509write_crt_set_validity(&crt, "20010101000000", "20301231235959"), "VAL");
	CHECK(mbedtls_x509write_crt_set_subject_name(&crt, cn.c_str()), "SN");
	CHECK(mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1), "SBC");

	CHECK(mbedtls_x509write_crt_set_subject_key_identifier(&crt), "SET KEY");
	CHECK(mbedtls_x509write_crt_set_authority_key_identifier(&crt), "SET CA KEY");

	uint8_t output_buf[14096];
	memset(output_buf, 0, 14096);
	CHECK(mbedtls_x509write_crt_pem(&crt, &output_buf[0], 14096, mbedtls_ctr_drbg_random, &ctr_drbg), "write");
	//CHECK(mbedtls_x509write_crt_der(&crt, output_buf, 14096, mbedtls_ctr_drbg_random, &ctr_drbg), "DER");
	return std::string((char *)&output_buf[0]);
}

void MITM::generateRSAPrivateKey() {
	if (hasPrivateKey()) {
		mbedtls_pk_free(&pk);
		mbedtls_pk_init(&pk);
	}

	mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
	mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk);
	mbedtls_rsa_init(rsa);

	CHECK(mbedtls_rsa_gen_key(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE, EXPONENT), "GEN RSA");
}

std::string MITM::getPrivateKey() {
	unsigned char output_buf[16000];
	memset(output_buf, 0, sizeof(output_buf));

	if (!hasPrivateKey()) {
		generateECCPrivateKey();
		//generateRSAPrivateKey();
	}

	if (mbedtls_pk_write_key_pem(&pk, output_buf, sizeof(output_buf)) != 0) {
		return std::string();
	}

	return std::string((char *)&output_buf[0]);
}

bool MITM::setPrivateKey(std::string pem) {
	if (hasPrivateKey()) {
		mbedtls_pk_free(&pk);
		mbedtls_pk_init(&pk);
	}
	if (mbedtls_pk_parse_key(&pk, (const uint8_t *)pem.c_str(), pem.length() + 1, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
		return false;
	}
	return true;
}

bool MITM::setCACertificate(std::string pem) {
	mbedtls_x509_crt_init(&cacert);
	CHECK(mbedtls_x509_crt_parse(&cacert, (unsigned char *)pem.c_str(), pem.length() + 1), "SET CERT");
	return true;
}

std::string MITM::getPublicKey() {
	unsigned char output_buf[16000];
	memset(output_buf, 0, sizeof(output_buf));

	if (!hasPrivateKey()) {
		generateECCPrivateKey();
		//generateRSAPrivateKey();
	}

	if (mbedtls_pk_write_pubkey_pem(&pk, output_buf, sizeof(output_buf)) != 0) {
		return std::string();
	}

	return std::string((char *)&output_buf[0]);
}

void MITM::generateECCPrivateKey() {
	if (hasPrivateKey()) {
		mbedtls_pk_free(&pk);
		mbedtls_pk_init(&pk);
	}
	CHECK(mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)), "ecse");
	CHECK(mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(pk), mbedtls_ctr_drbg_random, &ctr_drbg), "GEN");
}

std::shared_ptr<SSL> MITM::ssl() {
	return std::make_shared<SSL>(shared_from_this());
}

EMSCRIPTEN_BINDINGS(mitm) {
	class_<MITM>("MITM")
			.smart_ptr_constructor("MITM", &std::make_shared<MITM>)
			.property("log_level", &MITM::getLogLevel, &MITM::setLogLevel)
			.function("setLogLevel", &MITM::setLogLevel)
			.function("getLogLevel", &MITM::getLogLevel)
			.function("getPrivateKey", &MITM::getPrivateKey)
			.function("setPrivateKey", &MITM::setPrivateKey)
			.function("getPublicKey", &MITM::getPublicKey)
			.function("getCACertificate", &MITM::getCACertificate)
			.function("setCACertificate", &MITM::setCACertificate)
			.function("getFakeCertificate", &MITM::getFakeCertificate)
			.function("ssl", &MITM::ssl)
			.function("generateRSAPrivateKey", &MITM::generateRSAPrivateKey)
			.function("generateECCPrivateKey", &MITM::generateECCPrivateKey);

	class_<SSL>("SSL")
			.smart_ptr<std::shared_ptr<SSL>>("SSL")
			.function("setPacketOutCallback", &SSL::setPacketOutCallback)
			.function("setDataOutCallback", &SSL::setDataOutCallback)
			.function("getInfo", &SSL::getInfo)
			.function("close", &SSL::close)
			.function("dataIn", &SSL::dataIn)
			.function("packetIn", &SSL::packetIn);
}

psa_status_t mbedtls_psa_external_get_random(mbedtls_psa_external_random_context_t *context, uint8_t *output, size_t output_size, size_t *output_length) {
	for (int i = 0; i < output_size; ++i) {
		output[i] = 256.0f * emscripten_random();
	}
	*output_length = output_size;
	return 0;
}