/*
 * CryptpHelperLinux.cpp
 *
 *  Created on: Sep 14, 2014
 *
 */

#include <boost/algorithm/string.hpp>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <stdexcept>
#include <string>
#include <cstddef>
#include <stdexcept>

#include "crypto_helper_ssl.hpp"

namespace license {
using namespace std;

CryptoHelperLinux::CryptoHelperLinux() : m_pktmp(nullptr) {
	static int initialized = 0;
	if (initialized == 0) {
		initialized = 1;
		//ERR_load_ERR_strings();
		ERR_load_crypto_strings();
		OpenSSL_add_all_algorithms();
	}
}
void CryptoHelperLinux::generateKeyPair(int keyType, int keySize) {
	if (m_pktmp) {
		EVP_PKEY_free(m_pktmp);
		m_pktmp = nullptr;
	}

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(keyType, NULL);
	if (!ctx) {
		throw std::runtime_error("Failed to create EVP_PKEY_CTX");
	}

	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		throw std::runtime_error("Failed to initialize keygen");
	}

	if (keyType == EVP_PKEY_RSA) {
		if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keySize) <= 0) {
			EVP_PKEY_CTX_free(ctx);
			throw std::logic_error("Error setting RSA key properties");
		}
	} else if (keyType == EVP_PKEY_EC) {
		if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, keySize) <= 0) {
			EVP_PKEY_CTX_free(ctx);
			throw std::logic_error("Error setting EC key properties");
		}
	}

	if (EVP_PKEY_keygen(ctx, &m_pktmp) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		throw std::logic_error("Error generating keypair");
	}

	EVP_PKEY_CTX_free(ctx);
}

const string CryptoHelperLinux::exportPrivateKey() const {
	if (m_pktmp == NULL) {
		throw logic_error(string("Export not initialized.Call generateKeyPair first."));
	}
	BIO *bio_private = BIO_new(BIO_s_mem());
	if (!bio_private) {
		throw std::runtime_error("Failed to create BIO");
	}

	if (!PEM_write_bio_PrivateKey(bio_private, m_pktmp, nullptr, nullptr, 0, nullptr, nullptr)) {
		BIO_free(bio_private);
		throw std::runtime_error("Failed to write private key");
	}

	int keylen = BIO_pending(bio_private);
	char *pem_key = (char *)calloc(keylen + 1, 1); // Null-terminate
	if (!pem_key) {
		BIO_free(bio_private);
		throw std::runtime_error("Failed to allocate memory");
	}

	BIO_read(bio_private, pem_key, keylen);
	BIO_free(bio_private);

	std::string dest(pem_key);
	free(pem_key);

	return dest;
}

const vector<unsigned char> CryptoHelperLinux::exportPublicKey() const {
	if (m_pktmp == NULL) {
		throw logic_error(string("Export not initialized.Call generateKeyPair first."));
	}
	BIO *bio_public = BIO_new(BIO_s_mem());
	if (!bio_public) {
		throw std::runtime_error("Failed to create BIO");
	}

	if (!PEM_write_bio_PUBKEY(bio_public, m_pktmp)) {
		BIO_free(bio_public);
		throw std::runtime_error("Failed to write public key");
	}

	int keylen = BIO_pending(bio_public);
	std::vector<unsigned char> buffer(keylen, 0);

	BIO_read(bio_public, buffer.data(), keylen);
	BIO_free(bio_public);

	return buffer;
}

const string CryptoHelperLinux::signString(const string &license) const {
	if (!m_pktmp) {
		throw logic_error("private key not initialized. Call generate or load first.");
	}

	size_t slen;
	unsigned char *signature = nullptr;
	/* Create the Message Digest Context */
	EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
	if (!mdctx) {
		throw logic_error("Message digest creation context");
	}

	/*Initialise the DigestSign operation - SHA-512 has been selected
	 * as the message digest function */
	if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha512(), NULL, m_pktmp)) {
		EVP_MD_CTX_destroy(mdctx);
	}
	/* Call update with the message */
	if (EVP_DigestSignUpdate(mdctx, (const void *)license.c_str(), (size_t)license.length()) != 1) {
		EVP_MD_CTX_destroy(mdctx);
		throw logic_error("Message signing exception");
	}
	/* Finalise the DigestSign operation */
	/* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
	 * signature. Length is returned in slen */
	if (EVP_DigestSignFinal(mdctx, NULL, &slen) != 1) {
		EVP_MD_CTX_destroy(mdctx);
		throw logic_error("Message signature finalization exception");
	}
	/* Allocate memory for the signature based on size in slen */
	if (!(signature = (unsigned char *)OPENSSL_malloc(sizeof(unsigned char) * slen))) {
		EVP_MD_CTX_destroy(mdctx);
		throw logic_error("Message signature memory allocation exception");
	}
	/* Obtain the signature */
	if (1 != EVP_DigestSignFinal(mdctx, signature, &slen)) {
		OPENSSL_free(signature);
		EVP_MD_CTX_destroy(mdctx);
		throw logic_error("Message signature exception");
	}

	string signatureStr = Opensslb64Encode(slen, signature);

	if (signature) OPENSSL_free(signature);
	EVP_MD_CTX_destroy(mdctx);
	return signatureStr;
}
void CryptoHelperLinux::loadPrivateKey(const std::string &privateKey) {
	if (m_pktmp) {
		EVP_PKEY_free(m_pktmp);
	}

	m_pktmp = nullptr;
	BIO *bio = BIO_new_mem_buf((void *)(privateKey.c_str()), static_cast<int>(privateKey.size()));
	if (!bio) {
		throw std::runtime_error("Failed to create BIO");
	}
	m_pktmp = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if (!m_pktmp) {
		throw logic_error("Private key [" + privateKey + "] can't be loaded");
	}
	int key_length = EVP_PKEY_bits(m_pktmp);
	if (key_length < 1024) {
		throw std::runtime_error("Private key length is less than 1024 bits");
	}
}

const string CryptoHelperLinux::Opensslb64Encode(const size_t slen, const unsigned char *signature) const {
	BIO *mem_bio = BIO_new(BIO_s_mem());
	BIO *b64 = BIO_new(BIO_f_base64());
	BIO *bio1 = BIO_push(b64, mem_bio);
	BIO_set_flags(bio1, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio1, signature, slen);
	BIO_flush(bio1);
	char *charBuf;
	int sz = BIO_get_mem_data(mem_bio, &charBuf);
	string signatureStr;
	signatureStr.assign(charBuf, sz);
	BIO_free_all(bio1);
	return signatureStr;
}

CryptoHelperLinux::~CryptoHelperLinux() {
	if (m_pktmp != nullptr) {
		EVP_PKEY_free(m_pktmp);
	}
}

} /* namespace license */
