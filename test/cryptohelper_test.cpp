#define BOOST_TEST_MODULE test_cryptohelper

#include <filesystem>
#include <boost/test/unit_test.hpp>
//#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>
#include <iostream>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
//#include <boost/filesystem.hpp>

#include <build_properties.h>
#include "../src/base_lib/crypto_helper.hpp"
#include "../src/base_lib/base.h"
#include "data/public_key.h" // from previously generated project along with private key in this directory
#include "data/signature.h" // generated using TEST_STRING in data.txt (file should not end with newline if test string doesn't)

//namespace fs = boost::filesystem;
namespace fs = std::filesystem;
using namespace license;
using namespace std;

namespace test {

const std::string loadPrivateKey() {
	fs::path pkf = fs::path(PROJECT_TEST_SRC_DIR) / "data" / PRIVATE_KEY_FNAME;
        std::cout << "Using private key from: " << pkf << std::endl;
	std::ifstream private_key_linux(pkf.string());
	BOOST_REQUIRE_MESSAGE(private_key_linux.good(), "test file found");
	const std::string pk_str((std::istreambuf_iterator<char>(private_key_linux)), std::istreambuf_iterator<char>());
	return pk_str;
}

BOOST_AUTO_TEST_CASE(test_generate_and_sign) {
	unique_ptr<CryptoHelper> crypto(CryptoHelper::getInstance());
	crypto->generateKeyPair();
	const string privateK = crypto->exportPrivateKey();
        //std::cout << "Private key=" << privateK << std::endl;
	BOOST_CHECK_MESSAGE(boost::starts_with(privateK, "-----BEGIN PRIVATE KEY-----"),
						"Private key is in openssl pkcs#8 format");
	const std::string signature = crypto->signString(TEST_STRING);
        std::cout << "Signature size=" << signature.size() << ", expected size=" << SIGNATURE_LEN << std::endl;
	BOOST_CHECK_MESSAGE(signature.size() == SIGNATURE_LEN, "signature is the right size");
	crypto.release();
	/*
	 ofstream myfile("private_key-linux.pem");
	 myfile << privateK;
	 myfile.close();*/
}

/**
 * Import a private key, export it again and check imported and exported are equal
 */
BOOST_AUTO_TEST_CASE(test_load_and_export_private) {
	unique_ptr<CryptoHelper> crypto(CryptoHelper::getInstance());
	const std::string pk_str = loadPrivateKey();
	crypto->loadPrivateKey(pk_str);
	std::string pk_exported = crypto->exportPrivateKey();
/*
	cout<< "orig:" << pk_str<<endl;
	cout<< "expo:" << pk_exported<<endl;
*/
	BOOST_CHECK_MESSAGE(boost::trim_copy(pk_exported) == boost::trim_copy(pk_str),
						"imported and exported keys are the same");
	crypto.release();
}

BOOST_AUTO_TEST_CASE(test_load_and_export_public_key) {
	unique_ptr<CryptoHelper> crypto(CryptoHelper::getInstance());
	const vector<unsigned char> expected_pubkey(PUBLIC_KEY);
	const std::string pk_str = loadPrivateKey();
	crypto->loadPrivateKey(pk_str);
	vector<unsigned char> pk_exported = crypto->exportPublicKey();
/*
	for (auto it : pk_exported) {
		cout << ((int)it) << ",";
	}
*/
        cout << std::endl << "exported_length=" << pk_exported.size() << ", expected_size=" << expected_pubkey.size() << ", defined size=" << PUBLIC_KEY_LEN << std::endl;
	ofstream myfile("public_key.pem");
	for (auto it : pk_exported) {
		myfile << it;
	}
	myfile.close();
	BOOST_CHECK_MESSAGE(expected_pubkey.size() == pk_exported.size(), "exported key and expected are the same size");
	BOOST_CHECK_MESSAGE(std::equal(expected_pubkey.begin(), expected_pubkey.end(), pk_exported.begin()),
						"exported key and expected have the same content");
	crypto.release();
}

BOOST_AUTO_TEST_CASE(test_load_and_sign) {
	unique_ptr<CryptoHelper> crypto(CryptoHelper::getInstance());
	const std::string pk_str = loadPrivateKey();
	crypto->loadPrivateKey(pk_str);
	const std::string signature = crypto->signString(TEST_STRING);
        std::cout << "Signature size=" << signature.size() << ", expected size=" << SIGNATURE_LEN << std::endl;
	BOOST_CHECK_MESSAGE(signature.size() == SIGNATURE_LEN, "signature is the right size");
	BOOST_CHECK_MESSAGE(signature == SIGNATURE, "signature is repeatable");
	crypto.release();
}

BOOST_AUTO_TEST_CASE(test_generate_export_import_and_sign) {
	unique_ptr<CryptoHelper> crypto(CryptoHelper::getInstance());
	crypto->generateKeyPair();
	const string pk = crypto->exportPrivateKey();
	crypto->loadPrivateKey(pk);
	const string signature = crypto->signString(TEST_STRING);
	//(1024/8)*(4/3)+4 (base64)
	BOOST_CHECK_MESSAGE(signature.size() == SIGNATURE_LEN, "signature is the right size");
	crypto.release();
}
}  // namespace test
