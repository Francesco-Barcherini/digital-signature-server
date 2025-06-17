
#include <iostream>
#include <iomanip>
#include <vector>
#include <stdexcept>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "test.h"

using namespace std;

void testSign()
{
    string path_to_private_key = "./server_priv.pem"; // Path to your PEM file containing the private key
    string path_to_public_key = "./server_pub.pem"; // Path to your PEM file containing the public key

    EVP_PKEY* private_key = nullptr;
    EVP_PKEY* public_key = nullptr;

    readPEMPrivateKey(path_to_private_key, &private_key);
    readPEMPublicKey(path_to_public_key, &public_key);

    // Message to sign
    const char* message = "Hello, OpenSSL RSA-SHA256 signing!";
    byte_vec data(message, message + strlen(message));

    byte_vec signature;

    signRsaSha256(signature, data, private_key);

    // Print signature in hex
    cout << "Signature (" << signature.size() << " bytes): ";
    for (unsigned char c : signature) {
        cout << hex << setw(2) << setfill('0') << (int)c;
    }
    cout << endl;

    bool ver= verifyRsaSha256(data, signature, public_key);

    if (ver) {
        cout << "Signature verification succeeded." << endl;
    } else {
        cout << "Signature verification failed." << endl;
    }

    signature[0] ^= 0xFF; // Modify the data to test verification failure
    ver = verifyRsaSha256(data, signature, public_key);
    if (ver) {
        cout << "Signature verification succeeded after modification (unexpected)." << endl;
    } else {
        cout << "Signature verification failed after modification as expected." << endl;
    }

}
