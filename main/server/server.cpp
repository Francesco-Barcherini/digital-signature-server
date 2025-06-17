#include "server.h"

#include <iostream>
#include <iomanip>
#include <vector>
#include <stdexcept>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace std;

using byte_vec = std::vector<unsigned char>;

// If your signRsaSha256 function expects the private key as a byte vector
extern void signRsaSha256(byte_vec& signature, const byte_vec& data, const byte_vec& private_key_pem);

int main()
{
    string path_to_private_key = "./server_priv.pem"; // Path to your PEM file containing the private key

    EVP_PKEY* private_key = nullptr;

    readPEMPrivateKey(path_to_private_key, &private_key);

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

    return 0;
}
