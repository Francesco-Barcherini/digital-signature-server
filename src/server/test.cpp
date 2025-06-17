
#include <iostream>
#include <iomanip>
#include <vector>
#include <stdexcept>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <cassert>

#include "test.h"

using namespace std;

void testSign()
{
    printf("\nTesting RSA-SHA256 signing and verification...\n\n");
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



void test_ffdhe2048_key_exchange()
{
    printf("\nTesting FFDHE2048 key exchange...\n\n");
    // Generate your keys
    byte_vec my_pubkey;
    EVP_PKEY* my_keypair = nullptr;
    ffdhe2048GenMsgAndKeys(my_pubkey, my_keypair);

    // Generate peer keys
    byte_vec peer_pubkey;
    EVP_PKEY* peer_keypair = nullptr;
    ffdhe2048GenMsgAndKeys(peer_pubkey, peer_keypair);

    // Compute shared secret from your side
    byte_vec shared_secret_1;
    ffdhe2048ComputeSharedSecret(peer_pubkey, my_keypair, shared_secret_1);

    // Compute shared secret from peer side
    byte_vec shared_secret_2;
    ffdhe2048ComputeSharedSecret(my_pubkey, peer_keypair, shared_secret_2);

    // Clean up keys
    EVP_PKEY_free(my_keypair);
    EVP_PKEY_free(peer_keypair);

    // Both shared secrets must match
    if (shared_secret_1 == shared_secret_2)
    {
        std::cout << "Test passed! Shared secrets match.\n";
    }
    else
    {
        std::cerr << "Test failed! Shared secrets do NOT match.\n";
        assert(false);
    }
}

void test_aes256gcm_encrypt_decrypt()
{
    printf("\nTesting AES-256-GCM encryption and decryption...\n\n");
    // Sample plaintext
    byte_vec plaintext = { 'T','h','i','s',' ','i','s',' ','a',' ','t','e','s','t','!' };

    // Generate random 32-byte key
    byte_vec key(32);
    if (!RAND_bytes(key.data(), (int)key.size()))
    {
        std::cerr << "Failed to generate random key\n";
        return;
    }

    byte_vec iv;           // IV will be generated in encrypt function if empty
    byte_vec ciphertext;
    byte_vec tag;
    byte_vec decrypted;

    try
    {
        aes256gcm_encrypt(plaintext, key, iv, ciphertext, tag);

        aes256gcm_decrypt(ciphertext, key, iv, tag, decrypted);

        if (decrypted == plaintext)
            std::cout << "AES-256-GCM test passed: Decrypted text matches plaintext.\n";
        else
            std::cerr << "AES-256-GCM test failed: Decrypted text DOES NOT match plaintext.\n";
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error during AES-256-GCM test: " << e.what() << "\n";
    }
}