#include "server.h"

#include <iostream>
#include <iomanip>
#include <vector>
#include <stdexcept>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "test.h" // Include the testSign header to access the signRsaSha256 function

using namespace std;

int main()
{
    testSign();
    test_ffdhe2048_key_exchange();
    test_aes256gcm_encrypt_decrypt();

}
