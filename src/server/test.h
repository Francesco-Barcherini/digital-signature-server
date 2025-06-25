#pragma once

#include <iostream>
#include <iomanip>
#include <vector>
#include <stdexcept>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "../common/common.h"

void testSign();
void test_ffdhe2048_key_exchange();
void test_aes256gcm_encrypt_decrypt();