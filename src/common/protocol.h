#include "common.h"

bool init_secure_conversation_client(int sockfd,
                                     EVP_PKEY *server_rsa_pub,
                                     byte_vec &shared_key);

bool init_secure_conversation_server(int sockfd,
                                     EVP_PKEY *server_rsa_priv,
                                     byte_vec &shared_key);