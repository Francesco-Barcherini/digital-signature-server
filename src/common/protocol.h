#include "common.h"

bool init_secure_conversation_client(int sockfd,
                                     EVP_PKEY *server_rsa_pub,
                                     byte_vec &shared_key);

bool init_secure_conversation_server(int sockfd,
                                     EVP_PKEY *server_rsa_priv,
                                     byte_vec &shared_key);

void send_secure_message(int sockfd,
                         const byte_vec &plaintext,
                         const byte_vec &key,
                         uint64_t &message_counter);

bool recv_secure_message(int sockfd,
                         const byte_vec &key,
                         uint64_t &last_received_counter,
                         byte_vec &plaintext);