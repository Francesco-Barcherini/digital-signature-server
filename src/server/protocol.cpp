#include "protocol.h"


int sockfd;
byte_vec shared_key(32); // Use a fixed AES key for now (should be negotiated or derived per session)
uint64_t counter = 0;
void server_init_connection(int conn_fd)
{
    sockfd = conn_fd;
    
    LOG(INFO, "Client handler started for fd=%d", sockfd);

    string path_to_private_key = "./server_priv.pem"; // Path to your PEM file containing the private key

    EVP_PKEY *server_rsa_priv = nullptr;
    readPEMPrivateKey(path_to_private_key, &server_rsa_priv);

    init_secure_conversation_server(sockfd, server_rsa_priv, shared_key);
}

void send_message(const byte_vec &msg)
{
    send_secure_message(sockfd, msg, shared_key, counter);
}

void recv_message(byte_vec &msg)
{
    recv_secure_message(sockfd, shared_key, counter, msg);
}