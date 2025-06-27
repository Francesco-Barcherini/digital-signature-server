#include "protocol.h"

thread_local int sockfd;
thread_local byte_vec shared_key(32);
thread_local uint64_t counter = 0;

byte_vec &get_shared_key()
{
    return shared_key;
}

void server_init_connection(int conn_fd)
{
    sockfd = conn_fd;

    LOG(INFO, "Client handler started for fd=%d", sockfd);

    string path_to_private_key = DATA_PATH + "/server/server_priv.pem"; // Path to your PEM file containing the private key

    EVP_PKEY *server_rsa_priv = nullptr;
    readPEMPrivateKey(path_to_private_key, &server_rsa_priv);

    init_secure_conversation_server(sockfd, server_rsa_priv, shared_key);

    EVP_PKEY_free(server_rsa_priv); // Free the private key after use
}

void send_message(const string &msg)
{
    byte_vec msg_bytes(msg.begin(), msg.end());
    msg_bytes.push_back('\0'); // Null-terminate the string for safety
    send_message(msg_bytes);
    memzero(msg_bytes);
}

void send_message(const byte_vec &msg)
{
    send_secure_message(sockfd, msg, shared_key, counter);
}

void recv_message(string &msg)
{
    byte_vec msg_bytes;
    recv_message(msg_bytes);
    msg = string(msg_bytes.begin(), msg_bytes.end()).c_str();
    memzero(msg_bytes);
}

void recv_message(byte_vec &msg)
{
    if (!recv_secure_message(sockfd, shared_key, counter, msg)){
        error("Connection closed");
    }
}