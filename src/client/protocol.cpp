#include "protocol.h"
#include <arpa/inet.h>

int connect_to_server(const std::string &host, uint16_t port)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        error("socket returned < 0");
    }

    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &serv_addr.sin_addr) <= 0)
    {
        error("intet_pton failed");
    }

    if (connect(sockfd, (sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        error("connect failed");
    }

    LOG(INFO, "Connected to server at %s:%d", host.c_str(), port);
    return sockfd;
}

byte_vec shared_key(32);
uint64_t counter = 1000;
int sockfd;
void client_init_connection()
{
    sockfd = connect_to_server("127.0.0.1", 1234);

    string path_to_public_key = DATA_PATH + "/common/server_pub.pem";

    EVP_PKEY *server_rsa_pub = nullptr;
    readPEMPublicKey(path_to_public_key, &server_rsa_pub);

    init_secure_conversation_client(sockfd,
                                    server_rsa_pub,
                                    shared_key);
}

void close_connection()
{
    if (sockfd >= 0)
    {
        close(sockfd);
        sockfd = -1;
    }
}

void send_message(const string &msg)
{
    byte_vec msg_bytes(msg.begin(), msg.end());
    msg_bytes.push_back('\0'); // Null-terminate the string for safety
    send_message(msg_bytes);
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
}

void recv_message(byte_vec &msg)
{
    recv_secure_message(sockfd, shared_key, counter, msg);
}
