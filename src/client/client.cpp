#include "client.h"

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
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

int main()
{
    int sockfd = connect_to_server("127.0.0.1", 1234);

    string path_to_public_key = "./server_pub.pem";

    EVP_PKEY *server_rsa_pub = nullptr;
    readPEMPublicKey(path_to_public_key, &server_rsa_pub);

    byte_vec shared_key(32); // Use a fixed AES key for now (should be negotiated or derived per session)
    init_secure_conversation_client(sockfd,
                                    server_rsa_pub,
                                    shared_key);

    sleep(10);

    return 0;
}