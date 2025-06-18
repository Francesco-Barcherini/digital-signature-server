#include "server.h"

#include <iostream>
#include <iomanip>
#include <vector>
#include <stdexcept>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "test.h" // Include the testSign header to access the signRsaSha256 function

#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>

using namespace std;

void test()
{
    testSign();
    test_ffdhe2048_key_exchange();
    test_aes256gcm_encrypt_decrypt();
}

void client_handler(int client_fd)
{
    LOG(INFO, "Client handler started for fd=%d", client_fd);

    string path_to_private_key = "./server_priv.pem"; // Path to your PEM file containing the private key

    EVP_PKEY* server_rsa_priv = nullptr;
    readPEMPrivateKey(path_to_private_key, &server_rsa_priv);

    byte_vec shared_key(32); // Use a fixed AES key for now (should be negotiated or derived per session)
    init_secure_conversation_server(client_fd, server_rsa_priv, shared_key);
}


void start_server(uint16_t port)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return;
    }

    if (listen(server_fd, SOMAXCONN) < 0) {
        perror("listen");
        close(server_fd);
        return;
    }

    LOG(INFO, "Server listening on port %d", port);

    // Use fixed AES key for now (should be negotiated or derived per session)
    byte_vec shared_key(32);

    while (true) {
        sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int client_fd = accept(server_fd, (sockaddr*)&client_addr, &len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        LOG(INFO, "Client connected: fd=%d", client_fd);

        // Launch a thread to handle the client
        std::thread(client_handler, client_fd).detach();
    }

    close(server_fd);
}

int main(){
    test();

    start_server(1234); // Start server on port 1234


}