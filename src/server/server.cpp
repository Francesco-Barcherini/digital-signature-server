#include "protocol.h"
#include "EmployeeDB.h"
#include "commands.h"

#include "../common/common.h"
#include "../common/protocol.h"

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

EmployeeDB employeeDB;

void test()
{
    testSign();
    test_ffdhe2048_key_exchange();
    test_aes256gcm_encrypt_decrypt();
}

void connection_handler(int fd)
{
    server_init_connection(fd);

    byte_vec message;
    recv_message(message);
    LOG(INFO, "Received message from client: %s", string(message.begin(), message.end()).c_str());

    string loggedUser = "";
    while (running)
    {
        try
        {
            command_handler(loggedUser);
        }
        catch (...)
        {
            break;
        }
    }
}

void start_server(uint16_t port)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        perror("socket");
        return;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_fd, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        close(server_fd);
        return;
    }

    if (listen(server_fd, SOMAXCONN) < 0)
    {
        perror("listen");
        close(server_fd);
        return;
    }

    LOG(INFO, "Server listening on port %d", port);

    while (true)
    {
        sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int conn_fd = accept(server_fd, (sockaddr *)&client_addr, &len);
        if (conn_fd < 0)
        {
            perror("accept");
            continue;
        }

        LOG(INFO, "Client connected: fd=%d", conn_fd);

        // Launch a thread to handle the client
        std::thread(connection_handler, conn_fd).detach();
    }

    close(server_fd);
}

int main(int argc, char *argv[])
{
    // Set log level based on command line argument
    if (argc > 1)
        set_log_level(argv[1]);

    // test();
    employeeDB.registerEmployee("alice", "alicepass");
    employeeDB.registerEmployee("bob", "bobpass");
    employeeDB.registerEmployee("carl", "carlpass");
    LOG(INFO, "Employee registration completed");

    start_server(1234); // Start server on port 1234
}