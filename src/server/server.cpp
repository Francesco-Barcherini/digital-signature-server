#include "protocol.h"
#include "EmployeeDB.h"

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

void cmd_Login(int* sock_fd, string& loggedUser)
{
    byte_vec username, password;
    recv_message(username);
    recv_message(password);
    LOG(INFO, "Received login request for user: %s", string(username.begin(), username.end()).c_str());

    if (username.empty() || password.empty())
    {
        LOG(WARN, "Username or password is empty");
        send_message(string("Username or password cannot be empty"));
        return;
    }

    if (username.size() > MAX_TEXT_SIZE || password.size() > MAX_TEXT_SIZE)
    {
        LOG(WARN, "Username or password too long");
        send_message("Username or password too long (max " + to_string(MAX_TEXT_SIZE) + " characters)");
        return;
    }

    string username_str = string(username.begin(), username.end()).c_str();
    string password_str = string(password.begin(), password.end()).c_str();

    employeeDB.loginEmployee(username_str, password_str);
    
    loggedUser = username_str; // Store the username for the session
}

void cmd_Exit(int* sock_fd)
{
    close(*sock_fd);
    LOG(INFO, "Connection closed for socket %d", *sock_fd);
    *sock_fd = -1; // Mark the socket as closed
}

void command_handler(int* conn_fd, string& loggedUser)
{
    byte_vec command;
    string command_str;
    recv_message(command);
    command_str = string(command.begin(), command.end()).c_str();
    LOG(INFO, "Received command %s from socket %d", command_str.c_str(), *conn_fd);

    // if (command_str == "CreateKeys")
    //     cmd_CreateKeys(conn_fd);    
    // else if (command_str == "SignDoc")
    //     cmd_SignDoc(conn_fd);    
    // else if (command_str == "GetPublicKey")
    //     cmd_GetPublicKey(conn_fd);    
    // else if (command_str == "DeleteKeys")
    //     cmd_DeleteKeys(conn_fd);    
    // else 
    if (command_str == "Login") {
        if (!loggedUser.empty()) {
            LOG(WARN, "User %s is already logged in", loggedUser.c_str());
            send_message("You are already logged in as " + loggedUser);
            return;
        }

        cmd_Login(conn_fd, loggedUser);  
    }  
    else if (command_str == "Exit") {
        if (!loggedUser.empty())
            loggedUser.clear(); // Clear username on exit
        cmd_Exit(conn_fd);
    }
    else      
        LOG(WARN, "Unknown command received: %s", command_str);

    
}


void connection_handler(int conn_fd)
{
    server_init_connection(conn_fd);

    byte_vec message;
    recv_message(message);
    LOG(INFO, "Received message from client: %s", string(message.begin(), message.end()).c_str());

    string loggedUser = "";
    while(conn_fd >= 0) {
        command_handler(&conn_fd, loggedUser);
    }
        
}

// TODO tcp??? pachetti persi???
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

    // Use fixed AES key for now (should be negotiated or derived per session)
    byte_vec shared_key(32);

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

int main()
{
    // test();
    employeeDB.registerEmployee("alice", "alicepass");
    employeeDB.registerEmployee("bob", "bobpass");
    employeeDB.registerEmployee("carl", "carlpass");
    LOG(INFO, "Employee registration completed");

    start_server(1234); // Start server on port 1234
}