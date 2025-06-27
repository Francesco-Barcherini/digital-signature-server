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

void cmd_CreateKeys(const string &loggedUser)
{
    LOG(INFO, "Received request to create keys for user: %s", loggedUser.c_str());

    try
    {
        bool success = employeeDB.createKeys(loggedUser);
        if (success)
        {
            send_message("Keys created successfully");
            LOG(INFO, "Keys created successfully for user %s", loggedUser.c_str());
        }
        else
        {
            send_message("Failed to create keys or keys already exist");
            LOG(WARN, "Failed to create keys or keys already exist for user %s", loggedUser.c_str());
        }
    }
    catch (const runtime_error &e)
    {
        LOG(ERROR, "Error creating keys for user %s: %s", loggedUser.c_str(), e.what());
        send_message(e.what());
    }
}

void cmd_SignDoc(const string &loggedUser)
{

    LOG(INFO, "Received request to sign document for user: %s", loggedUser.c_str());

    try
    {
        employeeDB.signDocument(loggedUser);
        LOG(INFO, "Document signed successfully for user %s", loggedUser.c_str());
    }
    catch (const runtime_error &e)
    {
        LOG(ERROR, "Error signing document for user %s: %s", loggedUser.c_str(), e.what());
        send_message("SignDoc failed: " + string(e.what()));
    }
}

void cmd_GetPublicKey()
{
    byte_vec username;
    recv_message(username);
    LOG(INFO, "Received request for public key of user: %s", string(username.begin(), username.end()).c_str());

    if (username.empty())
    {
        LOG(WARN, "Username is empty");
        send_message("Username cannot be empty");
        return;
    }

    if (username.size() > MAX_TEXT_SIZE)
    {
        LOG(WARN, "Username too long");
        send_message("Username too long (max " + to_string(MAX_TEXT_SIZE) + " characters)");
        return;
    }

    string username_str = string(username.begin(), username.end()).c_str();

    try
    {
        string PEM_public_key = employeeDB.getPublicKey(username_str);
        cout << string(PEM_public_key.begin(), PEM_public_key.end()).c_str() << endl;
        send_message(PEM_public_key);
        LOG(INFO, "Sent public key for user %s", username_str.c_str());
    }
    catch (const runtime_error &e)
    {
        LOG(ERROR, "Error retrieving public key for user %s: %s", username_str.c_str(), e.what());
        send_message(e.what());
    }
}

void cmd_DeleteKeys(const string &loggedUser)
{
    LOG(INFO, "Received request to delete keys for user: %s", loggedUser.c_str());

    try
    {
        employeeDB.deleteKeys(loggedUser);
        send_message("Keys deleted successfully");
        LOG(INFO, "Keys deleted successfully for user %s", loggedUser.c_str());
    }
    catch (const runtime_error &e)
    {
        LOG(ERROR, "Error deleting keys for user %s: %s", loggedUser.c_str(), e.what());
        send_message(e.what());
    }
}

void cmd_Login(string &loggedUser)
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

void cmd_Exit(int *sock_fd)
{
    close(*sock_fd);
    LOG(INFO, "Connection closed for socket %d", *sock_fd);
    *sock_fd = -1; // Mark the socket as closed
}


void command_handler(string &loggedUser)
{
    byte_vec command;
    string command_str;
    recv_message(command);
    command_str = string(command.begin(), command.end()).c_str();
    LOG(INFO, "Received command %s", command_str.c_str());

    if (command_str == "CreateKeys")
    {
        if (loggedUser.empty())
        {
            LOG(WARN, "User must be logged for the operation");
            send_message("You must be logged in to execute the operation");
            return;
        }
        cmd_CreateKeys(loggedUser);
    }
    else if (command_str == "SignDoc")
    {
        if (loggedUser.empty())
        {
            LOG(WARN, "User must be logged for the operation");
            send_message("You must be logged in to execute the operation");
            return;
        }
        cmd_SignDoc(loggedUser);
    }
    else if (command_str == "GetPublicKey")
    {
        if (loggedUser.empty())
        {
            LOG(WARN, "User must be logged for the operation");
            send_message("You must be logged in to execute the operation");
            return;
        }
        cmd_GetPublicKey();
    }
    else if (command_str == "DeleteKeys")
    {
        if (loggedUser.empty())
        {
            LOG(WARN, "User must be logged for the operation");
            send_message("You must be logged in to execute the operation");
            return;
        }
        cmd_DeleteKeys(loggedUser);
    }
    else if (command_str == "Login")
    {
        if (!loggedUser.empty())
        {
            LOG(WARN, "User %s is already logged in", loggedUser.c_str());
            send_message("You are already logged in as " + loggedUser);
            return;
        }

        cmd_Login(loggedUser);
    }
    else if (command_str == "Exit")
    {
        if (!loggedUser.empty())
            loggedUser.clear(); // Clear username on exit
        // cmd_Exit(conn_fd);
    }
    else
        LOG(WARN, "Unknown command received: %s", command_str);
}

void connection_handler(int fd)
{
    server_init_connection(fd);

    byte_vec message;
    recv_message(message);
    LOG(INFO, "Received message from client: %s", string(message.begin(), message.end()).c_str());

    string loggedUser = "";
    while (1)
    {
        command_handler(loggedUser);
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

int main()
{
    // test();
    employeeDB.registerEmployee("alice", "alicepass");
    employeeDB.registerEmployee("bob", "bobpass");
    employeeDB.registerEmployee("carl", "carlpass");
    LOG(INFO, "Employee registration completed");

    start_server(1234); // Start server on port 1234
}