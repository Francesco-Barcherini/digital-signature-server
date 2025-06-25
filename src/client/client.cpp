#include "protocol.h"

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

string command;

string logged_username;

void cmd_CreateKeys() {
    
}

void cmd_SignDoc() {
    
}

void cmd_GetPublicKey() {
    
}

void cmd_DeleteKeys() {
    
}

bool change_password() {
    string new_password;
    cout << "Enter new password: ";
    cin >> new_password;
    if (new_password.size() > MAX_TEXT_SIZE) {
        cout << "Password too long (max " << MAX_TEXT_SIZE << " characters). Please try again." << endl;
        return false;
    }

    // send new_password
    byte_vec message(new_password.begin(), new_password.end());
    message.push_back('\0'); // Null-terminate the password
    send_message(message);

    // Receive response from server
    message.clear();
    recv_message(message);

    if (message.empty()) {
        cout << "Failed to receive response from server." << endl;
        return false;
    }

    // Convert byte_vec to string
    string response = string(message.begin(), message.end()).c_str();
    if (response == "Password changed successfully") {
        cout << "Password changed successfully! You can now use the application" << endl;
        return true;
    }
    
    cout << "Failed to change password: " << response << endl;   
    return false; 
}

void cmd_Login() {
    string username, password;
    cout << "Enter username: ";
    cin >> username;
    if (username.size() > MAX_TEXT_SIZE) {
        cout << "Username too long (max " << MAX_TEXT_SIZE << " characters). Please try again." << endl;
        return;
    }

    cout << "Enter password: ";
    cin >> password;
    if (password.size() > MAX_TEXT_SIZE) {
        cout << "Password too long (max " << MAX_TEXT_SIZE << " characters). Please try again." << endl;
        return;
    }

    // send cmd, username, password
    byte_vec message(command.begin(), command.end());
    message.push_back('\0'); // Null-terminate the command
    send_message(message);
    LOG(INFO, "Sent command %s to server", string(command.begin(), command.end()).c_str());

    message.clear();
    message.insert(message.end(), username.begin(), username.end());
    message.push_back('\0'); // Null-terminate the username
    send_message(message);
    LOG(INFO, "Sent username %s to server", string(username.begin(), username.end()).c_str());

    message.clear();
    message.insert(message.end(), password.begin(), password.end());
    message.push_back('\0'); // Null-terminate the password
    send_message(message);
    LOG(INFO, "Sent password to server");

    // Receive response from server
    message.clear();
    recv_message(message);

    if (message.empty()) {
        cout << "Failed to receive response from server." << endl;
        return;
    }

    // Convert byte_vec to string
    string response = string(message.begin(), message.end()).c_str();
    if (response == "Login successful") {
        cout << "Login successful!" << endl;
        logged_username = username;
    }
    else if (response == "First login: change password") {
        cout << "First login: change password" << endl;
        if (change_password())
            logged_username = username;
    }
    else
        cout << "Login failed: " << response << endl;    
}

void cmd_Exit() {
    // send exit command and close the connection
    byte_vec message(command.begin(), command.end());
    message.push_back('\0'); // Null-terminate the command
    send_message(message);
    LOG(INFO, "Sent %s command to server", string(command.begin(), command.end()).c_str());

    cout << "Exiting the application. Goodbye!" << endl;
    exit(0);
}

void print_menu() {
    cout << "Digital Signature Server\nMenu:\n";
    cout << "CreateKeys - Create a new key pair\n";
    cout << "SignDoc - Sign a document\n";
    cout << "GetPublicKey - Get a user's public key\n";
    cout << "DeleteKeys - Delete your key pair\n";
    cout << "Login - Login to the server\n";
    cout << "Exit - Exit the application\n";
}

void operation() {
    print_menu();
    cin >> command;

    if (command.size() > MAX_CMD_SIZE) {
        cout << "Command too long. Please try again." << endl;
        return;
    }

    if (command == "CreateKeys")
        cmd_CreateKeys();    
    else if (command == "SignDoc")
        cmd_SignDoc();    
    else if (command == "GetPublicKey")
        cmd_GetPublicKey();    
    else if (command == "DeleteKeys")
        cmd_DeleteKeys();    
    else if (command == "Login")
        cmd_Login();    
    else if (command == "Exit")
        cmd_Exit();  
    else      
        cout << "Unknown command: " << command << endl << endl;
}

int main()
{

    client_init_connection();

    logged_username = "";

    string msg = "Hello, Server!";
    byte_vec message(msg.begin(), msg.end());
    message.push_back('\0'); // Now it is null-terminated

    send_message(message);

    while(1)
        operation();

    return 0;
}