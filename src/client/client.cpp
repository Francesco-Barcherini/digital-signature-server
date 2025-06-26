#include "protocol.h"

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

string command;

string logged_username;

bool isLogged() {
    return !logged_username.empty();
}

void cmd_CreateKeys() {
    if (!isLogged()) {
        cout << "You must be logged in to create keys." << endl;
        return;
    }
    // send command and password
    byte_vec message(command.begin(), command.end());
    message.push_back('\0'); // Null-terminate the command
    send_message(message);
    LOG(INFO, "Sent command %s to server", string(command.begin(), command.end()).c_str());

    // send password
    string password;
    cout << "Enter password for key generation: ";
    cin >> password;
    if (password.size() > MAX_TEXT_SIZE) {
        cout << "Password too long (max " << MAX_TEXT_SIZE << " characters)" << endl;
        send_message(byte_vec()); // Send empty message to indicate failure
        return;
    }
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
    cout << response << endl;
}

bool verifySignature(const string& documentPath, const byte_vec& signature) {
    // read document content
    FILE* doc_file = fopen(documentPath.c_str(), "rb");

    fseek(doc_file, 0, SEEK_END);
    size_t doc_size = ftell(doc_file);
    fseek(doc_file, 0, SEEK_SET);

    byte_vec doc_content(doc_size);
    fread(doc_content.data(), 1, doc_size, doc_file);
    fclose(doc_file);

    // read public key
    string pubkey_path = DATA_PATH + "/server/" + logged_username + "/pub_key.pem";
    EVP_PKEY* pubkey = nullptr;
    readPEMPublicKey(pubkey_path, &pubkey);

    // verify signature
    bool valid = verifyRsaSha256(doc_content, signature, pubkey);
    EVP_PKEY_free(pubkey);

    if (!valid) {
        cout << "Signature verification failed." << endl;
        return false;
    }

    cout << "Signature verification succeeded." << endl;
    return true;
}

void cmd_SignDoc() {
    if (!isLogged()) {
        cout << "You must be logged in to sign a document." << endl;
        return;
    }

    // get document path
    string doc_name, doc_path;
    cout << "Enter document to sign: ";
    cin >> doc_name;
    if (doc_name.size() > MAX_TEXT_SIZE) {
        cout << "Document path too long (max " << MAX_TEXT_SIZE << " characters)" << endl;
        return; 
    }
    doc_path = DATA_PATH + "/client/" + logged_username + "/" + doc_name;

    // read document content
    FILE* doc_file = fopen(doc_path.c_str(), "rb");
    if (!doc_file) {
        cout << "Failed to open document file: " << doc_path << endl;
        return;
    }

    fseek(doc_file, 0, SEEK_END);
    size_t doc_size = ftell(doc_file);
    fseek(doc_file, 0, SEEK_SET);

    if (doc_size > MAX_DOC_SIZE) {
        cout << "Document size too large (max " << MAX_DOC_SIZE << " bytes)" << endl;
        fclose(doc_file);
        return;
    }

    byte_vec doc_content(doc_size);
    if (fread(doc_content.data(), 1, doc_size, doc_file) != doc_size) {
        cout << "Failed to read document file: " << doc_path << endl;
        fclose(doc_file);
        return;
    }

    fclose(doc_file);

    string privkey_password;
    cout << "Enter password for private key: ";
    cin >> privkey_password;
    if (privkey_password.size() > MAX_TEXT_SIZE) {
        cout << "Password too long (max " << MAX_TEXT_SIZE << " characters)" << endl;
        return;
    }

    // send command
    byte_vec message(command.begin(), command.end());
    message.push_back('\0'); // Null-terminate the command
    send_message(message);
    LOG(INFO, "Sent command %s to server", string(command.begin(), command.end()).c_str());

    // send document content
    message.clear();
    message.insert(message.end(), doc_content.begin(), doc_content.end());
    message.push_back('\0'); // Null-terminate the document content
    send_message(message);
    LOG(INFO, "Sent document content to server");

    // send private key password
    message.clear();
    message.insert(message.end(), privkey_password.begin(), privkey_password.end());
    message.push_back('\0'); // Null-terminate the password
    send_message(message);
    LOG(INFO, "Sent private key password to server");

    // Receive response from server
    message.clear();
    recv_message(message);
    if (message.empty()) {
        cout << "Failed to receive response from server." << endl;
        return;
    }

    string response = string(message.begin(), message.end()).c_str();
    // if response starts with SignDoc failed, print the error
    if (response.find("SignDoc failed") == 0) {
        cout << response << endl;
        return;
    }
    
    cout << "Signature: " << byte_vec_to_hex(message) << endl;

    //verifySignature(doc_path, message);
}

void cmd_GetPublicKey() {
    if (!isLogged()) {
        cout << "You must be logged in to get a public key." << endl;
        return;
    }

    string username;
    cout << "Enter username to get public key: ";
    cin >> username;
    if (username.size() > MAX_TEXT_SIZE) {
        cout << "Username too long (max " << MAX_TEXT_SIZE << " characters)" << endl;
        return;
    }

    // send command and username
    byte_vec message(command.begin(), command.end());
    message.push_back('\0'); // Null-terminate the command
    send_message(message);
    LOG(INFO, "Sent command %s to server", string(command.begin(), command.end()).c_str());

    // Send username
    message.clear();
    message.insert(message.end(), username.begin(), username.end());
    message.push_back('\0'); // Null-terminate the username
    send_message(message);
    LOG(INFO, "Sent username %s to server", string(username.begin(), username.end()).c_str());

    // Receive response from server
    byte_vec response;
    recv_message(response);
    if (response.empty()) {
        cout << "Failed to receive response from server." << endl;
        return;
    }

    // Convert byte_vec to string
    string public_key = string(response.begin(), response.end()).c_str();

    cout << public_key << endl;
}

void cmd_DeleteKeys() {
    if (!isLogged()) {
        cout << "You must be logged in to delete keys." << endl;
        return;
    }

    // send command
    byte_vec message(command.begin(), command.end());   
    message.push_back('\0'); // Null-terminate the command
    send_message(message);
    LOG(INFO, "Sent command %s to server", string(command.begin(), command.end()).c_str());

    // Receive response from server
    message.clear();
    recv_message(message);
    if (message.empty()) {
        cout << "Failed to receive response from server." << endl;
        return;
    }
    // Convert byte_vec to string
    string response = string(message.begin(), message.end()).c_str();
    cout << response << endl;
}

bool change_password() {
    string new_password;
    cout << "Enter new password: ";
    cin >> new_password;
    if (new_password.size() > MAX_TEXT_SIZE) {
        cout << "Password too long (max " << MAX_TEXT_SIZE << " characters). Please try again." << endl;
        send_message(byte_vec()); // Send empty message to indicate failure
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
    cout << endl;
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
    cout << "> ";
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
    else if (command == "Login") {
        if (!logged_username.empty()) {
            cout << "You are already logged in as " << logged_username << endl;
            return;
        }
        cmd_Login(); 
    }   
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