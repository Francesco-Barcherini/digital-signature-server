#include "EmployeeDB.h"

bool EmployeeDB::registerEmployee(const string& username, const string& password) {
    // Take the mutex lock on employees as early as possible to protect the whole operation
    lock_guard<mutex> lock(dbMutex);

    // Check if the employee already exists
    if (employees.find(username) != employees.end()) {
        LOG(WARN, "Employee %s already exists", username.c_str());
        return false; // Employee already exists
    }    
    
    // Create a new employee entry
    Employee newEmployee;
    
    // Generate salt and hash the password
    genRandomBytes(newEmployee.salt, SALT_SIZE);
    
    sha256(password, newEmployee.salt, newEmployee.passwordSaltHash);
    
    // Initialize other fields
    newEmployee.hasKeys = false; // Initially, the employee does not have keys
    newEmployee.firstLogin = true;
    newEmployee.deletedKeys = false;

    // Store the new employee in the database
    employees[username] = newEmployee;
    
    return true; // Registration successful
}

bool EmployeeDB::changePassword(Employee& employee) {
    string message = "First login: change password";

    byte_vec response(message.begin(), message.end());
    response.push_back('\0'); // Null-terminate the message
    send_message(response);

    string newPassword;
    recv_message(response);
    if (response.empty()) {
        LOG(ERROR, "Failed to receive new password from client");
        return false; // Failed to receive new password
    }
    newPassword = string(response.begin(), response.end()).c_str();

    if (newPassword == "bob1")
        LOG(DEBUG, "OK, new password is bob1");
    else
        LOG(DEBUG, "New password received: %s", newPassword.c_str());

    if (newPassword.size() > MAX_TEXT_SIZE) {
        LOG(WARN, "New password too long (max %d characters). Please try again.", MAX_TEXT_SIZE);
        return false; // New password too long
    }

    // Generate new salt and hash the new password
    employee.salt.resize(SALT_SIZE);
    if (RAND_bytes(employee.salt.data(), SALT_SIZE) != 1) {
        LOG(ERROR, "Failed to generate random salt for new password");
        return false; // Failed to generate random salt
    }
    sha256(newPassword, employee.salt, employee.passwordSaltHash);
    employee.firstLogin = false; // Mark as not first login anymore
    return true; // Password change successful
}

bool EmployeeDB::loginEmployee(const string& username, const string& password) {
    // Lock the mutex to protect access to the employee database
    lock_guard<mutex> lock(dbMutex);
    
    // Find the employee by username
    auto it = employees.find(username.c_str());
    if (it == employees.end()) {
        send_message(string("Employee " + username + " not found"));
        return false; // Employee not found
    }

    Employee& emp = it->second;

    // Verify the password
    if (!verify_sha256(password, emp.salt, emp.passwordSaltHash)) {
        LOG(WARN, "Invalid password for user %s", username.c_str());
        send_message(string("Invalid password for user " + username));
        return false; // Invalid password
    }

    // Check if it's the first login
    if (emp.firstLogin) {
        if (changePassword(emp)) {
            string message = "Password changed successfully";
            byte_vec response(message.begin(), message.end());
            response.push_back('\0'); // Null-terminate the message
            send_message(response);
            LOG(INFO, "User %s changed password successfully", username.c_str());
            return true; // Password changed successfully
        }
        string message = "First login: change password failed";
        byte_vec response(message.begin(), message.end());
        response.push_back('\0'); // Null-terminate the message
        send_message(response);
        LOG(WARN, "User %s failed to change password on first login", username.c_str());
        return false; // First login password change failed
    } else {
        string message = "Login successful";
        byte_vec response(message.begin(), message.end());
        response.push_back('\0'); // Null-terminate the message
        send_message(response);
        LOG(INFO, "User %s logged in successfully", username.c_str());
        return true; // Login successful
    }

    return false; // Login failed
}

Employee* EmployeeDB::getEmployee(const string& username) {
    // Lock the mutex to protect access to the employee database
    lock_guard<mutex> lock(dbMutex);
    
    auto it = employees.find(username.c_str());
    if (it != employees.end()) {
        return &it->second; // Return a pointer to the employee
    }
    
    return nullptr; // Employee not found
}

string EmployeeDB::getPublicKey(const string& username) {
    Employee* emp = getEmployee(username);
    if (!emp)
        throw runtime_error("Employee not found: " + username);

    if (!emp->hasKeys)
        throw runtime_error("Public key not set for employee: " + username);

    string filename = "data/server/" + username + "/pub_key.pem";

    FILE* file_PEM_pubkey = fopen(filename.c_str(), "r");
    if (!file_PEM_pubkey) {
        LOG(ERROR, "Failed to open public key file: %s", filename.c_str());
        throw runtime_error("Failed to open public key file: " + filename);
    }

    string PEM_public_key;
    unsigned char *buffer = NULL;
    // read PEM public key from file_PEM_pubkey and put into a string
    fseek(file_PEM_pubkey, 0, SEEK_END);
    long int PEM_pubkey_size = ftell(file_PEM_pubkey);
    fseek(file_PEM_pubkey, 0, SEEK_SET);

    buffer = (unsigned char*)malloc(PEM_pubkey_size);
    if (!buffer) {
        fclose(file_PEM_pubkey);
        LOG(ERROR, "Failed to allocate memory for public key buffer");
        throw runtime_error("Failed to allocate memory for public key buffer");
    }
    PEM_public_key.resize(PEM_pubkey_size);
    int bytesRead = fread(buffer, 1, PEM_pubkey_size, file_PEM_pubkey);
    if (bytesRead < PEM_pubkey_size) {
        fclose(file_PEM_pubkey);
        LOG(ERROR, "Failed to read public key from file: %s", filename.c_str());
        throw runtime_error("Failed to read public key from file: " + filename);
    }
    fclose(file_PEM_pubkey);

    PEM_public_key = string(buffer, buffer+bytesRead).c_str();

    LOG(INFO, "Public key retrieved for employee %s", username.c_str());
    return PEM_public_key; // Return the public key as a string

    // EVP_PKEY* pubkey = nullptr;
    // BIO* bio = BIO_new_file(filename.c_str(), "r");
    // if (!bio) {
    //     LOG(ERROR, "Failed to open public key file: %s", filename.c_str());
    //     throw runtime_error("Failed to open public key file: " + filename);
    // }
    // pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    // BIO_free(bio);
    // if (!pubkey) {
    //     LOG(ERROR, "Failed to read public key from file: %s", filename.c_str());
    //     throw runtime_error("Failed to read public key from file: " + filename);
    // }

    // unsigned char* pubKey_buf = NULL;
    // int pubKey_len = i2d_PUBKEY(pubkey, &pubKey_buf);
    // if (pubKey_len <= 0) {
    //     EVP_PKEY_free(pubkey);
    //     LOG(ERROR, "Failed to convert public key to DER format");
    //     throw runtime_error("Failed to convert public key to DER format");
    // }
    // byte_vec pubKey(pubKey_buf, pubKey_buf + pubKey_len);
    // OPENSSL_free(pubKey_buf);
    // EVP_PKEY_free(pubkey);
    // LOG(INFO, "Public key retrieved for employee %s", username.c_str());
    // return pubKey; // Return the public key as a byte vector
}

void EmployeeDB::generateRSAKeyPair(EVP_PKEY*& keypair) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
        error("Failed to create RSA context");
        

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        error("Failed to initialize RSA keygen");
    }


    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        error("Failed to set RSA key size");
    }

    if (EVP_PKEY_keygen(ctx, &keypair) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        error("Failed to generate RSA key pair");
    }

    EVP_PKEY_CTX_free(ctx);
}

bool EmployeeDB::createKeys(const string& username) {
    // recv the password
    string password;
    byte_vec message;
    recv_message(message);
    if (message.empty()) {
        LOG(ERROR, "Failed to receive password for key creation");
        error("Failed to receive password for key creation");
    }
    password = string(message.begin(), message.end()).c_str();
    LOG(INFO, "Received password for key creation for employee %s", username.c_str());

    Employee* emp = getEmployee(username);

    // Lock the mutex to protect access to the employee database
    lock_guard<mutex> lock(dbMutex);

    if (!emp) {
        LOG(ERROR, "Employee %s not found", username.c_str());
        error("Employee not found");
    }

    if (emp->hasKeys) {
        LOG(WARN, "Keys already exist for employee %s", username.c_str());
        error("Keys already exist for employee");
    }

    if (emp->deletedKeys) {
        LOG(WARN, "Keys were deleted for employee %s", username.c_str());
        error("Keys were deleted for employee");
    }

    EVP_PKEY* keypair = nullptr;
    generateRSAKeyPair(keypair);
    if (!keypair) {
        LOG(ERROR, "Failed to generate RSA key pair for employee %s", username.c_str());
        error("Failed to generate RSA key pair for employee");
    }


    // Save the public key into data/server/<username>/pub_key.pem
    string pub_file = "data/server/" + username + "/pub_key.pem";
    BIO* pub_bio = BIO_new_file(pub_file.c_str(), "w");
    if (!pub_bio) {
        EVP_PKEY_free(keypair);
        LOG(ERROR, "Failed to open public key file for writing: %s", pub_file.c_str());
        error("Failed to open public key file for writing");
    }

    if (PEM_write_bio_PUBKEY(pub_bio, keypair) <= 0) {
        BIO_free(pub_bio);
        EVP_PKEY_free(keypair);
        LOG(ERROR, "Failed to write public key to file: %s", pub_file.c_str());
        error("Failed to write public key to file");
    }

    BIO_free(pub_bio);

    // Save the private key into data/server/<username>/priv_key.pem, with passphrase encryption
    string priv_file = "data/server/" + username + "/priv_key.pem";
    BIO* priv_bio = BIO_new_file(priv_file.c_str(), "w");
    if (!priv_bio) {
        EVP_PKEY_free(keypair);
        LOG(ERROR, "Failed to open private key file for writing: %s", priv_file.c_str());
        error("Failed to open private key file for writing");
    }
    if (PEM_write_bio_PrivateKey(priv_bio, keypair, EVP_aes_256_cbc(), NULL, 0, NULL, (void*)password.c_str()) <= 0) {
        BIO_free(priv_bio);
        EVP_PKEY_free(keypair);
        LOG(ERROR, "Failed to write private key to file: %s", priv_file.c_str());
        error("Failed to write private key to file");
    }
    BIO_free(priv_bio);
    EVP_PKEY_free(keypair);
    emp->hasKeys = true; 
    return true; // Keys created successfully
}

void EmployeeDB::deleteKeys(const string& username) {    
    Employee* emp = getEmployee(username);

     // Lock the mutex to protect access to the employee database
    lock_guard<mutex> lock(dbMutex);

    if (!emp) {
        LOG(ERROR, "Employee %s not found", username.c_str());
        error("Employee not found");
    }

    if (!emp->hasKeys) {
        LOG(WARN, "No keys to delete for employee %s", username.c_str());
        error("No keys to delete for employee");
    }

    if (emp->deletedKeys) {
        LOG(WARN, "Keys were already deleted for employee %s", username.c_str());
        error("Keys were already deleted for employee");
    }

    // Delete the public and private key files
    string pub_file = "data/server/" + username + "/pub_key.pem";
    string priv_file = "data/server/" + username + "/priv_key.pem";

    if (remove(pub_file.c_str()) != 0) {
        LOG(ERROR, "Failed to delete public key file: %s", pub_file.c_str());
        error("Failed to delete public key file");
    }
    
    if (remove(priv_file.c_str()) != 0) {
        LOG(ERROR, "Failed to delete private key file: %s", priv_file.c_str());
        error("Failed to delete private key file");
    }

    emp->hasKeys = false; // Mark keys as deleted
    emp->deletedKeys = true; // Mark that keys were deleted
}


void EmployeeDB::signDocument(const string& username) {

    // receive document content
    byte_vec doc_content;
    recv_message(doc_content);
    
    //receive private key password
    byte_vec privkey_password;
    recv_message(privkey_password);

    if (doc_content.empty() || privkey_password.empty()) {
        LOG(ERROR, "Document content or private key password is empty");
        error("Document content or private key password is empty");
    }

    if (doc_content.size() > MAX_DOC_SIZE) {
        LOG(WARN, "Document content too long (max %d characters)", MAX_DOC_SIZE);
        error("Document content too long");
    }

    Employee* emp = getEmployee(username);

    // Lock the mutex to protect access to the employee database
    lock_guard<mutex> lock(dbMutex);

    if (!emp) {
        LOG(ERROR, "Employee %s not found", username.c_str());
        error("Employee not found");
    }

    if (!emp->hasKeys) {
        LOG(WARN, "No keys to sign document for employee %s", username.c_str());
        error("No keys to sign document for employee");
    }

    // retrieve user's private key from file
    string priv_file = "data/server/" + username + "/priv_key.pem";
    EVP_PKEY* privkey = nullptr;
    readPEMPrivateKey(priv_file, &privkey, string(privkey_password.begin(), privkey_password.end()).c_str());

    // compute signature
    byte_vec signature;
    signRsaSha256(signature, doc_content, privkey);
    EVP_PKEY_free(privkey); // Free the private key after use

    if (signature.empty()) {
        LOG(ERROR, "Failed to sign document for employee %s", username.c_str());
        error("Failed to sign document");
    }

    // Send the signature back to the client
    send_message(signature);

    // TODO: remove
    // LOG(INFO, "Test of the document signature");
    // EVP_PKEY* pubkey = nullptr;
    // string pub_file = "data/server/" + username + "/pub_key.pem";
    // readPEMPublicKey(pub_file, &pubkey);

    // if (!verifyRsaSha256(doc_content, signature, pubkey)) {
    //     LOG(ERROR, "Signature verification failed for employee %s", username.c_str());
    //     EVP_PKEY_free(pubkey);
    //     error("Signature verification failed");
    // } else {
    //     LOG(INFO, "Signature verification succeeded for employee %s", username.c_str());
    //     LOG(INFO, "Signature: %s", byte_vec_to_hex(signature).c_str());
    // }
}