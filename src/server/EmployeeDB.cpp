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
    newEmployee.salt.resize(SALT_SIZE);
    if (RAND_bytes(newEmployee.salt.data(), SALT_SIZE) != 1)
        error("Failed to generate random salt");
    
    sha256(password, newEmployee.salt, newEmployee.passwordSaltHash);
    
    // Initialize other fields
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

