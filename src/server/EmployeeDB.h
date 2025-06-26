#pragma once

#include "../common/common.h"
#include "protocol.h"

#include <unordered_map>
#include <mutex>

struct Employee {
    byte_vec passwordSaltHash;
    byte_vec salt;
    
    bool hasKeys;
    bool firstLogin;
    bool deletedKeys;
};

class EmployeeDB {
public:
    bool registerEmployee(const string& username, const string& password);
    bool loginEmployee(const string& username, const string& password);
    bool changePassword(Employee& employee);
    Employee* getEmployee(const string& username);
    byte_vec getPublicKey(const string& username);
    bool createKeys(const string& username);
    void generateRSAKeyPair(EVP_PKEY*& keypair);



private:
    unordered_map<string, Employee> employees;
    mutable mutex dbMutex; // Mutex to protect access to the employee database
};