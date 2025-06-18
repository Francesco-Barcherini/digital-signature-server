#include "protocol.h"

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main()
{

    client_init_connection();

    string msg = "Hello, Server!";
    byte_vec message(msg.begin(), msg.end());
    message.push_back('\0'); // Now it is null-terminated

    send_message(message);

    sleep(10);

    return 0;
}