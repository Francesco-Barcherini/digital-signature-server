#include "protocol.h"
#include "commands.h"

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char *argv[])
{
    // Set log level based on command line argument
    if (argc > 1)
        set_log_level(argv[1]);
    

    client_init_connection();

    string msg = "Hello, Server!";
    byte_vec message(msg.begin(), msg.end());
    message.push_back('\0'); // Now it is null-terminated

    send_message(message);

    while(1)
        operation();

    return 0;
}