#pragma once

#include "../common/common.h"
#include "../common/protocol.h"


int connect_to_server(const std::string &host, uint16_t port);
void client_init_connection();

void send_message(const byte_vec &msg);
void recv_message(byte_vec &msg);
