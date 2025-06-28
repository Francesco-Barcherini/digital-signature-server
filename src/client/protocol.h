#pragma once

#include "../common/common.h"
#include "../common/protocol.h"


int connect_to_server(const string &host, uint16_t port);
void client_init_connection();

void close_connection();

void send_message(const string &msg);
void send_message(const byte_vec &msg);
void recv_message(string &msg);
void recv_message(byte_vec &msg);
