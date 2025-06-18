#pragma once

#include "../common/common.h"
#include "../common/protocol.h"



void server_init_connection(int conn_fd);

void recv_message(byte_vec &msg);
void send_message(const byte_vec &msg);
