#pragma once

#include "../common/common.h"
#include "../common/protocol.h"

#include "commands.h"


extern thread_local int sockfd;

void server_init_connection(int conn_fd);

void send_message(const string &msg);
void send_message(const byte_vec &msg);
void recv_message(string &msg);
void recv_message(byte_vec &msg);
