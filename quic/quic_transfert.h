//
// Created by andrea on 05/10/23.
//

#ifndef QUIC_TRANSFERT
#define QUIC_TRANSFERT

#include <unistd.h>
#include <stdio.h>

#include "base.h"
#include "quic_conn.h"

int process_file_requests(quic_connection *);

void remove_file_request(char *, quic_connection *);

ssize_t write_file_to_packets(int, char *, quic_connection *);

#endif //QUIC_TRANSFERT
