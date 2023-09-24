//
// Created by andrea on 14/09/23.
//

#ifndef QUIC_SERVER
#define QUIC_SERVER

#include <unistd.h>
#include <netinet/in.h>
#include "quic_conn.h"
#include "packets.h"

// The default amount of time (in seconds) the
// server is willing to wait for the
// select_connection function
#define DEFAULT_TIMER 5

int start_server(int);

int process_incoming_packet(const char *, struct sockaddr_in *);

void build_server_transport_params(transport_parameter [9], conn_id, conn_id);

#endif //QUIC_SERVER
