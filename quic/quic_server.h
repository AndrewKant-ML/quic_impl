//
// Created by andrea on 14/09/23.
//

#ifndef QUIC_SERVER
#define QUIC_SERVER

#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include "quic_conn.h"
#include "packets.h"
#include "quic_errors.h"
#include "frames.h"

// The default amount of time (in seconds) the
// server is willing to wait for the
// select_connection function
#define DEFAULT_TIMER 5

int start_server(int);

int process_connection_request(initial_packet *, struct sockaddr_in *, time_ms);

void build_server_transport_params(transport_parameter [9], conn_id, conn_id);

int process_incoming_packet(char *, struct sockaddr_in *);

#endif //QUIC_SERVER
