//
// Created by andrea on 14/09/23.
//

#ifndef QUIC_CLIENT
#define QUIC_CLIENT

#include <netinet/in.h>
#include "quic_conn.h"
#include "packets.h"
#include "quic_errors.h"

int quic_connect(int, quic_connection *);

void build_client_transport_params(transport_parameter [8], conn_id);

#endif //QUIC_CLIENT
