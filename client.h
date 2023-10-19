//
// Created by andrea on 20/09/23.
//

#ifndef IIW_CLIENT_H
#define IIW_CLIENT_H

#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "quic/quic_client.h"
#include "quic/quic_transfert.h"
#include "errors.h"

void process_arguments(int, char *[]);

int open_connection(quic_connection *);

int client_load();

#endif //IIW_CLIENT_H
