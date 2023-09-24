//
// Created by andrea on 21/09/23.
//

#ifndef QUIC_BASE
#define QUIC_BASE

#include <stdbool.h>
#include <math.h>
#include <time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdint.h>

#include "varint.h"

typedef uint64_t pkt_num;

typedef uint64_t conn_id;

typedef uint64_t stream_id;

typedef unsigned long time_ms;

// QUIC version
#define VERSION 0x01

// UDP buffer size. Can store up to a maximum-size UDP datagram
#define UDP_BUF_SIZE 65536

typedef struct quic_connection_t quic_connection;

typedef struct sender_window_t sender_window;

typedef struct receiver_window_t receiver_window;

typedef struct stream_t stream;

typedef struct transfert_msg_t transfert_msg;

typedef enum PacketNumberSpace num_space;

enum peer_type {
    SERVER,
    CLIENT
};

int get_time(struct timespec *);

long get_time_millis();

#endif //QUIC_BASE
