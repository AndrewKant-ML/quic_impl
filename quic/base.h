//
// Created by andrea on 21/09/23.
//

#ifndef QUIC_BASE
#define QUIC_BASE

#include <stdbool.h>
#include <stddef.h>
#include <math.h>
#include <time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

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

typedef struct outgoing_packet_t outgoing_packet;

typedef struct incoming_packet_t incoming_packet;

typedef struct long_header_pkt_t long_header_pkt;

typedef struct initial_packet_t initial_packet;

typedef struct zero_rtt_packet_t zero_rtt_packet;

typedef struct retry_packet_t retry_packet;

typedef struct one_rtt_packet_t one_rtt_packet;

typedef struct ack_frame_t ack_frame;

typedef struct ack_range_t ack_range;

typedef struct frame_t frame;

typedef struct conn_set_t conn_set;

enum PacketType {
    TYPE_INITIAL,
    TYPE_RETRY,
    TYPE_ZERO_RTT,
    TYPE_ONE_RTT
};

enum PacketNumberSpace {
    INITIAL = 0,
    HANDSHAKE = 1,
    APPLICATION_DATA = 2
};

enum PeerType {
    SERVER,
    CLIENT
};

int get_time(struct timespec *);

long get_time_millis();

void log_msg(char *);

void log_quic_error(char *);

#endif //QUIC_BASE
