//
// Created by andrea on 18/09/23.
//

#ifndef STREAMS
#define STREAMS

#include <stdlib.h>

#include "base.h"
#include "varint.h"
#include "quic_conn.h"

#define STREAM_SRC_CLIENT 0x00
#define STREAM_SRC_SERVER 0x01
#define STREAM_MODE_BIDI 0x00
#define STREAM_MODE_UNI 0x02

#define STREAM_SRC_MASK 0x0000000000000001
#define STREAM_MODE_MASK 0x0000000000000002
#define STREAM_MASK 0x0000000000000003

#define CLIENT_BIDI_BASE 0x00
#define SERVER_BIDI_BASE 0x01
#define CLIENT_UNI_BASE 0x02
#define SERVER_UNI_BASE 0x03

enum StreamMode {
    UNIDIRECTIONAL,
    BIDIRECTIONAL
};

enum SendingState {
    READY,
    SEND,
    DATA_SENT,
    RESET_SENT,
    DATA_RECVD_S,
    RESET_RECVD_S
};

enum ReceivingState {
    RECV,
    SIZE_KNOWN,
    DATA_RECVD_R,
    RESET_RECVD_R,
    DATA_READ,
    RESET_READ
};

struct stream_t {
    stream_id id;
    enum StreamMode mode;
    enum PeerType peer;
    size_t size;
    enum SendingState sending_state;
};

stream_id get_stream(enum PeerType, enum StreamMode, quic_connection *);

void new_stream(enum PeerType, enum StreamMode, quic_connection *, stream *);

stream_id open_stream(enum PeerType, enum StreamMode, quic_connection *);

uint64_t new_stream_id(enum PeerType, enum StreamMode, quic_connection *);

#endif //STREAMS
