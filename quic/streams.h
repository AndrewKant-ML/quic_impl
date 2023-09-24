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

enum stream_mode {
    UNIDIRECTIONAL,
    BIDIRECTIONAL
};

struct stream_t {
    stream_id id;
    enum stream_mode mode;
    enum peer_type peer;
    size_t size;
};

void open_stream(enum peer_type, enum stream_mode, stream *);

uint64_t new_stream_id(enum peer_type, enum stream_mode);

#endif //STREAMS
