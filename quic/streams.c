//
// Created by andrea on 18/09/23.
//

#include "streams.h"

/**
 * @brief Opens a new stream
 *
 * Opens a new stream, setting its initial size to zero.
 *
 * @param peer  the peer opening the stream
 * @param mode  the stream type
 * @param str   where to store the opened stream
 */
void new_stream(enum PeerType peer, enum StreamMode mode, quic_connection *conn, stream *str) {
    str->id = new_stream_id(peer, mode, conn);
    str->mode = mode;
    str->peer = peer;
    str->size = 0;
    str->sending_state = READY;
}

/**
 * @brief Opens a new stream on a connection
 *
 * Tries to open a new stream over a connection, taking
 * into account stream initializer and mode
 *
 * @param peer  the stream initializer
 * @param mode  the stream mode
 * @param conn  the QUICLite connection
 * @return      0 no success, -1 on errors
 */
stream_id open_stream(enum PeerType peer, enum StreamMode mode, quic_connection *conn) {
    stream *s = (stream *) calloc(1, sizeof(stream));
    new_stream(peer, mode, conn, s);
    if (save_stream_to_conn(conn, s) == 0)
        return s->id;
    return (stream_id)-1;
}

/**
 * @brief Creates a new transfert_msg id
 *
 * @param peer  the type of peer generating the new transfert_msg (client or server)
 * @param mode  the transfert_msg type (unidirectional or bidirectional)
 * @return      the new transfert_msg ID
 */
uint64_t new_stream_id(enum PeerType peer, enum StreamMode mode, quic_connection *conn) {

    uint8_t peer_mask;
    if (peer == SERVER)
        peer_mask = STREAM_SRC_SERVER;
    else
        peer_mask = STREAM_SRC_CLIENT;

    stream *s;
    switch (mode) {
        case UNIDIRECTIONAL: {
            if (conn->uni_streams_num == 0)
                return peer_mask | STREAM_MODE_UNI;
            s = conn->uni_streams[conn->uni_streams_num - 1];
            return s->id + 0x04;
        }
        case BIDIRECTIONAL: {
            if (conn->bidi_streams_num == 0)
                return peer_mask | STREAM_MODE_BIDI;
            s = conn->uni_streams[conn->uni_streams_num - 1];
            return s->id + 0x04;
        }
    }
}
