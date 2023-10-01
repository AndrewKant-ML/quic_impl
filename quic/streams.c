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
void open_stream(enum PeerType peer, enum stream_mode mode, stream *str) {
    str->id = new_stream_id(peer, mode);
    str->mode = mode;
    str->peer = peer;
    str->size = 0;
}

/**
 * @brief Creates a new transfert_msg id
 *
 * @param peer  the type of peer generating the new transfert_msg (client or server)
 * @param mode  the transfert_msg type (unidirectional or bidirectional)
 * @return      the new transfert_msg ID
 */
uint64_t new_stream_id(enum PeerType peer, enum stream_mode mode) {

    uint8_t peer_mask, mode_mask;
    if (peer == SERVER)
        peer_mask = STREAM_SRC_SERVER;
    else
        peer_mask = STREAM_SRC_CLIENT;

    if (mode == UNIDIRECTIONAL)
        mode_mask = STREAM_MODE_UNI;
    else
        mode_mask = STREAM_MODE_BIDI;

    uint64_t stream_type_mask = peer_mask | mode_mask;
    return (((uint64_t) random()) << 2) & stream_type_mask;
}
