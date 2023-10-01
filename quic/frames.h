/**
 * This header file defines all QUIC frame types as
 * bitmask constants. Be aware to properly convert
 * them into *varint before creating the frame.
 *
 *
 * @note Although they have been defined, not all
 * frames are currently implemented in this version.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9000#name-frame-types-and-formats">Frame types and formats - RFC 9000</a>
 *
 * @author Andrea Cantarini
 */

#ifndef FRAMES
#define FRAMES

#include <string.h>

#include "varint.h"
#include "quic_conn.h"
#include "quic_errors.h"

#include "transfert/transfert_base.h"

#define TYPE_PADDING 0x00
#define TYPE_PING 0x01
#define TYPE_ACK 0x02
#define TYPE_ACK_ECN  0x03          // Not implemented
#define TYPE_RESET_STREAM 0x04
#define TYPE_STOP_SENDING 0x05
#define TYPE_CRYPTO 0x06 // Not implemented
#define TYPE_NEW_TOKEN 0x07
#define TYPE_STREAM_BASE 0x08 // In STREAM frames, the three least-significant
// bits determine the fields that are present in
// the frame.
#define OFF_BIT_MASK 0x04
#define LEN_BIT_MASK 0x02
#define FIN_BIT_MASK 0x01

#define TYPE_MAX_DATA 0x10
#define TYPE_MAX_STREAM_DATA 0x11
#define TYPE_MAX_STREAMS_BIDI 0x12
#define TYPE_MAX_STREAMS_UNI 0x13
#define TYPE_DATA_BLOCKED 0x14
#define TYPE_STREAM_DATA_BLOCKED 0x15
#define TYPE_STREAMS_BLOCKED_BIDI 0x16
#define TYPE_STREAMS_BLOCKED_UNI 0x17
#define TYPE_NEW_CONNECTION 0x18
#define TYPE_RETIRE_CONNECTION_ID 0x19
#define TYPE_PATH_CHALLENGE 0x1A      // Not implemented
#define TYPE_PATH_RESPONSE 0x1B      // Not implemented
#define TYPE_CONN_CLOSE_QUIC 0x1C
#define TYPE_CONN_CLOSE_APP 0x1D
#define TYPE_HANDSHAKE_DONE 0x1E

struct frame_t {
    uint8_t type;
    void *frame_data;
};

// ACK Range
struct ack_range_t {
    size_t gap;
    size_t ack_range_len;
};

struct ack_frame_t {
    uint8_t type;
    pkt_num largest_acked;
    time_ms ack_delay;
    size_t ack_range_count;
    size_t first_ack_range;
    ack_range **ranges;
};

void new_ack_range(size_t, size_t, ack_range *);

void new_ack_frame(pkt_num, uint64_t, size_t, size_t, ack_range *[], ack_frame *);

void new_close_connection_frame(uint64_t, char *, char *);

void new_reset_stream_frame(stream_id, uint64_t, char *);

size_t new_stream_frame(stream_id, size_t, size_t, char *, char *);

ssize_t process_frame(const char *, pkt_num, num_space, quic_connection *);

ssize_t parse_ack_frame(const char *, ack_frame *, const quic_connection *, time_ms);

char *write_frame_into_buf(frame *, size_t *);

ssize_t ack_frame_len(ack_frame *);

#endif //FRAMES
