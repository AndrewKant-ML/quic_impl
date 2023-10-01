/**
 * This header file defines transport error codes
 * as bitmask constants. Be aware to use these error
 * codes only in CONNECTION_CLOSE frames with a type
 * of 0x1c, and to properly convert them into *varint
 * before creating the frame.
 *
 * @note Although they have been defined, not all
 * frames are currently implemented in this version.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9000#name-error-codes">Error codes - RFC 9000</a>
 *
 * @author Andrea Cantarini
 */

#ifndef QUIC_ERRORS
#define QUIC_ERRORS

#include <stdint.h>

#define NO_ERROR                  0x00
#define INTERNAL_ERROR            0x01
#define CONNECTION_REFUSED        0x02
#define FLOW_CONTROL_ERROR        0x03
#define STREAM_LIMIT_ERROR        0x04
#define STREAM_STATE_ERROR        0x05
#define FINAL_SIZE_ERROR          0x06
#define FRAME_ENCODING_ERROR      0x07
#define TRANSPORT_PARAMETER_ERROR 0x08
#define CONNECTION_ID_LIMIT_ERROR 0x09
#define PROTOCOL_VIOLATION        0x0A
#define INVALID_TOKEN             0x0B
#define APPLICATION_ERROR         0x0C
#define CRYPTO_BUFFER_EXCEEDED    0x0D
#define KEY_UPDATE_ERROR          0x0E
#define AEAD_LIMIT_REACHED        0x0F
#define NO_VIABLE_PATH            0x10
#define CRYPTO_ERROR_BASE         0x100   // Not implemented

#endif //QUIC_ERRORS
