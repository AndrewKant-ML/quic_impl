//
// Created by andrea on 31/08/23.
//

#ifndef PACKETS
#define PACKETS

#include "transport_params.h"
#include "quic_conn.h"
#include "frames.h"
#include "quic_errors.h"

/**
 * To indicate the header format, the packet most-significant
 * bit is either set to 1 (long header) or 0 (short header).
 * Here, the packet first byte is used to specify the header
 * format and other packet-specific information.
 */
#define LONG_HEADER_FORM 0xC0
#define SHORT_HEADER_FORM 0x40

#define PACKET_HEADER_MASK 0xC0
#define SPIN_BIT_MASK 0x20;
#define SHORT_RESERVED_BITS_MASK 0x18
#define KEY_PHASE_MASK 0x04
#define PACKET_NUMBER_LENGTH_MASK 0x03

// For long packets format only
#define PACKET_TYPE_INITIAL 0x00
#define PACKET_TYPE_0_RTT 0x10
#define PACKET_TYPE_RETRY 0x30
#define TYPE_SPECIFIC_BITS_MASK 0x30
#define LONG_RESERVED_BITS_MASK 0x0C

// General outgoing packet struct, used inside sending window
struct outgoing_packet_t {
    pkt_num pkt_num;            // Packet number
    num_space space;            // Packet number space
    size_t length;              // Packet length in bytes (header + payload)
    time_ms send_time;          // Time at which the packet has been sent (in ms)
    bool ready_to_send;         // States if the packet has been put inside a datagram or not
    bool acked;                 // States if the packet has been acknowledged or not
    bool ack_eliciting;         // 0 = packet is not ack-eliciting, 1 = packet is ack_pkt_range-eliciting
    bool in_flight;             // 0 = packet is not in flight, 1 = packet is in flight
    bool lost;                  // 0 = packet is not lost, 1 = packet is lost
    void *pkt;                  // Actual packet
};

// General incoming packet struct, used inside receiver window
struct incoming_packet_t {
    pkt_num pkt_num;            // Packet number
    enum PacketType pkt_type;   // Packet type
    void *pkt;                  // Actual packet
};

// Long header packet format
struct long_header_pkt_t {
    uint8_t first_byte;
    uint32_t version;
    conn_id dest_conn_id;
    conn_id src_conn_id;
    char *payload;
};

/**
 * Initial Packet format:\n
 * <pre> Initial Packet {\n
        Header Form (1) = 1,\n
        Fixed Bit (1) = 1,\n
        Long Packet Type (2) = 0,\n
        Reserved Bits (2),\n
        Packet Number Length (2),\n
        Version (32),\n
        Destination Connection ID (64),\n
        Source Connection ID (64),\n
        Transport Parameters number (i), \n
        Transport Parameters (..), \n
        Length (i),\n
        Packet Number (i),\n
        Packet Payload (..),\n
    }</pre>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9000#name-initial-packet">Initial Packet - RFC 9000</a>
 */
struct initial_packet_t {
    uint8_t first_byte;
    uint32_t version;
    conn_id dest_conn_id;
    conn_id src_conn_id;
    size_t transport_parameters_number;
    transport_parameter transport_parameters[17];
    size_t length;
    pkt_num packet_number;
    char *payload;
};

/**
 * 0-RTT Packet format:\n
 * <pre> 0-RTT Packet {\n
        Header Form (1) = 1,\n
        Fixed Bit (1) = 1,\n
        Long Packet Type (2) = 1,\n
        Reserved Bits (2),\n
        Packet Number Length (2),\n
        Version (32),\n
        Destination Connection ID Length (8),\n
        Destination Connection ID (0..160),\n
        Source Connection ID Length (8),\n
        Source Connection ID (0..160),\n
        Length (i),\n
        Packet Number (8..32),\n
        Packet Payload (8..),\n
        }</pre>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9000#name-0-rtt">0-RTT Packet - RFC 9000</a>
 */
struct zero_rtt_packet_t {
    uint8_t first_byte;
    uint32_t version;
    size_t dest_conn_id_len;
    conn_id dest_conn_id;
    size_t src_conn_id_len;
    conn_id src_conn_id;
    varint *length;
    void *packet_number;
    char *payload;
};

/**
 * Retry Packet format:\n
 * <pre> Retry Packet {\n
        Header Form (1) = 1,\n
        Fixed Bit (1) = 1,\n
        Long Packet Type (2) = 3,\n
        Unused (4),\n
        Version (32),\n
        Destination Connection ID Length (8),\n
        Destination Connection ID (0..160),\n
        Source Connection ID Length (8),\n
        Source Connection ID (0..160),\n
        Retry Token (..),\n
        Retry Integrity Tag (128),\n
        }</pre>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9000#name-retry-packet">Retry Packet - RFC 9000</a>
 */
struct retry_packet_t {
    uint8_t first_byte;
    uint32_t version;
    size_t dest_conn_id_len;
    conn_id dest_conn_id;
    size_t src_conn_id_len;
    conn_id src_conn_id;
    void *retry_token;
    uint64_t retry_integrity_tag[2];
};

struct one_rtt_packet_t {
    uint8_t first_byte;
    conn_id dest_connection_id;
    pkt_num packet_number;
    size_t length;
    char *payload;
};

ssize_t process_incoming_dgram(char *, size_t, enum PeerType, struct sockaddr_in *, time_ms,
                               int (*)(initial_packet *, struct sockaddr_in *, time_ms));

ssize_t process_received_packets(quic_connection *);

void build_initial_packet(conn_id, conn_id, size_t, size_t, void *, pkt_num, initial_packet *);

void build_one_rtt_packet(conn_id dest_conn_id, size_t, void *payload, one_rtt_packet *pkt);

ssize_t write_packet_to_buf(char *, size_t off, const void *);

int pad_packet(outgoing_packet *, size_t);

size_t initial_pkt_len(const initial_packet *);

size_t zero_rtt_pkt_len(const zero_rtt_packet *);

size_t retry_pkt_len(const retry_packet *);

size_t one_rtt_pkt_len(const one_rtt_packet *);

int read_initial_packet(long_header_pkt *, initial_packet *);

int read_zero_rtt_packet(long_header_pkt *, zero_rtt_packet *);

int read_retry_packet(long_header_pkt *, retry_packet *);

int read_one_rtt_packet(void *, one_rtt_packet *);

int set_pkt_num(void *, pkt_num);

int process_packet_payload(const char *, pkt_num, size_t, num_space, quic_connection *);

int check_incoming_dgram(struct sockaddr_in *, quic_connection *);

void write_initial_packet_to_buffer_for_forwarding(char *, initial_packet *);

void write_one_rtt_packet_to_buffer_for_forwarding(char *, one_rtt_packet *);

#endif //PACKETS
