//
// Created by andrea on 05/09/23.
//

#ifndef QUIC_CONNECTION
#define QUIC_CONNECTION

#include "quic_errors.h"
#include "base.h"
#include "packets.h"
#include "frames.h"
#include "streams.h"

// Minimum and maximum datagram size, as described in RFC 9000
#define MIN_DATAGRAM_SIZE 1200
#define MAX_DATAGRAM_SIZE 65527

// Maximum number of per-connection connection IDs this peer can handle
#define MAX_CONNECTION_IDS 10

// Maximum number of concurrent active connections
#define MAX_CONNECTIONS 100

// Maximum time for a connection to be idle
#define MAX_IDLE_TIMEOUT_MS 120000

// Default max amount of bidirectional and unidirectional streams
#define MAX_STREAMS_BIDI 2
#define MAX_STREAMS_UNI 2

// ACK delay exponent
#define ACK_DELAY_EXP 3

// Max delay to wait an ACK
#define MAX_ACK_DELAY 16383

// Recommended packet threshold
#define kPACKET_THRESH 3

// Maximum reordering in time before time threshold loss detection considers a
// packet lost. Specified as an RTT multiplier.
#define kTIME_THRESH 9 >> 3

// Recommended timer granularity value (in ms)
#define kGRANULARITY 1

// Recommended value for initial RTT (in ms)
#define kINITIAL_RTT 333

// Default value for congestion window size
#define kINITIAL_WND (10 * MAX_DATAGRAM_SIZE)

// Minimum value for congestion window size
#define kMIN_WND (2 * MAX_DATAGRAM_SIZE)

// Congestion window reducing factor (applied after a loss event)
#define kLOSS_REDUCTION_FACTOR 0.5f

// Period of time for persistent congestion to be established, specified as a PTO multiplier
#define kPER_CONG_THRESH 3

// Transport parameter types
#define original_destination_connection_id 0x00     // Server-side only
#define max_idle_timeout 0x01
#define stateless_reset_token 0x02                  // Server-side only
#define max_udp_payload_size 0x03
#define initial_max_data 0x04                       // Not used
#define initial_max_stream_data_bidi_local 0x05     // Not used
#define initial_max_stream_data_bidi_remote 0x06    // Not used
#define initial_max_stream_data_uni 0x07            // Not used
#define initial_max_streams_bidi 0x08
#define initial_max_streams_uni 0x09
#define ack_delay_exponent 0x0A
#define max_ack_delay 0x0B
#define disable_active_migration 0x0C               // Not used
#define preferred_address 0x0D                      // Server-side only
#define active_connection_id_limit 0x0E
#define initial_source_connection_id 0x0F
#define retry_source_connection_id 0x10             // Server-side only

// Maximum buffer packets capacity
#define BUF_CAPACITY 1024

// Maximum number of per-connection Transfert requests that can be managed
#define TRANSFERT_MAX_REQUESTS 20

/* === SENDER WINDOW === */

struct sender_window_t {
    // 3 packets arrays, one for packet number space
    outgoing_packet **buffer;      // TODO CHECK ABSOLUTELY
    time_ms time_of_last_ack_eliciting_packet[3];
    time_ms loss_time[3];
    pkt_num largest_acked[3];
    pkt_num largest_in_space[3];
    size_t write_index;
    size_t read_index;
};

int ack_pkt_range(quic_connection *, pkt_num, pkt_num, num_space);

int get_first_lost(sender_window *, time_t, num_space, const pkt_num *);

outgoing_packet *get_oldest_not_ready(sender_window *);

int is_lost(sender_window *, outgoing_packet *, size_t, time_t);

size_t count_to_be_sent(sender_window *);

outgoing_packet *get_pkt_num_in_space(const sender_window *, pkt_num, num_space);

outgoing_packet *get_largest_acked_in_space(const sender_window *, num_space);

int put_in_sender_window(sender_window *, outgoing_packet *);

time_ms send_time_in_space(const sender_window *, pkt_num, num_space);

time_ms send_time(const sender_window *, pkt_num);

bool in_flight_ack_eliciting(sender_window *);

bool in_flight_ack_eliciting_in_space(sender_window *, num_space);

/* === RECEIVER WINDOW === */

struct receiver_window_t {
    incoming_packet **buffer;
    size_t write_index;
    size_t read_index;
};

int put_in_receiver_window(receiver_window *, incoming_packet *);

size_t count_to_be_processed(receiver_window *);

transfert_msg *is_message_in_wnd(receiver_window *, outgoing_packet *);

int get_last_from_receiver_window(receiver_window *, incoming_packet *);

typedef struct loss_detection_timer_t {
    time_ms start;   // Timer start time
    time_ms timeout; // Timer timeout (in ms)
} loss_detection_timer;

struct quic_connection_t {
    enum PeerType peer_type;                   // The peer holding this connection state

    conn_id local_conn_ids[MAX_CONNECTION_IDS]; // Set of connection IDs used locally
    size_t local_conn_ids_num;                  // Number of connection IDs used locally
    size_t peer_conn_ids_limit;                 // Peer's connection IDs number limit
    size_t peer_conn_ids_num;                   // Peer's connection IDs number
    conn_id *peer_conn_ids;                     // Peer's connection IDs
    bool handshake_done;                        // 0 = handshake not completed, 1 = handshake completed
    bool is_in_anti_amplification_limit;        // 0 = handshake not completed, 1 = handshake completed
    size_t incoming_bytes;                      // Incoming bytes in UDP datagram payload (used for anti-amplification)

    receiver_window *rwnd;                      // Receiver window
    sender_window *swnd;                        // Sender window

    struct sockaddr_in addr;                    // Peer's IP address and port number

    // Streams IDs
    stream **bidi_streams;                      // Bidirectional active opened streams
    stream **uni_streams;                       // Unidirectional active opened streams

    size_t bidi_streams_num;                    // Number of bidirectional active opened streams
    size_t uni_streams_num;                     // Number of unidirectional active opened streams

    // RTT parameters
    time_ms min_rtt;                            // Minimum RTT
    time_ms latest_rtt;                         // Latest RTT sample
    time_ms first_rtt_sample;                   // Latest RTT sample
    time_ms smoothed_rtt;                       // Smoothed RTT value
    time_ms rtt_var;                            // RTT EWMA

    loss_detection_timer loss_timer;            // Loss detection timer

    time_ms time_threshold;                     // Time threshold before declaring a packet lost

    // Info taken from transport parameters
    unsigned long max_idle_timeout_ms;          // Maximum connection idle time (in ms)
    size_t conn_max_udp_payload_size;           // Max UDP payload size (in bytes) the peer can handle. Default: 65527, min: 1200
    size_t max_conn_data;                       // Maximum amount of data that can be sent over the connection
    size_t max_streams_bidi;                    // Maximum number of bidirectional streams this peer can open towards the other peer
    size_t max_streams_uni;                     // Maximum number of unidirectional streams this peer can open towards the other peer
    unsigned short ack_delay_exp;               // Must be <= 20, default 3
    unsigned short conn_max_ack_delay;          // Must be < 16384 (2^14)
    size_t active_conn_id_limit;                // Must be >=2, default 2

    // PTO parameters
    unsigned int pto_count;                     // Number of PTO
    time_ms pto_timeout;
    num_space pto_space;

    // Congestion control parameters
    size_t max_datagram_size;                   // Sender maximum UDP payload size (in bytes). Min: 1200
    size_t bytes_in_flight;                     // The sum of the size in bytes of all sent packets that contain at least one ack_pkt_range-eliciting or PADDING frame and have not been acknowledged or declared lost.
    size_t cwnd;                                // Congestion window size
    time_ms recovery_start_time;                // Start time of current recovery period
    size_t ssthresh;                            // Slow start threshold (in bytes)

    time_ms last_active;

    // Transfert file to be sent
    char *sending_requests[TRANSFERT_MAX_REQUESTS];
    size_t requests_num;
};

int init();

int new_connection(quic_connection *, enum PeerType);

int issue_new_conn_id(quic_connection *);

conn_id get_random_local_conn_id(quic_connection *);

conn_id get_random_peer_conn_id(quic_connection *);

int is_retired(conn_id);

int is_globally_used(conn_id);

int is_internally_used(conn_id, quic_connection *);

quic_connection *multiplex(conn_id);

quic_connection *select_connection_r(time_ms);

quic_connection *select_connection_s(time_ms);

int enqueue(outgoing_packet *, quic_connection *);

int send_packets(int, quic_connection *);

void on_packet_sent_cc(quic_connection *, size_t);

int read_transport_parameters(initial_packet *, quic_connection *, enum PeerType);

void update_rtt(quic_connection *, time_ms);

void on_congestion_event(quic_connection *, time_ms);

int in_cong_recovery_state(const quic_connection *, time_ms);

time_ms get_loss_time(quic_connection *, num_space *);

time_ms get_pto_time(quic_connection *, num_space *);

void set_loss_detection_timer(quic_connection *);

void on_loss_detection_timeout(quic_connection *);

int add_file_req(char *, quic_connection *);

int detect_and_remove_lost_packets(quic_connection *, num_space, outgoing_packet *[BUF_CAPACITY]);

int detect_and_remove_acked_packets(quic_connection *, num_space);

int close_connection_with_error_code(int, conn_id, conn_id, quic_connection *, uint64_t, char *);

void free_conn(quic_connection *);

int close_all_connections();

int on_ack_received(quic_connection *, ack_frame *, num_space);

int on_packet_loss(quic_connection *, size_t, outgoing_packet *[BUF_CAPACITY]);

// Streams functions
int save_stream_to_conn(quic_connection *, stream *);

#endif //QUIC_CONNECTION
