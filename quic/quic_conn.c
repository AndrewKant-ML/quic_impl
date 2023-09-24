/*
 * This file provides mechanisms for:
 * · connection management (initialization, maintenance and closing)
 * · packets transmission and reception
 * · acknowledgment
 */

#include <sys/param.h>
#include <math.h>

#include "quic_conn.h"
#include "quic_errors.h"

// Array of all opened connections
quic_connection *connections[MAX_CONNECTIONS];
size_t active_connections = 0;
size_t last_checked = 0;

// List of invalidated connection IDs
const conn_id *invalidated;
size_t invalidated_ids_number = 0;

// Connection ID generation base
conn_id last_generated = 1;

/**
 * @brief Init the QUICLite layer
 *
 * Allocates memory for a list of retired connection IDs.
 * By default, 30 connection IDs are considered retired.
 * If this number increases in time, other memory is allocated
 *
 * @return 0 on success, -1 on errors
 */
int init() {
    if ((invalidated = (conn_id *) malloc(sizeof(conn_id) * 30)) == NULL)
        return -1;
    return 0;
}

/**
 * @brief Gets one of local connection IDs
 * @param conn  the connection
 * @return      one of local connection IDs
 */
conn_id get_local_conn_id(quic_connection *conn) {
    size_t index = (random() * 100) % conn->local_conn_ids_num;
    return conn->local_conn_ids[index];
}

/**
 * @brief Creates a new connection
 *
 * Initialize a new connection, issuing a new connection ID,
 * which will be used as destination connection ID for
 * following incoming packets.
 *
 * @param conn  the connection to be create
 * @return      0 on success, -1 on errors
 */
int new_connection(quic_connection *conn, enum peer_type type) {
    conn->peer_type = type;
    conn->local_conn_ids_num = 0;
    if (issue_new_conn_id(conn) != 0) {
        print_quic_error("An error occurred while issuing a new connection ID.");
        return -1;
    }
    conn->cwnd = kINITIAL_WND;   // Initial congestion window size
    conn->bytes_in_flight = 0;
    conn->recovery_start_time = 0;
    conn->ssthresh = UINT64_MAX;
    conn->pto_count = 0;

    conn->loss_timer.start = time(NULL);
    conn->loss_timer.timeout = 0;

    conn->latest_rtt = 0;
    conn->smoothed_rtt = kINITIAL_RTT;
    conn->rtt_var = (time_t) kINITIAL_RTT / 2;
    conn->min_rtt = 0;
    conn->first_rtt_sample = 0;

    conn->swnd.largest_acked[INITIAL] = UINT32_MAX;
    conn->swnd.largest_acked[HANDSHAKE] = UINT32_MAX;
    conn->swnd.largest_acked[APPLICATION_DATA] = UINT32_MAX;

    conn->swnd.time_of_last_ack_eliciting_packet[INITIAL] = 0;
    conn->swnd.time_of_last_ack_eliciting_packet[HANDSHAKE] = 0;
    conn->swnd.time_of_last_ack_eliciting_packet[APPLICATION_DATA] = 0;

    conn->swnd.loss_time[INITIAL] = 0;
    conn->swnd.loss_time[HANDSHAKE] = 0;
    conn->swnd.loss_time[APPLICATION_DATA] = 0;

    conn->rwnd.write_index = 0;
    conn->rwnd.read_index = 0;

    conn->peer_conn_ids = (conn_id *) malloc(sizeof(conn_id));
    conn->local_conn_ids_num = 0;
    conn->peer_conn_ids_num = 0;
    conn->peer_conn_ids_limit = 0;
    conn->handshake_done = false;

    // Saves newly created connection into active connections array
    int i = 0;
    while (i < MAX_CONNECTIONS && connections[i] != NULL)
        i++;
    if (i >= MAX_CONNECTIONS) {
        // Reached connections limit
        print_quic_error("Reached maximum active connection number.");
        free(conn);
        return -1;
    }
    connections[i] = conn;
    return 0;
}

/**
 * @brief Issue a new connection ID for a connection
 *
 * Issue a new connection ID for a connection. IDs generation
 * is accomplished by subsequent increments of the last generated ID,
 * starting from 0. The generated ID is then inserted in the connection's
 * IDs list.
 *
 * If the given connection pointer is NULL, it only checks that the
 * generated ID is (or has been) not yet used by another
 * connection.
 *
 * @param conn the connection requesting a new connection ID
 * @return -1 on errors, 0 otherwise
 */
int issue_new_conn_id(quic_connection *conn) {

    // If the number of IDs has reached its limit for the connection, an error is thrown
    if (conn->local_conn_ids_num > 1 && conn->local_conn_ids_num + 1 > conn->peer_conn_ids_limit) {
        print_quic_error("Connection has reached its connection IDs number limit");
        return -1;
    }

    conn_id generated;
    // Checks whether the generated ID is retired or used by another active connection
    do {
        generated = ++last_generated;
    } while (is_retired(generated) ||
             is_globally_used(generated) ||
             is_internally_used(generated, conn) ||
             generated < UINT64_MAX);

    // If connection IDs generation has achieved its limit, an error is thrown.
    if (generated == UINT64_MAX) {
        print_quic_error("Server has been running for too long: too many connection IDs have been issued."
                         "Please restart.");
        return -1;
    }

    // Assign connection ID to local connection ID pool
    conn->local_conn_ids_num++;
    conn->local_conn_ids[conn->local_conn_ids_num - 1] = generated;
    return 0;
}

/**
 * @brief Checks whether a given connection ID has
 * already been retired or not.
 *
 * Checks whether a given connection ID has
 * already been retired or not, by checking all
 * retired IDs.
 *
 * @param id the connection ID to be checked
 * @return 0 if the ID has not been retired yet,
 * 1 if it has.
 */
int is_retired(const conn_id id) {
    for (int i = 0; i < invalidated_ids_number; i++)
        if (id == invalidated[i])
            return 1;
    return 0;
}

/**
 * @brief Checks whether a given connection ID is
 * being used by another connection or not.
 *
 * Checks whether a given connection ID is
 * being used by another connection, by checking all
 * currently active connections IDs.
 *
 * @param id the connection ID to be checked
 * @return 0 if the ID is not being used,
 * 1 if it has.
 */
int is_globally_used(conn_id id) {
    return multiplex(id) != NULL;
}

/**
 * @brief Checks if a connection ID is used inside a connection
 *
 * @param id
 * @return
 */
int is_internally_used(conn_id id, quic_connection *conn) {
    for (int i = 0; conn != NULL && i < conn->local_conn_ids_num; i++)
        if (id == conn->local_conn_ids[i])
            return 1;
    return 0;
}

/**
 * @brief Finds a connection with data to be sent
 *
 * Iterate with an infinite loop, up to a given timeout,
 * if any of the active connections has data to sent on
 * its window.
 *
 * This function is inspired to Unix select() function.
 *
 * @param wait_time how much time (in seconds)
 * @return          the connection which has data to send, or NULL if the timer expires
 */
quic_connection *select_connection(time_ms wait_time, time_ms *timeout) {
    int i = 0;
    time_ms curr_time;
    if ((curr_time = get_time_millis()) > 0) {
        *timeout = curr_time + wait_time;
        while ((curr_time = get_time_millis()) < *timeout) {
            if (connections[i] != NULL)
                if (count_to_be_sent(&(connections[i]->swnd)) > 0)
                    // There are bytes to be sent on the connection window
                    return connections[i];
            i = (i + 1) % MAX_CONNECTIONS;
        }
    }
    return NULL;
}

/**
 * @brief Finds the connection which an incoming
 * packet belongs to.
 *
 * Compares all active connections' IDs to find the
 * one matching that of the incoming packet, returning
 * the matching connection. If no match is found,
 * NULL is returned.
 *
 * This function also implicitly validated peer's address.
 *
 * @param   id the destination connection ID of the incoming packet
 * @return  the packet matching connection, or NULL if no match is found
 */
quic_connection *multiplex(conn_id id) {
    for (int i = 0; i < active_connections; i++)
        if (is_internally_used(id, connections[i]))
            return connections[i];
    return NULL;
}

/**
 * @brief Enqueues a packet in the connection sender window
 *
 * @param pkt   the packet to be enqueued
 * @param conn  the connection
 * @return      0 on success, -1 on errors
 */
int enqueue(packet *pkt, quic_connection *conn) {
    return put_in_sender_window(&(conn->swnd), pkt);
}

/**
 * @brief Sends as many packets as possible, according
 * to the congestion control limits
 *
 * @param sd    the UDP socket descriptor
 * @param conn  the connection
 * @return      0 on success, -1 on errors
 */
int send_packets(int sd, quic_connection *conn) {
    long send_time;
    packet *pkt;
    int count = 0;
    while (conn->bytes_in_flight < conn->cwnd && count_to_be_sent(&(conn->swnd)) > 0) {
        pkt = get_oldest_not_sent(&(conn->swnd));
        if (pkt->length > conn->max_datagram_size) {
            print_quic_error("Packet is too big to be sent inside a UDP datagram.");
            return -1;
        }
        if (sendto(sd, (char *) pkt->pkt, pkt->length, 0, (struct sockaddr *) &conn->addr, sizeof(conn->addr)) > 0) {
            if ((send_time = get_time_millis()) != -1) {
                pkt->send_time = send_time;
                pkt->in_flight = true;
                count++;
            } else
                return -1;
        } else {
            print_quic_error("Error while sending packet.");
            return -1;
        }
        if (pkt->in_flight) {
            if (pkt->ack_eliciting)
                conn->swnd.time_of_last_ack_eliciting_packet[pkt->space] = send_time;
            on_packet_sent_cc(conn, pkt->length);
        }
    }
    return 0;
}

/**
 * @brief Gets the oldest packet not yet sent in the window
 *
 * @param wnd   the window
 * @return      the oldest packet not sent yet
 */
packet *get_oldest_not_sent(sender_window *wnd) {
    size_t i = wnd->read_index;
    while (i != wnd->write_index) {
        if (wnd->buffer[i]->send_time == 0)
            return wnd->buffer[i];
        i = (i + 1) % BUF_CAPACITY;
    }
    return NULL;
}

/**
 * @brief Increments the number of bytes in flight for a connection
 *
 * @param conn          the connection
 * @param sent_bytes    the bytes sent
 */
void on_packet_sent_cc(quic_connection *conn, size_t sent_bytes) {
    conn->bytes_in_flight += sent_bytes;
}

/**
 * @brief Reads initial packet's transport parameters
 *
 * Reads and parses transport parameters included inside an initial packet
 *
 * @param pkt   the initial packet
 * @param conn  a pointer to the connection struct to which save transport parameters data
 * @param type  the type of the endpoint (eg, server or client), because a server cannot accept some parameters
 * @return      0 on success, -1 on error. Also, on errors the connection must be closed with an error of type TRANSPORT_PARAMETER_ERROR
 */
int read_transport_parameters(initial_packet *pkt, quic_connection *conn, enum peer_type type) {
    for (int i = 0; i < read_var_int_62(pkt->transport_parameters_number); i++) {
        transport_parameter *tp = pkt->transport_parameters[i];
        uint8_t tp_id = tp->id;
        size_t tp_len = tp->len;
        switch (tp_id) {
            case original_destination_connection_id: {
                if (type == SERVER) // Server should not receive this parameter
                    return -1;
            }
            case max_idle_timeout: {
                // TODO check PTO
                uint64_t peer_max_idle_to = read_var_int_62(tp->data);
                conn->max_idle_timeout_ms = MIN(peer_max_idle_to, MAX_IDLE_TIMEOUT_MS);
            }
            case stateless_reset_token: {
                if (type == SERVER) // Server should not receive this parameter
                    return -1;
            }
            case max_udp_payload_size: {
                conn->conn_max_udp_payload_size = read_var_int_62(tp->data);
            }
            case initial_max_data: {
                conn->max_conn_data = read_var_int_62(tp->data);
            }
            case initial_max_streams_bidi: {
                conn->max_streams_bidi = read_var_int_62(tp->data);
                conn->bidi_streams = (stream **) malloc(sizeof(stream *) * conn->max_streams_bidi);
            }
            case initial_max_streams_uni: {
                conn->max_streams_uni = read_var_int_62(tp->data);
                conn->uni_streams = (stream **) malloc(sizeof(stream *) * conn->max_streams_uni);
            }
            case ack_delay_exponent: {
                uint64_t exp = read_var_int_62(tp->data);
                conn->ack_delay_exp = exp > 20 ? 3 : exp;
            }
            case max_ack_delay: {
                uint64_t delay = read_var_int_62(tp->data);
                conn->ack_delay_exp = delay > MAX_ACK_DELAY ? 25 : delay;
            }
            case disable_active_migration: {
            }
            case preferred_address: {
                if (type == SERVER) // Server should not receive this parameter
                    return -1;
            }
            case active_connection_id_limit: {
                uint64_t limit = read_var_int_62(tp->data);
                if (limit < 2)  // Error, must close connection with TRANSPORT_PARAMETER_ERROR
                    return -1;
                conn->active_conn_id_limit = limit;
            }
            case initial_source_connection_id: {
            }
            case retry_source_connection_id: {
                if (type == SERVER) // Server should not receive this parameter
                    return -1;
            }
            default: {
                print_quic_error("Unsupported transport parameter");
            }
        }
    }
    return 0;
}

/**
 * Executes congestion control operations
 * after a congestion event
 *
 * @param send_time the packet send time
 */
void on_congestion_event(quic_connection *conn, time_ms send_time) {
    // No operations in recovery period
    if (in_cong_recovery_state(conn, send_time))
        return;

    // Enter recovery period
    conn->recovery_start_time = time(NULL);
    conn->ssthresh = (size_t) ((float) conn->cwnd * kLOSS_REDUCTION_FACTOR);
    conn->cwnd = MAX(conn->ssthresh, kMIN_WND);
}

/**
 * @brief Updates connection RTT-related values.
 *
 * Please refer to <a href="https://www.rfc-editor.org/rfc/rfc9002.html#name-estimating-the-round-trip-t">Estimating the Round-Trip Time</a>
 *
 * @param ack_time      ACK arrival time
 * @param ack_delay     time elapsed between largest acknowledged packet send time and ack_time
 * @param largest_acked the packet number of the largest packet acknowledged
 * @param conn          the QUICLite connection
 * @return
 */
void update_rtt(quic_connection *conn, time_ms ack_delay) {
    if (conn->first_rtt_sample == 0) {
        conn->min_rtt = conn->latest_rtt;
        conn->smoothed_rtt = conn->latest_rtt;
        conn->rtt_var = conn->latest_rtt / 2;
        conn->first_rtt_sample = get_time_millis();
        return;
    }

    // min_rtt ignores acknowledgment delay.
    conn->min_rtt = MIN(conn->min_rtt, conn->latest_rtt);
    // Limit ack_delay by max_ack_delay after handshake confirmation
    if (conn->handshake_done)
        ack_delay = MIN(ack_delay, max_ack_delay);

    // Adjust for acknowledgment delay if plausible.
    time_ms adjusted_rtt = conn->latest_rtt;
    if (conn->latest_rtt >= conn->min_rtt + ack_delay)
        adjusted_rtt = conn->latest_rtt - ack_delay;

    time_ms diff =
            conn->smoothed_rtt > adjusted_rtt ? conn->smoothed_rtt - adjusted_rtt : adjusted_rtt - conn->smoothed_rtt;
    conn->rtt_var = 3 * (conn->rtt_var >> 2) + (diff >> 2);
    conn->smoothed_rtt = 7 * (conn->smoothed_rtt >> 3) + (adjusted_rtt >> 3);
}

/**
 * @brief Check recovery state
 *
 * Checks whether the current congestion control mechanism
 * is in recovery state or not
 *
 * @param send_time the packet send time
 * @return          1 if in recovery state, 0 if not
 */
int in_cong_recovery_state(const quic_connection *conn, time_ms send_time) {
    if (send_time <= conn->recovery_start_time)
        return 1;
    return 0;
}

/**
 * @brief Gets the earliest loss time on a connection
 *
 * @param conn      the connection
 * @param num_space a return-value argument, containing the packet space
 * @return          the earliest loss time on the connection
 */
time_ms get_loss_time(quic_connection *conn, num_space *space) {
    sender_window wnd = conn->swnd;
    time_ms min;
    time_ms init = wnd.loss_time[INITIAL];
    min = init;
    *space = INITIAL;
    time_ms appl = wnd.loss_time[APPLICATION_DATA];
    if (min == 0 || appl < min) {
        min = appl;
        *space = APPLICATION_DATA;
    }
    return min;
}

/**
 *
 * @param conn
 * @return
 */
time_ms get_pto_time(quic_connection *conn, num_space *space) {
    time_ms duration = (conn->smoothed_rtt + MAX(4 * conn->rtt_var, kGRANULARITY)) * (time_t) pow(2, conn->pto_count);
    // Anti-deadlock PTO starts from the current time
    if (!in_flight_ack_eliciting(&(conn->swnd)) && conn->handshake_done) {
        *space = INITIAL;
        return time(NULL) + duration;
    }
    time_ms pto_timeout = (time_t) -1;
    num_space pto_space = INITIAL;
    num_space spaces[] = {INITIAL, APPLICATION_DATA};
    time_ms t;
    for (int i = 0; i < 2; i++) {
        if (!in_flight_ack_eliciting_in_space(&(conn->swnd), spaces[i]))
            continue;
        if (i == 1) {
            // Skip Application Data until handshake confirmed.
            if (!conn->handshake_done) {
                *space = pto_space;
                return pto_timeout;
            }
            // Include conn_max_ack_delay and backoff for Application Data.
            duration += conn->conn_max_ack_delay + (time_t) pow(2, conn->pto_count);
        }
        t = conn->swnd.time_of_last_ack_eliciting_packet[spaces[i]] + duration;
        if (t < pto_timeout) {
            pto_timeout = t;
            pto_space = spaces[i];
        }
    }
    *space = pto_space;
    return pto_timeout;
}

void set_loss_detection_timer(quic_connection *conn) {
    num_space space;
    time_ms earliest_loss_time = get_loss_time(conn, &space);
    if (earliest_loss_time != 0) {
        // Time threshold loss detection
        conn->loss_timer.timeout = earliest_loss_time;
        return;
    }

    if (!conn->is_in_anti_amplification_limit) {
        // Server timer not set if nothing can be sent
        conn->loss_timer.start = 0;
        return;
    }

    if (!in_flight_ack_eliciting(&(conn->swnd)) && conn->handshake_done) {
        // There is nothing to detect lost, so no timer is set.
        // However, the client needs to arm the timer if the
        // server might be blocked by the anti-amplification limit.
        conn->loss_timer.start = 0;
    }

    conn->loss_timer.timeout = get_pto_time(conn, &space);
}

/**
 * Executes actions when loss detection timer expires
 *
 * @param conn  the connection
 */
void on_loss_detection_timeout(quic_connection *conn) {
    num_space space;
    time_ms earlier_lost_time = get_loss_time(conn, &space);
    if (earlier_lost_time != 0) {
        // Time threshold lost detection
        packet **lost_packets = (packet **) malloc(BUF_CAPACITY * sizeof(packet *));
        detect_and_remove_lost_packets(conn, space, lost_packets);
        // todo assert not empty & onpacketslost
        set_loss_detection_timer(conn);
        return;
    }

    if (!in_flight_ack_eliciting(&(conn->swnd)) && !conn->handshake_done) {
        // Client sends an anti-deadlock packet: Initial is padded
        // to earn more anti-amplification credit.
        // todo SendOneAckElicitingPaddedInitialPacket()
    } else {
        get_pto_time(conn, &space);
        // todo SendOneOrTwoAckElicitingPackets(pn_space)
    }

    conn->pto_count++;
    set_loss_detection_timer(conn);
}

/**
 * @brief Detects and remove lost packet in a certain space from the sender window
 *
 * @param conn          the connection
 * @param space         the packet number space
 * @param lost_packets  a return-value argument containing the lost packets
 * @return              the number of lost packet, or -1 on errors
 */
int detect_and_remove_lost_packets(quic_connection *conn, num_space space, packet *lost_packets[BUF_CAPACITY]) {
    if (conn->swnd.largest_acked[space] != UINT32_MAX) {
        conn->swnd.loss_time[space] = 0;
        int j = 0;
        time_ms loss_delay = kTIME_THRESH * MAX(conn->latest_rtt, conn->smoothed_rtt);

        // Minimum time of kGranularity before packets are deemed lost.
        loss_delay = MAX(loss_delay, kGRANULARITY);

        // Packets sent before this time are deemed lost.
        time_ms curr_time;
        if ((curr_time = get_time_millis()) < 0)
            return -1;
        time_ms lost_send_time = curr_time - loss_delay;

        size_t i = conn->swnd.read_index;
        packet *pkt;
        while (i != conn->swnd.write_index) {
            pkt = conn->swnd.buffer[i];
            if (!pkt->acked && pkt->space == space) {
                if (pkt->pkt_num > conn->swnd.largest_acked[space])
                    continue;
                // Mark packet as lost, or set time when it should be marked.
                // Note: The use of kPacketThreshold here assumes that there
                // were no sender-induced gaps in the packet number space.
                if (pkt->send_time <= lost_send_time ||
                    conn->swnd.largest_acked[space] >= pkt->pkt_num + kPACKET_THRESH) {
                    pkt->lost = true;
                    lost_packets[j] = pkt;
                    j++;
                    if (enqueue(pkt, conn) != 0)
                        print_quic_error("Error while re-enqueuing lost packet.");
                } else {
                    if (conn->swnd.loss_time[space] == 0)
                        conn->swnd.loss_time[space] = pkt->send_time + loss_delay;
                    else
                        conn->swnd.loss_time[space] = MIN(conn->swnd.loss_time[space], pkt->send_time + loss_delay);
                }
            }
            i = (i + 1) % BUF_CAPACITY;
        }
        return j;
    }
    return -1;
}

/**
 * @brief Detects and removes acknowledged packet from the sender window
 *
 * @param conn          the connection
 * @param space         the packet number space
 * @param largest_acked the newly largest acked packet (result-value parameter)
 * @return              0 if the newly acked packet did not include an ack-eliciting packet, 1 otherwise
 */
int detect_and_remove_acked_packets(quic_connection *conn, num_space space, packet *largest_acked) {
    size_t i = conn->swnd.read_index;
    int ack_eliciting = 0;
    packet *pkt;
    while (i != conn->swnd.write_index) {
        pkt = conn->swnd.buffer[i];
        if (pkt->space == space)
            if (pkt->ack_eliciting)
                ack_eliciting = 1;
        i = (i + 1) % BUF_CAPACITY;
    }
    *largest_acked = *get_largest_acked_in_space(&(conn->swnd), space);
    return ack_eliciting;
}

/**
 * Executes operations after an ACK frame reception
 *
 * @param conn  the connection to which the frame is arrived
 * @param ack   the ack frame
 * @param space the number space of the packet containing the ACK frame
 * @return
 */
int on_ack_received(quic_connection *conn, ack_frame *ack, num_space space, time_ms ack_time) {
    if (conn->swnd.largest_acked[space] == UINT64_MAX)
        conn->swnd.largest_acked[space] = ack->largest_acked;
    else
        conn->swnd.largest_acked[space] = MAX(conn->swnd.largest_acked[space], ack->largest_acked);

    packet largest_acked;
    int ack_eliciting = detect_and_remove_acked_packets(conn, space, &largest_acked);
    if (ack_eliciting == 1 && largest_acked.pkt_num == ack->largest_acked) {
        struct timespec now;
        if (get_time(&now) == -1)
            return -1;
        update_rtt(conn, ack->ack_delay);
    }

    packet *lost_packets[BUF_CAPACITY];
    detect_and_remove_lost_packets(conn, space, lost_packets);
    // TODO on packet lost on every lost packet

    if (conn->handshake_done)
        conn->pto_count = 0;
    set_loss_detection_timer(conn);
}

/**
 * @brief Execute actions after a packer loss
 * @param conn
 * @param num
 * @param lost_packets
 * @return
 */
int on_packet_loss(quic_connection *conn, size_t num, packet *lost_packets[BUF_CAPACITY]) {
    time_ms sent_time_of_last_loss = 0;
    packet *pkt;
    // Remove lost packets from bytes_in_flight
    for (size_t i = 0; i < num; i++) {
        pkt = lost_packets[i];
        if (pkt->in_flight) {
            conn->bytes_in_flight -= pkt->length;
            sent_time_of_last_loss = MAX(sent_time_of_last_loss, pkt->send_time);
        }
    }
    // Congestion event if in-flight packets were lost
    if (sent_time_of_last_loss != 0)
        on_congestion_event(conn, sent_time_of_last_loss);

    // Reset the congestion window if the loss of these
    // packets indicates persistent congestion.
    // Only consider packets sent after getting an RTT sample.
    if (conn->first_rtt_sample == 0)
        return 0;
    /*
     * pc_lost = []
for lost in lost_packets:
if lost.time_sent > first_rtt_sample:
pc_lost.insert(lost)
if (InPersistentCongestion(pc_lost)):
congestion_window = kMinimumWindow
congestion_recovery_start_time = 0
     */
    return 0;
}

/**
 * @brief Close a connection with an error code
 *
 * Immediately sends a
 *
 * @param fd            the socket file descriptor
 * @param conn          the connection to be closed
 * @param error_code    the error code
 * @param msg           the error reason
 * @return              0 on success, -1 on errors
 */
int close_connection_with_error_code(int fd, conn_id dest_conn_id, conn_id src_conn_id, quic_connection *conn,
                                     uint64_t error_code, char *msg) {
    char *stream_buf = (char *) calloc(1, strlen(msg) +
                                          bytes_needed(strlen(msg)) +
                                          bytes_needed(0x1c) +
                                          bytes_needed(error_code) + 1);
    new_close_connection_frame(error_code, msg, stream_buf);
    socklen_t len = sizeof(conn->addr);
    if (!conn->handshake_done) {
        // Handshake phase, send frame in Initial packet
        initial_packet pkt;
        build_initial_packet(dest_conn_id, src_conn_id, write_var_int_62(0), NULL, write_var_int_62(strlen(stream_buf)),
                             write_var_int_62(0), stream_buf, &pkt);
        set_pkt_num((void *) &pkt, 1);
        size_t initial_len = initial_pkt_len(&pkt);
        char *buf = (char *) malloc(initial_len);
        write_packet_to_buf(buf, initial_len, (void *) &pkt);
        if (sendto(fd, buf, initial_len, 0, (struct sockaddr *) &conn->addr, len) != 0) {
            print_quic_error("Error while closing connection during handshake phase.");
            return -1;
        }
        // Deallocates used memory
        free(pkt.length);
        free(pkt.token_len);
        free(pkt.transport_parameters_number);
        free(buf);
        return 0;
    } else {
        // Handshake done, send frame in 1-RTT packet
        one_rtt_packet pkt;
        build_one_rtt_packet(dest_conn_id, strlen(stream_buf), (void *) stream_buf, &pkt);
        pkt_num largest = get_largest_in_space(&(conn->swnd), APPLICATION_DATA)->pkt_num + 1;
        set_pkt_num(&pkt, largest);
        size_t one_rtt_len = one_rtt_pkt_len(&pkt);
        char *buf = (char *) malloc(one_rtt_len);
        write_packet_to_buf(buf, one_rtt_len, &pkt);
        if (sendto(fd, buf, one_rtt_len, 0, (struct sockaddr *) &conn->addr, len) != 0) {
            print_quic_error("Error while closing connection");
            return -1;
        }
        // Deallocates used memory
        free(buf);
        return 0;
    }
    free(stream_buf);
    return 0;
}

/**
 * @brief Frees a connection memory space
 * @param conn  the connection
 */
void free_conn(quic_connection *conn) {
    free(conn->peer_conn_ids);
    int i;
    for (i = 0; i < conn->bidi_streams_num; i++)
        free(conn->bidi_streams[i]);
    for (i = 0; i < conn->uni_streams_num; i++)
        free(conn->uni_streams[i]);
    free(conn->bidi_streams);
    free(conn->uni_streams);
    free(conn);
}

/**
 * @brief Saves a stream to a connection
 *
 * @param conn  the connection to which save the stream
 * @param str   the stream to be saved
 * @return      0 on success, -1 on errors
 */
int save_stream_to_conn(quic_connection *conn, stream *str) {
    switch (str->mode) {
        case UNIDIRECTIONAL: {
            if (conn->uni_streams_num == conn->max_streams_uni) {
                print_quic_error("Cannot open another unidirectional stream: limit reached.");
                return -1;
            }
            conn->uni_streams[conn->uni_streams_num] = str;
            conn->uni_streams_num++;
            break;
        }
        case BIDIRECTIONAL: {
            if (conn->bidi_streams_num == conn->max_streams_bidi) {
                print_quic_error("Cannot open another unidirectional stream: limit reached.");
                return -1;
            }
            conn->bidi_streams[conn->bidi_streams_num] = str;
            conn->bidi_streams_num++;
            break;
        }
    }
    return 0;
}
