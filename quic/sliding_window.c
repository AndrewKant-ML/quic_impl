//
// Created by andrea on 17/09/23.
//

#include "quic_conn.h"
#include "quic_errors.h"

/**
 * @brief Acknowledges a packet number range
 *
 * Checks if the buffer is empty. If not, marks
 * packets with number from star to end as acked.
 *
 * @param conn   the sending window
 * @param start the first packet number to be acked
 * @param end   the last packet number to be acked
 * @param space the packet number space
 * @return      0 on success, -1 on errors
 */
int ack_pkt_range(quic_connection *conn, pkt_num start, pkt_num end, num_space space) {

    // Start must be lower than or equal to end
    if (start > end) {
        log_quic_error("Start packet number cannot be greater than end packet number.");
        return -1;
    }

    // Neither start nor end indexes can refer to an already-acked packet
    pkt_num first_pkt_num = conn->swnd->buffer[conn->swnd->read_index]->pkt_num;
    if (start < first_pkt_num) {
        if (end < first_pkt_num)
            // Acknowledging already-acked packets, not a problem
            return 0;
        else
            // Moves start index forward to ack_pkt_range packets up to end index
            start = first_pkt_num;
    }

    // Checks if buffer is empty
    if (conn->swnd->write_index == conn->swnd->read_index) {
        log_quic_error("Window buffer is empty.");
        return -1;
    }

    // Search first and last packets indexes to ack_pkt_range
    // Finding last index is necessary to prevent
    // acknowledging other packets
    ssize_t start_index = -1;
    ssize_t end_index = -1;
    ssize_t i = (long) conn->swnd->read_index;
    while ((i % BUF_CAPACITY) != conn->swnd->write_index) {
        if (conn->swnd->buffer[i]->pkt_num == start && conn->swnd->buffer[i]->space == space)
            start_index = i;
        if (conn->swnd->buffer[i]->pkt_num == end && conn->swnd->buffer[i]->space == space)
            end_index = i;
        i++;
    }

    // Start packet number not found
    if (start_index == -1) {
        log_quic_error("Could not find start packet number.");
        return -1;
    }

    // End packet number not found
    if (end_index == -1) {
        log_quic_error("Could not find end packet number.");
        return -1;
    }

    // Marks packet from start to end as acked
    // and updates last byte acked index.
    // Adjusts congestion control window size too
    i = start_index;
    while (i <= end_index) {
        conn->swnd->buffer[i]->acked = 1;
        conn->bytes_in_flight -= conn->swnd->buffer[i]->length;

        // Do not increase cwnd if in recovery state
        if (!conn->swnd->buffer[i]->in_flight &&
            !in_cong_recovery_state(conn, conn->swnd->buffer[i]->send_time)) {
            if (conn->cwnd < conn->ssthresh)
                // Slow start state
                conn->cwnd += conn->swnd->buffer[i]->length;
            else
                // Congestion avoidance
                conn->cwnd += MAX_DATAGRAM_SIZE * conn->swnd->buffer[i]->length / conn->cwnd;
        }
        i++;
    }

    // Updates read index if packet are acked from the beginning
    if (start_index == conn->swnd->read_index)
        conn->swnd->read_index = (end_index + 1) % BUF_CAPACITY;
    return 0;
}

/**
 * @brief Finds the oldest packet to be declared lost
 *
 * @param wnd
 * @param threshold
 * @param pkt_num
 * @return
 *//*
int get_first_lost(sender_window *wnd, time_t threshold, num_space space, const pkt_num *pkt_num) {
    size_t i = wnd->read_index;
    do {
        // A packet can be declared lost if it is unacknowledged,
        // in flight, and was sent prior to an acknowledged packet
        packet *pkt = wnd->buffer[i];
        if (pkt->send_time != 0 && pkt->acked == 0 && is_lost(wnd, pkt, i, threshold) == 1) {
            // Packet is declared lost
        }
        i = (i + 1) % BUF_CAPACITY;
    } while (i != wnd->write_index);
}*/

/**
 * @brief Checks if there are any acknowledged packets after a given one
 *
 * @param wnd       the sliding window
 * @param pkt_num   the packet number to check
 * @return          1 if there are packets, 0 otherwise
 *//*
int is_lost(sender_window *wnd, packet *pkt, size_t start_index, time_t threshold) {
    size_t i = start_index;
    time_t current_time = time(NULL);
    do {
        // Checks if the packet is lost
        if (wnd->buffer[i]->pkt_num >= pkt->send_time + kPACKET_THRESH &&
            wnd->buffer[i]->acked == 1 &&
            (wnd->buffer[i]->space == pkt->space ||
             pkt->send_time <= current_time - threshold))
            return 1;
        i = (i + 1) % BUF_CAPACITY;
    } while (i != wnd->write_index);
    return 0;
}*/

/**
 * @brief Counts the packets to be sent on a window
 *
 * @param wnd   the sliding window to be checked
 * @return      the number of the packets to be sent (0 if none)
 */
size_t count_to_be_sent(sender_window *wnd) {
    if (wnd->read_index == wnd->write_index) {
        // Buffer is empty
        return 0;
    }

    size_t count = 0, i = wnd->read_index;
    outgoing_packet *pkt = wnd->buffer[i];
    while (i != wnd->write_index) {
        if (pkt->send_time == 0 &&
            !(pkt->in_flight ||
              pkt->acked ||
              pkt->lost))
            count++;
        i = (i + 1) % BUF_CAPACITY;
        pkt = wnd->buffer[i];
    }
    return count;
}

/**
 * @brief Gets a packet from the window
 *
 * @param wnd   the sliding window
 * @param pkt   the packet number
 * @param space the packet number space
 * @return      a pointer to the packet with the given packet number,
 *              NULL if the packet has not been found
 */
outgoing_packet *get_pkt_num_in_space(const sender_window *wnd, pkt_num pkt_num, num_space space) {
    size_t i = wnd->read_index;
    while (i != wnd->write_index) {
        if (wnd->buffer[i]->pkt_num == pkt_num && wnd->buffer[i]->space == space)
            return wnd->buffer[i];
    }
    return NULL;
}

/**
 * @brief Gets the largest packet number of processed packets
 * @param wnd   the packet window
 * @param space the packet number space
 * @return      the packet number found, or (pkt_num) -1 if not found
 */
outgoing_packet *get_largest_in_space(const sender_window *wnd, num_space space) {
    size_t i = (wnd->write_index - 1) % BUF_CAPACITY;
    while (i != wnd->read_index) {
        if (wnd->buffer[i]->space == space)
            return wnd->buffer[i];
        i = (i - 1) % BUF_CAPACITY;
    }
    return NULL;
}

/**
 * @brief Gets the largest packet number in a space
 * @param wnd   the packet window
 * @param space the packet number space
 * @return      the largest acknowledged packet number in the space
 */
outgoing_packet *get_largest_acked_in_space(const sender_window *wnd, num_space space) {
    size_t i = (wnd->write_index - 1) % BUF_CAPACITY;
    while (i != (wnd->read_index - 1) % BUF_CAPACITY) {
        if (wnd->buffer[i]->space == space)
            return wnd->buffer[i];
        i = (i - 1) % BUF_CAPACITY;
    }
    return NULL;
}

/**
 * @brief Puts a packet in the sender window
 *
 * Insert a packet into the sender window, if
 * this is not full.
 *
 * @param wnd   the sender window
 * @param pkt   the packet to be inserted
 * @return      0 on success, -1 on errors
 */
int put_in_sender_window(sender_window *wnd, outgoing_packet *pkt) {
    if ((wnd->write_index + 1) % BUF_CAPACITY == wnd->read_index) {
        log_quic_error("Buffer is full.");
        return -1;
    }
    wnd->buffer[wnd->write_index] = pkt;
    wnd->write_index = (wnd->write_index + 1) % BUF_CAPACITY;
    return 0;
}

/**
 * @brief Gets the send time of an packet in a number space
 *
 * Gets the send time of a packet with a given
 * packet number in a given number space. If the
 * packet has already been sent, returns 0.
 *
 * @param wnd       the sliding window where the packet is
 * @param pkt_num   the packet number
 * @return          0 is the packet has already been sent, otherwise its send time
 */
time_ms send_time_in_space(const sender_window *wnd, pkt_num pkt_num, num_space space) {
    size_t i = wnd->read_index;
    while (i != wnd->write_index) {
        if (wnd->buffer[i]->pkt_num == pkt_num && wnd->buffer[i]->space == space)
            return wnd->buffer[i]->send_time;
        i = (i + 1) % BUF_CAPACITY;
    }
    return 0;
}

/**
 * @brief Gets the send time of an packet
 *
 * Gets the send time of a packet with a given
 * packet number. If the packet has already been sent,
 * returns 0.
 *
 * @param wnd       the sliding window where the packet is
 * @param pkt_num   the packet number
 * @return          0 is the packet has already been sent, otherwise its send time
 */
time_ms send_time(const sender_window *wnd, pkt_num pkt_num) {
    size_t i = wnd->read_index;
    while (i != wnd->write_index) {
        if (wnd->buffer[i]->pkt_num == pkt_num)
            return wnd->buffer[i]->send_time;
        i = (i + 1) % BUF_CAPACITY;
    }
    return 0;
}

/**
 * @brief Checks whether there are ack-eliciting packets in flight or not
 *
 * @param wnd   the sliding window
 * @return      true if there are ack-eliciting packets in flight, false otherwise
 */
bool in_flight_ack_eliciting(sender_window *wnd) {
    outgoing_packet *pkt;
    size_t i = wnd->read_index;
    while (i != wnd->write_index) {
        pkt = wnd->buffer[i];
        if (pkt->in_flight && pkt->ack_eliciting)
            return true;
        i = (i + 1) % BUF_CAPACITY;
    }
    return false;
}

/**
 * @brief
 *
 * @param wnd
 * @param space
 * @return
 */
bool in_flight_ack_eliciting_in_space(sender_window *wnd, num_space space) {
    outgoing_packet *pkt;
    size_t i = wnd->read_index;
    while (i != wnd->write_index) {
        pkt = wnd->buffer[i];
        if (pkt->space == space && pkt->in_flight && pkt->ack_eliciting)
            return true;
        i = (i + 1) % BUF_CAPACITY;
    }
    return false;
}

/**
 * @brief Inserts an incoming inside a receiver window
 *
 * @param wnd       the receiver window
 * @param pkt       the incoming packet to put inside the receiver window
 * @return      0 on success, -1 on errors
 */
int put_in_receiver_window(receiver_window *wnd, incoming_packet *pkt) {
    if ((wnd->write_index + 1) % BUF_CAPACITY == wnd->read_index) {
        log_quic_error("Buffer is full.");
        return -1;
    }
    wnd->buffer[wnd->write_index] = pkt;
    wnd->write_index = (wnd->write_index + 1) % BUF_CAPACITY;
    return 0;

    // Checks if packet is already present in the window
    /*transfert_msg *old_msg;
    if ((old_msg = is_message_in_wnd(wnd, msg)) == NULL) {
        // Insert new message in window
        wnd->buffer[wnd->write_index] = msg;
        wnd->write_index = (wnd->write_index + 1) % BUF_CAPACITY;
        return 0;
    } else {
        // Marks end reached if needed
        if (msg->end_reached)
            old_msg->end_reached = true;
        // Puts message data to the existing one in the window, at a given offset
        if (offset < old_msg->len - 1) {
            // No need to reallocate new memory (assuming incoming data will not overlap)
            // Just copies bytes, do not rewrite null-terminating byte (\0)
            memcpy(old_msg->msg + offset, msg->msg, strlen(msg->msg));
        } else {
            // Writing after the string end, reallocating memory.
            // New size is computed from the end of the older message,
            // the added offset and the new message length
            size_t new_size = offset + msg->len;
            void *p = realloc(old_msg->msg, new_size);
            if (p == NULL) {
                log_quic_error("Error while reallocating message");
                return -1;
            }
            strcpy(old_msg->msg + offset, msg->msg);
            old_msg->len = new_size;
        }
        return 0;
    }*/
}

/**
 * @brief Counts how many packets have to be
 *          precessed inside the receiver window
 *
 * @param rwnd  the receiver window
 * @return      the number of packets to be processed on the window
 */
size_t count_to_be_processed(receiver_window *rwnd) {
    if (rwnd->read_index == rwnd->write_index) {
        // Buffer is empty
        return 0;
    }
    size_t i = rwnd->read_index, count = 0;
    while (i != (rwnd->write_index - 1) % BUF_CAPACITY) {
        count++;
        i = (i + 1) % BUF_CAPACITY;
    }
    return count;
}

/**
 * @brief Checks if a message is already inside the receiver window
 *
 * Checks message stream ID and offset to check if it was
 * already inserted inside a receiver window.
 *
 * @param wnd   the receiver window
 * @param msg   the transfert message
 * @return      true if the message was already inserted, false otherwise
 */
/*transfert_msg *is_message_in_wnd(receiver_window *wnd, transfert_msg *msg) {
    size_t i = wnd->read_index;
    while (i != wnd->write_index) {
        if (wnd->buffer[i]->stream_id == msg->stream_id)
            return wnd->buffer[i];
        i = (i + 1) % BUF_CAPACITY;
    }
    return NULL;
}*/

/**
 * @brief Gets the last inserted transfert_msg in the receiver window
 *
 * @param wnd   the receiver window
 * @param res   the result transfert_msg
 * @return      0 on success, if the window is empty
 */
int get_last_from_receiver_window(receiver_window *wnd, incoming_packet *res) {
    if (wnd->read_index == wnd->write_index)
        // Buffer is empty
        return -1;
    *res = *wnd->buffer[wnd->write_index];
    return 0;
}
