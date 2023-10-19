//
// Created by andrea on 05/09/23.
//

#include "packets.h"

/**
 * @brief Processes a datagram payload
 *
 * @param dgram     the datagram payload to be processed
 * @param len       the datagram payload length
 * @param peer      the type of peer processing the payload (client or server)
 * @return          0 on success, -1 on errors
 */
ssize_t
process_incoming_dgram(char *dgram, size_t len, enum PeerType peer, struct sockaddr_in *addr, time_ms rcv_time,
                       int (*on_new_conn_req)(initial_packet *, struct sockaddr_in *, time_ms)) {
    size_t read = 0;
    ssize_t parsed_packets = 0;
    while (read < len) {
        uint8_t first_byte = *(uint8_t *) dgram;

        // Header type and fixed bit check
        uint8_t pkt_type = first_byte & PACKET_HEADER_MASK;
        if (pkt_type == LONG_HEADER_FORM) {
            // Long header version check
            long_header_pkt *long_pkt = (long_header_pkt *) calloc(1, sizeof(long_header_pkt));
            long_pkt->first_byte = first_byte;
            size_t pkt_off = 1;
            long_pkt->version = (uint32_t) read_var_int_62((varint *) &dgram[read + pkt_off]);
            pkt_off += bytes_needed(long_pkt->version);
            long_pkt->dest_conn_id = (uint32_t) read_var_int_62((varint *) &dgram[read + pkt_off]);
            pkt_off += bytes_needed(long_pkt->dest_conn_id);
            long_pkt->src_conn_id = (uint32_t) read_var_int_62((varint *) &dgram[read + pkt_off]);
            pkt_off += bytes_needed(long_pkt->src_conn_id);
            long_pkt->payload = &dgram[read + pkt_off];
            if (long_pkt->version != VERSION) {
                log_quic_error(
                        "Incoming long header packet version number mismatch current protocol version. Sending version negotiation packet.");
                // TODO send version negotiation
            }
            quic_connection *conn = multiplex(long_pkt->dest_conn_id);

            incoming_packet *pkt = (incoming_packet *) calloc(1, sizeof(incoming_packet));

            // Long header packet type check
            pkt_type = pkt_type & TYPE_SPECIFIC_BITS_MASK;
            switch (pkt_type) {
                case PACKET_TYPE_INITIAL: {
                    initial_packet *initial_pkt = (initial_packet *) calloc(1, sizeof(initial_packet));
                    if (read_initial_packet(long_pkt, initial_pkt) == 0) {
                        if (conn == NULL) {
                            // New connection request
                            if (peer == CLIENT) {
                                // Client cannot accept incoming connection request
                                log_quic_error("Client cannot accept incoming connection request");
                                return -1;
                            } else if (parsed_packets == 0) {
                                // If the datagram did not include other packets
                                // before this Initial, must open a new connection
                                if ((*on_new_conn_req)(initial_pkt, addr, rcv_time) == 0) {
                                    log_msg("Successfully processed new connection request");
                                    // Return because client must not send other
                                    // packet together with the first Initial one
                                    parsed_packets++;
                                    read += initial_pkt_len(initial_pkt);
                                    free(long_pkt);
                                    break;
                                } else {
                                    log_quic_error("Error while processing new connection request");
                                    return -1;
                                }
                            }
                        } else {
                            if (peer == CLIENT) {
                                conn->peer_conn_ids[0] = long_pkt->src_conn_id;
                                conn->peer_conn_ids_num++;
                            }
                            // Already-opened connection, enqueue packet in receiver window
                            pkt->pkt_type = TYPE_INITIAL;
                            pkt->pkt_num = initial_pkt->packet_number;
                            pkt->pkt = (void *) initial_pkt;
                            if (put_in_receiver_window(conn->rwnd, pkt) == 0) {
                                //log_msg("Initial packet inserted inside receiver window");
                                read += initial_pkt_len(initial_pkt);
                                parsed_packets++;
                            } else {
                                // Receiver window is full, cannot insert packet
                                log_quic_error("Error while inserting Initial packet inside receiver window");
                                return -1;
                            }
                        }
                    } else {
                        log_quic_error("Error while parsing Initial packet");
                        return -1;
                    }
                    free(long_pkt);
                    break;
                }
                case PACKET_TYPE_RETRY: {

                }
                case PACKET_TYPE_0_RTT: {

                }
                default: {
                    log_quic_error("Unsupported packet type");
                    return -1;
                }
            }
        } else if (pkt_type == SHORT_HEADER_FORM) {
            one_rtt_packet *one_rtt = (one_rtt_packet *) calloc(1, sizeof(one_rtt_packet));
            if (read_one_rtt_packet(dgram + read, one_rtt) == 0) {
                quic_connection *conn = multiplex(one_rtt->dest_connection_id);
                incoming_packet *pkt = (incoming_packet *) calloc(1, sizeof(incoming_packet));
                pkt->pkt_type = TYPE_ONE_RTT;
                pkt->pkt_num = one_rtt->packet_number;
                pkt->pkt = (void *) one_rtt;
                if (put_in_receiver_window(conn->rwnd, pkt) == 0) {
                    parsed_packets++;
                    read += one_rtt->length;
                }
            } else {
                log_quic_error("Error while reading 1-RTT packet");
            }
        } else {
            // Fixed bit must always be set to 1
            log_quic_error("Fixed bit is not set to 1");
            return -1;
        }
    }
    return parsed_packets;
}

/**
 * @brief Processes received packets
 *
 * Processes all the packets in the connection receiver window
 *
 * @param conn  the QUICLite connection
 * @return      the processed packets number on success, -1 on errors
 */
ssize_t process_received_packets(quic_connection *conn) {
    size_t i = conn->rwnd->read_index;
    ssize_t processed = 0;
    incoming_packet *pkt;
    while (i != conn->rwnd->write_index) {
        pkt = conn->rwnd->buffer[i];
        switch (pkt->pkt_type) {
            case TYPE_INITIAL: {
                initial_packet *initial = (initial_packet *) pkt->pkt;
                if (process_packet_payload(initial->payload, initial->packet_number, initial->length, INITIAL, conn) ==
                    0) {
                    if (read_transport_parameters(initial, conn, conn->peer_type) == 0) {
                        log_msg("Successfully processed Initial packet payload");
                        processed++;
                        conn->rwnd->read_index += (conn->rwnd->read_index + 1) % BUF_CAPACITY;
                    } else
                        log_quic_error("Error while processing transport parameters");
                    break;
                } else
                    log_quic_error("Error while processing Initial packet payload");
                break;
            }
            case TYPE_RETRY:
                break;
            case TYPE_ZERO_RTT:
                break;
            case TYPE_ONE_RTT: {
                one_rtt_packet *one_rtt = (one_rtt_packet *) pkt->pkt;
                if (process_packet_payload(one_rtt->payload, one_rtt->packet_number, one_rtt->length, APPLICATION_DATA,
                                           conn) == 0) {
                    log_msg("Successfully processed 1-RTT packet payload");
                    processed++;
                    conn->rwnd->read_index++;
                } else
                    log_quic_error("Error while processing 1-RTT packet payload");
                break;
            }
            default: {
                log_quic_error("Unrecognized packet type");
                return -1;
            }
        }
        i = (i + 1) % BUF_CAPACITY;
    }
    return processed;
}

void build_initial_packet(conn_id dest_conn_id, conn_id src_conn_id, size_t length,
                          size_t transport_parameters_number, void *payload, pkt_num pkt_num,
                          initial_packet *pkt) {
    pkt->first_byte = LONG_HEADER_FORM | PACKET_TYPE_INITIAL;
    pkt->first_byte |= (uint8_t) log2((double) bytes_needed(pkt_num));
    pkt->version = VERSION;
    pkt->dest_conn_id = dest_conn_id;
    pkt->src_conn_id = src_conn_id;
    pkt->packet_number = pkt_num;
    pkt->transport_parameters_number = transport_parameters_number;

    size_t diff = MIN_DATAGRAM_SIZE - length;
    void *p = payload;
    if (diff > 0)
        p = realloc(payload, length + diff);
    if (p == NULL) {
        log_quic_error("Error while padding Initial packet");
        return;
    }
    uint8_t src = TYPE_PADDING;
    size_t src_len = sizeof(src);
    size_t pad = length;
    while (length < MIN_DATAGRAM_SIZE) {
        memcpy(p + pad, (void *) &src, src_len);
        pad += src_len;
        length += src_len;
    }
    pkt->length = length;
    pkt->payload = p;
}

void build_zero_rtt_packet(conn_id dest_conn_id, conn_id src_conn_id, varint *length,
                           void *packet_number, void *payload, zero_rtt_packet *pkt) {
    pkt->first_byte = LONG_HEADER_FORM | PACKET_TYPE_0_RTT;
    pkt->version = VERSION;
    pkt->dest_conn_id = dest_conn_id;
    pkt->src_conn_id = src_conn_id;
    pkt->length = length;
    pkt->packet_number = packet_number;
    pkt->payload = payload;
}

void build_retry_packet(conn_id dest_conn_id, conn_id src_conn_id, void *retry_token,
                        const uint64_t *retry_integrity_tag, retry_packet *pkt) {
    pkt->first_byte = LONG_HEADER_FORM | PACKET_TYPE_RETRY;
    pkt->version = VERSION;
    pkt->dest_conn_id = dest_conn_id;
    pkt->src_conn_id = src_conn_id;
    pkt->retry_token = retry_token;
    pkt->retry_integrity_tag[0] = *retry_integrity_tag;
    pkt->retry_integrity_tag[1] = *(retry_integrity_tag + 1);
}

void build_one_rtt_packet(conn_id dest_conn_id, size_t len, pkt_num pkt_num, void *payload, one_rtt_packet *pkt) {
    pkt->first_byte = SHORT_HEADER_FORM;
    pkt->first_byte |= (uint8_t) log2((double) bytes_needed(pkt_num));
    pkt->dest_connection_id = dest_conn_id;
    pkt->packet_number = pkt_num;
    pkt->length = len;
    pkt->payload = payload;
}

/**
 * @brief Writes a packet to a buffer as a byte transfert_msg
 *
 * @param buf   the buffer to which the packet has to be written
 * @param size  the buffer size
 * @param pkt   the packet to be written into the buffer
 * @return      0 on success, -1 on errors
 */
ssize_t write_packet_to_buf(char *buffer, size_t size, const void *pkt) {
    char *buf = buffer;
    char first_byte = ((char *) pkt)[0];
    switch (first_byte & PACKET_HEADER_MASK) {
        case LONG_HEADER_FORM: {
            // Long packet header
            switch (first_byte & TYPE_SPECIFIC_BITS_MASK) {
                case PACKET_TYPE_INITIAL: {
                    // Initial packet
                    initial_packet *initial = (initial_packet *) pkt;
                    if (size < initial_pkt_len(initial))
                        return -1;
                    buf[0] = first_byte;
                    buf++;
                    size_t len = sizeof(initial->version);
                    memcpy(buf, (char *) &(initial->version), len);
                    buf += len;
                    len = sizeof(initial->dest_conn_id);
                    memcpy(buf, (char *) &(initial->dest_conn_id), len);
                    buf += len;
                    memcpy(buf, (char *) &(initial->src_conn_id), len);
                    buf += len;
                    len = sizeof(initial->transport_parameters_number);
                    memcpy(buf, (void *) &initial->transport_parameters_number, len);
                    buf += len;
                    size_t n = initial->transport_parameters_number;
                    transport_parameter tp;
                    for (int i = 0; i < n; i++) {
                        tp = initial->transport_parameters[i];
                        len = sizeof(tp.id);
                        memcpy(buf, (char *) &(tp.id), len);
                        buf += len;
                        len = sizeof(tp.value);
                        memcpy(buf, (char *) &(tp.value), len);
                        buf += len;
                    }
                    len = sizeof(initial->length);
                    memcpy(buf, (char *) &(initial->length), len);
                    buf += len;
                    len = (size_t) pow(2, first_byte & PACKET_NUMBER_LENGTH_MASK);
                    memcpy(buf, (char *) &initial->packet_number, len);
                    buf += len;
                    len = initial->length;
                    if (len > 0)
                        memcpy(buf, (char *) initial->payload, len);
                    return 0;
                }
                case PACKET_TYPE_0_RTT: {
                    // Initial packet
                    break;
                }
                case PACKET_TYPE_RETRY: {
                    // Initial packet
                    break;
                }
            }
            break;
        }
        case SHORT_HEADER_FORM: {
            // Short packet header
            one_rtt_packet *one_rtt = (one_rtt_packet *) pkt;
            if (size < one_rtt_pkt_len(one_rtt))
                return -1;
            buf[0] = first_byte;
            buf++;
            size_t len = sizeof(one_rtt->dest_connection_id);
            memcpy(buf, (char *) &(one_rtt->dest_connection_id), len);
            buf += len;
            len = (first_byte & PACKET_NUMBER_LENGTH_MASK) + 1;
            memcpy(buf, (void *) &(one_rtt->packet_number), len);
            buf += len;
            varint *pkt_len = write_var_int_62(one_rtt->length);
            size_t pkt_len_len = varint_len(pkt_len);
            memcpy(buf, (char *) pkt_len, pkt_len_len);
            buf += pkt_len_len;
            free(pkt_len);
            len = one_rtt->length;
            if (len > 0)
                memcpy(buf, (char *) one_rtt->payload, len);
            return 0;
        }
        default: {
            // Fixed bit set to 0, error
            log_quic_error("Fixed bit cannot be set to 0.");
            return -1;
        }
    }
}

/**
 * Evaluates the size (in bytes) of an initial packet
 * @param pkt   the initial packet
 * @return      the size of the initial packet
 */
size_t initial_pkt_len(const initial_packet *pkt) {
    size_t len = sizeof(uint8_t) + bytes_needed(pkt->version) + bytes_needed(pkt->dest_conn_id) +
                 bytes_needed(pkt->src_conn_id);
    len += bytes_needed(pkt->transport_parameters_number);
    for (int i = 0; i < pkt->transport_parameters_number; i++) {
        len += bytes_needed(pkt->transport_parameters[i].id);
        len += bytes_needed(pkt->transport_parameters[i].value);
    }
    len += bytes_needed(pkt->length) + pkt->length;
    // Packet number length
    len += bytes_needed(pkt->packet_number);
    return len;
}

size_t zero_rtt_pkt_len(const zero_rtt_packet *pkt) {
    // TODO
}

size_t retry_pkt_len(const retry_packet *pkt) {
    // TODO
}

/**
 * Evaluates the size (in bytes) of a 1-RTT packet
 * @param pkt   the 1-RTT packet
 * @return      the size of the 1-RTT packet
 */
size_t one_rtt_pkt_len(const one_rtt_packet *pkt) {
    size_t len = sizeof(uint8_t) + bytes_needed(pkt->dest_connection_id);
    // Packet number length
    len += bytes_needed(pkt->packet_number);
    len += bytes_needed(pkt->length);
    len += pkt->length;
    return len;
}

/**
 * @brief Parse an Initial packet from a general long-header packet form
 *
 * Copies data of an unknown-type packet to a Initial packet
 * struct. After all operation is done, the unknown-type packet
 * memory is freed.
 *
 * @param pkt   a general long-header packet form
 * @param dest  the packet to be parsed
 * @return      0 on success, -1 on errors
 */
int read_initial_packet(long_header_pkt *pkt, initial_packet *dest) {
    dest->first_byte = pkt->first_byte;
    dest->version = pkt->version;
    dest->dest_conn_id = pkt->dest_conn_id;
    dest->src_conn_id = pkt->src_conn_id;
    uint64_t tp_num = read_var_int_62((varint *) pkt->payload);
    dest->transport_parameters_number = tp_num;
    size_t read = bytes_needed(tp_num);
    for (int i = 0; i < tp_num; i++) {
        dest->transport_parameters[i].id = read_var_int_62((varint *) &pkt->payload[read]);
        read += bytes_needed(dest->transport_parameters[i].id);
        dest->transport_parameters[i].value = read_var_int_62((varint *) &pkt->payload[read]);
        read += bytes_needed(dest->transport_parameters[i].value);
    }
    size_t pkt_len = read_var_int_62((varint *) &pkt->payload[read]);
    dest->length = pkt_len;
    read += bytes_needed(pkt_len);

    dest->packet_number = read_var_int_62((varint *) &pkt->payload[read]);
    read += bytes_needed(dest->packet_number);
    dest->payload = &pkt->payload[read];
    return 0;
}

int read_zero_rtt_packet(long_header_pkt *pkt, zero_rtt_packet *dest) {

}

int read_retry_packet(long_header_pkt *pkt, retry_packet *dest) {

}

int read_one_rtt_packet(char *pkt, one_rtt_packet *dest) {
    size_t read = 0;
    uint8_t first_byte = *(uint8_t *) pkt;
    dest->first_byte = first_byte;
    read++;

    dest->dest_connection_id = read_var_int_62((varint *) (pkt + read));
    read += bytes_needed(dest->dest_connection_id);

    dest->packet_number = read_var_int_62((varint *) (pkt + read));
    read += bytes_needed(dest->packet_number);

    dest->length = read_var_int_62((varint *) (pkt + read));
    read += bytes_needed(dest->length);

    dest->payload = (char *) calloc(1, dest->length);
    if (dest->payload == NULL)
        return -1;
    memcpy(dest->payload, pkt + read, dest->length);
    return 0;
}

/**
 * @brief Processes a packet's payload
 *
 * Processes all frame in a packet payload, until the computed
 * bytes number is equal to the packet payload length.
 *
 * @param buf   the packet payload
 * @param num   the packet number
 * @param len   the packet payload length
 * @param space the packet number space
 * @param conn  the connection to which the packet is associated
 * @return      0 on success, -1 on errors
 */
int process_packet_payload(const char *buf, pkt_num num, size_t len, num_space space, quic_connection *conn) {
    size_t frame_len, computed = 0;
    while (computed < len) {
        if ((frame_len = process_frame(buf + computed, num, space, conn)) > 0) {
            computed += frame_len;
        } else {
            log_quic_error("Error while processing frame");
            return -1;
        }
    }
    return 0;
}

/**
 * Checks if a connection-associated datagram origins from the same host
 *
 * @param addr  the sender host address
 * @param conn  the connection to which the datagram is intended
 * @return      0 if the datagram origins from the same client, -1 otherwise
 *
 * @note        this should not happen in a standard QUIC server implementation
 */
int check_incoming_dgram(struct sockaddr_in *addr, quic_connection *conn) {
    if (conn->addr.sin_port == addr->sin_port &&
        conn->addr.sin_addr.s_addr == addr->sin_addr.s_addr)
        return 0;
    return -1;
}

/**
 * @brief Writes an initial packet to a buffer
 *
 * Writes an initial packet to a buffer, also encoding
 * varint field values
 *
 * @param buf       the buffer to which write the packet
 * @param initial   the packet to be written
 * @return          0 on success, -1 on errors
 */
void write_initial_packet_to_buffer_for_forwarding(char *buf, initial_packet *initial) {
    memcpy(buf, (char *) &(initial->first_byte), 1);
    size_t read = 1;
    size_t len = bytes_needed(initial->version);
    varint *vi = write_var_int_62(initial->version);
    memcpy(&buf[read], (char *) vi, len);
    read += len;
    len = bytes_needed(initial->dest_conn_id);
    vi = write_var_int_62(initial->dest_conn_id);
    memcpy(&buf[read], (char *) vi, len);
    read += len;
    len = bytes_needed(initial->src_conn_id);
    vi = write_var_int_62(initial->src_conn_id);
    memcpy(&buf[read], (char *) vi, len);
    read += len;
    len = bytes_needed(initial->transport_parameters_number);
    vi = write_var_int_62(initial->transport_parameters_number);
    memcpy(&buf[read], (char *) &initial->transport_parameters_number, len);
    read += len;
    free(vi);
    size_t n = initial->transport_parameters_number;
    transport_parameter tp;
    for (int i = 0; i < n; i++) {
        tp = initial->transport_parameters[i];
        len = bytes_needed(tp.id);
        vi = write_var_int_62(tp.id);
        memcpy(&buf[read], (char *) vi, len);
        read += len;
        free(vi);
        len = bytes_needed(tp.value);
        vi = write_var_int_62(tp.value);
        memcpy(&buf[read], (char *) vi, len);
        read += len;
        free(vi);
    }
    len = bytes_needed(initial->length);
    vi = write_var_int_62(initial->length);
    memcpy(&buf[read], (char *) vi, len);
    read += len;
    free(vi);
    len = bytes_needed(initial->packet_number);
    vi = write_var_int_62(initial->packet_number);
    memcpy(&buf[read], (char *) vi, len);
    read += len;
    free(vi);
    len = initial->length;
    if (len > 0)
        memcpy(buf + read, (void *) initial->payload, len);
}

/**
 * @brief Serialize a 1-RTT packet
 *
 * @param buf   the buffer to which write the packet
 * @param pkt   the 1-RTT packet
 */
void write_one_rtt_packet_to_buffer_for_forwarding(char *buf, one_rtt_packet *pkt) {
    size_t written = 0;

    buf[written] = (char) pkt->first_byte;
    written++;

    varint *vi = write_var_int_62(pkt->dest_connection_id);
    size_t field_len = varint_len(vi);
    memcpy(&buf[written], (void *) vi, field_len);
    written += field_len;
    free(vi);

    vi = write_var_int_62(pkt->packet_number);
    field_len = varint_len(vi);
    memcpy(&buf[written], (void *) vi, field_len);
    written += field_len;
    free(vi);

    vi = write_var_int_62(pkt->length);
    field_len = varint_len(vi);
    memcpy(&buf[written], (void *) vi, field_len);
    written += field_len;
    free(vi);

    memcpy(&buf[written], pkt->payload, pkt->length);
}

/**
 * @brief Pad the packet of some bytes
 *
 * @param pkt       the packet to be padded
 * @param pad_len   the number of bytes in the padding
 * @return          0 on success, -1 on errors
 */
int pad_packet(outgoing_packet *pkt, size_t pad_len) {
    uint8_t padding = TYPE_PADDING;
    size_t padding_len = sizeof(padding);
    size_t off = 0;
    uint8_t first_byte = ((uint8_t *) pkt->pkt)[off++];
    if ((first_byte & PACKET_HEADER_MASK) == LONG_HEADER_FORM) {
        long_header_pkt long_header;
        long_header.first_byte = first_byte;
        long_header.version = read_var_int_62((varint *) (pkt->pkt + off));
        off += bytes_needed(long_header.version);
        long_header.src_conn_id = read_var_int_62((varint *) (pkt->pkt + off));
        off += bytes_needed(long_header.src_conn_id);
        long_header.dest_conn_id = read_var_int_62((varint *) (pkt->pkt + off));
        off += bytes_needed(long_header.dest_conn_id);
        long_header.payload = pkt->pkt + off;
        switch (first_byte & TYPE_SPECIFIC_BITS_MASK) {
            case PACKET_TYPE_INITIAL : {
                initial_packet initial_packet;
                read_initial_packet(&long_header, &initial_packet);
                initial_packet.length += pad_len;
                void *p = realloc(initial_packet.payload, initial_packet.length);
                if (p == NULL) {
                    log_quic_error("Realloc error");
                    return -1;
                }
                off = 0;
                for (int i = 0; i < pad_len / padding_len; i++) {
                    memcpy((void *) &initial_packet.payload[off], (void *) &padding, padding_len);
                    initial_packet.payload += padding_len;
                    off += padding_len;
                }

                pkt->length = initial_packet.length;
                write_initial_packet_to_buffer_for_forwarding(pkt->pkt, &initial_packet);
                return 0;
            }
            case PACKET_TYPE_0_RTT : {
                break;
            }
            case PACKET_TYPE_RETRY : {
                break;
            }
            default: {
                log_quic_error("Unrecognized long header packet type");
                return -1;
            }
        }
    } else {
        // Short header, 1-RTT packet
        one_rtt_packet *one_rtt = (one_rtt_packet *) calloc(1, sizeof(one_rtt_packet));
        read_one_rtt_packet((char *) pkt->pkt, one_rtt);

        size_t offset = 1;
        offset += varint_len((varint *) (pkt->pkt + offset));
        offset += varint_len((varint *) (pkt->pkt + offset));
        varint *vi_len = write_var_int_62(MIN_DATAGRAM_SIZE);
        memcpy(pkt->pkt + offset, vi_len, varint_len(vi_len));
        offset += varint_len(vi_len);
        memcpy(pkt->pkt + offset, one_rtt->payload, one_rtt->length);
        offset += one_rtt->length;

        for (size_t i = 0; i < pad_len / padding_len; i++) {
            memcpy(pkt->pkt + offset, &padding, padding_len);
            offset += padding_len;
        }
        return 0;
    }
}
