//
// Created by andrea on 05/09/23.
//

#include <string.h>
#include <math.h>

#include "packets.h"

void build_initial_packet(conn_id dest_conn_id, conn_id src_conn_id, varint *token_len,
                          void *token, varint *length, varint *transport_parameters_number,
                          void *payload, initial_packet *pkt) {
    pkt->first_byte = LONG_HEADER_FORM | PACKET_TYPE_INITIAL;
    pkt->version = VERSION;
    pkt->dest_conn_id = dest_conn_id;
    pkt->src_conn_id = src_conn_id;
    pkt->token_len = token_len;
    pkt->token = token;
    pkt->transport_parameters_number = transport_parameters_number;

    size_t len = read_var_int_62(length);
    free(length);
    size_t diff = MIN_DATAGRAM_SIZE - len;
    void *p = payload;
    if (diff > 0)
        p = realloc(payload, len + diff);
    if (p == NULL) {
        print_quic_error("Error while padding Initial packet");
        return;
    }
    void *buf = p;
    uint8_t src = TYPE_PADDING;
    size_t src_len = sizeof(src);
    while (len < MIN_DATAGRAM_SIZE) {
        memcpy(buf, (void *) &src, src_len);
        buf += src_len;
        len += src;
    }
    pkt->length = write_var_int_62(len);
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

void build_one_rtt_packet(conn_id dest_conn_id, size_t len, void *payload, one_rtt_packet *pkt) {
    pkt->first_byte = SHORT_HEADER_FORM;
    pkt->dest_connection_id = dest_conn_id;

    size_t diff = MIN_DATAGRAM_SIZE - len;
    void *p = payload;
    if (diff > 0)
        p = realloc(payload, len + diff);
    if (p == NULL) {
        print_quic_error("Error while padding Initial packet");
        return;
    }
    void *buf = p;
    uint8_t src = TYPE_PADDING;
    size_t src_len = sizeof(src);
    while (len < MIN_DATAGRAM_SIZE) {
        memcpy(buf, (void *) &src, src_len);
        buf += src_len;
        len += src;
    }
    pkt->length = len;
    pkt->payload = p;
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
    switch (first_byte & PACKET_TYPE_MASK) {
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
                    len = varint_len(initial->token_len);
                    memcpy(buf, (char *) &(initial->token_len), len);
                    buf += len;
                    len = read_var_int_62(initial->token_len);
                    if (len > 0) {
                        memcpy(buf, (char *) &(initial->token), len);
                        buf += len;
                    }
                    len = varint_len(initial->transport_parameters_number);
                    memcpy(buf, (char *) &(initial->transport_parameters_number), len);
                    buf += len;
                    size_t n = read_var_int_62(initial->transport_parameters_number);
                    transport_parameter *tp;
                    for (int i = 0; i < n; i++) {
                        tp = initial->transport_parameters[i];
                        len = sizeof(tp->id);
                        memcpy(buf, (char *) &(tp->id), len);
                        buf += len;
                        len = sizeof(tp->len);
                        memcpy(buf, (char *) &(tp->len), len);
                        buf += len;
                        len = tp->len;
                        memcpy(buf, (char *) &(tp->data), len);
                        buf += len;
                    }
                    len = varint_len(initial->length);
                    memcpy(buf, (char *) &(initial->length), len);
                    buf += len;
                    len = first_byte & PACKET_NUMBER_LENGTH_MASK + 1;
                    memcpy(buf, (char *) initial->packet_number, len);
                    buf += len;
                    len = read_var_int_62(initial->length);
                    if (len > 0)
                        memcpy(buf, (char *) initial->payload, len);
                    return 0;
                }
                case PACKET_TYPE_0_RTT: {
                    // Initial packet
                    break;
                }
                case PACKET_TYPE_HANDSHAKE: {
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
            len = first_byte & PACKET_NUMBER_LENGTH_MASK + 1;
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
            print_quic_error("Fixed bit cannot be set to 0.");
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
    size_t len = sizeof(uint8_t) + sizeof(uint32_t) + 2 * sizeof(conn_id);
    len += varint_len(pkt->token_len) + read_var_int_62(pkt->token_len);
    len += varint_len(pkt->transport_parameters_number) +
           read_var_int_62(pkt->transport_parameters_number) * sizeof(transport_parameter *);
    len += varint_len(pkt->length) + read_var_int_62(pkt->length);
    // Packet number length
    len += pkt->first_byte & PACKET_NUMBER_LENGTH_MASK + 1;
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
    size_t len = sizeof(uint8_t) + sizeof(conn_id);
    // Packet number length
    len += pkt->first_byte & PACKET_NUMBER_LENGTH_MASK + 1;
    varint *pkt_len = write_var_int_62(pkt->length);
    len += varint_len(pkt_len) + pkt->length;
    free(pkt_len);
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
int read_initial_packet(long_header_pkt *pkt, initial_packet *dest, quic_connection *conn) {
    dest->first_byte = pkt->first_byte;
    dest->version = pkt->version;
    dest->dest_conn_id = pkt->dest_conn_id;
    dest->src_conn_id = pkt->src_conn_id;
    uint64_t token_len = read_var_int_62(pkt->payload);
    dest->token_len = write_var_int_62(token_len);
    if (token_len == 0) {
        // No retry token
        dest->token = NULL;
        pkt->payload++;
    } else {
        // Parse retry token
        pkt->payload += varint_len(dest->token_len);
        dest->token = malloc(token_len);
        if (dest->token == NULL) {
            // malloc() error
            print_quic_error("Error while allocating retry token buffer.");
            return -1;
        }
        memcpy(dest->token, pkt->payload, token_len);
        pkt->payload += token_len;
    }
    uint64_t tp_num = read_var_int_62(pkt->payload);
    dest->transport_parameters_number = write_var_int_62(tp_num);
    size_t tp_len;
    for (int i = 0; i < tp_num; i++) {
        dest->transport_parameters[i] = malloc(sizeof(transport_parameter));
        if (dest->transport_parameters[i] == NULL) {
            // malloc() error
            print_quic_error("Error while allocating transport parameter buffer.");
            return -1;
        }
        dest->transport_parameters[i]->id = read_var_int_62(pkt->payload);
        pkt->payload += sizeof(uint64_t);
        tp_len = read_var_int_62(pkt->payload);
        dest->transport_parameters[i]->len = tp_len;
        pkt->payload += varint_len((varint *) pkt->payload);
        dest->transport_parameters[i]->data = malloc(tp_len);
        memcpy(dest->transport_parameters[i]->data, pkt->payload, tp_len);
        pkt->payload += tp_len;
    }

    size_t pkt_len = read_var_int_62(pkt->payload);
    dest->length = write_var_int_62(pkt_len);
    size_t pkt_num_len = (dest->first_byte & PACKET_NUMBER_LENGTH_MASK);
    dest->packet_number = read_var_int_62(pkt->payload);
    pkt->payload += (size_t) pow(2, (double) pkt_num_len);
    memcpy(dest->payload, pkt->payload, pkt_len);
    free(pkt);
    return 0;
}

int read_zero_rtt_packet(long_header_pkt *pkt, zero_rtt_packet *dest) {

}

int read_retry_packet(long_header_pkt *pkt, retry_packet *dest) {

}

int read_one_rtt_packet(void *pkt, one_rtt_packet *dest) {
    uint8_t first_byte = *(uint8_t *) pkt;
    dest->first_byte = first_byte;
    pkt += sizeof(dest->first_byte);

    dest->dest_connection_id = *(conn_id *) pkt;
    pkt += sizeof(dest->dest_connection_id);

    size_t pkt_len = first_byte & PACKET_NUMBER_LENGTH_MASK;
    dest->packet_number = (pkt_num) read_var_int_62((varint *) pkt);
    pkt += pkt_len;

    uint64_t len = read_var_int_62((varint *) pkt);
    dest->length = len;
    pkt += varint_len((varint *) pkt);

    dest->payload = malloc(len);
    memcpy(dest->payload, pkt, len);
    return 0;
}

/**
 * @brief Set the encoded packet number to the packet
 *
 * @param pkt   the raw packet
 * @param num   the packet number
 * @return      0 on success, -1 on errors
 */
int set_pkt_num(void *pkt, pkt_num num) {
    uint8_t header_type = *(uint8_t *) pkt & PACKET_TYPE_MASK;
    if (header_type == LONG_HEADER_FORM) {
        uint8_t pkt_type = *(uint8_t *) pkt & PACKET_TYPE_MASK;
        switch (pkt_type) {
            case PACKET_TYPE_INITIAL: {
                initial_packet *init_pkt = (initial_packet *) pkt;
                init_pkt->packet_number = num;
                init_pkt->first_byte &= (uint8_t) log2((double) bytes_needed(num));
                break;
            }
            case PACKET_TYPE_HANDSHAKE: {
                break;
            }
            case PACKET_TYPE_RETRY: {
                break;
            }
            case PACKET_TYPE_0_RTT: {
                break;
            }
            default: {
                print_quic_error("Unrecognized long header packet type.");
                return -1;
            }
        }
    } else if (header_type == SHORT_HEADER_FORM) {
        one_rtt_packet *one_rtt = (one_rtt_packet *) pkt;
        one_rtt->packet_number = num;
        one_rtt->first_byte &= (uint8_t) log2((double) bytes_needed(num));
    } else {
        print_quic_error("Unrecognized header type.");
        return -1;
    }
    return 0;
}

void *encode(pkt_num num, size_t bytes) {
    pkt_num mask = 0;
    for (int i = 0; i < 8 * bytes; i++)
        mask += 1 << i;
    return write_var_int_62(num & mask);
}

/**
 * Encodes a packet number
 *
 * @param num           the packet number to be encoded
 * @param largest_acked the largest packet number acked by the peer in the same space
 * @param len           a return-value parameter, that states the legth of the result
 * @return              a pointer to the truncated packet number
 */
void *encode_pkt_num(pkt_num num, ssize_t largest_acked, size_t *len) {
    pkt_num num_unacked;
    if (largest_acked == -1)
        num_unacked = num + 1;
    else
        num_unacked = num - largest_acked;

    double min_bits = log2((double) num_unacked) + 1;
    size_t num_bytes = ceil(min_bits / 8);
    *len = num_bytes;

    return encode(num, num_bytes);
}

/**
 * Decodes a truncated packet number value
 * @param largest   the largest packet number processed in the same packet number space
 * @param truncated the truncated packet number value
 * @param bits      bits in the packet number field (8, 16, 24 or 32)
 * @return          the decoded packet number
 */
pkt_num decode_pkt_num(pkt_num largest, pkt_num truncated, size_t bits) {

    pkt_num expected;
    if (largest == (pkt_num) -1)
        expected = 0;
    else
        expected = largest + 1;
    pkt_num win = 1 << bits;
    pkt_num hwin = win >> 1;
    pkt_num mask = win - 1;

    pkt_num candidate = (expected & !mask) | truncated;
    if (candidate <= expected - hwin && candidate < ((pkt_num) 1 << 62) - win)
        return candidate + win;
    if (candidate > expected + hwin && candidate >= win)
        return candidate - win;
    return candidate;
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
    do {
        if ((frame_len = process_frame(buf, num, space, conn)) > 0) {
            computed += frame_len;
        } else {
            print_quic_error("Error while processing frame");
            return -1;
        }
    } while (computed < len);
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
