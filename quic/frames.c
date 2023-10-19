//
// Created by andrea on 17/09/23.
//

#include "frames.h"

/**
 * @brief Processes a frame
 *
 * @param buf   the buffer containing the frame
 * @param num   the packet number of the packet containing the frame
 * @param space the number space of the packet containing the frame
 * @param conn  the quic connection
 * @param res   a pointer to which store the frame content
 * @return      on success, the processed frame length, or -1 on errors
 */
ssize_t process_frame(const char *buf, pkt_num num, num_space space, quic_connection *conn) {
    uint64_t frame_type = read_var_int_62((varint *) buf);
    bool generate_ack = false;
    ssize_t len;
    frame **response_frames = NULL;
    size_t response_frames_num;
    if (frame_type >= TYPE_STREAM_BASE && frame_type <= TYPE_STREAM_BASE + 0x07) {
        generate_ack = true;
        // STREAM frame, check for fields
        len = (ssize_t) bytes_needed(frame_type);
        stream_id sid = read_var_int_62((varint *) (buf + len));
        size_t offset, length;
        len += (ssize_t) bytes_needed(sid);
        // Offset filed parsing
        if ((frame_type & 0x04) != 0) {
            offset = read_var_int_62((varint *) (buf + len));
            len += (ssize_t) bytes_needed(offset);
        }
        // Length field parsing
        length = read_var_int_62((varint *) (buf + len));
        len += (ssize_t) bytes_needed(length);
        bool end_stream = false;
        if ((frame_type & 0x01) == 0x01) {
            // Fin bit, end of stream
            end_stream = true;
        }

        // Check stream ID
        switch (conn->peer_type) {
            case SERVER: {
                if ((sid & STREAM_MASK) == STREAM_SRC_MASK + STREAM_SRC_MASK) {
                    log_quic_error("Server cannot accept server-initiated unidirectional stream.");
                    // TODO send RESET_STREAM frame with connection error 400
                    return -1;
                }

                // Server could receive stream, check message type
                transfert_msg *msg = (transfert_msg *) calloc(1, sizeof(transfert_msg));
                msg->type = get_message_type(buf + len);

                if ((sid & STREAM_MODE_MASK) == 0 && msg->type == DATA) {
                    // Server cannot accept DATA messages in bidirectional streams
                    log_quic_error("Server cannot accept DATA messages inside bidirectional streams.");
                    // TODO send RESET_STREAM frame with connection error 400
                    return -1;
                }
                // Server can receive stream
                // Parse message and put in receiver window
                msg->stream_id = sid;
                msg->len = length + 1;
                msg->msg = calloc(1, msg->len);
                strncat(msg->msg, (void *) (buf + len), msg->len - 1);
                msg->bytes_written = msg->len;
                msg->end_reached = end_stream;
                char *res = exec(msg);
                switch (msg->type) {
                    case LIST: {
                        size_t res_buf_len = strlen(res) + 1 + 3;
                        char *res_buf = (char *) calloc(1, res_buf_len);
                        write_response(OK, res, res_buf);

                        if (write_message_to_packets(res_buf, sid, true, conn) == 0 - 1) {
                            log_quic_error("Error while writing LIST command response to packets");
                            return -1;
                        }
                        break;
                    }
                    case GET: {
                        if (add_file_req(res, conn) == -1) {
                            log_quic_error("Error while adding sending request");
                            return -1;
                        }
                    }
                    case PUT: {

                        break;
                    }
                    case DATA:
                        break;
                }

                /*if (put_in_receiver_window(&(conn->rwnd)) == -1) {
                    log_quic_error("Error while inserting received message into receiver window.");
                    return -1;
                }*/
                /*if ((stream_id & STREAM_MODE_MASK) == 0)
                    // Bidirectional stream, server can only accept LIST, GET and PUT messages
                    switch (get_incoming_message_type(buf)) {
                        case LIST: {
                            char *res = parse_and_exec_list_msg(buf);
                            if (res == NULL) {
                                log_quic_error("LIST command bad format.");
                                // Send error response message
                                frame rst_str_frame;
                                rst_str_frame.type = TYPE_RESET_STREAM;
                                char *stream_buf = (char *) malloc(
                                        bytes_needed(TYPE_RESET_STREAM) + bytes_needed(stream_id) +
                                        bytes_needed(BAD_REQUEST));
                                new_reset_stream_frame(stream_id, BAD_REQUEST, stream_buf);
                                response_frames[generated_response_frames++] = rst_str_frame;
                            } else {
                                // LIST command ok
                                size_t res_len = strlen(res);
                                char *res_buf;
                                if (res_len == 0)
                                    res_buf = (char *) calloc(1, sizeof(uint8_t) + 1);
                                else
                                    res_buf = (char *) calloc(1, res_len + 3 + sizeof(uint8_t));
                                write_response(OK, res_len == 0 ? NULL : res, res_buf);
                                res_len = strlen(res_buf);
                                off_t off = 0;
                                char *stream_buf;
                                size_t stream_buf_size = bytes_needed(stream_id) + bytes_needed(off) +
                                                         bytes_needed(255) + 255 * sizeof(char);
                                if (res_len >= 255)
                                    stream_buf = (char *) calloc(1, stream_buf_size);
                                while (off + 255 < res_len) {
                                    frame stream_frame;
                                    stream_frame.type = TYPE_STREAM_BASE + 0x06;
                                    // Builds STREAM fields of 255 bytes each
                                    if (res_len - off == 255)
                                        stream_frame.type += 0x01;
                                    new_stream_frame(stream_id, off, 255, res_buf + off, stream_buf);
                                    stream_frame.frame_data = malloc(sizeof(stream_buf_size));
                                    memcpy(stream_frame.frame_data, stream_buf, stream_buf_size);
                                    response_frames[generated_response_frames++] = stream_frame;
                                    off += 255;
                                }
                                if (res_len - off > 0) {
                                    frame stream_frame;
                                    stream_frame.type = TYPE_STREAM_BASE + 0x07;
                                    stream_buf_size = bytes_needed(stream_id) + bytes_needed(off) +
                                                      bytes_needed(res_len - off) + (res_len - off) * sizeof(char);
                                    stream_buf = (char *) malloc(stream_buf_size);
                                    new_stream_frame(stream_id, off, res_len - off, res_buf + off, stream_buf);
                                    stream_frame.frame_data = malloc(sizeof(stream_buf_size));
                                    memcpy(stream_frame.frame_data, stream_buf, stream_buf_size);
                                    response_frames[generated_response_frames++] = stream_frame;
                                }
                            }
                            break;
                        }
                        case GET: {
                            // Server received GET message
                            */
                /*char *file_name = parse_get_or_put_msg(buf);
                            if (strlen(file_name) > 0) {
                                // File parsed, put message in receiver window
                                transfert_msg get_msg;
                                get_msg.type = GET;
                                get_msg.end_reached = end_stream;
                            } else {
                                // No specified file
                            }*/
                /*


                            break;
                        }
                        case PUT:
                            break;
                        default: {
                            // Cannot accept this
                        }
                    }*/
                len += (ssize_t) length;
                return len;
            }
            case CLIENT: {
                if ((sid & STREAM_MASK) == STREAM_SRC_MASK) {
                    log_quic_error("Client cannot accept client-initiated unidirectional stream.");
                    // TODO send RESET_STREAM frame with connection error 400
                    return -1;
                }

                // Client could receive stream, check created streams
                transfert_msg msg;
                if ((sid & STREAM_MODE_MASK) == 0) {
                    // Client is waiting for a response
                    // Checks opened streams for the request
                    int i;
                    for (i = 0; i < conn->bidi_streams_num; i++) {
                        if (conn->bidi_streams[i]->id == sid) {
                            // Found request stream, put response into receiver window
                            msg.stream_id = sid;
                            msg.len = length + 1;
                            msg.msg = calloc(1, msg.len);
                            strncat(msg.msg, (void *) buf, msg.len - 1);
                            msg.bytes_written = msg.len;
                            msg.end_reached = end_stream;
                            /*if (put_in_receiver_window(&(conn->rwnd), &msg, offset) == -1) {
                                log_quic_error("Error while inserting received message into receiver window.");
                                return -1; todo fix
                            }*/
                            return length;
                        }
                        return -1;
                    }
                } else {
                    // Unidirectional streams, client can accept only DATA messages
                    if (msg.type != DATA) {
                        log_quic_error("Client cannot accept request messages inside unidirectional streams.");
                        // TODO send RESET_STREAM frame with connection error 400
                        return -1;
                    }
                    // DATA message inside unidirectional stream, puts message into receiver window
                    msg.stream_id = sid;
                    msg.len = length + 1;
                    msg.msg = calloc(1, msg.len);
                    strncat(msg.msg, (void *) buf, msg.len - 1);
                    msg.bytes_written = msg.len;
                    msg.end_reached = end_stream;
                    /*if (put_in_receiver_window(&(conn->rwnd), &msg, offset) == -1) {
                        log_quic_error("Error while inserting received message into receiver window.");
                        return -1; todo fix
                    }*/
                    return 0;
                }
            }
        }
    }
    switch (frame_type) {
        case TYPE_PADDING: {
            // Do nothing but generate ACK
            len = (ssize_t) bytes_needed(TYPE_PADDING);
            break;
        }
        case TYPE_PING: {
            // Must ACK packet
            generate_ack = true;
            len = (ssize_t) bytes_needed(TYPE_PING);
            break;
        }
        case TYPE_ACK: {
            time_ms ack_time;
            if ((ack_time = get_time_millis()) == -1) {
                log_quic_error("Cannot get current time.");
                return -1;
            }
            ack_frame ack;
            if ((len = parse_ack_frame(buf, &ack, conn, ack_time)) > 0) {
                pkt_num largest, smallest;
                largest = ack.largest_acked;
                smallest = largest - ack.first_ack_range;
                if (ack_pkt_range(conn, smallest, largest, space) != -1) {
                    // First acknowledge ok
                    int i = 0;
                    ack_range range;
                    while (i < ack.ack_range_count) {
                        range = *ack.ranges[i];
                        largest = smallest - range.gap - 2;
                        smallest = largest - range.ack_range_len;
                        if (ack_pkt_range(conn, smallest, largest, space) != 0)
                            // Acknowledge gone wrong, return
                            return -1;
                        i++;
                    }
                    if (space == INITIAL) {
                        conn->handshake_done = true;
                        log_msg("Handshake completed");
                        if (conn->peer_type == CLIENT)
                            generate_ack = true;
                    }
                    on_ack_received(conn, &ack, space);
                    break;
                }
            } else return -1;
        }
        case TYPE_RESET_STREAM: {
        }
        case TYPE_STOP_SENDING: {
        }
        case TYPE_NEW_TOKEN: {
        }
        case TYPE_MAX_DATA: {
        }
        case TYPE_MAX_STREAM_DATA: {
        }
        case TYPE_MAX_STREAMS_BIDI: {
        }
        case TYPE_MAX_STREAMS_UNI: {
        }
        case TYPE_DATA_BLOCKED: {
        }
        case TYPE_STREAM_DATA_BLOCKED: {
        }
        case TYPE_STREAMS_BLOCKED_BIDI: {
        }
        case TYPE_STREAMS_BLOCKED_UNI: {
        }
        case TYPE_NEW_CONNECTION: {
        }
        case TYPE_RETIRE_CONNECTION_ID: {
        }
        case TYPE_CONN_CLOSE_QUIC: {
        }
        case TYPE_CONN_CLOSE_APP: {
        }
        case TYPE_HANDSHAKE_DONE: {
        }
        default: {
            log_quic_error("Unsupported frame type");
            return -1;
        }
    }
    if (generate_ack) {
        switch (space) {
            case INITIAL: {
                if (conn->peer_type == CLIENT) {
                    initial_packet *initial = (initial_packet *) calloc(1, sizeof(initial_packet));
                    build_initial_packet(get_random_peer_conn_id(conn), get_random_local_conn_id(conn), 0, 0, NULL,
                                         conn->swnd->largest_in_space[INITIAL], initial);
                    outgoing_packet *pkt = (outgoing_packet *) calloc(1, sizeof(outgoing_packet));
                    pkt->space = INITIAL;
                    pkt->pkt_num = initial->packet_number;
                    pkt->in_flight = false;
                    pkt->length = initial_pkt_len(initial);
                    pkt->ready_to_send = false;
                    pkt->ack_eliciting = false;
                    pkt->lost = false;
                    pkt->acked = false;
                    pkt->pkt = calloc(1, pkt->length);

                    write_initial_packet_to_buffer_for_forwarding((char *) pkt->pkt, initial);

                    if (enqueue(pkt, conn) == 0)
                        log_msg("Successfully enqueued 2nd Initial packet for the server");
                    else
                        log_quic_error("Errors while enqueuing 2nd Initial packet for the server");
                }
                break;
            }
            case HANDSHAKE:
                break;
            case APPLICATION_DATA: {
                size_t i = conn->rwnd->write_index - 1 & BUF_CAPACITY;
                incoming_packet *pkt = conn->rwnd->buffer[i];
                pkt_num largest_acked = 0;
                largest_acked = pkt->pkt_num;
                i = (i - 1) % BUF_CAPACITY;
                if (i != conn->rwnd->read_index) {
                    pkt = conn->rwnd->buffer[i];
                    size_t first_ack_range = 0;
                    while (pkt->pkt_num == largest_acked - first_ack_range - 1 || i == conn->rwnd->read_index) {
                        first_ack_range++;
                        i = (i - 1) & BUF_CAPACITY;
                        pkt = conn->rwnd->buffer[i];
                    }
                }
                break;
            }
        }
    }
    return len;
}

/**
 * @brief Parses raw data into an ACK frame
 *
 * @param raw       the raw frame data
 * @param ack_frame the struct to where store the parsed data
 * @return          0 on success, -1 on errors
 */
ssize_t parse_ack_frame(const char *raw, ack_frame *ack_frame, const quic_connection *conn, time_ms ack_time) {
    size_t read = 0;

    ack_frame->type = TYPE_ACK;
    read += bytes_needed(ack_frame->type);

    uint32_t largest_acked = read_var_int_62((varint *) raw + read);
    ack_frame->largest_acked = largest_acked;
    read += bytes_needed(ack_frame->largest_acked);

    ack_frame->ack_delay = read_var_int_62((varint *) raw + read) << ACK_DELAY_EXP;
    read += varint_len((varint *) raw + read);

    uint64_t ack_range_count = read_var_int_62((varint *) raw + read);
    ack_frame->ack_range_count = ack_range_count;
    read += bytes_needed(ack_range_count);

    ack_frame->first_ack_range = read_var_int_62((varint *) raw + read);
    read += bytes_needed(ack_frame->first_ack_range);

    if (ack_range_count > 0) {
        ack_frame->ranges = (ack_range **) calloc(ack_range_count, sizeof(ack_range *));
        ack_range range;
        for (int i = 0; i < ack_range_count; i++) {
            ack_frame->ranges[i] = calloc(1, sizeof(ack_range));
            range.gap = read_var_int_62((varint *) raw);
            read += bytes_needed(range.gap);
            range.ack_range_len = read_var_int_62((varint *) raw);
            read += bytes_needed(range.ack_range_len);
            memcpy(ack_frame->ranges[i], &range, sizeof(range));
            // Resets buffer space
            explicit_bzero(&range, sizeof(range));
        }
    } else
        ack_frame->ranges = NULL;
    return (ssize_t) read;
}

/**
 * @brief Builds an ACK range
 *
 * @param gap           the range gap
 * @param ack_range_len the range length
 * @param range         the range struct
 */
void new_ack_range(size_t gap, size_t ack_range_len, ack_range *range) {
    range->gap = gap;
    range->ack_range_len = ack_range_len;
}

/**
 * @brief Builds a new ACK frame
 *
 * @param largest_acked     the largest packet number acked by this frame
 * @param ack_delay         the ack generation delay
 * @param ack_range_count   the number of ack ranges
 * @param first_ack_range   the first ack range
 * @param ranges            the other ranges
 * @param frame             the ACK frame struct
 */
void new_ack_frame(pkt_num largest_acked, uint64_t ack_delay, size_t ack_range_count, size_t first_ack_range,
                   ack_range *ranges[], ack_frame *frame) {
    frame->type = TYPE_ACK;
    frame->largest_acked = largest_acked;
    frame->ack_delay = ack_delay;
    frame->ack_range_count = ack_range_count;
    frame->first_ack_range = first_ack_range;
    frame->ranges = ranges;
}

/**
 * @brief Builds a CLOSE_CONNECTION frame
 *
 * @param error_code    the error code
 * @param reason        the error reason message
 * @param buf           the buffer to which store the created frame
 */
void new_close_connection_frame(uint64_t error_code, char *reason, char *buf) {
    uint8_t type = 0x1c;
    sprintf(buf, "%u", type);
    varint *error = write_var_int_62(error_code);
    memcpy((void *) &buf[strlen(buf)], (void *) error, varint_len(error));
    free(error);
    varint *reason_len = write_var_int_62(strlen(reason));
    memcpy((void *) &buf[strlen(buf)], (void *) reason_len, varint_len(reason_len));
    free(reason_len);
    snprintf(&buf[strlen(buf)], strlen(reason) + 1, "%s", reason);
}

/**
 * @brief Writes a RESET_STREAM frame into a buffer
 *
 * @param stream_id         the ID of the stream to be reset
 * @param appl_error_code   the application error code
 * @param buf               the buffer to which write the stream
 */
void new_reset_stream_frame(stream_id stream_id, uint64_t appl_error_code, char *buf) {
    varint *vi_stream_id = write_var_int_62(stream_id);
    size_t len = varint_len(vi_stream_id);
    memcpy((void *) buf, (void *) vi_stream_id, len);
    buf += len;
    free(vi_stream_id);

    varint *vi_err_code = write_var_int_62(appl_error_code);
    len += varint_len(vi_err_code);
    memcpy((void *) buf, (void *) vi_err_code, len);
    buf += len;
    free(vi_err_code);
}

/**
 * @brief Writes a new STREAM frame to a buffer
 *
 * @param stream_id     the stream ID
 * @param offset        the frame offset
 * @param length        the frame length
 * @param data          the frame data
 * @param buf           the buffer to which store the frame
 * @return              the final STREAM frame size
 */
size_t new_stream_frame(stream_id stream_id, size_t offset, size_t length, bool fin, char *data, char *buf) {
    size_t written = 0;

    uint8_t type = TYPE_STREAM_BASE;
    if (offset != 0)
        type |= 0x04;
    if (length != 0)
        type |= 0x02;
    if (fin)
        type |= 0x01;

    varint *vi = write_var_int_62(type);
    size_t len = varint_len(vi);
    memcpy((void *) (buf + written), (void *) vi, len);
    written += len;
    free(vi);

    vi = write_var_int_62(stream_id);
    len = varint_len(vi);
    memcpy((void *) (buf + written), (void *) vi, len);
    written += len;
    free(vi);

    if (offset != 0) {
        varint *vi_offset = write_var_int_62(offset);
        len = varint_len(vi_offset);
        memcpy((void *) (buf + written), (void *) vi_offset, len);
        written += len;
        free(vi_offset);
    }

    if (length != 0) {
        varint *vi_length = write_var_int_62(length);
        len = varint_len(vi_length);
        memcpy((void *) (buf + written), (void *) vi_length, len);
        written += len;
        free(vi_length);
        memcpy(buf + written, data, length);
        written += length;
        return written;
    } else
        return snprintf((void *) (buf + written), 255, "%s", data);
}

/**
 * @brief Writes a frame into a buffer
 *
 * @param frame the frame to be written
 * @param len   the number of bytes written
 * @return      a pointer to the memory where the frame is written
 */
char *write_frame_into_buf(frame *frame, size_t *len) {
    char *buffer;
    uint8_t frame_type = frame->type;
    switch (frame_type) {
        case TYPE_PADDING:
        case TYPE_PING:
        case TYPE_HANDSHAKE_DONE: {
            buffer = malloc(sizeof(frame->type));
            if (buffer == NULL) {
                log_quic_error("Error while allocating buffer memory");
                break;
            }
            memcpy((void *) buffer, (void *) write_var_int_62(frame->type), 1);
            *len = 1;
            return buffer;
        }
        case TYPE_ACK: {
            ack_frame *ack = (ack_frame *) frame;
            varint *frame_type_vi = write_var_int_62(ack->type);
            varint *largest_acked = write_var_int_62(ack->largest_acked);
            size_t largest_size = varint_len(largest_acked);
            varint *ack_delay = write_var_int_62(ack->ack_delay >> ACK_DELAY_EXP);
            size_t delay_size = varint_len(ack_delay);
            varint *range_count = write_var_int_62(ack->ack_range_count);
            size_t range_size = varint_len(range_count);
            varint *first_range = write_var_int_62(ack->first_ack_range);
            size_t first_range_size = varint_len(first_range);
            size_t size = sizeof(ack->type) + largest_size + delay_size + range_size +
                          first_range_size + sizeof(ack_range) * ack->ack_range_count;
            buffer = calloc(1, size);
            *len = size;
            char *buf = buffer;
            if (buf == NULL) {
                log_quic_error("Error while allocating buffer memory");
                return NULL;
            }
            memcpy((void *) buf, (void *) frame_type_vi, varint_len(frame_type_vi));
            buf += varint_len(frame_type_vi);
            memcpy((void *) buf, (void *) largest_acked, largest_size);
            buf += largest_size;
            memcpy((void *) buf, (void *) ack_delay, delay_size);
            buf += delay_size;
            memcpy((void *) buf, (void *) range_count, range_size);
            buf += range_size;
            memcpy((void *) buf, (void *) first_range, first_range_size);
            buf += first_range_size;
            for (int i = 0; i < ack->ack_range_count; i++) {
                memcpy((void *) buf, (void *) ack->ranges[i], sizeof(ack_range));
                buf += sizeof(ack_range);
            }
            return buffer;
        }
        case TYPE_RESET_STREAM: {
        }
        case TYPE_STOP_SENDING: {
        }
        case TYPE_NEW_TOKEN: {
        }
        case TYPE_STREAM_BASE: {
        }
        case TYPE_MAX_DATA: {
        }
        case TYPE_MAX_STREAM_DATA: {
        }
        case TYPE_MAX_STREAMS_BIDI: {
        }
        case TYPE_MAX_STREAMS_UNI: {
        }
        case TYPE_DATA_BLOCKED: {
        }
        case TYPE_STREAM_DATA_BLOCKED: {
        }
        case TYPE_STREAMS_BLOCKED_BIDI: {
        }
        case TYPE_STREAMS_BLOCKED_UNI: {
        }
        case TYPE_NEW_CONNECTION: {
        }
        case TYPE_RETIRE_CONNECTION_ID: {
        }
        case TYPE_CONN_CLOSE_QUIC: {
        }
        case TYPE_CONN_CLOSE_APP: {
        }
        default: {
            log_quic_error("Unrecognized frame type.");
            return NULL;
        }
    }
    return NULL;
}

/**
 * @brief Evaluates an ACK frame length
 *
 * @param ack   the ACK frame
 * @return      the frame size in bytes
 */
ssize_t ack_frame_len(ack_frame *ack) {
    size_t len = 0;
    len += bytes_needed(ack->type);
    len += bytes_needed(ack->ack_delay);
}

/**
 * @brief Writes a Transfert message into packets
 *
 * Builds STREAM frames containing the Transfert
 * message, as many as needed to contain it.
 * Then, puts these frames into packets, as many
 * as needed. Each packet is then put into
 * the sender window.
 *
 * @param msg           the message to be written
 * @param stream_id     the stream ID
 * @param stream_fin    if true, the final STREAM frame will be marked with a FIN bit
 * @param conn          the QUICLite connection
 * @return              0 on success, -1 on errors
 */
int write_message_to_packets(char *msg, stream_id stream_id, bool stream_fin, quic_connection *conn) {
    size_t written = 0, msg_len = strlen(msg), i = 0;
    // Evaluates how many STREAM frames are needed to store
    // the message. Each STREAM frame is 255 bytes long.
    size_t streams_num = ceil((double) msg_len / 255);
    char **streams = (char **) calloc(streams_num, sizeof(char *));
    size_t final_size = 0;
    do {
        if (msg_len > 255) {
            streams[i] = (char *) calloc(1, bytes_needed(TYPE_STREAM_BASE) + 255 + bytes_needed(stream_id) +
                                            bytes_needed(written) + bytes_needed(255));
            final_size += new_stream_frame(
                    stream_id,
                    written,
                    255,
                    false,
                    msg,
                    streams[i]
            );
            written += 255;
        } else {
            if (written == 0)
                streams[i] = (char *) calloc(1,
                                             bytes_needed(TYPE_STREAM_BASE) + msg_len + bytes_needed(stream_id) +
                                             bytes_needed(msg_len - written));
            else
                streams[i] = (char *) calloc(1,
                                             bytes_needed(TYPE_STREAM_BASE) + msg_len + bytes_needed(stream_id) +
                                             bytes_needed(written) +
                                             bytes_needed(msg_len - written));
            final_size += new_stream_frame(
                    stream_id,
                    written,
                    msg_len - written,
                    stream_fin,
                    msg,
                    streams[i]
            );
            written += msg_len - written;
        }
        i++;
    } while (written < msg_len);

    // Builds packets of maximum size MAX_UDP_PAYLOAD and enqueue them
    written = 0;
    do {
        one_rtt_packet *one_rtt = (one_rtt_packet *) calloc(1, sizeof(one_rtt_packet));
        outgoing_packet *pkt = (outgoing_packet *) calloc(1, sizeof(outgoing_packet));
        size_t size;
        pkt->space = APPLICATION_DATA;
        pkt->in_flight = false;
        pkt->ack_eliciting = true;
        pkt->lost = false;
        pkt->acked = false;
        // Considering a sequence of packets 1,...,N, then packets
        // from 1 to N-1 have size MAX_DATAGRAM_SIZE, while N-th
        // packet's length covers the remaining bytes
        if (final_size > MAX_DATAGRAM_SIZE) {
            build_one_rtt_packet(get_random_peer_conn_id(conn), MAX_DATAGRAM_SIZE,
                                 conn->swnd->largest_in_space[APPLICATION_DATA] + 1, streams[written],
                                 one_rtt);
            size = one_rtt_pkt_len(one_rtt);
            pkt->pkt = calloc(1, size);
            pkt->length = size;
            pkt->pkt_num = one_rtt->packet_number;
            write_one_rtt_packet_to_buffer_for_forwarding(pkt->pkt, one_rtt);
            written += MAX_DATAGRAM_SIZE;
        } else {
            // Last packet
            conn_id cid = get_random_peer_conn_id(conn);
            build_one_rtt_packet(cid, final_size,
                                 conn->swnd->largest_in_space[APPLICATION_DATA] + 1, streams[written],
                                 one_rtt);
            size = one_rtt_pkt_len(one_rtt);
            pkt->pkt = calloc(1, size);
            pkt->length = size;
            pkt->pkt_num = one_rtt->packet_number;
            write_one_rtt_packet_to_buffer_for_forwarding(pkt->pkt, one_rtt);
            written = final_size;
        }
        if (enqueue(pkt, conn) == 0) {
            log_msg("Packet ready_to_send");
        } else {
            log_quic_error("Error while enqueuing packet");
        }
    } while (written < final_size);
    return 0;
}

/**
 * @brief Writes a response message into STREAM frames
 *
 * @param msg               the message to be written
 * @param response_frames   an array of pointers to the response frames
 * @return                  the number of created response frames, -1 on errors
 */
size_t create_response_frames(char *msg, stream_id sid, size_t frames_num, frame **response_frames) {
    size_t i, written = 0, final_size = 0;
    size_t len = strlen(msg);
    for (i = 0; i < frames_num; i++) {
        response_frames[i] = (frame *) calloc(1, sizeof(frame));
        response_frames[i]->type = TYPE_STREAM_BASE;
        if (len - written >= 255) {
            response_frames[i]->frame_data = calloc(1, 1 + 255 + bytes_needed(written) + bytes_needed(255));
            final_size += new_stream_frame(sid, written, 255, false, msg + written, response_frames[i]->frame_data);
            written += 255;
        } else {
            response_frames[i]->frame_data = calloc(1, 1 + len - written + bytes_needed(written) +
                                                       bytes_needed(len - written));
            final_size += new_stream_frame(sid, written, len - written, false, msg + written,
                                           response_frames[i]->frame_data);
            written += len - written;
        }
    }
    return final_size;
}
