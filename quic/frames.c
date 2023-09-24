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
    frame response_frames[100] = {};
    size_t generated_response_frames = 0;
    uint64_t frame_type = read_var_int_62((varint *) buf);
    bool generate_ack = false;
    if (frame_type >= TYPE_STREAM_BASE && frame_type <= TYPE_STREAM_BASE + 0x07) {
        generate_ack = true;
        // STREAM frame, check for fields
        buf++;
        stream_id stream_id = read_var_int_62((varint *) buf);
        size_t offset, length;
        buf += varint_len((varint *) buf);
        // Offset filed parsing
        offset = read_var_int_62((varint *) buf);
        buf += varint_len((varint *) buf);
        // Length field parsing
        length = read_var_int_62((varint *) buf);
        buf += varint_len((varint *) buf);
        bool end_stream = false;
        if ((frame_type & 0x01) == 0x01) {
            // Fin bit, end of stream
            end_stream = true;
        }

        // Check stream ID
        switch (conn->peer_type) {
            case SERVER: {
                if ((stream_id & STREAM_MASK) == STREAM_SRC_MASK + STREAM_SRC_MASK) {
                    print_quic_error("Server cannot accept server-initiated unidirectional stream.");
                    // TODO send RESET_STREAM frame with connection error 400
                    return -1;
                }

                // Server could receive stream, check message type
                transfert_msg msg;
                msg.type = get_incoming_message_type(buf);
                if ((stream_id & STREAM_MODE_MASK) == 0 && msg.type == DATA) {
                    // Server cannot accept DATA messages in bidirectional streams
                    print_quic_error("Server cannot accept DATA messages inside bidirectional streams.");
                    // TODO send RESET_STREAM frame with connection error 400
                    return -1;
                }
                if ((stream_id & STREAM_MODE_MASK) == STREAM_MODE_MASK && msg.type != DATA) {
                    // Server cannot accept LIST, GET or PUT messages
                    print_quic_error("Server cannot accept request messages inside bidirectional streams.");
                    // in unidirectional streams (cannot send back response)
                    // TODO send RESET_STREAM frame with connection error 400
                    return -1;
                }
                // Server can receive stream
                // Parse message and put in receiver window
                msg.stream_id = stream_id;
                msg.len = length + 1;
                msg.msg = calloc(1, msg.len);
                strncat(msg.msg, (void *) buf, msg.len - 1);
                msg.bytes_written = msg.len;
                msg.end_reached = end_stream;
                if (put_in_receiver_window(&(conn->rwnd), &msg, offset) == -1) {
                    print_quic_error("Error while inserting received message into receiver window.");
                    return -1;
                }
                /*if ((stream_id & STREAM_MODE_MASK) == 0)
                    // Bidirectional stream, server can only accept LIST, GET and PUT messages
                    switch (get_incoming_message_type(buf)) {
                        case LIST: {
                            char *res = parse_and_exec_list_msg(buf);
                            if (res == NULL) {
                                print_quic_error("LIST command bad format.");
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
                            *//*char *file_name = parse_get_or_put_msg(buf);
                            if (strlen(file_name) > 0) {
                                // File parsed, put message in receiver window
                                transfert_msg get_msg;
                                get_msg.type = GET;
                                get_msg.end_reached = end_stream;
                            } else {
                                // No specified file
                            }*//*


                            break;
                        }
                        case PUT:
                            break;
                        default: {
                            // Cannot accept this
                        }
                    }*/
                break;
            }
            case CLIENT: {
                if ((stream_id & STREAM_MASK) == STREAM_SRC_MASK) {
                    print_quic_error("Client cannot accept client-initiated unidirectional stream.");
                    // TODO send RESET_STREAM frame with connection error 400
                    return -1;
                }

                // Client could receive stream, check message type
                transfert_msg msg;
                msg.type = get_incoming_message_type(buf);
                if ((stream_id & STREAM_MODE_MASK) == 0) {
                    if (msg.type == DATA) {
                        print_quic_error("Client cannot accept DATA messages inside bidirectional streams.");
                        // TODO send RESET_STREAM frame with connection error 400
                        return -1;
                    } else {
                        // Client is waiting for a response
                        // Checks opened streams for the request
                        int i;
                        for (i = 0; i < conn->bidi_streams_num; i++) {
                            if (conn->bidi_streams[i]->id==stream_id) {
                                // Found request stream, put response into receiver window
                                msg.stream_id = stream_id;
                                msg.len = length + 1;
                                msg.msg = calloc(1, msg.len);
                                strncat(msg.msg, (void *) buf, msg.len - 1);
                                msg.bytes_written = msg.len;
                                msg.end_reached = end_stream;
                                if (put_in_receiver_window(&(conn->rwnd), &msg, offset) == -1) {
                                    print_quic_error("Error while inserting received message into receiver window.");
                                    return -1;
                                }
                                return 0;
                            }
                        }
                        return -1;
                    }
                } else {
                    // Unidirectional streams, client can accept only DATA messages
                    if (msg.type != DATA) {
                        print_quic_error("Client cannot accept request messages inside unidirectional streams.");
                        // TODO send RESET_STREAM frame with connection error 400
                        return -1;
                    }
                    // DATA message inside unidirectional stream, puts message into receiver window
                    msg.stream_id = stream_id;
                    msg.len = length + 1;
                    msg.msg = calloc(1, msg.len);
                    strncat(msg.msg, (void *) buf, msg.len - 1);
                    msg.bytes_written = msg.len;
                    msg.end_reached = end_stream;
                    if (put_in_receiver_window(&(conn->rwnd), &msg, offset) == -1) {
                        print_quic_error("Error while inserting received message into receiver window.");
                        return -1;
                    }
                    return 0;
                }
            }
        }
    }
    switch (frame_type) {
        case TYPE_PADDING: {
            // Do nothing
            break;
        }
        case TYPE_PING: {
            // Must ACK packet
            generate_ack = true;
            break;
        }
        case TYPE_ACK: {
            time_ms ack_time;
            if ((ack_time = get_time_millis()) == -1) {
                print_quic_error("Cannot get current time.");
                return -1;
            }
            ack_frame ack;
            if (parse_ack_frame(buf, &ack, conn, ack_time) == 0) {
                pkt_num largest, smallest;
                largest = ack.largest_acked;
                smallest = largest - ack.first_ack_range;
                if (ack_pkt_range(conn, smallest, largest, space) == 0) {
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
                    on_ack_received(conn, &ack, space, ack_time);
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
            print_quic_error("Unsupported frame type.");
            return -1;
        }
    }
    return 0;
}

/**
 * @brief Parses raw data into an ACK frame
 *
 * @param raw       the raw frame data
 * @param ack_frame the struct to where store the parsed data
 * @return          0 on success, -1 on errors
 */
int parse_ack_frame(const char *raw, ack_frame *ack_frame, const quic_connection *conn, time_ms ack_time) {
    ack_frame->type = TYPE_ACK;
    raw += sizeof(ack_frame->type);

    uint32_t largest_acked = read_var_int_62((varint *) raw);
    ack_frame->largest_acked = largest_acked;
    raw += sizeof(ack_frame->largest_acked);

    ack_frame->ack_delay = read_var_int_62((varint *) raw);
    raw += varint_len((varint *) raw);

    uint64_t ack_range_count = read_var_int_62((varint *) raw);
    ack_frame->ack_range_count = ack_range_count;
    raw += sizeof(ack_range_count);

    ack_frame->first_ack_range = read_var_int_62((varint *) raw);
    raw += sizeof(ack_frame->first_ack_range);

    ack_frame->ranges = (ack_range **) malloc(ack_range_count * sizeof(ack_range *));
    ack_range range;
    for (int i = 0; i < ack_range_count; i++) {
        ack_frame->ranges[i] = malloc(sizeof(ack_range));
        range.gap = read_var_int_62((varint *) raw);
        raw += sizeof(range.gap);
        range.ack_range_len = read_var_int_62((varint *) raw);
        raw += sizeof(range.ack_range_len);
        memcpy(ack_frame->ranges[i], &range, sizeof(range));
        // Resets buffer space
        explicit_bzero(&range, sizeof(range));
    }
    return 0;
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
 */
void new_stream_frame(stream_id stream_id, size_t offset, size_t length, char *data, char *buf) {
    varint *vi_stream_id = write_var_int_62(stream_id);
    size_t len = varint_len(vi_stream_id);
    memcpy((void *) buf, (void *) vi_stream_id, len);
    buf += len;
    free(vi_stream_id);

    varint *vi_offset = write_var_int_62(offset);
    len = varint_len(vi_offset);
    memcpy((void *) buf, (void *) vi_offset, len);
    buf += len;
    free(vi_offset);

    varint *vi_length = write_var_int_62(length);
    len = varint_len(vi_length);
    memcpy((void *) buf, (void *) vi_length, len);
    buf += len;
    free(vi_length);

    snprintf(buf, len, "%s", data);
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
                print_quic_error("Error while allocating buffer memory");
                break;
            }
            memcpy((void *) buffer, (void *) write_var_int_62(frame->type), 1);
            *len = 1;
            return buffer;
        }
        case TYPE_ACK: {
            ack_frame *ack = (ack_frame *) frame;
            varint *largest_acked = write_var_int_62(ack->largest_acked);
            size_t largest_size = varint_len(largest_acked);
            varint *ack_delay = write_var_int_62(ack->ack_delay);
            size_t delay_size = varint_len(ack_delay);
            varint *range_count = write_var_int_62(ack->ack_range_count);
            size_t range_size = varint_len(range_count);
            varint *first_range = write_var_int_62(ack->first_ack_range);
            size_t first_range_size = varint_len(first_range);
            size_t size = sizeof(ack->type) + largest_size + delay_size + range_size +
                          first_range_size + sizeof(ack_range) * ack->ack_range_count;
            buffer = malloc(size);
            *len = size;
            char *buf = buffer;
            if (buf == NULL) {
                print_quic_error("Error while allocating buffer memory");
                return NULL;
            }
            memcpy((void *) buf, (void *) &(ack->type), sizeof(uint8_t));
            buf += sizeof(uint8_t);
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
            print_quic_error("Unrecognized frame type.");
            return NULL;
        }
    }
    return NULL;
}
