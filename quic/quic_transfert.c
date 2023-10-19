//
// Created by andrea on 05/10/23.
//

#include "quic_transfert.h"

/**
 * @brief Processes file sending requests
 *
 * @param conn  the QUICLite connection
 * @return      0 on success, -1 on errors
 */
int process_file_requests(quic_connection *conn) {
    for (int i = 0; i < TRANSFERT_MAX_REQUESTS; i++) {
        if (conn->sending_requests[i] != NULL) {
            int fd = exec_get_request(conn->sending_requests[i]);
            if (write_file_to_packets(fd, conn->sending_requests[i], conn) == -1) {
                log_quic_error("Errors while sending file");
                return -1;
            }
        }
    }
    return 0;
}

/**
 * @brief Removes a file sending requests
 *
 * @param file_name     the file name
 * @param conn          the QUICLite connection
 */
void remove_file_request(char *file_name, quic_connection *conn) {
    for (int i = 0; i < TRANSFERT_MAX_REQUESTS; i++) {
        if (strcmp(file_name, conn->sending_requests[i]) == 0) {
            free(conn->sending_requests[i]);
            conn->sending_requests[i] = NULL;
        }
    }
}

/**
 * @brief Writes a file into packets
 *
 * @param fd            the file descriptor
 * @param file_name     the file name
 * @param conn          the QUICLite connection
 * @return              0 on success, -1 on errors
 */
ssize_t write_file_to_packets(int fd, char *file_name, quic_connection *conn) {
    if (fd < 0) {
        // File does not exist
        log_quic_error("File does not exist");
        return -1;
    } else {
        // File exists

        // Creates first line
        char first_line[255] = {0};
        off_t file_size = lseek(fd, 0, SEEK_END);
        if (file_size == (off_t) -1) {
            log_quic_error("Error while seeking file end");
            return -1;
        }
        snprintf(first_line, 255, "%s %zu\r\n", file_name, file_size);

        // Opens new stream
        stream_id sid = new_stream_id(conn->peer_type, UNIDIRECTIONAL, conn);

        off_t off = 0;
        ssize_t res, written, rd = 0;
        char *buff;

        // Writes first line
        do {
            buff = (char *) calloc(1, 1024);
            written = snprintf(buff, 1024, "%s", first_line + off);
            off += written;
            if (written == 1024) {
                if (write_message_to_packets(buff, sid, false, conn) == -1) {
                    log_quic_error("Error while writing first line to packets");
                    return -1;
                }
            }
        } while (written >= 1024);

        // Read up to EOF
        while ((res = read(fd, buff + (off % 1024), 1024 - (off % 1024))) != 0) {
            if (res > 0) {
                // Something has been read
                rd += res;
                if (rd == file_size) {
                    // EOF reached
                    if (write_message_to_packets(buff, sid, true, conn) == -1) {
                        log_quic_error("Error while writing final file data to streams");
                        return -1;
                    }
                } else {
                    if (write_message_to_packets(buff, sid, false, conn) == -1) {
                        log_quic_error("Error while writing file data to streams");
                        return -1;
                    }
                }
                off += res;
            } else {
                // Read problems
                log_quic_error("Error while reading from file");
                return -1;
            }
        }
        remove_file_request(file_name, conn);
        return 0;
    }
}