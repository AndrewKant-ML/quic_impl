//
// Created by andrea on 13/09/23.
//

#include <stdio.h>
#include <string.h>

#include "messages.h"

/**
 * @brief Creates a command transfert_msg
 *
 * @param buf       the buffer where to store the transfert_msg
 * @param cmd       the Transfert command
 * @param file_name the file name (optional)
 * @return          the transfert_msg size in bytes, or 0 on errors
 */
size_t create_cmd_message(char *buf, char cmd[], char *file_name) {
    size_t bytes;
    if ((file_name == NULL || strlen(file_name) == 0) && strcmp(cmd, CMD_LIST) == 0) {
        bytes = strlen(cmd);
        memcpy(buf, cmd, bytes);
        return bytes;
    } else {
        size_t file_len = strlen(file_name);
        if (file_len > 0) {
            bytes = strlen(cmd) + file_len + 1;
            char *message = (char *) malloc(bytes + 1);
            if (snprintf(message, bytes + 1, "%s %s", cmd, file_name) > 0) {
                memcpy(buf, message, bytes);
                return bytes;
            }
        }
    }
    return 0;
}

/**
 * @brief Create a response transfert_msg
 *
 * @param buf       the buffer where to store the transfert_msg
 * @param sc        the response status code
 * @param message   the response transfert_msg text
 * @param data      the optional response data (only if the command was list)
 * @return          the response size in bytes, or 0 on errors
 */
size_t create_res_message(char *buf, status_code sc, char *message, char *data) {
    // TODO implement after defining status codes
}

/**
 * @brief Writes a data transfert_msg into a file
 *
 * Writes a data transfert_msg into a file by using its descriptor,
 * with the format <br>
 *
 * <code> file_name &lt;SP&gt; size &lt;SP&gt; off &lt;SP&gt; len &lt;CRLF&gt; <br> data.. </code>
 *
 * @param fd        the file descriptor
 * @param file_name the file name
 * @param size      the total size of the file
 * @param off       the offset of the data field
 * @param len       the length of the data field
 * @param data      a portion of the file to be written
 * @return          the number of written byte, or 0 on errors
 */
size_t create_data_msg(char *buf, char *file_name, size_t size, size_t off, size_t len, void *data) {
    // 5 additional bytes for 3 <SP>, one <CRLF> (2 bytes) and terminating null byte
    size_t file_len = strlen(file_name);
    if (file_len > 0) {
        size_t info_bytes = 3 * sizeof(size_t) + file_len + 6;
        void *info_string = malloc(info_bytes);
        if (info_string != NULL &&
            snprintf(info_string, info_bytes, "%s %zu %zu %zu\r\n", file_name, size, off, len) > 0) {
            size_t bytes = info_bytes - 1 + len;    // Info + data bytes (excluding terminating null byte)
            if (buf != NULL) {
                // Copies string to buffer, except for terminating null byte
                memcpy(buf, info_string, info_bytes - 1);
                // Copies data at the end of the buffer
                memcpy(buf + info_bytes - 1, data, len);
                return bytes;
            }
        }
    }
    return 0;
}