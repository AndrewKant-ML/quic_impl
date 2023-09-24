//
// Created by andrea on 22/09/23.
//

#include <malloc.h>
#include "transfert_base.h"

/**
 * @brief Checks a transfert_msg semantics
 * @param msg   the transfert_msg to be checked
 * @return      0 if the transfert_msg has right semantics, -1 otherwise
 */
int check_msg_semantics(char *msg) {
    regex_t regex;
    size_t i;
    regmatch_t pmatch[1];
    for (i = 0; i < 3; i++) {
        if (regcomp(&regex, PATTERNS[i], REG_ICASE) == 0) {
            // Successful compilation
            if (regexec(&regex, msg, 1, pmatch, 0) == 0) {
                if (pmatch[0].rm_so == 0 && strlen(msg) == (pmatch[0].rm_eo - pmatch[0].rm_so)) {
                    regfree(&regex);
                    return 0;
                }
            }
        }
    }
    regfree(&regex);
    return -1;
}

/**
 * @brief Gets the total length of a data transfert_msg
 * @param msg   the data transfert_msg
 * @return      the data transfert_msg length
 */
size_t data_msg_len(data_msg *msg) {
    return msg->length + 3 * sizeof(size_t) + strlen(msg->file_name);
}

/**
 * @brief Writes a data transfert_msg to a buffer
 * @param buf   the buffer to write to
 * @param msg   the transfert_msg to be written
 * @return      0 on success, -1 on errors
 */
int write_data_msg_to_buf(char *buf, data_msg *msg) {
    char *buffer = buf;
    char *first_line = malloc(data_msg_len(msg) - msg->length + 6);
    if (snprintf(buffer,
                 strlen(first_line) + 1,
                 first_line, "%s %d %d %d\r\n",
                 msg->file_name,
                 msg->size,
                 msg->offset,
                 msg->length) == strlen(first_line)) {
        memcpy((void *) buf, msg->data, msg->length);
        return 0;
    }
    return -1;
}

/**
 * @brief Gets the incoming transfert_msg type
 *
 * @param raw
 * @return
 */
enum message_type get_incoming_message_type(const char *raw) {
    if (strncmp(raw, CMD_LIST, 4) == 0)
        return LIST;
    if (strncmp(raw, CMD_GET, 3) == 0)
        return GET;
    if (strncmp(raw, CMD_PUT, 3) == 0)
        return PUT;
    return DATA;
}

/**
 * @brief Parses and executes a data transfert_msg
 *
 * Parses a data transfert_msg. Then, opens the specified file
 * and appends to it the bytes received with the transfert_msg.
 *
 * @param raw   the raw data transfert_msg received
 * @return      0 on success, -1 on errors
 */
int parse_and_exec_data_msg(char *raw) {
    data_msg data_msg;
    if (sscanf(raw,
               "%ms %zu %zu %zu\r\n",
               &data_msg.file_name,
               &data_msg.length,
               &data_msg.offset,
               &data_msg.size) == 4) {
        char *file_path = (char *) malloc(strlen(BASE_DIR) + strlen(data_msg.file_name) + 2);
        sprintf(file_path, "%s/%s", BASE_DIR, data_msg.file_name);
        /*FILE *fp = fopen(file_path, "a");
        if (fp == NULL) return -1;
        if (fwrite(data_msg.data, data_msg.size, 1, fp) != 1)
            return -1;*/

        return 0;
        return 0;
    }
    return -1;
}

int save_partial_data(transfert_msg *data_msg) {

}
