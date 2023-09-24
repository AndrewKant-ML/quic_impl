//
// Created by andrea on 12/09/23.
//

#include "server_func.h"

char *parse_and_exec_list_msg(char *raw) {
    if (check_msg_semantics(raw) == 0) {
        char *buf = calloc(1, 1024 * sizeof(char));
        DIR *dir = opendir(BASE_DIR);
        struct dirent *d;
        if (dir) {
            while ((d = readdir(dir)) != NULL) {
                if (d->d_type != DT_DIR) {
                    strcat(buf, "\r\n");
                    strcat(buf, d->d_name);
                }
            }
        }
        closedir(dir);
        return buf;
    }
    return NULL;
}

char *parse_get_or_put_msg(char *raw) {
    if (check_msg_semantics(raw) == 0) {
        char *file_name = (char *) malloc(128 * sizeof(char));
        strcpy(file_name, raw + 4);
        return file_name;
    }
    return NULL;
}

/**
 * @brief Writes a response message to a buffer
 *
 * @param code  the response code
 * @param list  the list response (nullable)
 * @param buf   the buffer to which store the response
 */
void write_response(uint8_t code, char *list, char *buf) {
    if (list != NULL) {
        // Response
        strcat(buf, (char *) &code);
        strcat(buf, "\r\n");
        strcat(buf, list);
    } else {
        // No response
        snprintf(buf, sizeof(code) + 1, "%u", code);
    }
}

/**
 * @brief Executes actions upon the received message
 * @param raw
 * @return
 */
char *exec(transfert_msg *msg) {
    switch (msg->type) {
        case LIST: {
            char *parsed = parse_and_exec_list_msg(msg->msg);
            if (parsed == NULL)
                print_transfert_error("LIST command bad formatting.");
            return parsed;
        }
        case GET: {
            char *file_name = parse_get_or_put_msg(msg->msg);
            if (file_name == NULL) {
                print_transfert_error("GET command bad formatting.");
                return NULL;
            } else
                // Execute GET request
                break;
        }
        case PUT: {
            char *file_name = parse_get_or_put_msg(msg->msg);
            if (file_name == NULL) {
                print_transfert_error("PUT command bad formatting.");
                return NULL;
            } else

                break;
        }
        case DATA:
            break;
    }
}