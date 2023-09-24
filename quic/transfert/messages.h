//
// Created by andrea on 12/09/23.
//

#ifndef MESSAGES
#define MESSAGES

#include <stddef.h>
#include <stdlib.h>
#include "../quic_conn.h"

#define MAX_MSG_LEN

typedef unsigned short status_code;

#define CMD_LIST "list"
#define CMD_GET "read"
#define CMD_PUT "put_in_sender_window"

size_t create_cmd_message(char *, char [], char *);

size_t create_res_message(char *, status_code, char *, char *);

size_t create_data_msg(char *, char *, size_t, size_t, size_t, void *);

int parse_cmd_message(char *);

int parse_res_message(char *);

int parse_data_message(char *);

#endif //MESSAGES
