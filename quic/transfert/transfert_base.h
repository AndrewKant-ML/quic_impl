//
// Created by andrea on 12/09/23.
//

#ifndef TRANSFERT_BASE
#define TRANSFERT_BASE

#include <regex.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "messages.h"
#include "../base.h"

#define SERVER_PORT 5010

#define LIST_CMD_RGX "^list$"
#define GET_CMD_RGX "^get ([a-zA-Z]+\\/)*[a-zA-Z]+([\\.]{1}[a-zA-Z]+)*$"
#define PUT_CMD_RGX "^put_in_sender_window ([a-zA-Z]+\\/)*[a-zA-Z]+([\\.]{1}[a-zA-Z]+)*$"

static const char *PATTERNS[] = {LIST_CMD_RGX, GET_CMD_RGX, PUT_CMD_RGX};

#define BASE_DIR "./../files"

typedef struct data_msg_t {
    char *file_name;
    size_t size;
    size_t offset;
    size_t length;
    void *data;
} data_msg;

enum message_type {
    LIST,
    GET,
    PUT,
    DATA
};

struct transfert_msg_t {
    enum message_type type; // Transfert message type
    uint64_t stream_id;     // The ID of the stream containing the message
    char *msg;              // Actual transfert message contained in a STREAM frame
    size_t len;             // Stored message length
    size_t bytes_written;   // Counter for written bytes (<= len)
    bool end_reached;       // true: the message end has been store, false: it has not
};

void new_transfert_msg(transfert_msg *);

int check_msg_semantics(char *);

size_t data_msg_len(data_msg *);

int write_data_msg_to_buf(char *, data_msg *);

enum message_type get_incoming_message_type(const char *);

int parse_and_exec_data_msg(char *);

int save_partial_data(transfert_msg *);

#endif // TRANSFERT_BASE