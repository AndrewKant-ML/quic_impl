//
// Created by andrea on 13/09/23.
//

#include "errors.h"

void print_error(char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
}

void print_error_verbose(char *msg) {
    fprintf(stderr, "Error: %s\nErrno: %d (%s)", msg, errno, strerror(errno));
}