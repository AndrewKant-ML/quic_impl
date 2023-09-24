//
// Created by andrea on 16/09/23.
//

#include <stdio.h>

#include "quic_errors.h"

void print_quic_error(char *err_msg) {
    fprintf(stderr, "\033[1;31m QUICLite error: %s\n \033[1;0m", err_msg);
}