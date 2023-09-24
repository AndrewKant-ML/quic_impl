//
// Created by andrea on 23/09/23.
//

#include "transfert_errors.h"

void print_transfert_error(char *err_msg) {
    fprintf(stderr, "\033[1;31m Transfert error: %s\n \033[1;0m", err_msg);
}