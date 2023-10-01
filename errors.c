//
// Created by andrea on 13/09/23.
//

#include "errors.h"

void print_error(char *msg) {
    time_t t;
    time(&t);
    fprintf(stderr, "%s | Transfert error: %s.\n", strtok(ctime(&t), "\n"), msg);
}

void print_log(char *msg) {
    time_t t;
    time(&t);
    printf("%s | Transfert: %s.\n", strtok(ctime(&t), "\n"), msg);
}