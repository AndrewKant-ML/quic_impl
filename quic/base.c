//
// Created by andrea on 22/09/23.
//

#include "base.h"

int get_time(struct timespec *val) {
    if (clock_gettime(CLOCK_REALTIME, val) == -1) {
        log_quic_error("Cannot get current time");
        return -1;
    }
    return 0;
}

long get_time_millis() {
    struct timespec time;
    if (get_time(&time) == 0) {
        return time.tv_sec * 1000 + time.tv_nsec / 1000000;
    }
    return -1;
}

void log_msg(char *msg) {
    time_t t;
    time(&t);
    printf("%s | QUICLite: %s.\n", strtok(ctime(&t), "\n"), msg);
}

void log_quic_error(char *err_msg) {
    time_t t;
    time(&t);
    fprintf(stderr, "\033[1;31m %s | QUICLite %s.\n \033[1;0m", strtok(ctime(&t), "\n"), err_msg);
}
