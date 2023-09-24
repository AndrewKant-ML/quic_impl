//
// Created by andrea on 22/09/23.
//

#include "base.h"
#include "quic_errors.h"

int get_time(struct timespec *val) {
    if (clock_gettime(CLOCK_REALTIME, val) == -1) {
        print_quic_error("Cannot get current time.");
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