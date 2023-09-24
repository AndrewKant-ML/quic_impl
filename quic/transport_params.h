//
// Created by andrea on 21/09/23.
//

#ifndef QUIC_TRANSPORT_PARAMS
#define QUIC_TRANSPORT_PARAMS

#include "base.h"

// Definition of a single transport parameter
typedef struct transport_parameter_t {
    uint64_t id;
    uint64_t len;
    void *data;
} transport_parameter;


#endif //QUIC_TRANSPORT_PARAMS
