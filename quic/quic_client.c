//
// Created by andrea on 14/09/23.
//

#include <string.h>

#include "quic_client.h"

/**
 * @brief Opens a QUICLite connection towards the server
 *
 * @param sd    the socket descriptor
 * @param conn  the connection
 * @return      0 on success, -1 on errors
 */
int quic_connect(int sd, quic_connection *conn) {
    // Creates new connection
    if (new_connection(conn, CLIENT) == 0) {
        // Sets arbitrary initial destination connection ID
        conn->peer_conn_ids[0] = 1;
        transport_parameter *parameters = (transport_parameter *) malloc(8 * sizeof(transport_parameter));
        build_client_transport_params(parameters, conn->local_conn_ids[0]);
        initial_packet initial_pkt;
        build_initial_packet(conn->peer_conn_ids[0], conn->local_conn_ids[0], write_var_int_62(0), NULL,
                             write_var_int_62(0), write_var_int_62(8), NULL, &initial_pkt);
        for (int i = 0; i < 8; i++) {
            initial_pkt.transport_parameters[i] = (transport_parameter *) malloc(sizeof(transport_parameter));
            memcpy((void *) initial_pkt.transport_parameters[i], (void *) &parameters[i], sizeof(transport_parameter));
        }

        // Initial packet ready to be sent
        packet pkt;
        pkt.space = INITIAL;
        pkt.pkt_num = initial_pkt.packet_number;
        pkt.length = initial_pkt_len(&initial_pkt);
        pkt.ack_eliciting = true;
        pkt.acked = false;
        pkt.in_flight = false;
        pkt.send_time = 0;

        if (enqueue(&pkt, conn) == 0) {
            if (send_packets(sd, conn) != 0)
                print_quic_error("Cannot send packet to server.");
        } else
            print_quic_error("Error while enqueuing packet.");
        return 0;
    }
    return -1;
}

/**
 * @brief Builds client transport parameters
 *
 * @param parameters    memory area to which store the transport parameters
 * @param init_src      initial source connection ID
 */
void build_client_transport_params(transport_parameter parameters[8], conn_id init_src) {
    transport_parameter param;

    param.id = max_idle_timeout;
    param.data = (void *) write_var_int_62(MAX_IDLE_TIMEOUT_MS);
    param.len = varint_len((varint *) param.data);
    parameters[0] = param;

    param.id = max_udp_payload_size;
    param.data = (void *) write_var_int_62(MAX_DATAGRAM_SIZE);
    param.len = varint_len((varint *) param.data);
    parameters[1] = param;

    param.id = initial_max_streams_bidi;
    param.data = (void *) write_var_int_62(MAX_STREAMS_BIDI);
    param.len = varint_len((varint *) param.data);
    parameters[2] = param;

    param.id = initial_max_streams_uni;
    param.data = (void *) write_var_int_62(MAX_STREAMS_UNI);
    param.len = varint_len((varint *) param.data);
    parameters[3] = param;

    param.id = ack_delay_exponent;
    param.data = (void *) write_var_int_62(ACK_DELAY_EXP);
    param.len = varint_len((varint *) param.data);
    parameters[4] = param;

    param.id = max_ack_delay;
    param.data = (void *) write_var_int_62(MAX_ACK_DELAY);
    param.len = varint_len((varint *) param.data);
    parameters[5] = param;

    param.id = active_connection_id_limit;
    param.data = (void *) write_var_int_62(MAX_CONNECTION_IDS);
    param.len = varint_len((varint *) param.data);
    parameters[6] = param;

    param.id = initial_source_connection_id;
    param.data = (void *) write_var_int_62(init_src);
    param.len = varint_len((varint *) param.data);
    parameters[7] = param;
}