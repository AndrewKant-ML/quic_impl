//
// Created by andrea on 14/09/23.
//

#include <string.h>

#include "quic_client.h"

/**
 * @brief Tries to open a QUICLite connection towards the server
 *
 * Sends an Initial packet to the server, trying opening a
 * new connection. The server response is processed later.
 *
 * @param sd    the socket descriptor
 * @param conn  the connection
 * @return      0 on success, -1 on errors
 */
int quic_connect(int sd, quic_connection *conn) {
    // Creates new connection
    if (new_connection(conn, CLIENT) == 0) {
        // Sets arbitrary initial destination connection ID
        conn->local_conn_ids[0] = 1;
        conn->local_conn_ids_num = 1;
        transport_parameter *parameters = (transport_parameter *) calloc(8, sizeof(transport_parameter));
        build_client_transport_params(parameters, conn->local_conn_ids[0]);
        initial_packet initial_pkt;
        build_initial_packet(conn->peer_conn_ids[0], conn->local_conn_ids[0], 0, 8, NULL,
                             conn->swnd->largest_in_space[INITIAL] + 1, &initial_pkt);
        for (int i = 0; i < 8; i++) {
            initial_pkt.transport_parameters[i].id = parameters[i].id;
            initial_pkt.transport_parameters[i].value = parameters[i].value;
        }

        // Initial packet ready to be sent
        outgoing_packet *pkt = (outgoing_packet *) calloc(1, sizeof(outgoing_packet));
        pkt->space = INITIAL;
        pkt->pkt_num = initial_pkt.packet_number;
        pkt->length = initial_pkt_len(&initial_pkt);
        pkt->ack_eliciting = true;
        pkt->ready_to_send = false;
        pkt->acked = false;
        pkt->in_flight = false;
        pkt->send_time = 0;
        pkt->pkt = calloc(1, pkt->length);
        write_initial_packet_to_buffer_for_forwarding(pkt->pkt, &initial_pkt);

        // Enqueues packet
        if (enqueue(pkt, conn) != 0) {
            log_quic_error("Error while enqueuing packet");
            return -1;
        }
        // Sends enqueued packets
        if (send_packets(sd, conn) != 0) {
            log_quic_error("Cannot send packet to server");
            return -1;
        }
        log_msg("Sent connection opening request, waiting for the server to accept");
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
    param.value = MAX_IDLE_TIMEOUT_MS;
    parameters[0] = param;

    param.id = max_udp_payload_size;
    param.value = MAX_DATAGRAM_SIZE;
    parameters[1] = param;

    param.id = initial_max_streams_bidi;
    param.value = MAX_STREAMS_BIDI;
    parameters[2] = param;

    param.id = initial_max_streams_uni;
    param.value = MAX_STREAMS_UNI;
    parameters[3] = param;

    param.id = ack_delay_exponent;
    param.value = ACK_DELAY_EXP;
    parameters[4] = param;

    param.id = max_ack_delay;
    param.value = MAX_ACK_DELAY;
    parameters[5] = param;

    param.id = active_connection_id_limit;
    param.value = MAX_CONNECTION_IDS;
    parameters[6] = param;

    param.id = initial_source_connection_id;
    param.value = init_src;
    parameters[7] = param;
}