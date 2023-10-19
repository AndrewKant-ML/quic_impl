/*
 * QUICLite server.
 * General lifecycle:
 * 1 - Read incoming data from a client
 * 2 - Insert packets into receiver window
 * 3 - Process received packets
 * 4 - Build response packets
 * 5 - Send as many packets as possible
 */

#include "quic_server.h"

int listensd;
struct sockaddr_in serveraddr, cliaddr;
socklen_t len;
quic_connection *cli_conn;

int start_server(int port) {
    if ((listensd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        log_quic_error("Unable to create socket.");
        exit(EXIT_FAILURE);
    }

    memset((void *) &serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;                            // Address family IPv4
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);     // Accepts incoming packets from any network interface
    serveraddr.sin_port = htons(port);                  // Server port: 501

    // Binds server address to socket
    if ((bind(listensd, (struct sockaddr *) &serveraddr, sizeof(serveraddr))) < 0) {
        log_quic_error("Unable to bind socket to address.");
        exit(EXIT_FAILURE);
    }

    // Sets client address to 0
    memset((void *) &cliaddr, 0, sizeof(cliaddr));
    len = sizeof(cliaddr);

    // Init active connections array
    init();

    char *buff = calloc(1, sizeof(char) * MAX_DATAGRAM_SIZE);
    ssize_t n;

    fd_set fdset = {0};
    FD_ZERO(&fdset);
    FD_SET(listensd, &fdset);

    struct timeval tv = {0};
    tv.tv_sec = 3;
    tv.tv_usec = 0;

    int ret;

    for (;;) {
        ret = select(listensd + 1, &fdset, NULL, NULL, &tv);
        if (ret < 0) {
            log_quic_error("select() error");
        } else if (ret == 0) {
            //log_msg("select() timeout");
        } else {
            // Reads incoming data in non-blocking mode
            if (FD_ISSET(listensd, &fdset)) {
                n = recvfrom(listensd, buff, MAX_DATAGRAM_SIZE, 0, (struct sockaddr *) &cliaddr, &len);
                time_ms curr_time = get_time_millis();
                if (n > 0) {
                    // 1200 bytes is the minimum acceptable datagram size
                    if (n >= MIN_DATAGRAM_SIZE) {
                        if (process_incoming_dgram(buff, n, SERVER, &cliaddr, curr_time, &process_connection_request) >
                            0) {
                            cli_conn = select_connection_r(DEFAULT_TIMER);
                            if (cli_conn != NULL) {
                                // Send data on the connection
                                if (process_received_packets(cli_conn) == 0)
                                    log_quic_error("Error while processing incoming packets packets from client");
                                else
                                    log_msg("Packets processed");
                            }
                            cli_conn = select_connection_s(DEFAULT_TIMER);
                            if (cli_conn != NULL) {
                                // Send data on the connection
                                if (send_packets(listensd, cli_conn) != 0)
                                    log_quic_error("Error while sending packets to client");
                                else
                                    log_msg("Packets sent");
                            }
                        } else {
                            // Error while processing packet
                            log_quic_error("Error while processing packets from client.");
                        }
                    } else {
                        log_quic_error("Incoming datagram is too short.");
                    }
                }
            }
        }
        // Reset client address struct
        memset((void *) &cliaddr, 0, sizeof(cliaddr));
        FD_SET(listensd, &fdset);
    }
}

/**
 * @brief Process an incoming connection request from the client
 *
 * @param initial_pkt   the Initial packet sent from the client
 * @param addr          source IP address and UDP port of incoming packet
 * @param receive_time  the packet receive time
 * @return              0 on success, -1 on errors
 */
int
process_connection_request(initial_packet *initial_pkt, struct sockaddr_in *addr, time_ms receive_time) {
    // New connection, start server-side handshake
    quic_connection *conn = calloc(1, sizeof(quic_connection));
    if (new_connection(conn, SERVER) != 0) {
        log_quic_error("Error while creating new connection");
        free_conn(conn);
        return -1;
    }

    // Copies sender address and port into the connection struct
    memcpy(&(conn->addr), addr, sizeof(conn->addr));

    if (read_transport_parameters(initial_pkt, conn, SERVER) == -1) {
        // TODO Must close connection with error TRANSPORT_PARAMETER_ERROR
        close_connection_with_error_code(listensd, initial_pkt->src_conn_id, get_random_local_conn_id(conn),
                                         conn, TRANSPORT_PARAMETER_ERROR,
                                         "Forbidden transport parameter");
        free_conn(conn);
        return -1;
    }
    conn->peer_conn_ids = (conn_id *) calloc(conn->peer_conn_ids_limit, sizeof(conn_id));
    conn->peer_conn_ids[0] = initial_pkt->src_conn_id;
    conn->peer_conn_ids_num++;

    conn->last_active = receive_time;
    // If everything is ok, sends an Initial packet with an ACK frame to the client
    ack_frame ack;
    time_ms curr_time, ack_delay = receive_time;
    if ((curr_time = get_time_millis()) == -1) {
        log_quic_error("Error while getting current time.");
        return -1;
    }
    ack_delay += curr_time;
    new_ack_frame(initial_pkt->packet_number, ack_delay, 0, 0, NULL, &ack);
    size_t payload_len;
    char *payload = write_frame_into_buf((frame *) &ack, &payload_len);
    initial_packet new_init_pkt;
    build_initial_packet(initial_pkt->src_conn_id, conn->local_conn_ids[0], payload_len,
                         9, (void *) payload,
                         conn->swnd->largest_in_space[INITIAL] + 1, &new_init_pkt);
    // Sets initial packet transport parameters
    transport_parameter parameters[9];
    build_server_transport_params(parameters, new_init_pkt.dest_conn_id, initial_pkt->src_conn_id);
    for (int i = 0; i < 9; i++) {
        new_init_pkt.transport_parameters[i].id = parameters[i].id;
        new_init_pkt.transport_parameters[i].value = parameters[i].value;
    }
    outgoing_packet *pkt = (outgoing_packet *) calloc(1, sizeof(outgoing_packet));
    pkt->pkt_num = new_init_pkt.packet_number;
    pkt->length = new_init_pkt.length;
    pkt->space = INITIAL;
    pkt->acked = false;
    pkt->in_flight = false;
    pkt->lost = false;
    pkt->ack_eliciting = true;
    pkt->send_time = 0;
    pkt->pkt = calloc(1, initial_pkt_len(&new_init_pkt));

    write_initial_packet_to_buffer_for_forwarding(pkt->pkt, &new_init_pkt);

    // Tries to enqueue packets. If the sender
    // window is full, send packets
    int enqueued;
    do {
        enqueued = enqueue(pkt, conn);
        // Send packets if the window is full
        if (enqueued == -1)
            send_packets(listensd, conn);
    } while (enqueued != 0);

    if (send_packets(listensd, conn) != 0) {
        log_quic_error("Error while sending first server initial packet.");
        return -1;
    }
    return 0;
}

/**
 * @brief Builds server's transport parameters
 *
 * @param parameters        the transport parameters
 * @param init_src          the initial source connection ID
 * @param origin_dest_id    the original destination connection ID sent by the client
 */
void build_server_transport_params(transport_parameter parameters[9], conn_id init_src, conn_id origin_dest_id) {
    transport_parameter param;

    param.id = original_destination_connection_id;
    param.value = origin_dest_id;
    parameters[0] = param;

    param.id = max_idle_timeout;
    param.value = MAX_IDLE_TIMEOUT_MS;
    parameters[1] = param;

    param.id = max_udp_payload_size;
    param.value = MAX_DATAGRAM_SIZE;
    parameters[2] = param;

    param.id = initial_max_streams_bidi;
    param.value = MAX_STREAMS_BIDI;
    parameters[3] = param;

    param.id = initial_max_streams_uni;
    param.value = MAX_STREAMS_UNI;
    parameters[4] = param;

    param.id = ack_delay_exponent;
    param.value = ACK_DELAY_EXP;
    parameters[5] = param;

    param.id = max_ack_delay;
    param.value = MAX_ACK_DELAY;
    parameters[6] = param;

    param.id = active_connection_id_limit;
    param.value = MAX_CONNECTION_IDS;
    parameters[7] = param;

    param.id = initial_source_connection_id;
    param.value = init_src;
    parameters[8] = param;
}
