//
// Created by andrea on 14/09/23.
//

#include "client.h"

char *serv_addr = "127.0.0.1";
int serv_port = 5010;
double loss_prob = 0.2;
int verbose = 0;

int main(int argc, char *argv[]) {

    process_arguments(argc, argv);

    int sock;
    int i, read, maxd;
    ssize_t n;
    socklen_t addr_len;
    struct sockaddr_in addr;
    char msg[255];
    char buf[UDP_BUF_SIZE];
    fd_set rset;
    FD_ZERO(&rset);
    time_ms curr_time;

    // Client socket creation
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        print_error("Unable to create client socket.");
        exit(EXIT_FAILURE);
    }
    print_log("Socket created");

    // Address initialization
    memset((void *) &addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(serv_port);

    // Address building
    if (inet_pton(AF_INET, serv_addr, &addr.sin_addr) <= 0) {
        print_error("Unable to parse server address. Please use IPv4 dotted-decimal notation.");
        exit(EXIT_FAILURE);
    }
    addr_len = sizeof(addr);
    print_log("Address parsed");

    // Sends connection opening request to the server
    quic_connection *conn = (quic_connection *) calloc(1, sizeof(quic_connection));
    conn->addr = addr;
    if (quic_connect(sock, conn) == 0) {
        // Waits for server data
        while (1) {
            if (conn->handshake_done) {
                printf("Insert a command: ");
                fflush(stdout);
                FD_SET(fileno(stdin), &rset);
            }
            FD_SET(sock, &rset);
            maxd = MAX(fileno(stdin), sock) + 1;
            if (select(maxd, &rset, NULL, NULL, NULL) < 0) {
                print_error("Select error.");
                exit(EXIT_FAILURE);
            }

            // Checks if socket is readable
            if (FD_ISSET(sock, &rset)) {
                // Must read something
                if ((n = recvfrom(sock, buf, sizeof buf, 0, NULL, NULL)) < 0) {
                    print_error("Error while reading from socket");
                    // todo close everything
                }

                if (n >= MIN_DATAGRAM_SIZE) {
                    printf("%s\n\n\n", buf);
                    if ((curr_time = get_time_millis()) < 0) {
                        log_quic_error("Cannot get current time");
                    } else if (process_incoming_dgram(buf, n, CLIENT, &addr, curr_time, NULL) != -1) {
                        if (conn->rwnd->write_index != conn->rwnd->read_index) {
                            // There are packets in the receiver window
                            if (process_received_packets(conn) != -1)
                                log_msg("Packets processes successfully");
                            else
                                log_quic_error("Error while processing received packets");
                        }
                    } else {
                        log_quic_error("Error while processing incoming datagram");
                    }
                } else {
                    log_quic_error("Incoming datagram is too short");
                }
            }

            if (process_file_requests(conn) == -1)
                log_quic_error("Error while processing file requests");

            if (conn->swnd->write_index != conn->swnd->read_index) {
                // There are packets to send
                if (send_packets(sock, conn) == 0)
                    log_msg("Packets sent successfully");
                else
                    log_quic_error("Error while sending enqueued packets");
            }

            if (FD_ISSET(fileno(stdin), &rset)) {
                if (scanf("%s", msg) == 1) {
                    if (check_msg_semantics(msg) == 0) {
                        // TODO build and send packet
                        stream_id sid;
                        switch (get_message_type(msg)) {
                            case LIST: {
                                if ((sid = open_stream(CLIENT, BIDIRECTIONAL, conn)) != (stream_id) -1) {
                                    if (write_message_to_packets(msg, sid, false, conn) != 0)
                                        log_quic_error("Error while creating message packets");
                                    else
                                        log_msg("Successfully sent LIST command");
                                }
                                break;
                            }
                            case GET: {
                                break;
                            }
                            case PUT: {
                                if ((sid = open_stream(CLIENT, BIDIRECTIONAL, conn)) != (stream_id) -1) {
                                    // Sends data to stream
                                    if (write_message_to_packets(msg, sid, false, conn) != 0)
                                        log_quic_error("Error while creating message packets");
                                    else {
                                        char *file_name = parse_get_or_put_msg(msg);
                                        if (add_file_req(file_name, conn) == 0)
                                            log_msg("Successfully added file request");
                                        else
                                            log_quic_error("Errors while adding file request");
                                    }
                                } else {
                                    log_quic_error("Cannot open a new bidirectional stream");
                                }
                                break;
                            }
                            default: {
                                log_quic_error("Unrecognized Transfert command");
                                break;
                            }
                        }
                        if (send_packets(sock, conn) == 0)
                            log_msg("Packets sent successfully");
                        else
                            log_quic_error("Error while sending packets");
                    }
                }
            }
        }
    } else {
        print_error("Cannot establish connection to server");
        exit(EXIT_FAILURE);
    }
}

/**
 * @brief Processes program arguments
 *
 * Process program arguments according to
 * the following semantics: <br>
 * · -s server_address: sets server IPv4 address (default: localhost) <br>
 * · -p server_port: sets server UDP port (default: 501) <br>
 * · -l loss_probability: sets packet loss probability (default: 0) <br>
 * · -v true | false: sets verbose output (default: false) <br>
 *
 * @param argc the number of command line arguments
 * @param argv array of command line arguments
 */
void process_arguments(int argc, char *argv[]) {
    // Iterate up to argc-1 to always check the arguments in pairs
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "-s") == 0) {
            serv_addr = argv[i + 1];
        } else if (strcmp(argv[i], "-p") == 0) {
            serv_port = (int) strtol(argv[i + 1], NULL, 10);
        } else if (strcmp(argv[i], "-l") == 0) {
            loss_prob = strtod(argv[i + 1], NULL);
        } else if (strcmp(argv[i], "-v") == 0) {
            if (strcmp(argv[i + 1], "true") == 0)
                verbose = 1;
            else if (strcmp(argv[i + 1], "false") != 0) {
                print_error("Unrecognized verbose options: use -v true|false.");
                exit(EXIT_FAILURE);
            }
        } else {
            print_error("Unrecognised argument. Use the following semantics:\n"
                        "-s a.b.c.d: sets server address (default: 127.0.0.1);\n"
                        "-p n: sets server UDP port number (default: 501);\n"
                        "-l d: sets loss probability, must be between 0 and 1 (default: 0);\n"
                        "-v true|false: sets verbose output (default: false);");
            exit(EXIT_FAILURE);
        }
    }
}
