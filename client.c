//
// Created by andrea on 14/09/23.
//

#include "client.h"

char *serv_addr = "127.0.0.1";
int serv_port = 501;
double loss_prob = 0;
int verbose = 0;

/*int main(int argc, char *argv[]) {

    process_arguments(argc, argv);

    int sock;
    int i, read, maxd;
    ssize_t n;
    socklen_t addr_len;
    struct sockaddr_in addr;
    char msg[255];
    void *buf[UDP_BUF_SIZE];
    fd_set rset;
    FD_ZERO(&rset);

    // Client socket creation
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        print_error("Unable to create client socket");
        exit(EXIT_FAILURE);
    }

    // Address initialization
    memset((void *) &addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);

    // Address building
    if (inet_pton(AF_INET, serv_addr, &addr.sin_addr) <= 0) {
        print_error("Unable to parse server address. Please use IPv4 dotted-decimal notation.");
        exit(EXIT_FAILURE);
    }
    addr_len = sizeof(addr);

    // Opens connection
    quic_connection conn;
    conn.addr = addr;
    quic_connect(sock, &conn);

    while (1) {
        printf("Insert a command: ");
        FD_SET(fileno(stdin), &rset);
        FD_SET(sock, &rset);
        maxd = MAX(fileno(stdin), sock) + 1;
        if (select(maxd, &rset, NULL, NULL, NULL) < 0) {
            print_error("Select error.");
            exit(EXIT_FAILURE);
        }

        // Checks if socket is readable
        if (FD_ISSET(sock, &rset)) {
            // Must read something
            if ((n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *) &addr, &addr_len)) < 0) {
                print_error("Error while reading from socket.");
                // todo close everything
            }
            // todo process incoming packet

        }

        if (FD_ISSET(fileno(stdin), &rset)) {
            if(scanf("%s", msg) == 1) {
                if (check_msg_semantics(msg) == 0) {
                    // TODO build and process packet
                }
            }
        }
    }
}*/

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
