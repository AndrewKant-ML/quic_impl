cmake_minimum_required(VERSION 3.26)
project(iiw C)

set(CMAKE_C_STANDARD 11)

add_executable(iiw_server
        quic/base.h
        server.c
        quic/varint.h
        quic/frames.h
        quic/quic_errors.h
        quic/varint.c
        quic/quic_conn.h
        quic/quic_conn.c
        quic/packets.h
        quic/packets.c
        quic/transfert/transfert_base.h
        quic/transfert/messages.h
        quic/transfert/server_func.c
        quic/transfert/client_func.c
        quic/transfert/messages.c
        errors.c
        errors.h
        quic/quic_client.c
        quic/quic_server.c
        quic/quic_client.h
        quic/quic_server.h
        quic/quic_errors.c
        quic/frames.c
        quic/sliding_window.c
        quic/streams.h
        quic/streams.c
        quic/transport_params.h
        quic/transfert/transfert_base.c
        quic/base.c
        quic/transfert/server_func.h
        quic/transfert/transfert_errors.h
        quic/transfert/transfert_errors.c
        quic/transfert/client_func.h
        quic/quic_transfert.h
        quic/quic_transfert.c
)

add_executable(iiw_client
        quic/base.h
        quic/varint.h
        quic/frames.h
        quic/quic_errors.h
        quic/varint.c
        quic/quic_conn.h
        quic/quic_conn.c
        quic/packets.h
        quic/packets.c
        quic/transfert/transfert_base.h
        quic/transfert/messages.h
        quic/transfert/server_func.c
        quic/transfert/client_func.c
        quic/transfert/messages.c
        errors.c
        errors.h
        client.c
        quic/quic_client.c
        quic/quic_server.c
        quic/quic_client.h
        quic/quic_server.h
        quic/quic_errors.c
        quic/frames.c
        quic/sliding_window.c
        quic/streams.h
        quic/streams.c
        client.h
        quic/transport_params.h
        quic/transfert/transfert_base.c
        quic/base.c
        quic/transfert/server_func.h
        quic/transfert/transfert_errors.h
        quic/transfert/transfert_errors.c
        quic/transfert/client_func.h
        quic/quic_transfert.h
        quic/quic_transfert.c
)

target_link_libraries(iiw_server PRIVATE m)
target_link_libraries(iiw_client PRIVATE m)