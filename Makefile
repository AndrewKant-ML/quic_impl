CC = gcc
CFLAGS = -Wall

SRC_QUIC = quic/quic_conn.c quic/base.c \
           quic/varint.c quic/quic_errors.c quic/streams.c quic/frames.c \
           quic/sliding_window.c quic/packets.c quic/transfert/transfert_base.c \
           quic/transfert/transfert_errors.c quic/transfert/server_func.c

SRC_SRV = server.c quic/quic_server.c $(SRC_QUIC)
SRC_CLI = client.c quic/quic_client.c errors.c $(SRC_QUIC)

OBJ_SRV = $(SRC_SRV:.c=.o)
OBJ_CLI = $(SRC_CLI:.c=.o)

QUIC_HDR = quic/quic_server.h quic/frames.h quic/quic_errors.h quic/quic_conn.h \
           quic/base.h quic/varint.h quic/streams.h quic/transport_params.h

TRANSFERT_HDR = quic/transfert/transfert_base.h quic/transfert/messages.h \
                quic/transfert/transfert_errors.h quic/transfert/server_func.h

server: $(OBJ_SRV) $(TRANSFERT_HDR) $(QUIC_HDR)
	${CC} -o server $(OBJ_SRV) -lm

client: $(OBJ_CLI) $(TRANSFERT_HDR) $(QUIC_HDR) errors.h
	${CC} -o client $(OBJ_CLI) -lm

server.o: quic/quic_server.h quic/transfert/transfert_base.h
quic_server.o: $(QUIC_HDR) $(TRANSFERT_HDR)

quic/quic_conn.o: $(QUIC_HDR) $(TRANSFERT_HDR)
quic/base.o: $(QUIC_HDR) $(TRANSFERT_HDR)
quic/base.o: $(QUIC_HDR) $(TRANSFERT_HDR)
quic/varint.o: $(QUIC_HDR) $(TRANSFERT_HDR)
quic/quic_errors.o: $(QUIC_HDR) $(TRANSFERT_HDR)
quic/streams.o: $(QUIC_HDR) $(TRANSFERT_HDR)
quic/frames.o: $(QUIC_HDR) $(TRANSFERT_HDR)
quic/sliding_window.o: $(QUIC_HDR) $(TRANSFERT_HDR)
quic/packets.o: $(QUIC_HDR) $(TRANSFERT_HDR)
quic/transfert/transfert_base.o: $(QUIC_HDR) $(TRANSFERT_HDR)
quic/transfert/transfert_errors.o: $(QUIC_HDR) $(TRANSFERT_HDR)
quic/transfert/server_func.o: $(QUIC_HDR) $(TRANSFERT_HDR)

client.o: client.h quic/quic_client.h errors.h
quic/quic_client.c: $(QUIC_HDR) $(TRANSFERT_HDR)

errors.o: errors.h

clean:
	rm -f *.o core
	rm -f quic/*.o core

cleanall:
	rm -f *.o core client

.PHONY: clean cleanall
