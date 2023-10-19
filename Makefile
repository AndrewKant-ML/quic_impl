CC = gcc
CFLAGS = -Wall

SRC_QUIC = quic/quic_conn.c quic/base.c \
           quic/varint.c quic/quic_errors.c quic/streams.c quic/frames.c \
           quic/sliding_window.c quic/packets.c quic/quic_transfert.c \
           quic/transfert/transfert_base.c quic/transfert/transfert_errors.c \
           quic/transfert/server_func.c

SRC_SRV = server.c quic/quic_server.c $(SRC_QUIC)
SRC_CLI = client.c quic/quic_client.c errors.c $(SRC_QUIC)

OBJ_SRV = $(SRC_SRV:.c=.o)
OBJ_CLI = $(SRC_CLI:.c=.o)

QUIC_HDR_SRV = quic/quic_server.h quic/frames.h quic/quic_errors.h quic/quic_conn.h \
           quic/base.h quic/varint.h quic/streams.h quic/transport_params.h quic/quic_transfert.h

QUIC_HDR_CLI = quic/quic_client.h quic/frames.h quic/quic_errors.h quic/quic_conn.h \
           quic/base.h quic/varint.h quic/streams.h quic/transport_params.h errors.h \
           quic/quic_transfert.h

TRANSFERT_HDR_SRV = quic/transfert/transfert_base.h quic/transfert/messages.h \
                quic/transfert/transfert_errors.h quic/transfert/server_func.h

TRANSFERT_HDR_CLI = quic/transfert/transfert_base.h quic/transfert/messages.h \
                quic/transfert/transfert_errors.h quic/transfert/client_func.h

server: $(OBJ_SRV) $(TRANSFERT_HDR_SRV) $(QUIC_HDR_SRV)
	${CC} -o server $(OBJ_SRV) -lm

client: $(OBJ_CLI) $(TRANSFERT_HDR_CLI) $(QUIC_HDR_CLI)
	${CC} -o client $(OBJ_CLI) -lm

server.o: quic/quic_server.h quic/transfert/transfert_base.h
quic_server.o: $(QUIC_HDR_SRV) $(TRANSFERT_HDR_SRV)

quic/quic_conn.o: $(QUIC_HDR_SRV) $(TRANSFERT_HDR_SRV)
quic/base.o: $(QUIC_HDR_SRV) $(TRANSFERT_HDR_SRV)
quic/base.o: $(QUIC_HDR_SRV) $(TRANSFERT_HDR_SRV)
quic/varint.o: $(QUIC_HDR_SRV) $(TRANSFERT_HDR_SRV)
quic/quic_errors.o: $(QUIC_HDR_SRV) $(TRANSFERT_HDR_SRV)
quic/streams.o: $(QUIC_HDR_SRV) $(TRANSFERT_HDR_SRV)
quic/frames.o: $(QUIC_HDR_SRV) $(TRANSFERT_HDR_SRV)
quic/sliding_window.o: $(QUIC_HDR_SRV) $(TRANSFERT_HDR_SRV)
quic/packets.o: $(QUIC_HDR_SRV) $(TRANSFERT_HDR_SRV)
quic/transfert/transfert_base.o: $(QUIC_HDR_SRV) $(TRANSFERT_HDR_SRV)
quic/transfert/transfert_errors.o: $(QUIC_HDR_SRV) $(TRANSFERT_HDR_SRV)
quic/transfert/server_func.o: $(QUIC_HDR_SRV) $(TRANSFERT_HDR_SRV)

client.o: client.h quic/quic_client.h errors.h
quic/quic_client.o: $(QUIC_HDR_CLI) $(TRANSFERT_HDR_CLI)

errors.o: errors.h

clean:
	rm -f *.o
	rm -f quic/*.o
	rm -f quic/transfert/*.o
	rm -f *.gch
	rm -f quic/*.gch
	rm -f quic/transfert/*.gch

cleanall:
	rm -f *.o client

.PHONY: clean cleanall
