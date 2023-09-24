CC = gcc
CFLAGS = -Wall -lm
SRC_SRV = server.c quic_server.c
QUIC_SRV_SRC = quic/quic_conn.c quic/base.c quic/varint.c quic/quic_errors.c quic/streams.c quic/frames.c \
                              			quic/sliding_window.c quic/packets.c quic/transfert/transfert_base.c \
                              			quic/transfert/transfert_errors.c quic/transfert/server_func.c \
                              			quic/quic_server.h quic/frames.h quic/quic_errors.h quic/quic_conn.h \
                              			quic/base.h quic/varint.h quic/streams.h quic/transport_params.h \
                              			quic/transfert/transfert_base.h quic/transfert/messages.h \
                              			quic/transfert/transfert_errors.h quic/transfert/server_func.h
OBJ_SRV = $(SRC_SRV:.c=.o)

server: $(OBJ_SRV)
	${CC} -o server $(OBJ_SRV)

server.o: quic/quic_server.h quic/transfert/transfert_base.h
quic_server.o: $(QUIC_SRV_SRC)
	${CC} -c $(QUIC_SRV_SRC)

quic_conn.o:   quic/quic_errors.h
base.o: quic/base.h quic/quic_errors.c quic/varint.h
base.o: quic/base.h quic/quic_errors.c quic/varint.h
varint.o: quic/varint.h
quic_errors.o: quic/quic_errors.h
streams.o: quic/streams.h
frames.o: quic/frames.h quic/varint.h quic/quic_conn.h \
			quic/quic_errors.h quic/transfert/transfert_base.h
sliding_window.o: quic/base.h quic/quic_conn.h quic/quic_errors.h
packets.o: quic/packets.h quic/base.h quic/transport_params.h \
			quic/quic_conn.h quic/frames.h quic/quic_errors.h
transfert_base.o: quic/transfert/transfert_base.h quic/base.h quic/transfert/messages.h
transfert_errors.o: quic/transfert/transfert_errors.h
server_func.o: quic/transfert/server_func.h quic/transfert/transfert_base.h \
				quic/transfert/transfert_errors.h quic/transfert/messages.h

client.o: client.h

errors.o: errors.h

clean:
	rm -f *.o core

cleanall:
	rm -f *.o core client

.PHONY: clean cleanall
