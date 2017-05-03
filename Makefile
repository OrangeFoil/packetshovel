CC = clang
OBJS = base64encode.o ipv6_packet.o structs.o
LIBS = -lpcap
CFLAGS = -Wall -O2

all: $(OBJS) packetshovel

packetshovel: main.c
	$(CC) $(CFLAGS) $(LIBS) $^ $(OBJS) -o $@

base64encode.o: base64encode.c
	$(CC) -c $(CFLAGS) $^ -o $@

ipv6_packet.o: ipv6_packet.c
	$(CC) -c $(CFLAGS) $^ -o $@

structs.o: structs.c
	$(CC) -c $(CFLAGS) $^ -o $@

clean:
	$(RM) $(OBJS) packetshovel
