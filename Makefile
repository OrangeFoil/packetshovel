CC = gcc
OBJS = base64encode.o ipv4_packet.o ipv6_packet.o
LIBS = -lpcap
CFLAGS = -Wall -O2

all: $(OBJS) packetshovel

packetshovel: main.c
	$(CC) $(CFLAGS) $(LIBS) $^ $(OBJS) -o $@

base64encode.o: base64encode.c
	$(CC) -c $(CFLAGS) $^ -o $@

ipv4_packet.o: ipv4_packet.c
	$(CC) -c $(CFLAGS) $^ -o $@

ipv6_packet.o: ipv6_packet.c
	$(CC) -c $(CFLAGS) $^ -o $@

clean:
	$(RM) $(OBJS) packetshovel
