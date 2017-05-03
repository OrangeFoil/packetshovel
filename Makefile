CC = gcc
OBJS = base64encode.o ipv4_packet.o ipv6_packet.o
LIBS = -lpcap
CFLAGS = -Wall -O2

all: $(OBJS) packetshovel

packetshovel: main.c
	$(CC) $(CFLAGS) $(LIBS) $^ $(OBJS) -o $@

%.o: %.c
	$(CC) -c $(CFLAGS) $^ -o $@

clean:
	$(RM) $(OBJS) packetshovel
