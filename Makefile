CC = gcc
OBJS = base64encode.o ipv4_packet.o ipv6_packet.o main.o
LIBS = -lpcap
CFLAGS = -Wall -O2

all: $(OBJS) packetshovel

packetshovel: $(OBJS)
	$(CC) $(CFLAGS) $(LIBS) $^ -o $@

%.o: %.c
	$(CC) -c $(CFLAGS) $^ -o $@

clean:
	$(RM) $(OBJS) packetshovel

format:
	clang-format -style="{BasedOnStyle: llvm, IndentWidth: 4, AllowShortFunctionsOnASingleLine: None, KeepEmptyLinesAtTheStartOfBlocks: false}" -i *.c *.h
