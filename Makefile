CC = gcc
BIN = ./bin
SRC = ./src
OBJS = $(BIN)/base64encode.o $(BIN)/ipv4_packet.o $(BIN)/ipv6_packet.o $(BIN)/main.o
LIBS = -lpcap
CFLAGS = -Wall -O2

all: $(OBJS) packetshovel

packetshovel: $(OBJS)
	$(CC) $(CFLAGS) $(LIBS) $^ -o $(BIN)/$@

$(BIN)/%.o: $(SRC)/%.c
	$(CC) -c $(CFLAGS) $^ -o $@

clean:
	$(RM) $(OBJS) packetshovel

format:
	clang-format -style="{BasedOnStyle: llvm, IndentWidth: 4, AllowShortFunctionsOnASingleLine: None, KeepEmptyLinesAtTheStartOfBlocks: false}" -i *.c *.h
