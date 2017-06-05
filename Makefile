CC = gcc
BIN = ./bin
SRC = ./src
INSTALL_PATH = /usr/local
OBJS = $(BIN)/arguments.o $(BIN)/base64encode.o $(BIN)/esper_socket.o $(BIN)/ethernet_frame.o $(BIN)/ipv4_packet.o $(BIN)/ipv6_packet.o $(BIN)/main.o $(BIN)/sniffer.o
LIBS = -lpcap
CFLAGS = -Wall -O2 -std=gnu11

all: $(OBJS) packetshovel

packetshovel: $(OBJS)
	$(CC) $(CFLAGS) $(LIBS) $^ -o $(BIN)/$@

$(BIN)/%.o: $(SRC)/%.c
	$(CC) -c $(CFLAGS) $^ -o $@

clean:
	$(RM) $(OBJS) packetshovel

format:
	clang-format -style="{BasedOnStyle: llvm, IndentWidth: 4, AllowShortFunctionsOnASingleLine: None, KeepEmptyLinesAtTheStartOfBlocks: false}" -i src/*.c src/*.h

install:
	makedir -p $(INSTALL_PATH)/bin/
	cp $(BIN)/packetshovel $(INSTALL_PATH)/bin/

uninstall:
	$(RM) $(INSTALL_PATH)/bin/packetshovel
