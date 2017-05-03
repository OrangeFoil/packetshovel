CC = clang
OBJS = base64encode.o structs.o
LIBS = -lpcap
CFLAGS = -Wall -O2

all: $(OBJS) packetshovel

packetshovel: main.c
	$(CC) $(CFLAGS) $(LIBS) $^ $(OBJS) -o $@

base64encode.o: base64encode.c
	$(CC) -c -Wall -O2 $^ -o $@

structs.o: structs.c
	$(CC) -c $(CFLAGS) $^ -o $@

clean:
	$(RM) $(OBJS) packetshovel
