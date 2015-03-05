EXEC=wavecmd
OBJS=wavecmd.o regaddr.o debug.o datarate.o opmode.o clear.o fchange.o rfpower.o txpkt.o macaddr.o amc.o
OBJS+=cntmac.o landbg.o
CC=arm-none-linux-gnueabi-gcc
##CC=gcc
CFLAGS=-Wimplicit -Wall

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) -g -o $@ $(OBJS) -lpthread -lm
	cp -rf $(EXEC) ../binary

clean :
	rm -rf *.o
	rm -rf $(EXEC)
