EXEC=wsm
OBJS=wsm.o 
#CC=arm-none-linux-gnueabi-gcc
CC=gcc
CFLAGS=-I../include -Wimplicit -Wall

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) -g -o $@ $(OBJS) -lJ2735 -lpthread
	cp -rf $(EXEC) ../binary

clean :
	rm -rf *.o
	rm -rf $(EXEC)
