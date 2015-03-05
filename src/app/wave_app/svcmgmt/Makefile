EXEC=libsvcmgmt.so
OBJS=svcmain.o svcwsmp.o
CC=arm-none-linux-gnueabi-gcc
##CC=gcc
CFLAGS=-Wimplicit -Wall -fPIC -g

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) -shared -o $(EXEC) $(OBJS) -lpthread
	cp -rf $(EXEC) ../Libs

clean :
	rm -rf *.o
	rm -rf $(EXEC)
