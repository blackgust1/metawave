PWD=$(shell pwd)

EXEC=rsmgmt
OBJS=rsmgmt.o rm_mem.o network.o wave_ioctl.o wsmp.o
CC=arm-none-linux-gnueabi-gcc
##CC=gcc
CFLAGS=-I. -Wimplicit -Wall -fPIC -g
QLIB = -L../Libs -lsvcmgmt -lJ2735

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) ${QLIB} -lpthread
	cp -rf $(EXEC) ../binary

clean :
	rm -rf *.o
	rm -rf $(EXEC)
