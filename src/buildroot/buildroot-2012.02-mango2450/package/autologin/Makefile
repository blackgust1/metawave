EXEC = autologin
CROSS_COMPILE=arm-none-linux-gnueabi-
CC = $(CROSS_COMPILE)gcc
OBJS = autologin.o

#CFLAGS +=-I$(ROOTDIR)/$(LINUXDIR)/include -I$(ROOTDIR)/$(LINUXDIR)/arch/arm/include -I$(ROOTDIR)/$(LINUXDIR)/arch/arm/mach-s3c2510/include -D__KERNEL__
CFLAGS +=-I$(ROOTDIR)/$(LINUXDIR)/include -I$(ROOTDIR)/$(LINUXDIR)/arch/arm/include -I$(ROOTDIR)/$(LINUXDIR)/arch/arm/mach-s3c2510/include

#CFLAGS +=-I$(ROOTDIR)/$(LINUXDIR)/include -I$(ROOTDIR)/$(LINUXDIR)/arch/arm/include
#CFLAGS += -DPARANOID_TTYS -DTERMCAP -DUSE_TERMIO -DKLUDGELINEMODE -D_GNU_SOURCE
LDLIBS += -lpthread -lm

all: $(EXEC)

#$(OBJS): linked_list.h task.h type_def.h

#uses non LGPL librarys
$(EXEC): $(OBJS)
#	$(CC) $(LDFLAGS) -o $@ $(OBJS) -lg $(LDLIBS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

