EXEC = wavedsrc
LIBTARGET = libmy.a
CROSS_COMPILE=arm-none-linux-gnueabi-
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar


OBJS = ether_rx.o ether_tx.o gps.o main.o monitor.o network.o plme.o timer.o util.o wave_int.o wave_mac.o wave_modem.o \
	wave_manage_frame.o wave_multi_ch.o \
	./1609_2_driver/wave_aes_ccm.o ./1609_2_driver/ecdsa_driver.o ./1609_2_driver/ecies_driver.o \
	./1609_2_driver/sha_driver.o


#CFLAGS +=-I$(ROOTDIR)/$(LINUXDIR)/include -I$(ROOTDIR)/$(LINUXDIR)/arch/arm/include -I$(ROOTDIR)/$(LINUXDIR)/arch/arm/mach-s3c2510/include -D__KERNEL__
CFLAGS +=-I$(ROOTDIR)/$(LINUXDIR)/include -I$(ROOTDIR)/$(LINUXDIR)/arch/arm/include -I$(ROOTDIR)/$(LINUXDIR)/arch/arm/mach-s3c2510/include \
	-I ./h -I ./aes_ccm -I ./sha -I ./ecies -I ./ecdsa

#CFLAGS +=-I$(ROOTDIR)/$(LINUXDIR)/include -I$(ROOTDIR)/$(LINUXDIR)/arch/arm/include
#CFLAGS += -DPARANOID_TTYS -DTERMCAP -DUSE_TERMIO -DKLUDGELINEMODE -D_GNU_SOURCE
CFLAGS += -D_REENTRANT -D_POSIX_TIMERS
#LDLIBS += -lpthread -lm -lgmp -lrt
LDLIBS += -lpthread -lm -lgmp -lrt -lmy -L./

#all: $(EXEC)
all: $(EXEC) $(LIBTARGET)

#$(LIBTARGET) : $(LIB_OBJS)
#	$(AR) rcv $@ $(LIB_OBJS)



#uses non LGPL librarys
#$(EXEC): $(OBJS)
$(EXEC): $(OBJS) $(LIBTARGET)
#	$(CC) $(LDFLAGS) -o $@ $(OBJS) -lg $(LDLIBS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/$(EXEC)

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

