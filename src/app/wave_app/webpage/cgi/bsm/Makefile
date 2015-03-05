NAME = bsm_test

CC = arm-none-linux-gnueabi-gcc
QLIB = -L../../../Libs -lqdecoder -lsvcmgmt -lJ2735

CFLAGS = -O2 -g -I../../include

all: ${NAME}.cgi
$(NAME).cgi:bsm_test.c
	$(CC) -o $(NAME).cgi bsm_test.c ${CFLAGS} ${QLIB} 
	cp -rf *.cgi /var/www

clean:
	rm -rf ./*.cgi

