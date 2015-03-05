#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include "wave_shell.h"

extern int send_wavecmd(int rdwr, int category, int cmd,int length, unsigned char *data);

static void rfpower_usage_message(void)
{
	printf("Usage : %s (A | B) mode\n",RFPOWER);
	printf("\t0 : Power Level is Etri Set\n");
	printf("\t1 : Power Level is Ranix Set\n");
}

int rfpower(char **reqs)
{
	int arg=0,len = 0;
	int op,val,cmd;
    unsigned char data[COMMAND_DATA_LENGTH];

	if(reqs[arg] == NULL){
		rfpower_usage_message();
		return -1;
	}
	if((!strcmp(reqs[arg],"a")) || (!strcmp(reqs[arg],"A"))){
		data[len] = MAC_A;
	}else if((!strcmp(reqs[arg],"b")) || (!strcmp(reqs[arg],"B"))){
		data[len] = MAC_B;
	}else{
		rfpower_usage_message();
		return -1;
	}
	len += 1;
	arg += 1;

	val = atoi(reqs[arg]);
	if((val == 0) || (val == 1)){
		data[len] = val;
	}else{
		rfpower_usage_message();
		return -1;
	}
	len += 1;
	arg += 1;

	op = IOCTL_WRITE;

	if(len > 0){
		send_wavecmd(op,MAC_CATEGORY,RFPOWER_CMD,len,data);
	}
	return 0;
} // main(int argc, char **argv)
