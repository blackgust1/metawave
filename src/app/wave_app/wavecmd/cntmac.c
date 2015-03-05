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

static void cntmac_usage_message(void)
{
	printf("Usage : %s (A|B)\n",CNTMAC_COUNT);
}

int cntmac(char **reqs)
{
	int arg=0,len = 0;
	int op,cmd;
    unsigned char data[COMMAND_DATA_LENGTH];

	if(reqs[arg] == NULL){
		cntmac_usage_message();
		return -1;
	}
	if((!strcmp(reqs[arg],"a")) || (!strcmp(reqs[arg],"A"))){
		data[len] = MAC_A;
		len += 1;
	}else if((!strcmp(reqs[arg],"b")) || (!strcmp(reqs[arg],"B"))){
		data[len] = MAC_B;
		len += 1;
	}else{
		cntmac_usage_message();
		return -1;
	}
	op = IOCTL_WRITE;

	if(len > 0){
		send_wavecmd(op,MAC_CATEGORY,CNTMAC_CMD,len,data);
	}
	return 0;
} // main(int argc, char **argv)
