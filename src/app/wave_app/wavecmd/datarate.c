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

static void datarate_usage_message(void)
{
	printf("Usage : %s (3, 4, 6, 9, 12, 18, 24, 27 M)\n",DATARATE);
}

int datarate(char **reqs)
{
	int arg=0,len = 0;
	int op,val;
    unsigned char data[COMMAND_DATA_LENGTH];

	if(reqs[arg] == NULL){
		datarate_usage_message();
		return -1;
	}

	val = atoi(reqs[arg]);
	if( !((val == 3) || (val == 4) || (val == 6) || (val == 9) || (val == 12) || (val == 18) || (val == 24) || (val == 27)) ){
		datarate_usage_message();
		return -1;
	} /// if((val == 3) || (val == 4) || (val == 6) || (val == 9) || (val == 12) || (val == 18) || (val == 24) || (val == 27)){

	data[len] = val;
	len += 1;
	op = IOCTL_WRITE;

	if(len > 0){
		send_wavecmd(op,MAC_CATEGORY,DATARATE_CMD,len,data);
	}

	return 0;
} // main(int argc, char **argv)
