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

static void opmode_usage_message(void)
{
	printf("Usage : %s (ORSU | ERSU | OBU)\n",OPMODE);
}

int opmode(char **reqs)
{
	int arg=0,len = 0;
	int op,val;
    unsigned char data[COMMAND_DATA_LENGTH];

	if(reqs[arg] == NULL){
		opmode_usage_message();
		return -1;
	}

	if(!strcmp(reqs[arg],"orsu")){
		data[len] = 0x00;
	}else if(!strcmp(reqs[arg],"ersu")){
		data[len] = 0x10;
	}else if(!strcmp(reqs[arg],"obu")){
		data[len] = 0x20;
	}else{
		opmode_usage_message();
		return -1;
	}

	len += 1;

	op = IOCTL_WRITE;

	if(len > 0){
		send_wavecmd(op,MAC_CATEGORY,OPMODE_CMD,len,data);
	}

	return 0;
} // opmode
