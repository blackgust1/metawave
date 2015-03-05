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

static void amc_onoff_usage_message(void)
{
	printf("Usage : %s Adaptive Modulation and Coding Scheme(AMC) on/off !!!!\n",AMC);
}

int amc_onoff(char **reqs)
{
	int arg=0,len = 0;
	int op,cmd;
    unsigned char data[COMMAND_DATA_LENGTH];

	if(reqs[arg] == NULL){
		amc_onoff_usage_message();
		return -1;
	}
	if(!strcmp(reqs[arg],"ON") || !strcmp(reqs[arg],"on")){
		data[len] = 1;
	}else if(!strcmp(reqs[arg],"OFF") || !strcmp(reqs[arg],"off")){
		data[len] = 0;
	}else{
		amc_onoff_usage_message();
		return 1;
	}
	len += 1;

	op = IOCTL_WRITE;

	if(len > 0){
		send_wavecmd(op,MLME_CATEGORY,AMC_CMD,len,data);
	}
	return 0;
} // main(int argc, char **argv)
