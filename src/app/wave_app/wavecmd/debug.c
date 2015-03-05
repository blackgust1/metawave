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

static void dbgmsg_usage_message(void)
{
	printf("Usage : %s level(decimal digit) !!!!\n",DEBUG_MSG);
}

int dbgmsg(char **reqs)
{
	int arg=0,len = 0;
	int op,cmd;
    unsigned char data[COMMAND_DATA_LENGTH];

	if(reqs[arg] == NULL){
		dbgmsg_usage_message();
		return -1;
	}
	data[len] = atoi(reqs[0]);
	len += 1;
	op = IOCTL_WRITE;

	if(len > 0){
		send_wavecmd(op,ETC_CATEGORY,DEBUG_LEVEL_CMD,len,data);
	}
	return 0;
} // main(int argc, char **argv)
