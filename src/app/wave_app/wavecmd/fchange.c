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

static void fchange_usage_message(void)
{
	printf("Usage : %s (A | B) freq\n",FCHANGE);
	printf("\tif freq is %d, RF Frequency is 5.850 GHz\n",SHELL_FREQ_5850);
	printf("\tif freq is %d, RF Frequency is 5.860 GHz\n",SHELL_FREQ_5860);
	printf("\tif freq is %d, RF Frequency is 5.870 GHz\n",SHELL_FREQ_5870);
	printf("\tif freq is %d, RF Frequency is 5.880 GHz\n",SHELL_FREQ_5880);
	printf("\tif freq is %d, RF Frequency is 5.890 GHz\n",SHELL_FREQ_5890);
	printf("\tif freq is %d, RF Frequency is 5.900 GHz\n",SHELL_FREQ_5900);
	printf("\tif freq is %d, RF Frequency is 5.910 GHz\n",SHELL_FREQ_5910);
	printf("\tif freq is %d, RF Frequency is 5.920 GHz\n",SHELL_FREQ_5920);
}

int fchange(char **reqs)
{
	int arg=0,len = 0;
	int op,val,cmd;
    unsigned char data[COMMAND_DATA_LENGTH];

	if(reqs[arg] == NULL){
		fchange_usage_message();
		return -1;
	}
	if((!strcmp(reqs[arg],"a")) || (!strcmp(reqs[arg],"A"))){
		data[len] = MAC_A;
	}else if((!strcmp(reqs[arg],"b")) || (!strcmp(reqs[arg],"B"))){
		data[len] = MAC_B;
	}else{
		fchange_usage_message();
		return -1;
	}
	len += 1;
	arg += 1;

	val = atoi(reqs[arg]);
	switch(val){
	case SHELL_FREQ_5850:
		data[len] = 50;
		break;
	case SHELL_FREQ_5860:
		data[len] = 60;
		break;
	case SHELL_FREQ_5870:
		data[len] = 70;
		break;
	case SHELL_FREQ_5880:
		data[len] = 80;
		break;
	case SHELL_FREQ_5890:
		data[len] = 90;
		break;
 	case SHELL_FREQ_5900:
		data[len] = 100;
		break;
	case SHELL_FREQ_5910:
		data[len] = 110;
		break;
	case SHELL_FREQ_5920:
		data[len] = 120;
		break;
	default:
		fchange_usage_message();
		return -1;
	} // switch(val)
	len += 1;
	arg += 1;

	op = IOCTL_WRITE;

	if(len > 0){
		send_wavecmd(op,MAC_CATEGORY,FCHANGE_CMD,len,data);
	}
	return 0;
} // main(int argc, char **argv)
