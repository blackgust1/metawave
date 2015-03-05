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
extern unsigned char Hex(unsigned char ch);

static void regaddr_usage_message(void)
{
	printf("%s (r2|r4|w2|w4) BaseAddr offset(hex) value(hex)\n",REGADDR);
	printf("\tBaseAddr : WAVE_DSRC -> 1\n");
	printf("\tBaseAddr : CPU GPIO -> 2\n");
	printf("\tBaseAddr : CPU INTR -> 3\n");
}

int regaddr(char **reqs)
{
	int arg=0, op =-1, type,width,len = 0;
	unsigned int command;
	unsigned int value;
    unsigned char data[COMMAND_DATA_LENGTH];
	unsigned char *ptr;

	if(reqs[arg] == NULL){
		regaddr_usage_message();
		return -1;
	}
	if(!strcmp(reqs[arg],"r2")){
		value = IOCTL_READ_2BYTE;
		op = IOCTL_READ;
	}else if(!strcmp(reqs[arg],"r4")){
		value = IOCTL_READ_4BYTE;
		op = IOCTL_READ;
	}else if(!strcmp(reqs[arg],"w2")){
		value = IOCTL_WRITE_2BYTE;
		op = IOCTL_WRITE;
	}else if(!strcmp(reqs[arg],"w4")){
		value = IOCTL_WRITE_4BYTE;
		op = IOCTL_WRITE;
	}else{
		regaddr_usage_message();
		return -1;
	}
	data[len] = value;
	len += 1;
	arg += 1;

	if(reqs[arg] == NULL){
		regaddr_usage_message();
		return -1;
	}
	value = atoi(reqs[arg]);
	if(value != WAVE_DSRC_ADDR && value != CPU_GPIO_ADDR && value != CPU_INTR_ADDR){
		regaddr_usage_message();
		return -1;
	}
	command = value;
	arg += 1;

	if(reqs[arg] == NULL){
		regaddr_usage_message();
		return -1;
	}
	value = strtoul(reqs[arg],NULL,16);
	PUT_32BIT_TO_FOUR_CHARS(data[len++], data[len++], data[len++], data[len++], value);
	arg += 1;

	if(op == IOCTL_WRITE){
		if(reqs[arg] == NULL){
			regaddr_usage_message();
			return -1;
		}
		value = strtoul(reqs[arg],NULL,16);
		PUT_32BIT_TO_FOUR_CHARS(data[len++], data[len++], data[len++], data[len++], value);
		arg += 1;
	}

	if(len > 0){
		send_wavecmd(op,REGADDR_CATEGORY,command,len,data);
		if(op == IOCTL_READ){
			GET_32BIT_FROM_FOUR_CHARS(value, data[0], data[1], data[2], data[3]);
			printf("value --> 0x%04x\n",value);
		}
	}

	return 0;
} // main(int argc, char **argv)
