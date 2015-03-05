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
extern	unsigned char Hex(unsigned char ch);

static void mac_usage_message(void)
{
	printf("Usage : %s (dest | gw) address(xx:xx:xx:xx:xx:xx)\n",MACADDR);
}

int mac(unsigned char *addr,unsigned char *data)
{
	int i,idx=0;
	unsigned char hw,hw2;

	for(i=0; i<6; i++){
		if(*(addr+idx) == ':')  idx += 1;
		hw = Hex(*(addr+idx));
		hw2 = Hex(*(addr+idx+1));
		if((hw == 'X') || (hw2 == 'X'))	return 1;	// invalid
		data[i] = (hw << 4) | hw2;
		idx += 2;
	}
	
	return 0;
}

int macaddr(char **reqs)
{
	int arg=0,len = 0;
	int op,val;
    unsigned char data[COMMAND_DATA_LENGTH];

	if(reqs[arg] == NULL){
		mac_usage_message();
		return -1;
	}

	/* 1st argument (Dest Mac or Gateway Mac) */
	if(!strcmp(reqs[arg],"dest")){
		data[len] = DESTMAC_ADDR;
	}else if(!strcmp(reqs[arg],"gw")){
		data[len] = GATEWAY_ADDR;
	}else{
		mac_usage_message();
		return -1;
	}

	len += 1;
	arg += 1;

    /* 2nd argument (MAC Address) */
    if(reqs[arg] == NULL)   {
        printf("mac address is nedded !!!\n");
        return -1;
    }
    if(mac(reqs[arg],&data[len])){
        mac_usage_message();
        return -1;
    }
    len += 6;
    arg += 1;

	op = IOCTL_READ;

	if(len > 0){
		send_wavecmd(op,VMC_CATEGORY,MACADDR_CMD,len,data);
	}

	return 0;
} // main(int argc, char **argv)
