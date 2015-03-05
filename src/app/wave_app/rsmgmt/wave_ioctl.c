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

int send_wavecmd(int rdwr, int category, int cmd,int length, unsigned char *data)
{
	struct wave_req *user=NULL;
	struct ifreq req;
	int retval = length;
	int i,wave;
	
	if((user = (struct wave_req *)malloc(sizeof(struct wave_req))) == NULL)	return -1;
	memset(user, 0, sizeof(struct wave_req));
	req.ifr_data = (struct wave_req *)user;
	strcpy(req.ifr_name, "vmc0");

	wave = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (wave < 0) {
		printf("%d: socket() open error !!!!\n", wave);
		retval = 0;
		goto _Exit;
	}

	user->cmd = cmd;
	memcpy(&user->data[0],data,length);

#if 0
	printf("category : %d, user->cmd : %d and data length : %d\n",category,user->cmd, length);
	for(i=0; i<length; i++){
		printf("0x%02x ",user->data[i]);
	}
	printf("\n");
#endif

	if (ioctl(wave, (SIOCDEVPRIVATE+category), &req) < 0) {
		printf("ioctl(SIOCDEVPRIVATE) : ioctl error\n");
		retval = 0;
		goto _Exit;
	}
	if(rdwr == IOCTL_READ){
		memcpy(data,&user->data[0],COMMAND_DATA_LENGTH);
	}

_Exit:
	free(user);
	close(wave);
	return retval;
}

int Send_rsmgmt_pid(int pid)
{
    int op, arg=0,len = 0;
    unsigned char data[COMMAND_DATA_LENGTH];

    data[len] = RSMGMT_PID;
	len += 1;
	PUT_32BIT_TO_FOUR_CHARS(data[len], data[len+1], data[len+2], data[len+3], pid);
    len += 4;
    op = IOCTL_WRITE;

    if(len > 0){
        send_wavecmd(op,ETC_CATEGORY,PID_CMD,len,data);
    }
    return 0;
}

unsigned char Get_rsmgmt_mode(void)
{
    int op, arg=0,len = 0;
    unsigned char data[COMMAND_DATA_LENGTH];

    data[len] = GET_OPMODE_CMD;
	len += 1;
    op = IOCTL_READ;

    if(len > 0){
        send_wavecmd(op,MAC_CATEGORY,GET_OPMODE_CMD,len,data);
		return data[0];
    }
    return 0;
}
