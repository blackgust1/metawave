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

static void usage_message(int cmd)
{
	if(cmd == TX_CMD){
		printf("Usage : %s mac channel length frame power datarate delay\n",TX);
	}else if(cmd == TXPKT_CMD){
		printf("Usage : %s mac channel length frame power datarate delay\n",TXPKT);
	}else if(cmd == TXMGT_CMD){
		printf("Usage : %s mac channel length frame power datarate delay\n",TXMGT);
	}
	printf("\tmac : A (MacA) or B (MacB)\n");
	printf("\tchannel : ch1|ch2|ch3|ch4|sh1\sh2\sh3\sh4\n");
	printf("\tlength : Data length\n");
	printf("\tframe : frame number\n");
	printf("\tpower : tx power (dec. 0~15)\n");
	printf("\tdatarate : 3, 4, 6, 9, 12, 18, 24, 27\n");
	printf("\tdelay : time delay (msec)\n");
}

int testpkt(char **reqs,int cmd)
{
	int arg=0,len = 0;
	int op;
	unsigned int val;
    unsigned char data[COMMAND_DATA_LENGTH];

	if(reqs[arg] == NULL){
		usage_message(cmd);
		return -1;
	}

	/* 1st argument (MAC A or B) */
	if((!strcmp(reqs[arg],"a")) || (!strcmp(reqs[arg],"A"))){
		data[len] = MAC_A;
	}else if((!strcmp(reqs[arg],"b")) || (!strcmp(reqs[arg],"B"))){
		data[len] = MAC_B;
	}else{
		printf("Invalid MAC => A or B\n");
		return -1;
	}
	len += 1;
	arg += 1;

	/* 2nd argument (Channel Num) */
	if(!strcmp(reqs[arg],"ch1")){
		data[len] = CCH_AC1;
	}else if(!strcmp(reqs[arg],"ch2")){
		data[len] = CCH_AC2;
	}else if(!strcmp(reqs[arg],"ch3")){
		data[len] = CCH_AC3;
	}else if(!strcmp(reqs[arg],"ch4")){
		data[len] = CCH_AC4;
	}else if(!strcmp(reqs[arg],"sh1")){
		data[len] = SCH_AC1;
	}else if(!strcmp(reqs[arg],"sh2")){
		data[len] = SCH_AC2;
	}else if(!strcmp(reqs[arg],"sh3")){
		data[len] = SCH_AC3;
	}else if(!strcmp(reqs[arg],"sh4")){
		data[len] = SCH_AC4;
	}else{
		printf("Invalid channel => ch1|ch2|ch3|ch4|sh1\sh2\sh3\sh4\n");
		return -1;
	}
	len += 1;
	arg += 1;

	/* 3rd argument (Data length) */
	if(reqs[arg] == NULL)	{
		printf("length is limitted between 0 and 0x914(dec. 0~2000)\n");
		return -1;
	}
	val = atoi(reqs[arg]);
	if((val < 0) || (val > 2000)){
		printf("length is limitted between 0 and 0x914(dec. 0~2000)\n");
		return -1;
	}
	PUT_16BIT_TO_TWO_CHARS(data[len], data[len+1],val);
	len += 2;
	arg += 1;

	/* 4th argument (Frame Counts) */
	if(reqs[arg] == NULL)	{
		printf("Frame number is needed !!!\n");
		return -1;
	}
	val = atoi(reqs[arg]);
	if(val <= 0){
		printf("Frame nember range fail (%d) !!!!\n",val);
		return -1;
	}

	PUT_32BIT_TO_FOUR_CHARS(data[len], data[len+1], data[len+2], data[len+3],val);
	len += 4;
	arg += 1;

	/* 5th argument (Tx Power) */
	if(reqs[arg] == NULL)	{
		printf("Tx Power is needed !!!\n");
		return -1;
	}
	val = atoi(reqs[arg]);
	if(val <= 0){
		printf("Tx Power range is limitted between 0 and 0xf(dec. 0~15) !!!!\n");
		return -1;
	}

	data[len] = val;
	len += 1;
	arg += 1;

	/* 6th argument (Datarate) */
	if(reqs[arg] == NULL)	{
		printf("Datarate is needed !!!\n");
		return -1;
	}
	val = atoi(reqs[arg]);
	if( !((val == 3) || (val == 4) || (val == 6) || (val == 9) || (val == 12) || (val == 18) || (val == 24) || (val == 27)) ){
		printf("data rate is limitted 3, 4, 6, 9, 12, 18, 24, 27\n");
		return -1;
	}
	data[len] = val;
	len += 1;
	arg += 1;

	/* 7th argument (Delay Time) */
	if(reqs[arg] == NULL)	{
		printf("Delay Time is needed !!!\n");
		return -1;
	}
	val = atoi(reqs[arg]);
	if(val <= 0){
		printf("Delay Time range fail (%d) !!!!\n",val);
		return -1;
	}
	data[len] = val;
	len += 1;
	arg += 1;

	op = IOCTL_WRITE;

	if(len > 0){
		send_wavecmd(op,VMC_CATEGORY,cmd,len,data);
	}
	return 0;
} // main(int argc, char **argv)
