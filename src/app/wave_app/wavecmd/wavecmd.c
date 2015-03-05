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

extern	int regaddr(char **reqs);
extern	int cntmac(char **reqs);
extern	int dbgmsg(char **reqs);
extern	int landbg(char **reqs);
extern	int datarate(char **reqs);
extern	int opmode(char **reqs);
extern	int clrcnt(char **reqs);
extern	int fchange(char **reqs);
extern	int rfpower(char **reqs);
extern	int testpkt(char **reqs,int cmd);
extern	int macaddr(char **reqs);
extern	int amc_onoff(char **reqs);

unsigned char Hex(unsigned char ch)
{
    unsigned char hex;

    if ('0'<=ch && ch<='9')
        hex = ch -'0';
    else if('A'<=ch && ch<='F')
        hex = ch - 'A' + 0xa;
    else if('a'<=ch && ch<='f')
        hex = ch - 'a' + 0xa;
	else	
		hex = 'X';

    return hex;
}

int send_lancmd(int rdwr, int category, int cmd,int length, unsigned char *data)
{
	struct wave_req *user=NULL;
	struct ifreq req;
	int i,wave;
	
	if((user = (struct wave_req *)malloc(sizeof(struct wave_req))) == NULL)	return -1;
	memset(user, 0, sizeof(struct wave_req));
	req.ifr_data = (struct wave_req *)user;
	strcpy(req.ifr_name, "eth0");

	wave = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (wave < 0) {
		printf("%d: socket() open error !!!!\n", wave);
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
		printf("ioctl(SIOCDEVPRIVATE) : LAN911x ioctl error\n");
	}
	if(rdwr == IOCTL_READ){
		memcpy(data,&user->data[0],COMMAND_DATA_LENGTH);
	}

_Exit:
	free(user);
	close(wave);
	return -1;
}
int send_wavecmd(int rdwr, int category, int cmd,int length, unsigned char *data)
{
	struct wave_req *user=NULL;
	struct ifreq req;
	int i,wave;
	
	if((user = (struct wave_req *)malloc(sizeof(struct wave_req))) == NULL)	return -1;
	memset(user, 0, sizeof(struct wave_req));
	req.ifr_data = (struct wave_req *)user;
	strcpy(req.ifr_name, "vmc0");

	wave = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (wave < 0) {
		printf("%d: socket() open error !!!!\n", wave);
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
		printf("ioctl(SIOCDEVPRIVATE) : LAN9215 ioctl error\n");
	}
	if(rdwr == IOCTL_READ){
		memcpy(data,&user->data[0],COMMAND_DATA_LENGTH);
	}

_Exit:
	free(user);
	close(wave);
	return -1;
}

int simple_cmd(int category, int command)
{
    unsigned char data[COMMAND_DATA_LENGTH];
	int op;

	op = IOCTL_WRITE;

	send_wavecmd(op,category,command,1,data);

	return 0;
}

static void wavecmd_usage_message(void)
{
	printf("===== WAVE Shell Command =====\n");
	printf("%s : register Read/Write\n",REGADDR);
	printf("%s : Set mac address\n",MACADDR);
	printf("%s : Read mac count\n",CNTMAC_COUNT);
	printf("%s : clear Counter\n",CLRCNT);
	printf("%s : Set Debug Level\n",DEBUG_MSG);
	printf("%s : Set EtherLan Debug Level\n",LAN_DEBUG_MSG);
	printf("%s : Set DataRate\n",DATARATE);
	printf("%s : Set Operation Mode\n",OPMODE);
	printf("%s : RF Frequency change\n",FCHANGE);
	printf("%s : Set RF Power\n",RFPOWER);
	printf("%s : Send test packet\n",TXPKT);
	printf("%s : Send test packet (to destination)\n",TX);
	printf("%s : Print Mac Table\n",MACTABLE);
	printf("%s : Adaptive Modulation and Coding Scheme(AMC) on/off\n",AMC);
}

int whichcommand(char *cmd)
{
	if(!strcmp(cmd,REGADDR)){
		return(REGADDR_CMD);
	}
	if(!strcmp(cmd,CNTMAC_COUNT)){
		return(CNTMAC_CMD);
	}
	if(!strcmp(cmd,DEBUG_MSG)){
		return(DEBUG_LEVEL_CMD);
	}
	if(!strcmp(cmd,LAN_DEBUG_MSG)){
		return(LAN_DBG_CMD);
	}
	if(!strcmp(cmd,DATARATE)){
		return(DATARATE_CMD);
	}
	if(!strcmp(cmd,OPMODE)){
		return(OPMODE_CMD);
	}
	if(!strcmp(cmd,CLRCNT)){
		return(CLRCNT_CMD);
	}
	if(!strcmp(cmd,FCHANGE)){
		return(FCHANGE_CMD);
	}
	if(!strcmp(cmd,RFPOWER)){
		return(RFPOWER_CMD);
	}
	if(!strcmp(cmd,TXPKT)){
		return(TXPKT_CMD);
	}
	if(!strcmp(cmd,TXMGT)){
		return(TXMGT_CMD);
	}
	if(!strcmp(cmd,TX)){
		return(TX_CMD);
	}
	if(!strcmp(cmd,MACADDR)){
		return(MACADDR_CMD);
	}
	if(!strcmp(cmd,MACTABLE)){
		return(MACTABLE_CMD);
	}
	if(!strcmp(cmd,AMC)){
		return(AMC_CMD);
	}
	return -1;
}

int main(int argc, char **argv)
{
	int command;

	if(argc == 1){
		wavecmd_usage_message();
		return 1;
	}

	command = whichcommand(argv[1]);
	switch(command){
	case REGADDR_CMD:
		regaddr(&argv[2]);
		break;
	case MACADDR_CMD:
		macaddr(&argv[2]);
		break;
	case CNTMAC_CMD:
		cntmac(&argv[2]);
		break;
	case DEBUG_LEVEL_CMD:
		dbgmsg(&argv[2]);
		break;
	case DATARATE_CMD:
		datarate(&argv[2]);
		break;
	case OPMODE_CMD:
		opmode(&argv[2]);
		break;
	case CLRCNT_CMD:
		clrcnt(&argv[2]);
		break;
	case FCHANGE_CMD:
		fchange(&argv[2]);
		break;
	case RFPOWER_CMD:
		rfpower(&argv[2]);
		break;
	case TXPKT_CMD:
		testpkt(&argv[2], TXPKT_CMD);
		break;
	case TXMGT_CMD:
		testpkt(&argv[2], TXMGT_CMD);
		break;
	case TX_CMD:
		testpkt(&argv[2], TX_CMD);
		break;
	case MACTABLE_CMD:
		simple_cmd(MAC_CATEGORY,MACTABLE_CMD);
		break;
	case AMC_CMD:
		amc_onoff(&argv[2]);
		break;
	case LAN_DBG_CMD:
		landbg(&argv[2]);
		break;
	default:
		wavecmd_usage_message();
		break;
	}
	
	return 1;
} // main(int argc, char **argv)
