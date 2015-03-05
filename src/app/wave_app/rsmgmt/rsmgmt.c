#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <termio.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include "rsmgmt.h"

#include "../comm_inc/svcdefs.h"
#include "../comm_inc/asn.h"

extern	int rsmgmt_mutex_init(struct rsmgmt_wave *rsmgmt);
extern	int rsmgmt_mem_init(struct rsmgmt_wave *rsmgmt);
extern	void rsmgmt_mem_free(struct rsmgmt_wave *rsmgmt);
extern	struct rsmgmt_pkt * rsmgmt_nl_NewQueue(struct rsmgmt_wave *rsmgmt);
extern	struct rsmgmt_pkt * rsmgmt_nl_Dequeue(struct rsmgmt_wave *rsmgmt);
extern	int rsmgmt_nl_SetEnqueue(struct rsmgmt_wave *rsmgmt);
extern	int rsmgmt_nl_FreeDequeue(struct rsmgmt_wave *rsmgmt);
extern	int GetNetLinkInterface(int prototype,int group,int pid);
extern	int GetBasicSaftyMsg(struct rsmgmt_wave *rsmgmt,struct _BSM *bsmMsg);
extern	int RecvNetLinkData(int sockfd,int length,int pid, unsigned char *buffer);
extern	int Send_rsmgmt_pid(int pid);
extern	int BasicSaftyMsg_init(struct rsmgmt_wave *rsmgmt);
extern	void BasicSaftyMsg_free(struct rsmgmt_wave *rsmgmt);
extern	void MakeWSM_request(struct rsmgmt_wave *rsmgmt, unsigned char *wsmData, unsigned short size);

int DebugLevel = 0;
struct rsmgmt_wave RSMGMT;
static int	rsmgmt_Recv_Running = 0;
static int	rsmgmt_Event_Running = 0;
static int	svcReq_Running = 0;

void * rsmgmt_Recv_Thread(void * arg)
{
	struct rsmgmt_wave *rsmgmt = (struct rsmgmt_wave *)arg;
	struct rsmgmt_pkt *pkt;
	int rcv_count;
	unsigned char buf[WAVE_RM_SIZE];

	rsmgmt_Recv_Running = 1;
	while(rsmgmt_Recv_Running){
		if((rcv_count = RecvNetLinkData(rsmgmt->socknl,WAVE_RM_SIZE,rsmgmt->rsmgmt_pid,buf)) > 0){
			pkt = rsmgmt_nl_NewQueue(rsmgmt);
			if(pkt != NULL){
#if 0
				printf("\n======= %d bytes received =======\n",rcv_count);
				for(i=0; i<rcv_count; i++){
           			if((i % 16) == 0)   printf("\n");
					printf("%02x ",buf[i]);
				}
				printf("\n=================================\n");
#endif
				memcpy(&pkt->rmpkt[0],buf,rcv_count);
				pkt->datalen = rcv_count;
				pkt->dataptr = (unsigned char *)&pkt->rmpkt[0];
				rsmgmt_nl_SetEnqueue(rsmgmt);
			}
		}
	}
	pthread_exit("end");
}

void RecvWsmMsgFromEther(struct rsmgmt_wave *rsmgmt,unsigned char * message, int len)
{
	unsigned char destmac[ETH_ALEN]={0,};
	unsigned char srcmac[ETH_ALEN]={0,};
	unsigned char psid[4]={0,};
	int i,datalen = len;
	int offset = ETH_HLEN;

#if 1
	printf("RecvWsmMsgFromEther : data length (%d)\n",len);
	printf("\t-> dest mac address : ");
	for(i=0; i<ETH_ALEN; i++){
		printf("%02x ",message[i]);
	}
	printf("\n");
	
	printf("\t-> src mac address : ");
	for(i=0; i<ETH_ALEN; i++){
		printf("%02x ",message[ETH_ALEN+i]);
	}
	printf("\n");
#endif

	offset += GET_PSID_OCTET_STR(&message[offset],&psid[0]);

#if 1
	printf("\t-> psid\n");
	for(i=0; i<4; i++){
		printf("%02x ",psid[i]);
	}
	printf("\n");
#endif

	datalen -= offset;

#if 1
	printf("\t-> bsm data (%d)\n",datalen);
	for(i=0; i<datalen; i++){
		if((i % 16) == 0)   printf("\n");
		printf("%02x ",message[offset+i]);
	}
	printf("\n");
#endif

//    request_decode( OUT_DER, &message[offset], datalen );
    WSM_WaveShortMessage_request( psid, &message[offset], datalen );
}

void * rsmgmt_Event_Thread(void * arg)
{
	struct rsmgmt_wave *rsmgmt = (struct rsmgmt_wave *)arg;
	struct rsmgmt_pkt *pkt;
	int i;
	unsigned short reqType = 0;

	rsmgmt_Event_Running = 1;
	while(rsmgmt_Event_Running){
		if((pkt = rsmgmt_nl_Dequeue(rsmgmt)) != NULL){
			if(DebugLevel == EVENT_MSG_LEVEL){
				printf("\n======= rsmgmt_Event_Thread : %d bytes received =======\n",pkt->datalen);
				for(i=0; i<pkt->datalen; i++){
       				if((i % 16) == 0)   printf("\n");
					printf("%02x ",pkt->rmpkt[i]);
				}
				printf("\n=======================================================\n");
			}
			if((pkt->rmpkt[ETH_HLEN-2] == 0x88) && (pkt->rmpkt[ETH_HLEN-1] == 0xdc)){	// Ether Type = WSM (0x88dc)	
				RecvWsmMsgFromEther(rsmgmt,&pkt->rmpkt[0],pkt->datalen);
			}else{
				GET_16BIT_FROM_TWO_CHARS(reqType,pkt->rmpkt[0],pkt->rmpkt[1]);
				//	printf("--> svcRequest type is %d\n",reqType);
				//	printf("--> %s\n",&svcbuf[2]);
				switch(reqType){
				case WSM_WAVESHORTMESSAGE_CONFIRM:
					printf("WSM_WAVESHORTMESSAGE_CONFIRM !!!\n");
					break;
				} // switch(reqType)
			}
			rsmgmt_nl_FreeDequeue(rsmgmt);
		} // if((pkt = rsmgmt_nl_Dequeue(rsmgmt)) != NULL)
	}
	pthread_exit("end");
} //  rsmgmt_Event_Thread

int SendSvcMsgToApp(int sock,unsigned char * message, int len)
{
	int result = 0;
	if((result = send(sock, message,len, 0)) < 0) {
		printf("Ack Send error");
	}
	return result;
}

void * ServiceEvent_Thread(void * arg)
{
	struct rsmgmt_wave *rsmgmt = (struct rsmgmt_wave *)arg;
	struct _BSM *BSMmsg;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	struct timeval tv;
	fd_set read_fds, tmp_read_fds;
	int csock;
	int fd;
	int optvalue = 1;
	int optlen = sizeof(optvalue);
	unsigned int clen;
	int result = 0;
	unsigned short reqType = 0;
	unsigned char svcbuf[SVC_EVENT_MAX_BUF] = {0,};
	char tempbuf[SVC_EVENT_MAX_BUF] = {0,};

    if ((rsmgmt->svcsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        printf("svcsock socket error \n");
		goto _Exit;
    }

	tv.tv_sec = 1;
	setsockopt(rsmgmt->svcsock, SOL_SOCKET, SO_REUSEADDR, &optvalue, optlen);
	setsockopt(rsmgmt->svcsock, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &tv, sizeof(struct timeval));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htons(INADDR_ANY);
    server_addr.sin_port = htons(SVC_TCP_PORT);

	if(bind(rsmgmt->svcsock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("m_adt_ssock bind error");
		goto _Exit;
    }

	if (listen(rsmgmt->svcsock, 5) < 0) {
		printf("m_adt_ssock listen error");
	}

	svcReq_Running = 1;
    clen = sizeof(client_addr);
    FD_ZERO(&read_fds);
    FD_SET(rsmgmt->svcsock, &read_fds);

//    printf("ServiceEvent_Thread call sucess\n" );
	while(svcReq_Running){
		tmp_read_fds = read_fds;
		if (select(FD_SETSIZE, &tmp_read_fds, (fd_set *)0, (fd_set *)0, (struct timeval *)0) < 1) {
			printf("select error");
		}
		for(fd = 0; fd < FD_SETSIZE; fd++){
			if(FD_ISSET(fd, &tmp_read_fds)) {
				if(fd == rsmgmt->svcsock){
					csock = accept(rsmgmt->svcsock, (struct sockaddr *)&client_addr, &clen);
					FD_SET(csock, &read_fds);
				}else{
					result = recv(fd, &svcbuf, sizeof(svcbuf), 0);
				//	printf("svc received byte is %d\n",result);
					if(result >= 2){
					//    printf("svc received byte is %d\n",result);
						GET_16BIT_FROM_TWO_CHARS(reqType,svcbuf[0],svcbuf[1]);
					//	printf("--> svcRequest type is %d\n",reqType);
					//	printf("--> %s\n",&svcbuf[2]);
						switch(reqType){
						case GET_BSM_MSG_REQEUEST:
							BSMmsg = malloc(sizeof(struct _BSM));
							if(GetBasicSaftyMsg(rsmgmt,BSMmsg) > 0){
								SendSvcMsgToApp(fd,(unsigned char *)BSMmsg, sizeof(struct _BSM));
							}
							free(BSMmsg);
							break;
						case WSM_WAVESHORTMESSAGE_REQUEST:
                     //       printf("-->WSM_WAVESHORTMESSAGE_REQUEST\n");
							MakeWSM_request(rsmgmt, &svcbuf[2], (result-2));
							break;
						} // switch(reqType)
					}		
				}
			} // if(FD_ISSET(fd, &tmp_read_fds))
		} // for (fd = 0; fd < FD_SETSIZE; fd++)
	}

_Exit:
	close(rsmgmt->svcsock);
	rsmgmt->svcsock = 0;
	pthread_exit("end");
} //  ServiceEvent_Thread

#if 1	// For wsm client testing
extern	void wsm_client_test(char **reqs,struct rsmgmt_wave *rsmgmt);
#endif

void delBridge(void)
{
	char command[50]={0,};

	sprintf(command,"brctl delif br0 eth0");
	system(command);

	memset(command,0,sizeof(command));
	sprintf(command,"brctl delif br0 vmc0");
	system(command);

	memset(command,0,sizeof(command));
	sprintf(command,"ifconfig br0 down");
	system(command);

	memset(command,0,sizeof(command));
	sprintf(command,"brctl delbr0 br0");
	system(command);
}

void addBridge(char *address)
{
	char command[50]={0,};

	sprintf(command,"brctl addbr br0");
	system(command);

	memset(command,0,sizeof(command));
	sprintf(command,"brctl addif br0 eth0");
	system(command);

	memset(command,0,sizeof(command));
	sprintf(command,"brctl addif br0 vmc0");
	system(command);

	memset(command,0,sizeof(command));
	sprintf(command,"ifconfig br0 %s",address);
	system(command);
}

void setRSUmode(void)
{
	char command[50]={0,};

	printf("--> setRSUmode !!!!\n");
	sprintf(command,"/etc/rsu.sh");
	system(command);
}

int SetBR0_IPAddress(struct  in_addr ipaddr)
{
	int i,j=0;
	char address[24]={0,};
	char command[50]={0,};
	char *str = &address[0];
	
	strcpy(address,inet_ntoa(ipaddr));
//	printf("address is %s\n",address);

	if(strncmp(address,"0.0.0.0",6)){
		for(i=0; i<24; i++){
			if(str[i] == '.'){
				j += 1;
				if(j >= 3){
					str[i+1] = '2';
					str[i+2] = '5';
					str[i+3] = '4';
					str[i+4] = NULL;
					addBridge(address);
					break;
				}
			}
		}
		return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int argIndex = 1;
	pthread_t 	rsmgmtRecvThread;
	pthread_t 	rsmgmtEventThread;
	pthread_t 	svcEventThread;

	if(argc >= 3){
		if(!strcmp(argv[argIndex],"-d")){
			argIndex += 1;
			DebugLevel = atoi(argv[argIndex++]);
			printf("DebugLevel is %d\n",DebugLevel);
		}
	}

	if(rsmgmt_mem_init(&RSMGMT) == -1){
		printf("rsmgmt_mem_init fail !!!!\n");
		return 1;
	}
 
	if(rsmgmt_mutex_init(&RSMGMT) == -1){
		printf("rsmgmt_mutex_init fail !!!!\n");
		rsmgmt_mem_free(&RSMGMT);	
		pthread_mutex_destroy(&RSMGMT.rsmgmt_nl_mutex);		
		return 1;
	}

	RSMGMT.rsmgmt_pid = getpid();  
	if((RSMGMT.socknl = GetNetLinkInterface(NETLINK_RSMGMT,0,RSMGMT.rsmgmt_pid)) == -1){
		printf("NetLink Interface Init Fail !!\n");	
		rsmgmt_mem_free(&RSMGMT);	
		return 1;
	}
	DBG_MSG(BASIC_MSG_LEVEL,"NetLink Interface : netlink sock (%d), pid(%d)!!\n",RSMGMT.socknl,RSMGMT.rsmgmt_pid);	

	if(pthread_create(&rsmgmtRecvThread, NULL, rsmgmt_Recv_Thread, &RSMGMT) != 0){
		printf("rsmgmt_Recv_Thread create error");
		goto _Exit;
	}

	if(pthread_create(&rsmgmtEventThread, NULL, rsmgmt_Event_Thread, &RSMGMT) != 0){
		printf("rsmgmt_Event_Thread create error");
		goto _Exit;
	}

    if(BasicSaftyMsg_init(&RSMGMT) == -1) {
        printf("BasicSaftyMsg_init Failed !!!!\n");
		goto _Exit;
	}

	if(pthread_create(&svcEventThread, NULL, ServiceEvent_Thread, &RSMGMT) != 0){
		printf("SvcEvent_Thread create error");
		goto _Exit;
	}

	Send_rsmgmt_pid(RSMGMT.rsmgmt_pid);
	RSMGMT.mode = Get_rsmgmt_mode();
/*
    if((RSMGMT.mode == EVEN_RSU_MODE) || (RSMGMT.mode == ODD_RSU_MODE)){
		setRSUmode();
	}
*/

#if 0	// For wsm client testing
	if(argv[argIndex] != NULL){
		if(!strcmp(argv[argIndex],"client")){
			argIndex += 1;
			wsm_client_test(&argv[argIndex],&RSMGMT);
			sleep(2);
			goto _Exit;
		}
	}
#endif
	
	while(1);

_Exit:
	rsmgmt_Recv_Running = 0;
	rsmgmt_Event_Running = 0;
	svcReq_Running = 0;
	rsmgmt_mem_free(&RSMGMT);	
	BasicSaftyMsg_free(&RSMGMT);
	pthread_mutex_destroy(&RSMGMT.rsmgmt_nl_mutex);		
	close(RSMGMT.socknl);
	return 1;
} // main
