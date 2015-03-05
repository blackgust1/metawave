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
#include "svcmgmt.h"
#include "../comm_inc/svcdefs.h"

int WSM_WaveShortMessage_request(unsigned char *psid,unsigned char *wsmData,unsigned short size)
{
	struct sockaddr_in server_addr;
    int csock;
    int result=0,datalen=0,offset=0;
	char svcbuf[SVC_EVENT_MAX_BUF] = {0,};
    char tempbuf[SVC_EVENT_MAX_BUF] = {0,};

    csock = socket(AF_INET, SOCK_STREAM, 0);
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(SVC_TCP_PORT);

    if( psid == NULL || wsmData == NULL || size == 0 )
    {
        return 0;
    }

	if(connect(csock, (struct sockaddr*) &server_addr, sizeof(server_addr)) < 0){
		printf("svc sock connect fail\n");
		return 0;
    }

	PUT_16BIT_TO_TWO_CHARS(svcbuf[offset++], svcbuf[offset++], WSM_WAVESHORTMESSAGE_REQUEST);
	offset += PUT_PSID_OCTET_STR(&svcbuf[offset],psid);

	memcpy(&svcbuf[offset],wsmData,size);
//	strcpy(&svcbuf[2],"GetBasicSaftyMsg_request"); 
	datalen = offset+size;

	result = send(csock, svcbuf, datalen, 0);
	close(csock);
	return result;
}

int GetBasicSaftyMsg_request(struct _BSM *bsmMsg)
{
	struct sockaddr_in server_addr;
    int csock;
    int result=0,datalen=0;
	char svcbuf[SVC_EVENT_MAX_BUF] = {0,};

    csock = socket(AF_INET, SOCK_STREAM, 0);
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(SVC_TCP_PORT);

	if(connect(csock, (struct sockaddr*) &server_addr, sizeof(server_addr)) < 0){
		printf("svc sock connect fail\n");
		return 0;
    }

	PUT_16BIT_TO_TWO_CHARS(svcbuf[0], svcbuf[1], GET_BSM_MSG_REQEUEST);
//	strcpy(&svcbuf[2],"GetBasicSaftyMsg_request"); 
	datalen = 2;
	if(send(csock, svcbuf, datalen, 0) > 0){
		if((result = recv(csock, &svcbuf, sizeof(svcbuf), 0)) > 0){
			printf("GetBasicSaftyMsg_request received byte is %d\n",result);
			memcpy(bsmMsg,svcbuf,result);
		}
    }
	close(csock);
	return result;
}
