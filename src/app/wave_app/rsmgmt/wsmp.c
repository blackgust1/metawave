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

#define	MAX_BUF_SIZE	100
static struct _BSM *BasicSaftyMsg=NULL;

extern	int SendNetLinkData(int sockfd,int length,int pid, unsigned char *buffer);

static void PutWSMReqHeader(struct _WSM_MsgReq *wsmReqMsg, char *buf)
{
	int i;
	unsigned int lval;
	char *pval;

	pval = get_conf_value("WSMP_VERSION", buf);
	if(pval != NULL){
		wsmReqMsg->wsmp_ver = atoi(pval);
		return;
	}

	pval = get_conf_value("PSID", buf);
	if(pval != NULL){
		if(!strncmp(pval, "0x", 2)){
			lval = strtoul(pval,NULL,16);
		}else{
			lval = atoi(pval);
		}
		PUT_32BIT_TO_FOUR_CHARS(wsmReqMsg->psid[0], wsmReqMsg->psid[1], wsmReqMsg->psid[2], wsmReqMsg->psid[3], lval);
	//	wsmReqMsg->psid = lval;
		return;
	}

	pval = get_conf_value("DST_MAC", buf);
	if(pval != NULL){
		for(i=0; i<6; i++){
			if(*pval == ':')	pval += 1;
			wsmReqMsg->dstmac[i] = (Hex(*(pval++)) << 4) | Hex(*(pval++));
    	}
		return;
	}

	pval = get_conf_value("WSMP_EXT", buf);
	if(pval != NULL){
       	wsmReqMsg->ext = atoi(pval);
		return;
	}

	pval = get_conf_value("EXPIRY_TIME", buf);
	if(pval != NULL){
       	wsmReqMsg->expirytime = atoi(pval);
		return;
	}

	pval = get_conf_value("USER_PRIORITY", buf);
	if(pval != NULL){
       	wsmReqMsg->priority = atoi(pval);
		return;
	}

	if(wsmReqMsg->ext){
		pval = get_conf_value("CHANNEL", buf);
		if(pval != NULL){
   	    	wsmReqMsg->channel = atoi(pval);
			return;
		}
		pval = get_conf_value("DATARATE", buf);
		if(pval != NULL){
   	    	wsmReqMsg->datarate = atoi(pval);
			return;
		}
		pval = get_conf_value("TRANSPOWER", buf);
		if(pval != NULL){
   	    	wsmReqMsg->txpower = atoi(pval);
			return;
		}
	} // if(ext->flag)

	pval = get_conf_value("WSMP_EID", buf);
	if(pval != NULL){
		if(!strncmp(pval, "0x", 2)){
			lval = strtoul(pval,NULL,16);
		}else{
			lval = atoi(pval);
		}
		wsmReqMsg->weid = lval;
		return;
	}
}

static int getWSMReqHeaderFromFile(char *file,struct _WSM_MsgReq *wsmReqMsg)
{
	FILE *fp;
	char buff[MAX_BUF_SIZE]={0,};

	fp = fopen(file,"r");
    if(fp == NULL){
        printf("%s file open error !!!\n",file);
        return -1;
    }

	while(1){
		if(fgets((char *)&buff[0], MAX_BUF_SIZE, fp) == NULL)	break;
		PutWSMReqHeader(wsmReqMsg,buff);
	} // while(1)

    if(DebugLevel == WSMP_MSG_LEVEL){
        printf("wsmReqMsg->wsmp_ver is (%d)\n",wsmReqMsg->wsmp_ver);	/* The version of the WSM protocol */
        printf("wsmReqMsg->psid is %02x%02x%02x%02x\n",wsmReqMsg->psid[0],wsmReqMsg->psid[1],wsmReqMsg->psid[2],wsmReqMsg->psid[3]);
        printf("wsmReqMsg->dstmac is (%02x:%02x:%02x:%02x:%02x:%02x)\n",wsmReqMsg->dstmac[0],wsmReqMsg->dstmac[1],wsmReqMsg->dstmac[2],
                    wsmReqMsg->dstmac[3],wsmReqMsg->dstmac[4],wsmReqMsg->dstmac[5]);
        printf("wsmReqMsg->expirytime is (%lld)\n",wsmReqMsg->expirytime);
        printf("wsmReqMsg->priority is (%d)\n",wsmReqMsg->priority);
        printf("wsmReqMsg->weid is (%d)\n",wsmReqMsg->weid);
        if(wsmReqMsg->ext){
            printf("External Field : channel(%d),datarate(%d),power(%d)\n",wsmReqMsg->channel,wsmReqMsg->datarate,wsmReqMsg->txpower);	
        }
    }

	fclose(fp);
	return 0;
}

void MakeWSM_request(struct rsmgmt_wave *rsmgmt, unsigned char *wsmData, unsigned short size)
{
	struct _WSM_MsgReq *wsmReqMsg;
	int i,offset=0;
	unsigned char psidoctet[4]={0,};
	unsigned char frame[WAVE_FRAME_MAX_BUF]={0,};

	if((wsmReqMsg = malloc(sizeof(struct _WSM_MsgReq))) == NULL){
		printf ("unable to alloc memory for WSM_MsgReq !!!\n");
		return;
	}
	memset(wsmReqMsg,0,sizeof(struct _WSM_MsgReq));

	if(getWSMReqHeaderFromFile("/etc/wsmreq.sch",wsmReqMsg) != -1){
		PUT_16BIT_TO_TWO_CHARS(frame[offset++], frame[offset++], WSM_WAVESHORTMESSAGE_REQUEST);
		for(i=0 ;i<ETH_ALEN; i++){
			frame[offset+i] = wsmReqMsg->dstmac[i];
		}
		offset += (ETH_ALEN * 2);
		PUT_16BIT_TO_TWO_CHARS(frame[offset++], frame[offset++], IPV4_WSMP_PROTOCOL_TYPE);

		frame[offset++] = wsmReqMsg->wsmp_ver;	/* The version of the WSM protocol */
		offset += PUT_PSID_OCTET_STR(&frame[offset],&wsmReqMsg->psid[0]);

		frame[offset++] = wsmReqMsg->ext;
		if(wsmReqMsg->ext){
			/* Channel Number */
			frame[offset++] = CHANNEL_NUMBER;
			frame[offset++] = 1;
			frame[offset++] = wsmReqMsg->channel;
			
			/* DataRate */
			frame[offset++] = DATARATE;
			frame[offset++] = 1;
			frame[offset++] = wsmReqMsg->datarate;
			
			/* Tx Power */
			frame[offset++] = TRANSMIT_POWER_USED;
			frame[offset++] = 1;
			frame[offset++] = wsmReqMsg->txpower;
			
		//	printf("External Field : channel(%d),datarate(%d),power(%d)\n",wsmReqMsg->channel,wsmReqMsg->datarate,wsmReqMsg->txpower);
		} // if(ext->flag)

		frame[offset++] = wsmReqMsg->weid;
		PUT_16BIT_TO_TWO_CHARS(frame[offset++],frame[offset++],size);
		memcpy(&frame[offset],wsmData,size);

        if(DebugLevel == WSMP_MSG_LEVEL){
            printf( "frmame data size = %d\n", (size+offset) );
            for( i = 0; i < (size+offset); i++ )
            {
                if( (i % 16) == 0 ) printf( "\n" );

                printf( "%02x ", frame[i]);
            }
            printf( "\n" );
        }

		SendNetLinkData(rsmgmt->socknl,(size+offset),rsmgmt->rsmgmt_pid,frame);
	} // if(getWSMReqHeaderFromFile("/etc/wsmreq.sch",wsmReqMsg) != -1)

	free(wsmReqMsg);
} // MakeWSM_request

int GetBasicSaftyMsg(struct rsmgmt_wave *rsmgmt,struct _BSM *bsmMsg)
{
	int result = -1;
	pthread_mutex_lock(&rsmgmt->bsmMsg_mutex);

	if(BasicSaftyMsg != NULL){
		result = sizeof(struct _BSM);
		memcpy(bsmMsg,BasicSaftyMsg,result);
	}

	pthread_mutex_unlock(&rsmgmt->bsmMsg_mutex);
	return result;
} // GetBasicSaftyMsg_request

int BasicSaftyMsg_init(struct rsmgmt_wave *rsmgmt)
{
	if((BasicSaftyMsg = malloc(sizeof(struct _BSM))) == NULL)	return -1;
	memset(BasicSaftyMsg,0, sizeof(struct _BSM));
	return 1;
}

void BasicSaftyMsg_free(struct rsmgmt_wave *rsmgmt)
{
	if(BasicSaftyMsg != NULL)	free(BasicSaftyMsg);
}
