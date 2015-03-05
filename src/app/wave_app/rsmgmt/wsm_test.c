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
#include "wave_defs.h"
#include "wsm.h"

extern	int SendNetLinkData(int sockfd,int length,int pid, unsigned char *buffer);
static int DispMsgOn = 0;
struct ifreq if_hwaddr;
struct _BSM BSMmsg;
struct _WSMP WSMPmsg;

unsigned char Hex(unsigned char ch)
{
    unsigned char hex;

    if ('0'<=ch && ch<='9')
        hex = ch -'0';
    else if('A'<=ch && ch<='F')
        hex = ch - 'A' + 0xa;
    else if('a'<=ch && ch<='f')
        hex = ch - 'a' + 0xa;

    return hex;
}

char * get_conf_value(char *buf)
{
	char *str;

	str = strchr(buf,'=');
	str++;
	while(*str != NULL){
		if(*str != 0x20)	return str; 
		str++;
	} // while(*str == NULL){
	return NULL;
}

char * get_conf_value_by_split(char *buf,char *tmp,char splt)
{
	int i=0;
	char *str;

	str = buf;

	while(1){
		if((*str == NULL) || (*str == splt)){
			buf = str;
			return str;;
		}
		tmp[i++] = *str++;
	} // while(1){
}

int get_wsmp_conf(struct _WSMP *wsmp)
{
	FILE *fp;
	char *pval;
	char buff[CONF_BUF_SIZE];
	
	fp = fopen(WSMP_CONF_FILE,"r");
	if(fp == NULL){
		printf("%s file open error !!!\n",WSMP_CONF_FILE);
		return -1;
	}

	while(1){
		memset (buff, 0, CONF_BUF_SIZE);
		if(fgets(buff, CONF_BUF_SIZE, fp) == NULL) break;

		if(!strncmp(buff, WSMP_VER_CONF, strlen(WSMP_VER_CONF))){
			pval = get_conf_value(buff);
			if(!strncmp(pval, "0x", 2)){
				wsmp->wsmp_ver = strtoul(pval,NULL,16);
			}else{
				wsmp->wsmp_ver = atoi(pval);
			}
			if(DispMsgOn)	printf("Find %s and value is %d !!!!\n", WSMP_VER_CONF,wsmp->wsmp_ver);
		}else if(!strncmp(buff, PSID_CONF, strlen(PSID_CONF))){
			pval = get_conf_value(buff);
			if(!strncmp(pval, "0x", 2)){
				wsmp->psid = strtoul(pval,NULL,16);
			}else{
				wsmp->psid = atoi(pval);
			}
			if(DispMsgOn)	printf("Find %s and value is 0x%x !!!!\n", PSID_CONF,wsmp->psid);
		}else if(!strncmp(buff, WSMP_EXT_CONF, strlen(WSMP_EXT_CONF))){
			pval = get_conf_value(buff);
			if(!strncmp(pval, "0x", 2)){
				wsmp->wsmp_ext = strtoul(pval,NULL,16);
			}else{
				wsmp->wsmp_ext = atoi(pval);
			}
			if(DispMsgOn)	printf("Find %s and value is %d !!!!\n",WSMP_EXT_CONF,wsmp->wsmp_ext);
		}else if(!strncmp(buff, WSMP_EID_CONF, strlen(WSMP_EID_CONF))){
			pval = get_conf_value(buff);
			if(!strncmp(pval, "0x", 2)){
				wsmp->wsmp_eid = strtoul(pval,NULL,16);
			}else{
				wsmp->wsmp_eid = atoi(pval);
			}
			if(DispMsgOn)	printf("Find %s and value is %d !!!!\n", WSMP_EID_CONF,wsmp->wsmp_eid);
		}else if(!strncmp(buff, WSMP_USER_PRIORITY_CONF, strlen(WSMP_USER_PRIORITY_CONF))){
			pval = get_conf_value(buff);
			if(!strncmp(pval, "0x", 2)){
				wsmp->priority = strtoul(pval,NULL,16);
			}else{
				wsmp->priority = atoi(pval);
			}
			if(DispMsgOn)	printf("Find %s and value is %d !!!!\n", WSMP_USER_PRIORITY_CONF,wsmp->priority);
		}else if(!strncmp(buff, WSMP_CH_NUM_CONF, strlen(WSMP_CH_NUM_CONF))){
			pval = get_conf_value(buff);
			if(!strncmp(pval, "0x", 2)){
				wsmp->chid = strtoul(pval,NULL,16);
			}else{
				wsmp->chid = atoi(pval);
			}
			if(DispMsgOn)	printf("Find %s and value is %d !!!!\n", WSMP_CH_NUM_CONF,wsmp->chid);
		}else if(!strncmp(buff, WSMP_DATARATE_CONF, strlen(WSMP_DATARATE_CONF))){
			pval = get_conf_value(buff);
			if(!strncmp(pval, "0x", 2)){
				wsmp->datarate = strtoul(pval,NULL,16);
			}else{
				wsmp->datarate = atoi(pval);
			}
			if(DispMsgOn)	printf("Find %s and value is %d !!!!\n", WSMP_DATARATE_CONF,wsmp->datarate);
		}else if(!strncmp(buff, WSMP_POWER_CONF, strlen(WSMP_POWER_CONF))){
			pval = get_conf_value(buff);
			if(!strncmp(pval, "0x", 2)){
				wsmp->power = strtoul(pval,NULL,16);
			}else{
				wsmp->power = atoi(pval);
			}
			if(DispMsgOn)	printf("Find %s and value is %d !!!!\n", WSMP_POWER_CONF,wsmp->power);
		}else if(!strncmp(buff, WSMP_DISP_MSG, strlen(WSMP_DISP_MSG))){
			pval = get_conf_value(buff);
			if(atoi(pval) == 0){
				DispMsgOn = 0;
			}
		}

	} // while(1)

	fclose(fp);
	return 0;
} //  get_wsmp_conf(void)

int get_bsm_conf(struct _BSM *bsm)
{
	FILE *fp;
	int i;
	char *pval;
	char buff[CONF_BUF_SIZE];
	char tmp[TMP_BUF_SIZE];
	
	fp = fopen(BSM_CONF_FILE,"r");
	if(fp == NULL){
		printf("%s file open error !!!\n",BSM_CONF_FILE);
		return -1;
	}

	while(1){
		memset (buff, 0, CONF_BUF_SIZE);
		if(fgets(buff, CONF_BUF_SIZE, fp) == NULL) break;

		if(!strncmp(buff, MSG_TYPE, strlen(MSG_TYPE))){
			pval = get_conf_value(buff);
			bsm->msg_type = atoi(pval);
			if(DispMsgOn)	printf("Find %s and value is %d !!!!\n", MSG_TYPE,bsm->msg_type);
		}else if(!strncmp(buff, SEND_ID, strlen(SEND_ID))){
			pval = get_conf_value(buff);
			bsm->send_id = atoi(pval);
			if(DispMsgOn)	printf("Find %s and value is 0x%d !!!!\n", SEND_ID,bsm->send_id);
		}else if(!strncmp(buff, COUNT, strlen(COUNT))){
			pval = get_conf_value(buff);
			bsm->count = atoi(pval);
			if(DispMsgOn)	printf("Find %s and value is 0x%d !!!!\n", COUNT,bsm->count);
		}else if(!strncmp(buff, MARK, strlen(MARK))){
			pval = get_conf_value(buff);
			bsm->mark = atoi(pval);
			if(DispMsgOn)	printf("Find %s and value is 0x%d !!!!\n", MARK,bsm->mark);
		}else if(!strncmp(buff, VEHICLE_ID, strlen(VEHICLE_ID))){
			pval = get_conf_value(buff);
			bsm->vehicle_id = atoi(pval);
			if(DispMsgOn)	printf("Find %s and value is %d !!!!\n", VEHICLE_ID,bsm->vehicle_id);
		}else if(!strncmp(buff, LATITUDE, strlen(LATITUDE))){
			pval = get_conf_value(buff);
			bsm->latitude = atoi(pval);
			if(DispMsgOn)	printf("Find %s and value is %d !!!!\n", LATITUDE,bsm->latitude);
		}else if(!strncmp(buff, LONGITUDE, strlen(LONGITUDE))){
			pval = get_conf_value(buff);
			bsm->longitude = atoi(pval);
			if(DispMsgOn)	printf("Find %s and value is %d !!!!\n", LATITUDE,bsm->longitude);
		}else if(!strncmp(buff, ELEVATION, strlen(ELEVATION))){
			pval = get_conf_value(buff);
			bsm->elevation = atoi(pval);
			if(DispMsgOn)	printf("Find %s and value is %d !!!!\n", ELEVATION,bsm->elevation);
		}else if(!strncmp(buff, ACCURACY, strlen(ACCURACY))){
			pval = get_conf_value(buff);
			bsm->accuracy = atoi(pval);
			if(DispMsgOn)	printf("Find %s and value is %d !!!!\n", ACCURACY,bsm->accuracy);
		}else if(!strncmp(buff, SPEED, strlen(SPEED))){
			pval = get_conf_value(buff);
			bsm->speed = atoi(pval);
			if(DispMsgOn)	printf("Find %s and value is %d !!!!\n", SPEED,bsm->speed);
		}else if(!strncmp(buff, HEADING, strlen(HEADING))){
			pval = get_conf_value(buff);
			bsm->heading = atoi(pval);
			if(DispMsgOn)	printf("Find %s and value is %d !!!!\n", HEADING,bsm->heading);
		}else if(!strncmp(buff, ANGLE, strlen(ANGLE))){
			pval = get_conf_value(buff);
			bsm->angle = atoi(pval);
			if(DispMsgOn)	printf("Find %s and value is %d !!!!\n", ANGLE,bsm->angle);
		}else if(!strncmp(buff, ACCELERATION, strlen(ACCELERATION))){
			pval = get_conf_value(buff);
			if(DispMsgOn)	printf("Find %s and value is ",ACCELERATION);
			for(i=0; i<ACCELERATION_LENGTH; i++){
				memset(tmp, 0, TMP_BUF_SIZE);
				pval = get_conf_value_by_split(pval,tmp,',');
				bsm->acceleration[i] = atoi(tmp);
				pval += 1;
				if(DispMsgOn)	printf("%d ",bsm->acceleration[i]);
			}
			if(DispMsgOn)	printf("\n");
		}else if(!strncmp(buff, BRAKE, strlen(BRAKE))){
			pval = get_conf_value(buff);
			bsm->brake = atoi(pval);
			if(DispMsgOn)	printf("Find %s and value is %d !!!!\n", BRAKE,bsm->brake);
		}else if(!strncmp(buff, VEHICLE_WIDE, strlen(VEHICLE_WIDE))){
			pval = get_conf_value(buff);
			bsm->veh_wide = atoi(pval);
			if(DispMsgOn)	printf("Find %s and value is %d !!!!\n", VEHICLE_WIDE,bsm->veh_wide);
		}else if(!strncmp(buff, VEHICLE_LENGTH, strlen(VEHICLE_LENGTH))){
			pval = get_conf_value(buff);
			bsm->veh_length = atoi(pval);
			if(DispMsgOn)	printf("Find %s and value is %d !!!!\n", VEHICLE_LENGTH,bsm->veh_length);
		}else if(!strncmp(buff, VARIABLE, strlen(VARIABLE))){
			pval = get_conf_value(buff);
			bsm->variable = atoi(pval);
			if(DispMsgOn)	printf("Find %s and value is %d !!!!\n", VARIABLE,bsm->variable);
		}
	} // while(1)

	fclose(fp);
	return 0;
} //  get_bsm_conf(void)

#if 0
void sendWSMmsg(unsigned char * message, int len)
{
	struct sockaddr_nl sAddr;
	struct nlmsghdr *nlh = NULL;
	struct msghdr msg;
	struct iovec iov;

	memset(&sAddr, 0, sizeof(struct sockaddr_nl));  
	sAddr.nl_family = AF_NETLINK;  
	sAddr.nl_pid = 0;   /* For Linux Kernel */  
	sAddr.nl_groups = 0; /* unicast */  

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(WSM_FRAME_SIZE));  
	memset(nlh, 0, NLMSG_SPACE(WSM_FRAME_SIZE));  
	nlh->nlmsg_len = NLMSG_LENGTH(0);  
	nlh->nlmsg_pid = AppPID_Num;  
	nlh->nlmsg_flags = 0;

	memcpy(NLMSG_DATA(nlh),message,len);  

	iov.iov_base = message;  
	iov.iov_len = len;  

	msg.msg_name = &sAddr;  
	msg.msg_namelen = sizeof(sAddr);  
	msg.msg_iov = &iov;  
	msg.msg_iovlen = 1;  

//    pthread_mutex_lock(&WMS_Sock_Mutex);
	printf("pid(%d), nlmsg_len (%d), data len (%d)\n",nlh->nlmsg_pid,nlh->nlmsg_len,len);
	send(Sockfd, nlh, (nlh->nlmsg_len+len), 0);
 //   pthread_mutex_unlock(&WMS_Sock_Mutex);
	free(nlh);
} //    sendADTmsgToPAD
#endif

int make_wsm_header(unsigned char *frame,unsigned char *dest_mac,struct _WSMP *wsmp)
{
	int offset = 0;

	memset(frame,0x00,sizeof(WSM_FRAME_SIZE));

	memcpy(&frame[offset], (void*)dest_mac, ETH_ALEN);
	offset += ETH_ALEN;

	memcpy((void*)(frame+offset), (void*)if_hwaddr.ifr_hwaddr.sa_data,ETH_ALEN);
	offset += ETH_ALEN;

	frame[offset] = WAVE_ETH_TYPE;
	frame[offset+1] = WSM_ETH_TYPE;
	offset += ETHER_TYPE_SIZE;
		
	PUT_32BIT_TO_FOUR_CHARS(frame[offset], frame[offset+1], frame[offset+2], frame[offset+3], wsmp->psid);
	offset += PSID_SIZE;

//	offset += WSM_PREFIX_SIZE;

#if 0
	frame[offset] = wsmp->wsmp_ver;
	offset += WSMP_VERSION_LENGTH;

	PUT_32BIT_TO_FOUR_CHARS(frame[offset], frame[offset+1], frame[offset+2], frame[offset+3], wsmp->psid);
	offset += PSID_LENGTH;
#endif	// #if 0

/*	WSM_PREFIX_SIZE 	*/
	frame[offset] = wsmp->wsmp_ext;
	offset += WSMP_EXT_LENGTH;

	frame[offset] = wsmp->priority;
	offset += WAVE_USER_PRIORITY_LENGTH;

	frame[offset] = wsmp->chid;
	offset += WSMP_CHANNEL_NUM_LENGTH;

	frame[offset] = wsmp->power;
	offset += TRANSMIT_POWER_USED_LENGTH;

	frame[offset] = wsmp->datarate;
	offset += WSMP_DATARATE_LENGTH;

	/* WSM Element ID 추가	*/
	frame[offset] = wsmp->wsmp_eid;
	offset += WAVE_EID_LENGTH;
/*	WSM_PREFIX_SIZE 	*/

#if 0
	PUT_16BIT_TO_TWO_CHARS(frame[offset], frame[offset+1], offset);	/* WSM Length 추가 */
	offset += WSMP_WSM_SIZE_LENGTH;
#endif	// #if 0

    return (offset);
}

int make_bsm_msg(unsigned char *frame,struct _BSM *bsm,int index)
{
	int i, offset = index;

	frame[offset] = bsm->msg_type;
	offset += MSG_TYPE_LENGTH;

	frame[offset] = BSM_MSG_TOTAL_LENGTH;
	offset += TOTAL_MSG_LENGTH;

	PUT_32BIT_TO_FOUR_CHARS(frame[offset], frame[offset+1], frame[offset+2], frame[offset+3], bsm->send_id);
	offset += SEND_ID_LENGTH;

	frame[offset] = bsm->count;
	offset += COUNT_LENGTH;

	PUT_16BIT_TO_TWO_CHARS(frame[offset], frame[offset+1], bsm->mark);
	offset += MARK_LENGTH;

	PUT_32BIT_TO_FOUR_CHARS(frame[offset], frame[offset+1], frame[offset+2], frame[offset+3], bsm->vehicle_id);
	offset += VEHICLE_ID_LENGTH;

	PUT_32BIT_TO_FOUR_CHARS(frame[offset], frame[offset+1], frame[offset+2], frame[offset+3], bsm->latitude);
	offset += LATITUDE_LENGTH;

	PUT_32BIT_TO_FOUR_CHARS(frame[offset], frame[offset+1], frame[offset+2], frame[offset+3], bsm->longitude);
	offset += LONGITUDE_LENGTH;

	PUT_16BIT_TO_TWO_CHARS(frame[offset], frame[offset+1], bsm->elevation);
	offset += ELEVATION_LENGTH;

	PUT_32BIT_TO_FOUR_CHARS(frame[offset], frame[offset+1], frame[offset+2], frame[offset+3], bsm->accuracy);
	offset += ACCURACY_LENGTH;

	PUT_16BIT_TO_TWO_CHARS(frame[offset], frame[offset+1], bsm->speed);
	offset += SPEED_LENGTH;

	PUT_16BIT_TO_TWO_CHARS(frame[offset], frame[offset+1], bsm->heading);
	offset += HEADING_LENGTH;

	frame[offset] = bsm->angle;
	offset += ANGLE_LENGTH;

	for(i=0; i<ACCELERATION_LENGTH; i++){
		frame[offset+i] = bsm->acceleration[i];
	}
	offset += ACCELERATION_LENGTH;


	PUT_16BIT_TO_TWO_CHARS(frame[offset], frame[offset+1], bsm->brake);
	offset += BRAKE_LENGTH;

	frame[offset] = bsm->veh_wide;
	offset += VEHICLE_WIDE_LENGTH;

	PUT_16BIT_TO_TWO_CHARS(frame[offset], frame[offset+1], bsm->veh_length);
	offset += VEHICLE_LENGTH_LENGTH;

	frame[offset] = bsm->variable;
	offset += VARIABLE_LENGTH;

    return (offset);
}

int ParseWSMPmsg(unsigned char *buf,int count)
{
	struct _BSM rcvbsm;
	struct _WSMP rcvwsmp;
	int i,idx=0;
	unsigned value16,value32;

	memset(&rcvbsm,0,sizeof(struct _BSM));
	memset(&rcvwsmp,0,sizeof(struct _WSMP));

//	printf("===== Receviced %d WSMP Message ======\n",count);
	printf("===== Receviced WSMP Message ======\n");
	printf("\n++++++++  Ethernet Header  +++++++++\n");
	printf("Dest Mac --> %02x:%02x:%02x:%02x:%02x:%02x\n",buf[idx],buf[idx+1],buf[idx+2],buf[idx+3],buf[idx+4],buf[idx+5]);
	idx += ETH_ALEN;

	printf("Source Mac --> %02x:%02x:%02x:%02x:%02x:%02x\n",buf[i],buf[idx+1],buf[idx+2],buf[idx+3],buf[idx+4],buf[idx+5]);
	idx += ETH_ALEN;

	printf("Ethernet Type --> %02x%02x\n",buf[idx],buf[idx+1]);
	idx += ETHER_TYPE_SIZE;

	GET_32BIT_FROM_FOUR_CHARS(value32, buf[idx], buf[idx+1], buf[idx+2], buf[idx+3]);
	printf("PSID --> 0x%x(%d)\n",value32,value32);
	idx += PSID_LENGTH;

	if(value32 == 1234){
		idx += (WSM_PREFIX_SIZE - 2);
	}else{
		idx += WSM_PREFIX_SIZE;
	}
#if 0
	printf("\n++++++++  WSMP Header Data <Start>  +++++++++\n");
	printf("WSMP Version --> %02x\n",buf[idx]);
	idx += WSMP_VERSION_LENGTH;

	GET_32BIT_FROM_FOUR_CHARS(value32, buf[idx], buf[idx+1], buf[idx+2], buf[idx+3]);
	printf("PSID --> 0x%x\n",value32);
	idx += PSID_LENGTH;

	if(buf[idx] != 0){
		printf("\n+++++++++++ WSMP Ext Field <Start> ++++++++++\n");
		if((buf[idx] & WSMP_CHANNEL_NUM) == WSMP_CHANNEL_NUM){
			printf("\tWSMP_CHANNEL_NUM (%x), Length(%d), Channel ID (%d)\n",buf[idx],buf[idx+1],buf[idx+2]);
			idx += WAVE_EID_LENGTH+WSMP_CHANNEL_NUM_LENGTH+WSMP_CHANNEL_NUM_LENGTH;
		}
		if((buf[idx] & WSMP_DATARATE) == WSMP_DATARATE){
			printf("\tWSMP_DATARATE (%x), Length(%d), Data Rate (%d)\n",buf[idx],buf[idx+1],buf[idx+2]);
			idx += WAVE_EID_LENGTH+WSMP_DATARATE_LENGTH+WSMP_DATARATE_LENGTH;
		}
		if((buf[idx] & TRANSMIT_POWER_USED) == TRANSMIT_POWER_USED){
			printf("\tTRANSMIT_POWER_USED (%x), Length(%d), Power (%d)\n",buf[idx],buf[idx+1],buf[idx+2]);
			idx += WAVE_EID_LENGTH+TRANSMIT_POWER_USED_LENGTH+TRANSMIT_POWER_USED_LENGTH;
		}
		printf("+++++++++++ WSMP Ext Field <End> ++++++++++\n");
	}else{
		printf("WSMP Ext Header is NONE !!!\n");
		idx += WSMP_EXT_LENGTH;
	}

	printf("WSM Element ID --> %d\n",buf[idx]);
	idx += WAVE_EID_LENGTH;

	GET_16BIT_FROM_TWO_CHARS(value16,buf[idx],buf[idx+1]);
	printf("WSM Length --> %d\n",value16);
	idx += WSMP_WSM_SIZE_LENGTH;
	printf("\n++++++++  WSMP Header Data <END> +++++++++\n");
#endif	// #if 0
	printf("\n++++++++  BSM Data <Start>  +++++++++\n");
	printf("++++++++  BSM Header <Start>  +++++++++\n");
	printf("BSM Message Type ID --> %d\n",buf[idx]);
	idx += MSG_TYPE_LENGTH;

	printf("BSM Message Total Length --> %d\n",buf[idx]);
	idx += TOTAL_MSG_LENGTH;

	GET_32BIT_FROM_FOUR_CHARS(value32, buf[idx], buf[idx+1], buf[idx+2], buf[idx+3]);
	printf("BSM Send ID --> %d\n",value32);
	idx += SEND_ID_LENGTH;
	printf("++++++++  BSM Header <End>  +++++++++\n");
	printf("\n++++++++  BSM Body <Start>  +++++++++\n");
	printf("BSM Message Count --> %d\n",buf[idx]);
	idx += COUNT_LENGTH;

	GET_16BIT_FROM_TWO_CHARS(value16,buf[idx],buf[idx+1]);
	printf("BSM secMark --> %d\n",value16);
	idx += MARK_LENGTH;

	GET_32BIT_FROM_FOUR_CHARS(value32, buf[idx], buf[idx+1], buf[idx+2], buf[idx+3]);
	printf("BSM Vehicle_ID --> %d\n",value32);
	idx += VEHICLE_ID_LENGTH;

	GET_32BIT_FROM_FOUR_CHARS(value32, buf[idx], buf[idx+1], buf[idx+2], buf[idx+3]);
	printf("BSM Latitude --> %d\n",value32);
	idx += LATITUDE_LENGTH;

	GET_32BIT_FROM_FOUR_CHARS(value32, buf[idx], buf[idx+1], buf[idx+2], buf[idx+3]);
	printf("BSM Longitude --> %d\n",value32);
	idx += LONGITUDE_LENGTH;

	GET_16BIT_FROM_TWO_CHARS(value16,buf[idx],buf[idx+1]);
	printf("BSM Elevation --> %d\n",value16);
	idx += ELEVATION_LENGTH;

	GET_32BIT_FROM_FOUR_CHARS(value32, buf[idx], buf[idx+1], buf[idx+2], buf[idx+3]);
	printf("BSM Accuracy --> %d\n",value32);
	idx += ACCURACY_LENGTH;

	GET_16BIT_FROM_TWO_CHARS(value16,buf[idx],buf[idx+1]);
	printf("BSM Speed --> %d\n",value16);
	idx += SPEED_LENGTH;

	GET_16BIT_FROM_TWO_CHARS(value16,buf[idx],buf[idx+1]);
	printf("BSM Heading --> %d\n",value16);
	idx += HEADING_LENGTH;

	printf("BSM Angle --> %d\n",buf[idx]);
	idx += ANGLE_LENGTH;

	printf("BSM Acceleration --> ");
	for(i=0; i<ACCELERATION_LENGTH; i++){
		printf("%d ",buf[idx+i]);
	}
	printf("\n");
	idx += ACCELERATION_LENGTH;

	GET_16BIT_FROM_TWO_CHARS(value16,buf[idx],buf[idx+1]);
	printf("BSM Brake --> %d\n",value16);
	idx += BRAKE_LENGTH;

	printf("BSM Vehicle_Wide --> %d\n",buf[idx]);
	idx += VEHICLE_WIDE_LENGTH;

	GET_16BIT_FROM_TWO_CHARS(value16,buf[idx],buf[idx+1]);
	printf("BSM Vehicle_Length --> %d\n",value16);
	idx += VEHICLE_LENGTH_LENGTH;

	printf("BSM Variable --> %d\n",buf[idx]);
	idx += VEHICLE_WIDE_LENGTH;

	printf("++++++++  BSM Body <End>  +++++++++\n");
	printf("++++++++  BSM Data <End>  +++++++++\n");

	return 1;
} //  ParseWSMPmsg(unsigned char *buf,int rcv_count)

static void wsm_client_usage_message(void)
{       
	printf("Usage : rsmgmt client interface destmac[HEX] framecount !!!!\n");
}  

void wsm_client_test(char **reqs,struct rsmgmt_wave *rsmgmt)
{
    int s=socket(PF_PACKET,SOCK_RAW,0);
	int i,interval,retval,framecnt,arg=0;
	unsigned char *mac;
	unsigned char buf[WSM_FRAME_SIZE]={0,};
	unsigned char dest_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	if(reqs[arg] == NULL){
        wsm_client_usage_message();
        return;
    } 
	memset(&BSMmsg,0,sizeof(struct _BSM));
	memset(&WSMPmsg,0,sizeof(struct _WSMP));

    strcpy(if_hwaddr.ifr_name,reqs[arg]);
    ioctl(s,SIOCGIFHWADDR,&if_hwaddr);
    close(s);
	arg += 1;

	if(reqs[arg] == NULL){
        wsm_client_usage_message();
        return;
    } 

    if(strlen(reqs[arg]) != 12){
        printf("Usage : Mac address input error\n");
        return;
    }
    
	mac = (unsigned char *)reqs[arg];
	for(i=0; i<6; i++){
		dest_mac[i] = (Hex(*(mac+2*i)) << 4) | Hex(*(mac+2*i+1));
	}

	arg += 1;
	if(reqs[arg] == NULL){
        wsm_client_usage_message();
        return;
    }

	framecnt = atoi(reqs[arg]);
	interval = 10000;

	printf("\n\n======================== wsm client test ============================\n");
	printf("client inf(%s), destmac(%02x:%02x:%02x:%02x:%02x:%02x),framecount(%d)\n",
        reqs[0],dest_mac[0],dest_mac[1],dest_mac[2],dest_mac[3],dest_mac[4],dest_mac[5],framecnt);

	if(get_wsmp_conf(&WSMPmsg) == -1){
		printf("WSMP config error\n");
		return;
	}

	if(get_bsm_conf(&BSMmsg) == -1){
		printf("bsm config error\n");
		return;
	}

	if((retval=make_wsm_header(buf,dest_mac,&WSMPmsg)) > 0){
		retval = make_bsm_msg(buf,&BSMmsg,retval);
#if 0
		printf("%d bytes WSMP Message send \n",retval);
		for(i=0; i<retval; i++){
			if((i % 16) == 0)   printf("\n");
			printf("%02x ",buf[i]);
		}
		printf("=====================================\n");
#endif
		while(framecnt > 0){
	//		printf("\n--> Send PSID (0x%x) and BSM data !!!\n",WSMPmsg.psid);
			SendNetLinkData(rsmgmt->socknl,retval,rsmgmt->rsmgmt_pid,buf);
			usleep(interval);
			framecnt -= 1;
		}
	}
}
