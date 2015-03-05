#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
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
#include "wave_defs.h"

#include "wsm.h"
#include "bsm_part2.h"

#include "../comm_inc/asn.h"
#include "../comm_inc/bsm.h"

///#define  TO_IOCTL    1
#define NETLINK_WSMP    20
#define BUFF_SIZE       1024
#define BLOB1_SIZE      38
#define BSM_VALUE       2

static int DispMsgOn = 1;
static pthread_mutex_t  WMS_Sock_Mutex;
int i,Sockfd; 
struct sockaddr_ll Sock_addr;
struct ifreq if_hwaddr;
struct _WSMP WSMPmsg;
static int WMS_Recv_Running;

bsm_t   bsm;
char    buff[BUFF_SIZE] = { 0, };

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
		if( fgets(buff, CONF_BUF_SIZE, fp) == NULL) break;

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

void sendWSMmsg(unsigned char * message, int len)
{
    int size;

    pthread_mutex_lock(&WMS_Sock_Mutex);
	size = sendto(Sockfd, message, len, 0, (struct sockaddr*)&Sock_addr, sizeof(struct sockaddr_ll));
    printf( "send size = %d\n", size );
    pthread_mutex_unlock(&WMS_Sock_Mutex);
} //    sendADTmsgToPAD

static inline int PUT_PSID_OCTET_STR(unsigned char *pkt,unsigned char *psid)
{
    int i;
    unsigned int length = 0;
    
    for(i=0; i<4; i++){
        if(*(psid+i) != 0x00){
            psid += i;
            break;
        }
    }
    
    if((*psid & 0x80) == 0){ /* 1byte PSID */
        pkt[0] = psid[0];
        length = 1;
    }else if((*psid & 0xc0) == 0x80){    /* 2byte PSID */
        pkt[0] = psid[0];
        pkt[1] = psid[1];
        length = 2;
     }else if((*psid & 0xe0) == 0xc0){    /* 3byte PSID */
        pkt[0] = psid[0];
        pkt[1] = psid[1];
        pkt[2] = psid[2];
        length = 3;
    }else if((*psid & 0xf0) == 0xe0){    /* 4byte PSID */
        pkt[0] = psid[0];
        pkt[1] = psid[1];
        pkt[2] = psid[2];
        pkt[3] = psid[3];
        length = 4;
    }else{
        return 0;   // Invalid PSID Format
    }
    
    return length;  // Success : Valid PSID Format
}

int make_wsm_header(unsigned char *frame,unsigned char *dest_mac,struct _WSMP *wsmp)
{
	int offset = 0;
    unsigned char *psid;
    unsigned char data[3];

	memset(frame,0x00,sizeof(WSM_FRAME_SIZE));

	memcpy(&frame[offset], (void*)dest_mac, ETH_ALEN);
	offset += ETH_ALEN;

	memcpy((void*)(frame+offset), (void*)if_hwaddr.ifr_hwaddr.sa_data,ETH_ALEN);
	offset += ETH_ALEN;

	frame[offset] = WAVE_ETH_TYPE;
	frame[offset+1] = WSM_ETH_TYPE;
	offset += ETHER_TYPE_SIZE;

//	PUT_32BIT_TO_FOUR_CHARS(frame[offset], frame[offset+1], frame[offset+2], frame[offset+3], wsmp->psid);
//	offset += PSID_SIZE;

    psid = (unsigned char *)&wsmp->psid;
    data[0] = psid[2];
    data[1] = psid[1];
    data[2] = psid[0];
    offset += PUT_PSID_OCTET_STR( &frame[offset], data );

//	offset += WSM_PREFIX_SIZE;

#if 0
	frame[offset] = wsmp->wsmp_ver;
	offset += WSMP_VERSION_LENGTH;

	PUT_32BIT_TO_FOUR_CHARS(frame[offset], frame[offset+1], frame[offset+2], frame[offset+3], wsmp->psid);
	offset += PSID_LENGTH;
#endif	// #if 0

#if 0
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
#endif

#if 0
	PUT_16BIT_TO_TWO_CHARS(frame[offset], frame[offset+1], offset);	/* WSM Length 추가 */
	offset += WSMP_WSM_SIZE_LENGTH;
#endif	// #if 0

    return (offset);
}

int ParseWSMPmsg(unsigned char *buf,int count)
{
	struct _BSMmsg  rcvbsm;
	struct _WSMP    rcvwsmp;
	int             i               = 0;
    int             idx             = 0;
	unsigned        value16;
    unsigned        value32;

	memset(&rcvbsm,0,sizeof(struct _BSMmsg));
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

int recv_data(unsigned char *buffer)
{
	int i,length = 0; /*length of the received frame*/ 
	int retval,fd_max;
	fd_set rfds;
	struct timeval timeover;

	for(i=0; i<5; i++)
	{
		FD_ZERO(&rfds);
		FD_SET(Sockfd,&rfds);
		fd_max = Sockfd;
	
		timeover.tv_sec = 1;
		timeover.tv_usec = 0;
		retval = select(fd_max+1, &rfds,0,0,&timeover);

		if(retval == 0)
			continue;
		else if(retval > 0 && FD_ISSET(Sockfd,&rfds))
		{
			length = recvfrom(Sockfd, buffer,WSM_FRAME_SIZE, 0, NULL, NULL);
			FD_CLR(Sockfd,&rfds);
			return length;
		}
	}

	return 0;	// Empty
}

void * WSM_Recv_Thread(void * arg)
{
	int rcv_count;
	unsigned char buf[WSM_FRAME_SIZE];

	WMS_Recv_Running = 1;
	while(WMS_Recv_Running){
		memset(buf,0x00,sizeof(buf));
    	pthread_mutex_lock(&WMS_Sock_Mutex);
		if((rcv_count = recv_data(buf)) > 0){
			if((buf[ETHER_TYPE_OFFSET] == WAVE_ETH_TYPE) && (buf[ETHER_TYPE_OFFSET+1] == WSM_ETH_TYPE)){
#if 0
				printf("\n======= %d bytes received =======\n",rcv_count);
				for(i=0; i<rcv_count; i++){
           			if((i % 16) == 0)   printf("\n");
					printf("%02x ",buf[i]);
				}
				printf("\n=================================\n",rcv_count);
#endif
				if(DispMsgOn)	ParseWSMPmsg(buf,rcv_count);
			} // if((buf[WSM_TYPE_OFFSET] == WAVE_ETH_TYPE) && (buf[WSM_TYPE_OFFSET+1] == WSM_ETH_TYPE))
		}
    	pthread_mutex_unlock(&WMS_Sock_Mutex);
	}
	pthread_exit("end");
}


void display_bsm( void )
{
    int i = 0;
    
    printf( "bsm.msgid = %02x\n", bsm.msgid );
    
    printf( "\nbsm.blob1 data \n" );
    for( i = 0; i < BLOB1_SIZE; i++ )
    {
        if( (i % 16) == 0 )   printf( "\n" );
        printf( "%02x ", bsm.blob1[i] );
    }
    printf( "\n" );
}

int encode_bsm_value( void )
{
    int     i       = 0;
    size_t  size    = 0;

    int     select  = 0;

    // TODO : 여기에 BSM 메시지 파싱
    
    // BSM id
    bsm.msgid = BSM_VALUE;
    
    // BSM Blob1
    for( i = 0; i < BLOB1_SIZE; i++ )
    {
        bsm.blob1[i] = 0x01 + i;
    }
    
    // BSM Part2 - Vehicle Safety Extension

    // BSM Part2 - Vehicle Status

    // bsm encoding
    size = request_encode( INP_DER, &bsm, buff, BUFF_SIZE );

    // bsm decoding
    request_decode( OUT_DER, buff, size );

    return size;
}

int make_bsm_value( unsigned char *buf, int index, int size)
{
    int offset = index;
    int i = 0;
    int j = 0;
    
    for( i = offset; i < (offset+size); i++ )
    {
        buf[i] = buff[j];
        j++;
    }

    return (offset+size);
}

int main(int argc, char **argv)
{
	pthread_t 	WSMRecvThread;
    int s=socket(PF_PACKET,SOCK_RAW,0);
	int i,retval;
	int interval=0;
	unsigned char *mac;
	unsigned char buf[WSM_FRAME_SIZE]={0,};
	unsigned char dest_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    int bsm_size = 0;

	if((argc != 4) && (argc != 5)){
		printf("Usage : wsm interface destmac[HEX] sever !!!!\n");
		printf("Usage : wsm interface destmac[HEX] client intervalTime(msec) !!!!\n");
		return 1;
	}
    if(strlen(argv[2]) != 12){
        printf("Usage : Mac address input error\n");
        return 1;
    }
    
	memset(&WSMPmsg,0,sizeof(struct _WSMP));

	Sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(Sockfd == -1){
		printf("socket create error\n");
		return -1;
	}
	memset(&Sock_addr,0,sizeof(struct sockaddr_ll));
	Sock_addr.sll_family   = AF_PACKET;
	Sock_addr.sll_protocol = htons(ETH_P_IP);
	Sock_addr.sll_ifindex  = if_nametoindex(argv[1]);
	if(Sock_addr.sll_ifindex == -1){
		printf("Cannot find the network interdace %s\n",argv[1]);
		close(Sockfd);
		return -1;
	}
	Sock_addr.sll_hatype   = ARPHRD_ETHER;
	Sock_addr.sll_pkttype  = PACKET_OTHERHOST;
	Sock_addr.sll_halen    = ETH_ALEN;
	for(i=0; i<ETH_ALEN; i++)
		Sock_addr.sll_addr[i]  = 0xff;

    strcpy(if_hwaddr.ifr_name,argv[1]);
    ioctl(s,SIOCGIFHWADDR,&if_hwaddr);
    close(s);

	mac = (unsigned char *)argv[2];
	for(i=0; i<6; i++){
		dest_mac[i] = (Hex(*(mac+2*i)) << 4) | Hex(*(mac+2*i+1));
	}

	printf("%s inf(%s), destmac(%02x:%02x:%02x:%02x:%02x:%02x),%s\n",
        argv[0],argv[1],dest_mac[0],dest_mac[1],dest_mac[2],dest_mac[3],dest_mac[4],dest_mac[5],argv[3]);

	if(!strcmp(argv[3],"client")){
		if(argv[4] == NULL){
			printf("Usage : wsm interface destmac[HEX] client intervalTime(msec) !!!!\n");
			printf("Interval time must be bigger then 10msec !!!!\n");
			printf("If(Interval time == 0) just one wsm message sending !!!!\n");
			goto _Exit;
		}
		if(atoi(argv[4]) < 10){
			if(atoi(argv[4]) == 0){
				interval = 0;
			}else{
				printf("Interval time must be bigger then 10msec !!!!\n");
				goto _Exit;
			}
		}else{
			interval = atoi(argv[4]) * 1000;
		}

		if(get_wsmp_conf(&WSMPmsg) == -1){
			printf("WSMP config error\n");
			close(Sockfd);
			return 1;
		}

        bsm_size = encode_bsm_value();
//        display_bsm();

		if((retval=make_wsm_header(buf,dest_mac,&WSMPmsg)) > 0){
			retval = make_bsm_value( buf, retval, bsm_size );

#if 0
			printf("%d bytes WSMP Message send \n",retval);
			for(i=0; i<retval; i++){
           		if((i % 16) == 0)   printf("\n");
				printf("%02x ",buf[i]);
			}
			printf("\n");
#endif

			printf("Interval time is %d\n",interval);
			while(1){
				printf("\n--> Send PSID (0x%x) and BSM data !!!\n",WSMPmsg.psid);
				sendWSMmsg(buf,retval);
        		if(interval)    usleep(interval);
				else	goto _Exit;
			}

		}
	} // if(!strcmp(argv[3],"server"))

	if(pthread_mutex_init(&WMS_Sock_Mutex,NULL)){
		printf("WMS_Sock_Mutex init error\n");
		return 1;
	}

	if(pthread_create(&WSMRecvThread, NULL, WSM_Recv_Thread, NULL) != 0){
		perror("WSM thread create error");
		pthread_mutex_destroy(&WMS_Sock_Mutex);		
		close(Sockfd);
		return 1;
	}

	while(1);

_Exit:
	close(Sockfd);
	return 1;
}
