#ifndef _RESOURCE_MGMT_H_
#define _RESOURCE_MGMT_H_

#define NETLINK_RSMGMT    	20
#define	WAVE_RM_SIZE		2048
#define	WAVE_RM_MAX_QUEUE	100
#define	WAVE_SVC_MAX_QUEUE	100

#define QUEUE_EMPTY         0
#define QUEUE_AVAILABLE     1
#define QUEUE_OCCUPIED      2

#define EVEN_RSU_MODE		0x00
#define ODD_RSU_MODE		0x10
#define OBU_MODE			0x20

struct rsmgmt_pkt {
	unsigned char	rmpkt[WAVE_RM_SIZE];
	unsigned char   *dataptr;
    struct  rsmgmt_pkt 	*link; /* address of get data in the list */
	int		datalen;
    char    valid;      /* size of the entire buffer, sum of all in the chain    */
};

struct rsmgmt_wave {
	pthread_mutex_t	rsmgmt_nl_mutex;
	pthread_mutex_t	bsmMsg_mutex;
	pthread_mutex_t	wsmHeader_mutex;
	struct	rsmgmt_pkt 	*rmpkt_nl;
	struct  in_addr eth0_addr;
	struct  in_addr vmc0_addr;
	struct  in_addr br0_addr;
	unsigned char eth0mac[6];
	unsigned char vmc0mac[6];
	unsigned char mode;	// RSU (0x00, 0x10), OBU (0x20)
	int	rsmgmt_pid;
	int socknl;	/* netlink	*/
	int svcsock;
};

extern  int DebugLevel;
#define BASIC_MSG_LEVEL			1
#define RECV_MSG_LEVEL			2
#define SEND_MSG_LEVEL			3
#define RECV_SEND_MSG_LEVEL		4
#define EVENT_MSG_LEVEL			5
#define SERVICE_MSG_LEVEL		6
#define WSMP_MSG_LEVEL		    7

#define DBG_MSG(level,format,arg...) if ((level == BASIC_MSG_LEVEL) || (DebugLevel == level)) {printf(format, ##arg);}
#endif	// ifndef _RESOURCE_MGMT_H_
