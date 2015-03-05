
#define CONF_BUF_SIZE   60
#define TMP_BUF_SIZE    10

#define	WSM_PREFIX_SIZE	6
#define	WSM_FRAME_SIZE	1024

#define WAVE_ETH_TYPE	0x88
#define WSM_ETH_TYPE	0xDC

#define	ETHER_TYPE_SIZE	2
#define	PSID_SIZE	4

#define	ETHER_TYPE_OFFSET	(ETH_ALEN*2)

#define	BSM_CONF_FILE	"/etc/bsm.conf"
char	MSG_TYPE[]=	"BSM_MSG_TYPE";
char	SEND_ID[]=	"BSM_MSG_SEND_ID";
char	COUNT[]=	"BSM_MSG_COUNT";
char	MARK[]=		"BSM_MSG_MARK";
char	VEHICLE_ID[]="BSM_MSG_VEHICLE_ID";
char	LATITUDE[]=	"BSM_MSG_LATITUDE";
char	LONGITUDE[]="BSM_MSG_LONGITUDE";
char	ELEVATION[]="BSM_MSG_ELEVATION";
char	ACCURACY[]=	"BSM_MSG_ACCURACY";
char	SPEED[]=	"BSM_MSG_SPEED";
char	HEADING	[]=	"BSM_MSG_HEADING";
char	ANGLE[]=	"BSM_MSG_ANGLE";
char	ACCELERATION[]=	"BSM_MSG_ACCELERATION";
char	BRAKE[]=		"BSM_MSG_BRAKE";
char	VEHICLE_WIDE[]=	"BSM_MSG_VEHICLE_WIDE";
char	VEHICLE_LENGTH[]="BSM_MSG_VEHICLE_LENGTH";
char	VARIABLE[]=	"BSM_MSG_VARIABLE";
		
#define	MSG_TYPE_LENGTH			1
#define	TOTAL_MSG_LENGTH		1
#define	SEND_ID_LENGTH			4
#define	COUNT_LENGTH			1
#define	MARK_LENGTH				2	
#define	VEHICLE_ID_LENGTH		4
#define	LATITUDE_LENGTH			4
#define	LONGITUDE_LENGTH		4
#define	ELEVATION_LENGTH		2
#define	ACCURACY_LENGTH			4
#define	SPEED_LENGTH			2
#define	HEADING_LENGTH			2
#define	ANGLE_LENGTH			1
#define	ACCELERATION_LENGTH		7
#define	BRAKE_LENGTH			2
#define	VEHICLE_WIDE_LENGTH		1
#define	VEHICLE_LENGTH_LENGTH	2
#define	VARIABLE_LENGTH			1

#define	BSM_MSG_TOTAL_LENGTH	(\
			TOTAL_MSG_LENGTH +	\
			SEND_ID_LENGTH +	\
			COUNT_LENGTH +	\
			MARK_LENGTH +	\
			VEHICLE_ID_LENGTH +	\
			LATITUDE_LENGTH	 +	\
			LONGITUDE_LENGTH +	\
			ELEVATION_LENGTH +	\
			ACCURACY_LENGTH	 +	\
			SPEED_LENGTH	 +	\
			HEADING_LENGTH	 +	\
			ANGLE_LENGTH	 +	\
			ACCELERATION_LENGTH +	\
			BRAKE_LENGTH	 +	\
			VEHICLE_WIDE_LENGTH	 +	\
			VEHICLE_LENGTH_LENGTH +	\
			VARIABLE_LENGTH	)	

#define PSID_INTERNET	0x00000000
#define	PSID_PROBEDATA	0x00000100
#define	PSID_TRAFFIC_INFO	0x00000101
#define	PSID_INTERSECTION_VINFO	0x00000200
#define	PSID_INTERSECTION_SINFO	0x00000201
#define	PSID_V2V_ACCIDENT	0x00000301
#define	PSID_V2V_COLLISION	0x00000302
#define PSID_V2V_TRAJECTORY	0x00000303
#define PSID_CCTV			0x00002710
#define PSID_WEB			0x00002711 
#define	PSID_V2V_EMERGENCY	0x00002712
#define PSID_SH_TRAFFIC_INFO	0x00002713

struct _BSMmsg  {
	unsigned char	msg_type;
	unsigned char	msg_len;
	unsigned int	send_id;
	unsigned char	count;
	unsigned short	mark;
	unsigned int	vehicle_id;
	unsigned int	latitude;
	unsigned int	longitude;
	unsigned short	elevation;
	unsigned int	accuracy;
	unsigned short	speed;
	unsigned short	heading;
	unsigned char	angle;	
	unsigned char	acceleration[ACCELERATION_LENGTH];	
	unsigned short	brake;
	unsigned char	veh_wide;	
	unsigned short	veh_length;	
	unsigned char	variable;
};

char	WSMP_DISP_MSG[]="WSMP_DISP_MSG";
char	WSMP_VER_CONF[]="WSMP_VERSION";
char	PSID_CONF[]=	"PSID";
char	WSMP_EXT_CONF[]="WSMP_EXT";
char	WSMP_CH_NUM_CONF[]="WSMP_CH_NUM";
char	WSMP_USER_PRIORITY_CONF[]="WSMP_USER_PRIORITY";
char	WSMP_DATARATE_CONF[]="WSMP_DATARATE";
char	WSMP_POWER_CONF[]="WSMP_TRANSPOWER";
char	WSMP_EID_CONF[]="WSMP_EID";

#define	WSMP_CONF_FILE	"/etc/wsmp.conf"
#define WAVE_EID_LENGTH				1
#define WSMP_CHANNEL_NUM			0x0F
#define WSMP_DATARATE				0x10
#define WSMP_CHANNEL_NUM_LENGTH		1
#define WSMP_DATARATE_LENGTH		1
#define TRANSMIT_POWER_USED			0x04
#define TRANSMIT_POWER_USED_LENGTH		1
#define WAVE_USER_PRIORITY_LENGTH		1

#define WSMP_HDR_EXT_NONE			0x0
#define WSMP_HDR_EXT_CH_NUM			0x1
#define WSMP_HDR_EXT_DATARATE		0x2
#define WSMP_HDR_EXT_TRANSPOWER		0x4

#define	WSMP_VERSION_LENGTH		1
#define	PSID_LENGTH				PSID_SIZE
#define	WSMP_EXT_LENGTH			1
#define	WSMP_WSM_SIZE_LENGTH	2

struct _WSMP  {
	unsigned char	wsmp_ver;
	unsigned int	psid;
	unsigned char	wsmp_ext;
	unsigned char	wsmp_eid;
	unsigned short	wsmp_wsm_length;	
	unsigned char	chid;
	/* wsmp_ext */ 
	unsigned char	priority;
	unsigned char	datarate;
	unsigned char	power;
	/* wsmp_ext */ 
};

