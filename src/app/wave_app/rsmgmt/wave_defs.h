#define	MATH_MMAP_SIZE		1024
#define	MATH_DATA_SIZE		100
#define	COMMAND_DATA_LENGTH	100
#define	MATH_UDP_PORT		9999

#define VMP_DISTANCE_OFFSET			0
#define VMP_DISTANCE_DATACNT		12
#define VMP_DISTANCE_RESP_OFFSET	(VMP_DISTANCE_DATACNT + 2)
#define	VMP_DISTANCE_REQ_HIGH		0x11
#define	VMP_DISTANCE_REQ_LOW		0x77
#define	VMP_DISTANCE_RESP			0x22BB

#define	MATH_DATA_LENGTH 	1
#define	MATH_DATA_OFFSET 	2

#define	TCP_PROTOCOL 	1
#define	UDP_PROTOCOL 	2

#define	WAVE_INF_NAME 	"VMC0"
#define WSMP_PROTOCOL_TYPE  0x88DC

enum
{
	STS_SUCCESS=0,
	STS_FAIL,
	STS_VMP_CALC_REQ,
	STS_VMP_CALC_RESP,
};

enum
{
	VMC_COMMAND=0,
	MAC_COMMAND,
	VMP_COMMAND,
	EEPROM_COMMAND,
	NMEA_COMMAND,
	MLME_COMMAND,
};

enum
{
	VMC_TXPKT=0,
	VMC_TXPKT1,
	VMC_BRPKT,
	VMC_TX,
	VMC_TXRC,
	VMC_TXMGT,
	VMC_TXMGT1,
	VMC_RXPKT,
	VMC_RXINFO,
	VMC_RXDP,
	VMC_RXDI,
	VMC_RX,
	VMC_EMAC,
	VMC_VMAC,
	VMC_GWMAC,
	VMC_REG_RD,
	VMC_REG_WR,
	WSA_TXPKT,
	WSA2_TXPKT,
	VMC_BCONMAC,
	VMC_DATAMAC,
	VMC_MAC_RESET,
	VMC_CLRTX_REG,
	VMC_CLRRX_REG,
	VMC_CLRCNT_REG,
};

enum
{
	LAN9215_REG_RD=0,
	LAN9215_REG_WR,
};

enum
{
	POWER_LEVEL=0,
	AMC_ONOFF,
	DATARATE,
	MAC_PRIORITY,
	MIDAMBLE,
	RTSCTS_THRESHOLD,
	RTSCTS_MODE,
	VENDOR_SPECIFIC_FRAME,
	LINK_SETUP_FRAME,
	TIMING_ADVERTISEMENT_FRAME,
	FCHANGE,
	SHOW_ETH_TABLE,
	SHOW_MAC_TABLE,
	SHOW_TAR_TABLE,
	SHOW_SRC_DEST_GW_ADDR,
	SHOW_MAC_HW_COUNTER,
	SHOW_OP_MODE,
	SET_OP_MODE,
	CNTMAC,
	CLEAR_INFO,
	MYINFO,
	SHOW_VERSION,
	IOTIME,
	GPS_IOTIME,
	TXPROFILE,
};

enum
{
	VMP_PCHANGE=0,
	VMP_TXSAFETY,
	VMP_TXHELLO,
	VMP_TABLE,
	VMP_BUFNUM,
	VMP_DEBUG,
	VMP_SHOW,
	VMP_TXAGING,
	VMP_AGING,
	VMP_RENUM,
	VMP_FREELIST,
	VMP_USEDLIST,
	VMP_SCH,
	VMP_MULTICHANNEL,
	VMP_MULTICHINV,
	VMP_MULTICHFREQ,
	VMP_MULTICHSET,
	VMP_MULTICHDEF,
	VMP_MULTICHGET,
	VMP_MULTICHTIMESET,
	VMP_MULTISLOT,
	VMP_WSM,
	VMP_TEST,
};

enum
{
	EEPROM_READ=0,
	EEPROM_WRITE,
};

enum
{
	GPS_GPRMC=0,
	GPS_GPVTG,
	GPS_MSG,
	GPS_DATA,
	GPS_ONOFF,
};

enum
{
	VSA_AGING=0,
	TA_AGING,
	USC_AGING,
	AMC_AGING,
	USER_TABLE,
	AVAILABLE_TABLE,
	PS_TABLE,
	CH_INFO_TABLE,
	WSM_TABLE,
	HANDOVER,
};

struct wave_req  {
    int cmd;
    unsigned char data[COMMAND_DATA_LENGTH];
};

#define	PUT_16BIT_TO_TWO_CHARS(high, low, source) \
		{\
			high = (source >> 8) & 0x00FF;\
			low = (source & 0x00FF);\
		}

#define PUT_32BIT_TO_FOUR_CHARS(char4, char3, char2, char1, source) \
        {\
            char4 = (source >> 24) & 0x00FF;\
            char3 = (source >> 16) & 0x00FF;\
            char2 = (source >> 8) & 0x00FF;\
            char1 = (source & 0x00FF);\
        }

#define	GET_16BIT_FROM_TWO_CHARS(dest,high, low) \
		{\
			dest = (high << 8);\
			dest |= (low & 0x00FF);\
		}

#define GET_32BIT_FROM_FOUR_CHARS(dest, char4, char3, char2, char1) \
        {\
            dest = (char4 << 24);\
            dest |= (char3 << 16);\
            dest |= (char2 << 8);\
            dest |= (char1 & 0x00FF);\
        }

static __inline int IS_CORRECT_TYPE(reqtype,srctype)
{
    unsigned short cmptype;
                    
    cmptype = (srctype<<8) | ((srctype>>8)&0x00ff);
                    
    if(cmptype == reqtype)  return 1;
    else    return 0;   
}                   
                    
static __inline int IS_CORRECT_MAC(reqmac,srcmac,len)
{               
    int i;              
    unsigned char *reqaddr = (unsigned char *)reqmac;
    unsigned char *srcaddr = (unsigned char *)srcmac;
                
    for(i=0; i<len; i++){
        if(reqaddr[i] != srcaddr[i])    return 0;
    }
    return 1;
}

