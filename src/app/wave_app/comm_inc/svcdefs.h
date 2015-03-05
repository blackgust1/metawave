#ifndef _SVC_DEFS_H_
#define _SVC_DEFS_H_
#include "bsm.h"

#define ROOT_NODE	0
#define CHILD_NODE	1

#define WAVE_FRAME_MAX_BUF	2400
#define SVC_EVENT_MAX_BUF   1000
#define SVC_UDP_PORT 		65510
#define SVC_TCP_PORT 		65520
#define SVC_NETLINK_TYPE 	20
#define IPV4_WSMP_PROTOCOL_TYPE  0x88DC

/*	>>>> J2735 MSG ID Values	*/
#define	J2735_RESERVED 						0
#define	J2735_ALACARTEMESSAGE 				1	// -- ACM
#define	J2735_BASICSAFETYMESSAGE 			2	// -- BSM, heartbeat msg
#define	J2735_BASICSAFETYMESSAGEVERBOSE 	3	// -- used for testing only
#define	J2735_COMMONSAFETYREQUEST 			4	// -- CSR
#define	J2735_EMERGENCYVEHICLEALERT 		5	// -- EVA
#define	J2735_INTERSECTIONCOLLISIONALERT 	6	// -- ICA
#define	J2735_MAPDATA 						7	// -- MAP, GID, intersections
#define	J2735_NMEACORRECTIONS 				8	// -- NMEA
#define	J2735_PROBEDATAMANAGEMENT 			9	// -- PDM
#define	J2735_PROBEVEHICLEDATA 				10	// -- PVD
#define	J2735_ROADSIDEALERT 				11	// -- RSA
#define	J2735_RTCMCORRECTIONS 				12	// -- RTCM
#define	J2735_SIGNALPHASEANDTIMINGMESSAGE 	13	// -- SPAT
#define	J2735_SIGNALREQUESTMESSAGE 			14	// -- SRM
#define	J2735_SIGNALSTATUSMESSAGE 			15	// -- SSM
#define	J2735_TRAVELERINFORMATION 			16	// -- TIM
/*	<<<< J2735 MSG ID Values	*/

/*	>>>> Element ID Values	*/
#define	WSA_SERVICE_INFO	1
#define	WSA_CHANNEL_INFO	2
#define	WSA_WRA				3

#define	TRANSMIT_POWER_USED			4	/* WSA header, WSMP header	*/
#define	_2D_LOCATION					5	/* WSA header	*/
#define	_3D_LOCATION_AND_CONFIDENCE	6	/* WSA header	*/
#define	ADVERTISER_IDENTIFIER		7	/* WSA header	*/
#define	PROVIDER_SERVICE_CONTEXT	8	/* WSA Service Info	*/
#define	IPV6_ADDRESS				9	/* WSA Service Info	*/
#define	SERVICE_PORT				10	/* WSA Service Info	*/
#define	PROVIDER_MAC_ADDRESS		11	/* WSA Service Info	*/

#define	EDCA_PARAMETER_SET			12	/* WSA Channel Info	*/

#define	SECONDARY_DNS				13	/* WSA WRA	*/
#define	GATEWAY_MAC_ADDRESS			14	/* WSA WRA	*/

#define	CHANNEL_NUMBER				15	/* WSMP header	*/
#define	DATARATE					16	/* WSMP header	*/

#define	REPEAT_RATE					17	/* WSA header	*/
#define	COUNTRY_STRING				18	/* WSA header	*/

#define	RCPI_THRESHOLD				19	/* WSA Service Info	*/
#define	WSA_COUNT_THRESHOLD			20	/* WSA Service Info	*/

#define	CHANNEL_ACCESS				21	/* WSA Channel Info	*/
#define	WSA_COUNT_THRESHOLD_INTERVAL	22	/* WSA Service Info	*/

#define	WAVE_SHORT_MESSAGE			128	/* WSMP header	*/
#define	WSMP_S						129	/* WSMP header : WSMP safety supplement	*/
#define	WSMP_I						130	/* WSMP header : WSMP identity supplement	*/
/*	<<<< Element ID Values	*/

/*	>>>> Protocol Svc ID Values : Important things are synchronized with values of wave_defs.h	*/
enum
{
    ACCEPTED=0,
    REJECTED_MAX_LENGTH,
    EXCEEDED,
    REJECTED_UNSPECIFIED,
};  // Confirm Status

#define WSM_WAVESHORTMESSAGE_REQUEST		0x1000
#define WSM_WAVESHORTMESSAGE_CONFIRM		0x1001
#define WSM_WAVESHORTMESSAGE_INDICATION		0x1002

#define WME_PROVIDERSERVICE_REQUEST			0x2010
#define WME_PROVIDERSERVICE_CONFIRM			0x2011

#define WME_USERSERVICE_REQUEST				0x2020
#define WME_USERSERVICE_CONFIRM				0x2021

#define WME_WSMSERVICE_REQUEST				0x2030
#define WME_WSMSERVICE_CONFIRM				0x2031

#define WME_CCHSERVICE_REQUEST 				0x2040
#define WME_CCHSERVICE_CONFIRM 				0x2041

#define WME_MANAGEMENTDATASERVICE_REQUEST 	0x2050
#define WME_MANAGEMENTDATASERVICE_CONFIRM 	0x2051
#define WME_MANAGEMENTDATASERVICE_INDICATION 	0x2052

#define WME_TIMINGADVERTISEMENTSERVICE_REQUEST	0x2060
#define WME_TIMINGADVERTISEMENTSERVICE_CONFIRM	0x2061

#define WME_NOTIFICATION_INDICATION			0x2070

#define WME_GET_REQUEST						0x2080
#define WME_GET_CONFIRM						0x2081

#define WME_SET_REQUEST						0x2090
#define WME_SET_CONFIRM						0x2091

#define WME_ADDRESSCHANGE_REQUEST			0x20A0
#define WME_ADDRESSCHANGE_CONFIRM			0x20A1

#define GET_BSM_MSG_REQEUEST				0x3000
/*	<<<< Protocol Svc ID Values	*/

#define	WSMP_VERSION	2

int WSM_BasicSaftyMsg_request(struct _BSM *bsmMsg,unsigned char *result);
int WSM_WaveShortMessage_request(unsigned char *psid,unsigned char *wsmData,unsigned short size);
int SendSvcMsg(int prototype,unsigned char *bufptr,int length,int repeat, int msdelay);
int GetInterfaceMacAddress(unsigned char *mac, char *infname);
char *get_conf_value(char *mark, char *buf);
unsigned char Hex(unsigned char ch);

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

static inline int GET_PSID_OCTET_STR(unsigned char *pkt,unsigned char *psid)
{
    unsigned int length = 0;

    if((*pkt & 0x80) == 0){ /* 1byte PSID */
		psid[0] = pkt[0];
        length = 1;
    }else if((*pkt & 0xc0) == 0x80){    /* 2byte PSID */
        psid[0] = pkt[0];
        psid[1] = pkt[1];
        length = 2;
    }else if((*pkt & 0xe0) == 0xc0){    /* 3byte PSID */
        psid[0] = pkt[0];
        psid[1] = pkt[1];
        psid[2] = pkt[2];
        length = 3;
    }else if((*pkt & 0xf0) == 0xe0){    /* 4byte PSID */
        psid[0] = pkt[0];
        psid[1] = pkt[1];
        psid[2] = pkt[2];
        psid[3] = pkt[3];
        length = 4;
    }else{
        return 0;   // Invalid PSID Format
    }

    return length;  // Success : Valid PSID Format
}

#define PUT_16BIT_TO_TWO_CHARS(high, low, source) \
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

#define GET_16BIT_FROM_TWO_CHARS(dest,high, low) \
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

#endif	//ifndef SVC_DEFS_H
