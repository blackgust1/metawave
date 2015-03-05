#ifndef _BSM_H_
#define _BSM_H_

#define BLOB1_SIZE              38

#define ACCELERATIONSET_LENGH	7

struct _BSM_TransAndSpeed{
    unsigned char	TransmissionState;
    unsigned char	Speed;
};

struct _BSM_blob{	// Part I, sent as a single octet blob
    unsigned char   msgLen;
    unsigned char	TemporaryID[4];	// Device ID
    unsigned short	DSecond;
    unsigned int	Latitude;
    unsigned int	Longitude;
    unsigned short	Elevation;
    unsigned int	PositionAccuracy;

	struct _BSM_TransAndSpeed TransmissionAndSpeed;

    unsigned short	Heading;
    unsigned char	SteeringWheelAngle;
    unsigned char	AccelerationSet4Way[ACCELERATIONSET_LENGH];

    unsigned char	BrakeSystemStatus[2];
    unsigned char	VehicleSize[3];
};

/*
struct _BSM_EtherHeader{
    unsigned char	dstmac[ETH_ALEN];
    unsigned char	srcmac[ETH_ALEN];
    unsigned char	type[2];
    unsigned char	psid[4];
};
*/

struct _BSM  {
//	struct _BSM_EtherHeader Header;
/*
    unsigned char	dstmac[6];
    unsigned char	srcmac[6];
    unsigned char	type[2];
    unsigned char	psid[4];
*/
    unsigned char   msgID;
	struct _BSM_blob	BSMblob;
};

struct _WSM_MsgReq{
	unsigned char channel;
	unsigned char datarate;
	char txpower;
	unsigned char psid[4];
	unsigned char priority;
	long long expirytime;
	short length;
	unsigned char *data;
	unsigned char dstmac[6];
	unsigned char ext;
	unsigned char weid;

	unsigned char wsmp_ver;	/* The version of the WSM protocol */
};

typedef struct BasicSafetyMessageASN {
    unsigned char                   msgid;
    unsigned char                   blob1[BLOB1_SIZE];
} bsm_t;

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

#endif	//ifndef _BSM_H_
