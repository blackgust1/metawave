#ifndef _WAVE_SHELL_H_
#define _WAVE_SHELL_H_

#define	COMMAND_DATA_LENGTH	60

#define	IOCTL_READ	0
#define	IOCTL_WRITE	1

#define	IOCTL_READ_2BYTE	2
#define	IOCTL_READ_4BYTE	3
#define	IOCTL_WRITE_2BYTE	4
#define	IOCTL_WRITE_4BYTE	5

#define	REGADDR				"regaddr"
#define	MACADDR				"macaddr"
#define	CNTMAC_COUNT		"cntmac"
#define	DEBUG_MSG			"debug"
#define	LAN_DEBUG_MSG		"landbg"
#define	DATARATE			"datarate"
#define	OPMODE				"opmode"
#define	CLRCNT				"clrcnt"
#define	FCHANGE				"fchange"
#define	RFPOWER				"rfpower"
#define	TXPKT				"txpkt"
#define	TXMGT				"txmgt"
#define	TX					"tx"
#define AMC                 "amc"
#define MACTABLE			"mtable"

#define     SHELL_FREQ_5850    850
#define     SHELL_FREQ_5860    860
#define     SHELL_FREQ_5870    870
#define     SHELL_FREQ_5880    880
#define     SHELL_FREQ_5890    890
#define     SHELL_FREQ_5900    900
#define     SHELL_FREQ_5910    910
#define     SHELL_FREQ_5920    920

/*	>>>>> LAN SMSC911x IOCTL Commands */
enum
{
	NOTIFY_RSU_MODE=0,
	NOTIFY_OBU_MODE,
	NOTIFY_ETHER_INPUT,
	NOTIFY_IOCTL_MSG,
};	// Category
/*	<<<<< LAN SMSC911x IOCTL Commands */

enum
{
	REGADDR_CATEGORY=0,
	MAC_CATEGORY,
	VMC_CATEGORY,
	ETC_CATEGORY,
	MLME_CATEGORY,
};	// Category

enum
{
	REGADDR_CMD=0,
	MACADDR_CMD,
	CNTMAC_CMD,
	DEBUG_LEVEL_CMD,
	DATARATE_CMD,
	OPMODE_CMD,
	GET_OPMODE_CMD,
	CLRCNT_CMD,
	FCHANGE_CMD,
	RFPOWER_CMD,
	TXPKT_CMD,
	TXMGT_CMD,
	TX_CMD,
	AMC_CMD,
	MACTABLE_CMD,
	PID_CMD,
	LAN_DBG_CMD,
};	// Commands

enum
{
	WAVE_DSRC_ADDR=1,
	CPU_GPIO_ADDR,
	CPU_INTR_ADDR,
};	// REGADDR_CMD

enum
{
	DESTMAC_ADDR=1,
	GATEWAY_ADDR,
};	// MACADDR_CMD

enum
{
	RSMGMT_PID=1,
};	// PID_CMD

enum
{
	SCH_AC1=1,
	SCH_AC2,
	SCH_AC3,
	SCH_AC4,
	CCH_AC1,
	CCH_AC2,
	CCH_AC3,
	CCH_AC4,
};

enum
{
	MAC_A=1,
	MAC_B=2,
};	// Mac Count CMD

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

#endif	// ifndef _WAVE_SHELL_H_
