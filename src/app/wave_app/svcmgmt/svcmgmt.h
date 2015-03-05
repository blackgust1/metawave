#ifndef _RESOURCE_MGMT_H_
#define _RESOURCE_MGMT_H_
#include "../comm_inc/svcdefs.h"

struct svcReqQueue {
	struct svcEvent	*Event;
    struct svcReqQueue *link; /* address of get data in the list */
};

#define PUT_TWO_CHARS(high, low, source) \
        {\
            high = (source >> 8) & 0x00FF;\
            low = (source & 0x00FF);\
        }

#define PUT_FOUR_CHARS(char4, char3, char2, char1, source) \
        {\
            char4 = (source >> 24) & 0x00FF;\
            char3 = (source >> 16) & 0x00FF;\
            char2 = (source >> 8) & 0x00FF;\
            char1 = (source & 0x00FF);\
        }

#define GET_16BIT(dest,high, low) \
        {\
            dest = (high << 8);\
            dest |= (low & 0x00FF);\
        }

#define GET_32BIT(dest, char4, char3, char2, char1) \
        {\
            dest = (char4 << 24);\
            dest |= (char3 << 16);\
            dest |= (char2 << 8);\
            dest |= (char1 & 0x00FF);\
        }

extern  int DebugLevel;
#define BASIC_MSG_LEVEL			1
#define RECV_MSG_LEVEL			2
#define SEND_MSG_LEVEL			3
#define RECV_SEND_MSG_LEVEL		4
#define EVENT_MSG_LEVEL			5

#define DBG_MSG(level,format,arg...) if ((level == BASIC_MSG_LEVEL) || (DebugLevel == level)) {printf(format, ##arg);}
#endif	// ifndef _RESOURCE_MGMT_H_
