
/* Management Frame Subtypes. 802.11 Table 7-1 ÂüÁ¶ */
#define MGMT_ASSOCIATE_REQ_SUBTYPE		     					0x00
#define MGMT_ASSOCIATE_RSP_SUBTYPE		     					0x01
#define MGMT_REASSOCIATE_REQ_SUBTYPE		     				0x02
#define MGMT_REASSOCIATE_RSP_SUBTYPE		     					0x03
#define MGMT_PROBE_REQ_SUBTYPE		     						0x04
#define MGMT_PROBE_RSP_SUBTYPE		     						0x05
#define MGMT_TIMING_ADVERTISE_SUBTYPE		     				0x06
#define MGMT_BEACON_SUBTYPE		     							0x08
#define MGMT_ATIM_SUBTYPE		     								0x09
#define MGMT_DIASSOCIATE_SUBTYPE		     						0x0A
#define MGMT_AUTHENTICATION_SUBTYPE		     					0x0B
#define MGMT_DEAUTHENTICATION_SUBTYPE		     				0x0C
#define MGMT_ACTION_SUBTYPE		     							0x0D



extern int proc_wave_mac_management_frame(U1 *rx_buf, U4 rx_len);

