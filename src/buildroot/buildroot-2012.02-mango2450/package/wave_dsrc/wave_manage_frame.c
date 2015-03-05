#include <pthread.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include "type_def.h"
#include "task.h"
#include "wave_reg.h"
#include "wave_mac.h"
#include "wave_int.h"
#include "wsmp.h"
#include "wave_manage_frame.h"
#include "linked_list.h"
#include "util.h"

extern U4 ta_un32RSSI;
int wsa_received_flag;

U1 WSA_SRC_MAC_ADDR[ETH_MAC_ADDR_LEN];	/* WSA를 송신한 기지국의 WAVE MAC 주소 */
U1 WSA_DEST_MAC_ADDR[ETH_MAC_ADDR_LEN];	/* WSA를 송신한 기지국과 연결된 PC MAC 주소 */

int psid_flag;		/* 0이면 psid 길이가 0으로 고정, 1이면 규격대로 psid 길이가 가변 */

int proc_wsa_frame(U1 *rx_buf, U4 rx_len)
{
	U1 *src_mac_addr;
	U1 protocol_ver;
	U1 secured;
	int status=0;
	U1 wave_ver;
	U1 change_count;
	int i;
	U1 wave_eid;
	U1 element_length;
	U4_T recv_psid;
	U1 service_priority;
	U1 ch_index;
	U1 Operating_Class;
	U1 ch_num;
	U1 adaptable;
	U1 data_rate;
	U1 tx_power;
	U1 gw_mac_addr[6];
	U1 provider_mac_addr[6];
	int psid_len = 0;
	U1 psid_val[4];
	int j;

	src_mac_addr = &rx_buf[10];
	protocol_ver = rx_buf[31];		/* 1609.2 protocol version */
	secured = rx_buf[32];

	if(secured == SECURED_WSA)
	{
		printf("[proc_wsa_frame] Not Supported Secured WSA!!\n") ;		
		status = -1;
		return (status);
	}

	wave_ver = rx_buf[33] >> 2;

	if(wave_ver != WAVE_VERSION)
	{
		printf("[proc_wsa_frame] Not Supported WAVE Version %d\n", wave_ver) ;		
		status = -1;
		return(status);
	}

	change_count = rx_buf[33] & 0x03;

	i = 34;
	
	//printf("[proc_wsa_frame] rx_len=%d \n", rx_len) ;
	while ( i < rx_len )
	{
		wave_eid = rx_buf[i++]; //WAVE Element ID

		
		switch (wave_eid)
		{

			case WSA_SERVICE_INFO_EID :
				//printf("[proc_wsa_frame] WSA_SERVICE_INFO_EID \n") ;
				if (psid_flag == 0)
				{
					recv_psid.b1[3] = rx_buf[i++];
					recv_psid.b1[2] = rx_buf[i++];
					recv_psid.b1[1] = rx_buf[i++];
					recv_psid.b1[0] = rx_buf[i++];
				}
				else
				{
					/* 1609.3 규격의 8.1.3 참조 */
					psid_len = 1;
					for ( j = 0; j < 4; j++)
					{
						if (  ( rx_buf[i] >> (7-j) ) & 0x01 )
						{
							psid_len++;
						}
						else
						{
							j = 4;
						}
					}

					for ( j = 0; j < psid_len; j++)
					{
						recv_psid.b1[(psid_len -1 - j)] = rx_buf[i++];
					}
				}

				service_priority = rx_buf[i++];
				ch_index = rx_buf[i++];

				WSA_SRC_MAC_ADDR[0] = src_mac_addr[0];
				WSA_SRC_MAC_ADDR[1] = src_mac_addr[1];
				WSA_SRC_MAC_ADDR[2] = src_mac_addr[2];
				WSA_SRC_MAC_ADDR[3] = src_mac_addr[3];
				WSA_SRC_MAC_ADDR[4] = src_mac_addr[4];
				WSA_SRC_MAC_ADDR[5] = src_mac_addr[5];
				break;

			case WSA_CHANNEL_INFO_EID :
				//printf("[proc_wsa_frame] EXT_WAVE_PROVIDER_MAC_ADDR_EID \n") ;
				Operating_Class = rx_buf[i++];
				ch_num= rx_buf[i++];
				adaptable = rx_buf[i++];
				data_rate = rx_buf[i++];
				tx_power = rx_buf[i++];
				break ;		

			case WSA_WRA_EID:
				i += 35;
				memcpy(gw_mac_addr, &rx_buf[i], ETH_MAC_ADDR_LEN);

				i += ETH_MAC_ADDR_LEN;
				i += 16;		/* Primary DNS(16bytes) */
				break ;		

			case EXT_WAVE_TRANSMIT_POWER_USED_EID :
				element_length = rx_buf[i++];  
		    		i += element_length;
				break;		

			case EXT_WAVE_WAVE_2D_LOCATION_EID :
				element_length = rx_buf[i++];  
		    		i += element_length;
				break;	

			case EXT_WAVE_3D_LOCATION_AND_CONFIDENCE_EID :
				element_length = rx_buf[i++];  
		    		i += element_length;
				break;		

			case EXT_WAVE_ADVERTISER_ID_EID :
				element_length = rx_buf[i++];  
		    		i += element_length;
				break;		

			case EXT_WAVE_PSC_EID :
				element_length = rx_buf[i++];  
		    		i += element_length;
				break;		

			case EXT_WAVE_IPV6ADDR_EID :
				element_length = rx_buf[i++];  
		    		i += element_length;
				break;		

			case EXT_WAVE_SVC_PORT_EID :
				element_length = rx_buf[i++];  
		    		i += element_length;
				break;	

			case EXT_WAVE_PROVIDER_MAC_ADDR_EID:
				//printf("[proc_wsa_frame] EXT_WAVE_PROVIDER_MAC_ADDR_EID \n") ;
				element_length = rx_buf[i++];

				provider_mac_addr[0] = rx_buf[i++];
				provider_mac_addr[1] = rx_buf[i++];
				provider_mac_addr[2] = rx_buf[i++];
				provider_mac_addr[3] = rx_buf[i++];
				provider_mac_addr[4] = rx_buf[i++];
				provider_mac_addr[5] = rx_buf[i++];
				break ;		

			case EXT_WAVE_EDCA_PARAM_SET_EID :
				element_length = rx_buf[i++];
				//printf("[proc_wsa_frame] EXT_WAVE_EDCA_PARAM_SET_EID=%d/%d \n", element_length, i) ;
				i += element_length;
				break;

			case EXT_WAVE_SECONDARY_DNS_EID :
				element_length = rx_buf[i++];
				i += element_length;
				break;

			case EXT_WAVE_CHANNEL_ACCESS_EID :
				element_length = rx_buf[i++];
				i += element_length;
				break;		

			case EXT_WAVE_RCPI_THRESHOLD_EID:
				element_length = rx_buf[i++];
				i += element_length;
				break;	

			case EXT_WAVE_WSA_COUNT_THRESHOLD_EID :
				element_length = rx_buf[i++];
				i += element_length;
				break;

			default:
				printf("[proc_wsa_frame] Unknown WAVE Element ID %d \n", wave_eid) ;
				status = -1;
	        		break;

		}/*end of switch(wave_eid)*/
	}

	return(status);
	
}

int prco_management_action_subtype(U1 *rx_buf, U4 rx_len)
{
	int status;
	U1 category;
	int i = 0;
	U1 management_id;
	U1 content_subtype;

	category = rx_buf[24];		/* MAC 헤더 바로 다음. */

	if (category == VENDOR_SPECIFIC_CATEGORY)
	{
		management_id = rx_buf[29] & 0x0f;

		if (management_id == WMID_1609_3)
		{
			content_subtype = 	rx_buf[30];

			if (content_subtype == WSA_SUBTYPE)
			{
				status = proc_wsa_frame(rx_buf, rx_len);
				if (status == 0)
					wsa_received_flag = 1;
			}
		}
		else
		{
			printf("[prco_management_action_subtype] Invalid management_id = 0x%02x\n", management_id);
			status = -1;
		}
	}
	else
	{
		printf("[prco_management_action_subtype] Invalid Category = 0x%02x\n", category);
		status = -1;
	}

	return(status);
}

int proc_wave_mac_management_frame(U1 *rx_buf, U4 rx_len)
{
	U4 subtype;
	int status = -1;

	subtype = (rx_buf[0] & 0xf0) >> 4;

	/* SHKO : 802.11 규격의 Table 7-1 참조 */
	switch (subtype)
	{
		case MGMT_ASSOCIATE_REQ_SUBTYPE:
			printf("[proc_wave_mac_management_frame]Not Supported Associate Request.\n");
			break;
            
		case MGMT_ASSOCIATE_RSP_SUBTYPE:
			printf("[proc_wave_mac_management_frame]Not Supported Associate Response.\n");
			break;

		case MGMT_REASSOCIATE_REQ_SUBTYPE:
			printf("[proc_wave_mac_management_frame]Not Supported ReAssociate Request.\n");
			break;
                
		case MGMT_REASSOCIATE_RSP_SUBTYPE:
			printf("[proc_wave_mac_management_frame]Not Supported ReAssociate Response.\n");
			break;
               
		case MGMT_PROBE_REQ_SUBTYPE:
			printf("[proc_wave_mac_management_frame]Not Supported Probe Request.\n");
			break;
                
		case MGMT_PROBE_RSP_SUBTYPE:
			printf("[proc_wave_mac_management_frame]Not Supported Probe Response.\n");
			break;

		case MGMT_TIMING_ADVERTISE_SUBTYPE:
			printf("[proc_wave_mac_management_frame]Not Supported Timing Advertisement.\n");
			break;
              
		case MGMT_BEACON_SUBTYPE:
			printf("[proc_wave_mac_management_frame]Not Supported Beacon.\n");
			break;
               
		case MGMT_ATIM_SUBTYPE:
			printf("[proc_wave_mac_management_frame]Not Supported ATIM.\n");
			break;
               
		case MGMT_DIASSOCIATE_SUBTYPE:
			printf("[proc_wave_mac_management_frame]Not Supported Diassociate.\n");
			break;
        
		case MGMT_AUTHENTICATION_SUBTYPE:
			printf("[proc_wave_mac_management_frame]Not Supported Authentication.\n");
			break;

		case MGMT_DEAUTHENTICATION_SUBTYPE:
			printf("[proc_wave_mac_management_frame]Not Supported DeAuthentication.\n");
			break;
			

		case MGMT_ACTION_SUBTYPE:
			status = prco_management_action_subtype(rx_buf, rx_len);   							
			break;

                /* In case of any other value for the sub-type field. */
                default:
			printf("[proc_wave_mac_management_frame]Invalid Subtype = 0x%02x\n", subtype);
			break;
	}

	return (status);
	
}

