

#include <stdio.h>   
#include <stdlib.h>   
#include <string.h>   
#include <unistd.h>   
#include <arpa/inet.h>
#include <sys/types.h>   
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

 
#include "type_def.h"
#include "linked_list.h"
#include "task.h"
#include "wave_mac.h"
#include "wave_int.h"
#include "wsmp.h"

extern __attribute__((aligned(4))) ETHER_RX_DATA	ether_rx_queue[ETHER_RX_QUEUE_NUM];
extern int ether_rx_queue_read_index;
extern int ether_rx_queue_write_index;

U1 wave_mac_dest_addr[ETH_MAC_ADDR_LEN];
U1 wave_mac_src_addr[ETH_MAC_ADDR_LEN];

int default_wave_tx_delay = 10;

extern int dev;
extern int wsa_received_flag;

void *ether_rx_proc_thread(void *data)
{
 	U1 *rcv_data;
 	int i = 0;
 	U2 rcv_len;
 	int header_len = 8;					/* LLC 헤더(3) + SNAP 헤더(5) */
 	U1 *org_data_ptr;	
 	U1 ether_type[2];
 	int ret = 0;
 	int tx_count = 5;
 	IOCTLWAVE_INFO ctrl_info;
 
	printf("[ether_rx_proc_thread] Start\n");
 
	while( 1 )
	{  
	
		if (ether_rx_queue_write_index != ether_rx_queue_read_index)
		{
			pthread_mutex_lock(&ether_rx_mutex);
			//if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
     			//	printf("[ether_rx_proc_thread] 1\n");
			org_data_ptr = ether_rx_queue[ether_rx_queue_read_index].data_ptr;
			
			wave_mac_dest_addr[0] = ether_rx_queue[ether_rx_queue_read_index].data_ptr[0];
	 		wave_mac_dest_addr[1] = ether_rx_queue[ether_rx_queue_read_index].data_ptr[1];
	 		wave_mac_dest_addr[2] = ether_rx_queue[ether_rx_queue_read_index].data_ptr[2];
	 		wave_mac_dest_addr[3] = ether_rx_queue[ether_rx_queue_read_index].data_ptr[3];
	 		wave_mac_dest_addr[4] = ether_rx_queue[ether_rx_queue_read_index].data_ptr[4];
	 		wave_mac_dest_addr[5] = ether_rx_queue[ether_rx_queue_read_index].data_ptr[5];

	 		wave_mac_src_addr[0] = ether_rx_queue[ether_rx_queue_read_index].data_ptr[6];
	 		wave_mac_src_addr[1] = ether_rx_queue[ether_rx_queue_read_index].data_ptr[7];
	 		wave_mac_src_addr[2] = ether_rx_queue[ether_rx_queue_read_index].data_ptr[8];
	 		wave_mac_src_addr[3] = ether_rx_queue[ether_rx_queue_read_index].data_ptr[9];
	 		wave_mac_src_addr[4] = ether_rx_queue[ether_rx_queue_read_index].data_ptr[10];
	 		wave_mac_src_addr[5] = ether_rx_queue[ether_rx_queue_read_index].data_ptr[11];

	 		ether_type[0] = ether_rx_queue[ether_rx_queue_read_index].data_ptr[12];
			ether_type[1] = ether_rx_queue[ether_rx_queue_read_index].data_ptr[13];

			ether_rx_queue[ether_rx_queue_read_index].data_ptr += 14;		/* 14 = 이더넷 헤더 길이 */
			ether_rx_queue[ether_rx_queue_read_index].data_len -= 14;

	 		
			rcv_data = ether_rx_queue[ether_rx_queue_read_index].data_ptr;

			rcv_len = (U2)ether_rx_queue[ether_rx_queue_read_index].data_len;
	
			rcv_data -= header_len;		/* LLC 헤더(3) + SNAP 헤더(5) */

			i = 0;
	
			/* LLC 헤더 */
			rcv_data[i++] = 0xAA;
			rcv_data[i++] = 0xAA;
			rcv_data[i++] = 0x03;

			/* 프로토콜 ID */
			rcv_data[i++] = 0x00;
			rcv_data[i++] = 0x00;
			rcv_data[i++] = 0x00;
	
			/* Ether Type */
			rcv_data[i++] = ether_type[0];
			rcv_data[i++] = ether_type[1];

			

#if 0	
			rcv_data[i++] = WSMP_VERSION;

			rcv_data[i++] = 0x20;		/* PSID */

			rcv_data[i++] = EXT_WAVE_TRANSMIT_POWER_USED_EID;
			rcv_data[i++] = 0x01;		/* Tx Power Length */
			rcv_data[i++] = 0x07;		/* Tx Power */

			rcv_data[i++] = EXT_WAVE_DATARATE_EID;
			rcv_data[i++] = 0x01;		/* Data Rate Length */
			rcv_data[i++] = 0x06;		/* Data Rate */

			rcv_data[i++] = EXT_WAVE_CHANNEL_NUM_EID;
			rcv_data[i++] = 0x01;		/* Channel Number Length */
			rcv_data[i++] = 0xAC;		/* Channel Number *//* 0xAC = 172, IEEE 802.11 규격의 17.3.8.3.2 Channel Numbering을 참조하면 된다. chnnel number가 172이면, Channel Center Frequncy는 5.86GHz가 된다. */

			rcv_data[i++] = WSMP_WSM_EID;	/* WSMP WAVE element ID */
			rcv_data[i++] = (rcv_len >> 8) & 0xFF;
			rcv_data[i++] = rcv_len & 0xFF;
#endif

			//pthread_mutex_lock(&ether_rx_mutex);		//SHKO, Origin
			ether_rx_queue[ether_rx_queue_read_index].data_len += header_len;
			ether_rx_queue[ether_rx_queue_read_index].data_ptr -= header_len;

			//print_dump_data(ether_rx_queue[ether_rx_queue_read_index].data_ptr, ether_rx_queue[ether_rx_queue_read_index].data_len, "[ether_rx_proc_thread] Recv Data");

			//Send_MPDU(DATA_FRAME, CONTROL_CHANNEL, AC4, ether_rx_queue[ether_rx_queue_read_index].data_len, wave_mac_default_tx_power, wave_mac_default_data_rate, EXT_TO_DS_FROM_DS, ether_rx_queue[ether_rx_queue_read_index].data_ptr);
#if THROUGHPUT_TX_COMP == 0		/* SHKO : 이렇게 할 때가 성능이 가장 잘 나옴. */
			//printf("[ether_rx_proc_thread] Test0\n");
			tx_count = 10;
			do 
			{
				//ret = Send_MPDU(DATA_FRAME, CONTROL_CHANNEL, AC1, ether_rx_queue[ether_rx_queue_read_index].data_len, wave_mac_default_tx_power, wave_mac_default_data_rate, IBSS_TO_DS_FROM_DS, ether_rx_queue[ether_rx_queue_read_index].data_ptr);
				if (wsa_received_flag)
				{
					ret = Store_Tx_Queue(0, DATA_FRAME, CONTROL_CHANNEL, AC1, ether_rx_queue[ether_rx_queue_read_index].data_len, wave_mac_default_tx_power, wave_mac_default_data_rate, EXT_TO_DS_FROM_DS, ether_rx_queue[ether_rx_queue_read_index].data_ptr);
				}
				else
				{
					ret = Store_Tx_Queue(0, DATA_FRAME, CONTROL_CHANNEL, AC1, ether_rx_queue[ether_rx_queue_read_index].data_len, wave_mac_default_tx_power, wave_mac_default_data_rate, IBSS_TO_DS_FROM_DS, ether_rx_queue[ether_rx_queue_read_index].data_ptr);
				}
				
				if (ret < 0)
				{
					
					tx_count--;
				#if 0	//SHKO, Origin
					my_nanosleep(0, 5000000);	// 5ms Sleep
					pthread_mutex_unlock(&ether_rx_mutex);
				#else
					time_delay(300);
				#endif
				}
				else
				{
					tx_count = 0;
					//printf("[Send_MPDU]fail0\n");
					
					//printf("[Send_MPDU]fail1\n");
					//time_delay(100);	/* 이것을 열면 AC1만을 사용할 때 최대 성능이 나옴 */
				}
					
			} while(tx_count);
			//printf("[ether_rx_proc_thread] Test01\n");

			if (ret < 0)
			{
				printf("[ether_rx_proc_thread] Send Fail\n");
			}
			
			ether_rx_queue[ether_rx_queue_read_index].data_ptr = org_data_ptr;

			if (ret == 0)
			{
				ether_rx_queue_read_index++;
				if (ether_rx_queue_read_index == ETHER_RX_QUEUE_NUM)
				{
					ether_rx_queue_read_index = 0;
				}
			}

			if (multi_ac_channel_alloc_flag == 0 )
				time_delay(default_wave_tx_delay);/* 이것을 열면 AC1만을 사용할 때 최대 성능이 나옴, 근데 multiac로 구동할 때는 7.5M 정도 나오는데, 중간에 out of order 가 나옴. */

			//if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
     			//	printf("[ether_rx_proc_thread] 2\n");
			pthread_mutex_unlock(&ether_rx_mutex);
#else
			ret  = ioctl(dev, IOCTLWAVE_READ, &ctrl_info);
			if (ret != 0)
			{
				perror("[ether_rx_proc_thread] ioctl:");
			}
			else
			{
				wave_resend_cch1_ac1_frame_write_count = ctrl_info.wave_resend_queue_write_index;
			}

			if ( ctrl_info.wave_resend_queue_write_index == ctrl_info.wave_resend_queue_read_index)
			{
				ret = Send_MPDU(DATA_FRAME, CONTROL_CHANNEL, AC1, ether_rx_queue[ether_rx_queue_read_index].data_len, wave_mac_default_tx_power, wave_mac_default_data_rate, IBSS_TO_DS_FROM_DS, ether_rx_queue[ether_rx_queue_read_index].data_ptr);
				if (ret < 0)
				{
					Store_Resend_WAVE_Tx_Queue(DATA_FRAME, CONTROL_CHANNEL, AC1, ether_rx_queue[ether_rx_queue_read_index].data_len, wave_mac_default_tx_power, wave_mac_default_data_rate, IBSS_TO_DS_FROM_DS, ether_rx_queue[ether_rx_queue_read_index].data_ptr);
					//time_delay(300);
				}
				
			}
			else
				printf("[ether_rx_proc_thread]wave_resend_queue_write_index=%d, wave_resend_queue_read_index=%d\n", ctrl_info.wave_resend_queue_write_index, ctrl_info.wave_resend_queue_read_index);


			ether_rx_queue[ether_rx_queue_read_index].data_ptr = org_data_ptr;
			
			ether_rx_queue_read_index++;
			if (ether_rx_queue_read_index == ETHER_RX_QUEUE_NUM)
			{
				ether_rx_queue_read_index = 0;
			}

			pthread_mutex_unlock(&ether_rx_mutex);
#endif
		}
		else
		{
			//print_dump_data(message, n, "[net_rcv_thread] Recv Data");
			//my_nanosleep(0, 10000000);	// 10ms Sleep 	
			//my_nanosleep(0, 5000000);	// 5ms Sleep 	
		}
	
	}   
	
	return 0;
}   
