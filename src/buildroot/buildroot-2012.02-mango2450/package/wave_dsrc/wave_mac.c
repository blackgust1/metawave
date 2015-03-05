#include <pthread.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include "type_def.h"
#include "task.h"
#include "wave_reg.h"
#include "wave_mac.h"
#include "wave_int.h"
#include "wave_manage_frame.h"
#include "wsmp.h"
#include "linked_list.h"
#include "util.h"

U2 data_seq_num;
U2 management_seq_num;
char address4_omit_flag = 0;
unsigned int tx_add_len = 0;

extern U1 *wave_dsrc_base;

U1	dest_mac[ETH_MAC_ADDR_LEN];

int wave_mac_default_tx_power;
int wave_mac_default_data_rate;
int multi_ac_channel_alloc_flag;

int cch_channel_access;		/* AC1, AC2, AC3, AC4 */

WAVE_MAC_TABLE		wave_rx_dest_mac_table[WAVE_MAC_TABLE_MAX_NUM];

U1 Broadcast_MAC_ADDR[ETH_MAC_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

RESEND_FRAME_DATA wave_resend_cch_ac1_frame[WAVE_RESEND_QUEUE_NUM];
int wave_resend_cch1_ac1_frame_write_count = 0;
int wave_resend_cch1_ac1_frame_read_count = 0;


int etri_flag = 0;

extern int dev;

U4	RTSCTStrl;
U4	un32MidCycle;
int  MIDCtrl;

extern U1 WSA_SRC_MAC_ADDR[ETH_MAC_ADDR_LEN];	/* WSA를 송신한 기지국의 WAVE MAC 주소 */
extern U1 WSA_DEST_MAC_ADDR[ETH_MAC_ADDR_LEN];	/* WSA를 송신한 기지국과 연결된 PC MAC 주소 */

int auto_dest_mac_flag = 1;

int wave_mac_rx_retry_count = 0;
int wave_mac_rx_duplication_count = 0;
int wave_mac_rx_no_retry_duplication_count = 0;

int tx_queue_pause_threshold = 254;

U1 sr5500_prev_modulation = 3;
U2 sr5500_prev_ap_len = 100;
U2 sr5500_prev_total_cnt;
int sr5500_prev_mac_rx_cnt;
U1 sr5500_rx_test_end_flag;
U1 sr5500_prev_start_flag = 1;

extern int sr5500_rx_test_flag;

/* 6 : 3M, 4.5M, 6M, 9M, 12M, 18M */
/* 5 : Len(100), Len(200), Len(400), Len(800), Len(1000) */
SR5500_TEST_DATA sr5500_test_info[6][5];

extern U4_T	psid;
extern U1	psid_len;
extern int mac_rx_count;
extern int total_wave_mac_rx_count;

extern timer_t SR5500_TEST_RX_TIMER_ID;

U4 g_rts_rate;

int wave_mac_thread_id;

extern U4 g_tx_reset_reg_test;

extern U1 g_display_mac_rx_seq_num_flag;

extern U1 g_ecdsa_sw_proc_flag;

U4 g_prev_iperf_seq_num;

extern int Decode_Encrypted_Message(U1 *rx_buf, U2 len);
extern int  SW_Verify_Signed_Message(U1 *rx_buf, U2 len);
extern int  Verify_Signed_Message(U1 *rx_buf, U2 len);

unsigned int read_wave_dsrc_reg32(int offset)
{
	U4_T reg_data;

	reg_data.b2[1] = reg_readw((wave_dsrc_base + offset));				/* High Data */
	reg_data.b2[0] = reg_readw((wave_dsrc_base + offset + 2));			/* Low Data */

	return(reg_data.b4);	
}

void  write_wave_dsrc_reg32(int offset, unsigned int data)
{
	U4_T reg_data;

	reg_data.b4 = data;

	reg_writew((wave_dsrc_base + offset), reg_data.b2[1]);			/* High Data */
	reg_writew((wave_dsrc_base + offset + 2), reg_data.b2[0]);		/* Low Data */

	return;	
}

unsigned int read_wave_ecc_reg32(int offset)
{
#if 0
	volatile U4 reg_data;
#else
	volatile U4 reg_data;
	volatile U4_T u_reg_data;
#endif

#if 0
	reg_data = reg_readl((wave_dsrc_base + offset));

	return(reg_data);
#else
	reg_data = reg_readl((wave_dsrc_base + offset));
	u_reg_data.b2[0] = (reg_data >> 16) & 0xFFFF;
	u_reg_data.b2[1] = reg_data & 0xFFFF;

	return(u_reg_data.b4);
#endif
}

void  write_wave_ecc_reg32(int offset, unsigned int data)
{
	
	U4_T reg_data;

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_data.b2[0] = (data >> 16) & 0xFFFF;
	reg_data.b2[1] = data & 0xFFFF;
	reg_writel((wave_dsrc_base + offset), reg_data.b4);
#else
	reg_writew((wave_dsrc_base + offset),  ((data >> 16) & 0xFFFF));		/* High Data */
	reg_writew((wave_dsrc_base + offset+2), (data & 0xFFFF));			/* Low Data */
#endif
	
	return;	
}

void  write_wave_ecc_reg32_by_16bit_or_32bit(int offset, unsigned int data)
{

#if 0	/* 32 bit */
	reg_writel((wave_dsrc_base + offset), data);
#else	/* 16bit */
	reg_writew((wave_dsrc_base + offset), (data & 0xFFFF));			/* High Data */
	reg_writew((wave_dsrc_base + offset + 2),  ((data >> 16) & 0xFFFF));		/* Low Data */
#endif
	
	
	return;	
}

void init_wave_rx_dest_mac_table(void)
{
	int i;
	int j;

	for ( i = 0; i < WAVE_MAC_TABLE_MAX_NUM; i++)
	{
		wave_rx_dest_mac_table[i].Ocupied = 0;
		wave_rx_dest_mac_table[i].seq_num = 0;
		wave_rx_dest_mac_table[i].fragment = 0;

		for ( j = 0; j < ETH_MAC_ADDR_LEN; j++)
			wave_rx_dest_mac_table[i].wave_rx_dest_mac_addr[j] = 0xFF;
	}
}

int find_empty_wave_rx_dest_mac_table(void)
{
	int i;

	for ( i = 0; i < WAVE_MAC_TABLE_MAX_NUM; i++)
	{
		if ( wave_rx_dest_mac_table[i].Ocupied == 0 )
		{
			return(i);
		}
	}
	return(-1);
}

int add_mac_addr_to_wave_rx_dest_mac_table(U1 *mac_addr, U2 fragment, U2 seq_num)
{
	int i;
	int j;

	for ( i = 0; i < WAVE_MAC_TABLE_MAX_NUM; i++)
	{
		if ( wave_rx_dest_mac_table[i].Ocupied == 0 )
		{
			for ( j = 0; j < ETH_MAC_ADDR_LEN; j++)
				wave_rx_dest_mac_table[i].wave_rx_dest_mac_addr[j] = mac_addr[j];

			wave_rx_dest_mac_table[i].Ocupied = 1;
			wave_rx_dest_mac_table[i].fragment= fragment;
			wave_rx_dest_mac_table[i].seq_num= seq_num;
			return(0);
		}
	}
	return(-1);
}

int find_wave_rx_dest_mac_table_with_mac_addr(U1 *mac_addr)
{
	int i;

	for ( i = 0; i < WAVE_MAC_TABLE_MAX_NUM; i++)
	{
		if ( wave_rx_dest_mac_table[i].Ocupied == 1 )
		{
			if( memcmp( wave_rx_dest_mac_table[i].wave_rx_dest_mac_addr, mac_addr, ETH_MAC_ADDR_LEN ) == 0)
				return(i);
		}
	}
	return(-1);
}

#if WAVE_MODEM || WAVE_MERGE
void wave_mac_init(void)
{
	int i;

	init_wave_rx_dest_mac_table();

	for ( i = 0; i < WAVE_MAC_RX_QUEUE_NUM; i++ )
	{
		wave_mac_rx_queue[i].data_len = 0;
		wave_mac_rx_queue[i].data_ptr = &wave_mac_rx_queue[i].packet[WAVE_MAC_RX_DATA_INITIAL_INDEX];
	}
	wave_mac_rx_queue_read_index = 0;
	wave_mac_rx_queue_write_index = 0;

	
	reg_writew((wave_dsrc_base + WAVE_MAC_A_ADDR16_REG_OFFSET), 0x0);
	
	write_wave_dsrc_reg32(WAVE_MAC_A_ADDR32_H_REG_OFFSET, 0x03);

	
	my_nanosleep(0, 2000);		/* 2usec delay */

	reg_writew((wave_dsrc_base + WAVE_MAC_A_BACKOFF_SEED_REG_OFFSET), 0x03);	/* backoff를 위한 랜덤 번호 발생기의 초기값 지정 */

	//reg_writel(WAVE_MAC_RESET_CLEAR_REG, 0xF);	/* MAC, Tx Queue, Rx Queue, Counter Reset*/
	reg_writew((wave_dsrc_base + WAVE_MODE_SET_H_REG_OFFSET), 0x00);
	
	reg_writew((wave_dsrc_base + WAVE_MULTICH_SET_H_REG_OFFSET), 0x00);

	write_wave_dsrc_reg32(WAVE_MAC_A_RSE_CCH_TIME_H_REG_OFFSET, 0x1388);	/* RSE의 컨트롤 채널 점유시간 값. Guard Interval 포함. */
	write_wave_dsrc_reg32(WAVE_MAC_A_OBU_CCH_TIME_H_REG_OFFSET, 0x4e20);

	write_wave_dsrc_reg32(WAVE_MAC_A_V2I_SCH_TIME_H_REG_OFFSET, 0x11170);		/* V2I를 위한 서비스 채널 점유 시간, Guard Interval 포함. */
	write_wave_dsrc_reg32(WAVE_MAC_A_V2V_SCH_TIME_H_REG_OFFSET, 0x0);		/* V2V를 위한 서비스 채널 점유 시간, Guard Interval 포함. */

	write_wave_dsrc_reg32(WAVE_MAC_A_CCH_SCH_CYCLE_TIME_H_REG_OFFSET, 0x186a0);
	write_wave_dsrc_reg32(WAVE_MAC_A_V2IV_SCH_REPEAT_CYCLE_TIME_H_REG_OFFSET, 0x186a0);
	write_wave_dsrc_reg32(WAVE_MAC_A_SYNC_TOLERANCE_H_REG_OFFSET, 0x3e8);	/* 각 장치간의 동기 오차 감안 시간. */
	write_wave_dsrc_reg32(WAVE_MAC_A_RF_SWITCH_TIME_H_REG_OFFSET, 0x3e8);

	
	reg_writew((wave_dsrc_base + WAVE_MAC_A_TIME_SLOT_LEN_REG_OFFSET), 0x1388);
	
	reg_writew((wave_dsrc_base + WAVE_MAC_A_NUM_OF_TIME_SLOT_FOR_CCH_REG_OFFSET), 0x4);			/* 컨트롤 채널을 위한 슬롯 수. OBU CCH만 해당.  */
	
	reg_writew((wave_dsrc_base + WAVE_MAC_A_NUM_OF_TIME_SLOT_FOR_V2I_SCH_REG_OFFSET), 0xe);		/* V2I 서비스 채널을 위한 슬롯 수 */
	
	reg_writew((wave_dsrc_base + WAVE_MAC_A_NUM_OF_TIME_SLOT_FOR_V2V_SCH_REG_OFFSET), 0x0);		/* V2V 서비스 채널을 위한 슬롯 수 */

#if WAVE_RX_TX_BUF_UPDATE
	reg_writew((wave_dsrc_base + WAVE_MAC_A_MODE_REG_OFFSET), 0x20);			/* OBU mode, CSMA/CA mode, Normal Mode */
#endif
	
	dest_mac[0] = 0xFF;
	dest_mac[1] = 0xFF;
	dest_mac[2] = 0xFF;
	dest_mac[3] = 0xFF;
	dest_mac[4] = 0xFF;
	dest_mac[5] = 0xFF;

	wave_mac_dest_addr[0] = 0xFF;
	wave_mac_dest_addr[1] = 0xFF;
	wave_mac_dest_addr[2] = 0xFF;
	wave_mac_dest_addr[3] = 0xFF;
	wave_mac_dest_addr[4] = 0xFF;
	wave_mac_dest_addr[5] = 0xFF;

	wave_mac_src_addr[0] = 0xFF;
	wave_mac_src_addr[1] = 0xFF;
	wave_mac_src_addr[2] = 0xFF;
	wave_mac_src_addr[3] = 0xFF;
	wave_mac_src_addr[4] = 0xFF;
	wave_mac_src_addr[5] = 0xFF;

	wave_mac_default_tx_power = 1;

	/* 3이면, DATA_RATE_3M_BPSK */
	/* 4이면, DATA_RATE_4_5M_BPSK */
	/* 6이면, DATA_RATE_6M_QPSK */
	/* 9이면, DATA_RATE_9M_QPSK */
	/* 12이면, DATA_RATE_12M_16QAM */
	/* 18이면, DATA_RATE_18M_16QAM */
	/* 24이면, DATA_RATE_24M_64QAM */
	/* 27이면, DATA_RATE_27M_64QAM */
	wave_mac_default_data_rate = 12;

	cch_channel_access = AC1;

	
	

}

#endif

#if WAVE_MERGE
void wave_mac_b_init(void)
{
	int i;

	init_wave_rx_dest_mac_table();

	for ( i = 0; i < WAVE_MAC_RX_QUEUE_NUM; i++ )
	{
		wave_mac_rx_queue[i].data_len = 0;
		wave_mac_rx_queue[i].data_ptr = &wave_mac_rx_queue[i].packet[WAVE_MAC_RX_DATA_INITIAL_INDEX];
	}
	wave_mac_rx_queue_read_index = 0;
	wave_mac_rx_queue_write_index = 0;

	
	reg_writew((wave_dsrc_base + WAVE_MAC_B_ADDR16_REG_OFFSET), 0x0);
	
	write_wave_dsrc_reg32(WAVE_MAC_B_ADDR32_H_REG_OFFSET, 0x03);

	
	my_nanosleep(0, 2000);		/* 2usec delay */

	reg_writew((wave_dsrc_base + WAVE_MAC_B_BACKOFF_SEED_REG_OFFSET), 0x03);	/* backoff를 위한 랜덤 번호 발생기의 초기값 지정 */

	//reg_writel(WAVE_MAC_RESET_CLEAR_REG, 0xF);	/* MAC, Tx Queue, Rx Queue, Counter Reset*/
	//reg_writew((wave_dsrc_base + WAVE_TOP_B_MODE_REG_OFFSET), 0x00);
	
	//reg_writew((wave_dsrc_base + WAVE_TOP_B_SYNC_REG_OFFSET), 0x00);

	write_wave_dsrc_reg32(WAVE_MAC_B_RSE_CCH_TIME_H_REG_OFFSET, 0x1388);	/* RSE의 컨트롤 채널 점유시간 값. Guard Interval 포함. */
	write_wave_dsrc_reg32(WAVE_MAC_B_OBU_CCH_TIME_H_REG_OFFSET, 0x4e20);

	write_wave_dsrc_reg32(WAVE_MAC_B_V2I_SCH_TIME_H_REG_OFFSET, 0x11170);		/* V2I를 위한 서비스 채널 점유 시간, Guard Interval 포함. */
	write_wave_dsrc_reg32(WAVE_MAC_B_V2V_SCH_TIME_H_REG_OFFSET, 0x0);		/* V2V를 위한 서비스 채널 점유 시간, Guard Interval 포함. */

	write_wave_dsrc_reg32(WAVE_MAC_B_CCH_SCH_CYCLE_TIME_H_REG_OFFSET, 0x186a0);
	write_wave_dsrc_reg32(WAVE_MAC_B_V2IV_SCH_REPEAT_CYCLE_TIME_H_REG_OFFSET, 0x186a0);
	write_wave_dsrc_reg32(WAVE_MAC_B_SYNC_TOLERANCE_H_REG_OFFSET, 0x3e8);	/* 각 장치간의 동기 오차 감안 시간. */
	write_wave_dsrc_reg32(WAVE_MAC_B_RF_SWITCH_TIME_H_REG_OFFSET, 0x3e8);

	
	reg_writew((wave_dsrc_base + WAVE_MAC_B_TIME_SLOT_LEN_REG_OFFSET), 0x1388);
	
	reg_writew((wave_dsrc_base + WAVE_MAC_B_NUM_OF_TIME_SLOT_FOR_CCH_REG_OFFSET), 0x4);			/* 컨트롤 채널을 위한 슬롯 수. OBU CCH만 해당.  */
	
	reg_writew((wave_dsrc_base + WAVE_MAC_B_NUM_OF_TIME_SLOT_FOR_V2I_SCH_REG_OFFSET), 0xe);		/* V2I 서비스 채널을 위한 슬롯 수 */
	
	reg_writew((wave_dsrc_base + WAVE_MAC_B_NUM_OF_TIME_SLOT_FOR_V2V_SCH_REG_OFFSET), 0x0);		/* V2V 서비스 채널을 위한 슬롯 수 */

#if WAVE_RX_TX_BUF_UPDATE
	reg_writew((wave_dsrc_base + WAVE_MAC_B_MODE_REG_OFFSET), 0x20);			/* OBU mode, CSMA/CA mode, Normal Mode */
#endif
	

	dest_mac[0] = 0xFF;
	dest_mac[1] = 0xFF;
	dest_mac[2] = 0xFF;
	dest_mac[3] = 0xFF;
	dest_mac[4] = 0xFF;
	dest_mac[5] = 0xFF;

	wave_mac_dest_addr[0] = 0xFF;
	wave_mac_dest_addr[1] = 0xFF;
	wave_mac_dest_addr[2] = 0xFF;
	wave_mac_dest_addr[3] = 0xFF;
	wave_mac_dest_addr[4] = 0xFF;
	wave_mac_dest_addr[5] = 0xFF;

	wave_mac_src_addr[0] = 0xFF;
	wave_mac_src_addr[1] = 0xFF;
	wave_mac_src_addr[2] = 0xFF;
	wave_mac_src_addr[3] = 0xFF;
	wave_mac_src_addr[4] = 0xFF;
	wave_mac_src_addr[5] = 0xFF;

	wave_mac_default_tx_power = 1;

	/* 3이면, DATA_RATE_3M_BPSK */
	/* 4이면, DATA_RATE_4_5M_BPSK */
	/* 6이면, DATA_RATE_6M_QPSK */
	/* 9이면, DATA_RATE_9M_QPSK */
	/* 12이면, DATA_RATE_12M_16QAM */
	/* 18이면, DATA_RATE_18M_16QAM */
	/* 24이면, DATA_RATE_24M_64QAM */
	/* 27이면, DATA_RATE_27M_64QAM */
	wave_mac_default_data_rate = 12;

	cch_channel_access = AC1;

	
	

}

#endif

U4 Get_Free_Len_Of_TX_Queue(int ch_kind, int access)
{
	U4 free_len;
	
	if (ch_kind == CONTROL_CHANNEL)
	{
		if (access == AC1)
		{
			free_len = read_wave_dsrc_reg32(WAVE_MAC_A_CCH_AC1_FREE_SPACE_H_REG_OFFSET);
		}
		else if (access == AC2)
		{
			free_len = read_wave_dsrc_reg32(WAVE_MAC_A_CCH_AC2_FREE_SPACE_H_REG_OFFSET);
		}
		else if (access == AC3)
		{
			free_len = read_wave_dsrc_reg32(WAVE_MAC_A_CCH_AC3_FREE_SPACE_H_REG_OFFSET);
		}
		else if (access == AC4)
		{
			free_len = read_wave_dsrc_reg32(WAVE_MAC_A_CCH_AC4_FREE_SPACE_H_REG_OFFSET);
		}
		else
			return(0);
	}
	else if (ch_kind == SERVICE_CHANNEL)
	{
		if (access == AC1)
		{
			free_len = read_wave_dsrc_reg32(WAVE_MAC_A_SCH_AC1_FREE_SPACE_H_REG_OFFSET);
		}
		else if (access == AC2)
		{
			free_len = read_wave_dsrc_reg32(WAVE_MAC_A_SCH_AC2_FREE_SPACE_H_REG_OFFSET);
		}
		else if (access == AC3)
		{
			free_len = read_wave_dsrc_reg32(WAVE_MAC_A_SCH_AC3_FREE_SPACE_H_REG_OFFSET);
		}
		else if (access == AC4)
		{
			free_len = read_wave_dsrc_reg32(WAVE_MAC_A_SCH_AC4_FREE_SPACE_H_REG_OFFSET);
		}
		else
			return(0);
	}
	else
		return(0);

	return(free_len);
}

#if WAVE_MERGE
U4 Get_Free_Len_Of_TX_Queue_B(int ch_kind, int access)
{
	U4 free_len;
	
	if (ch_kind == CONTROL_CHANNEL)
	{
		if (access == AC1)
		{
			free_len = read_wave_dsrc_reg32(WAVE_MAC_B_CCH_AC1_FREE_SPACE_H_REG_OFFSET);
		}
		else if (access == AC2)
		{
			free_len = read_wave_dsrc_reg32(WAVE_MAC_B_CCH_AC2_FREE_SPACE_H_REG_OFFSET);
		}
		else if (access == AC3)
		{
			free_len = read_wave_dsrc_reg32(WAVE_MAC_B_CCH_AC3_FREE_SPACE_H_REG_OFFSET);
		}
		else if (access == AC4)
		{
			free_len = read_wave_dsrc_reg32(WAVE_MAC_B_CCH_AC4_FREE_SPACE_H_REG_OFFSET);
		}
		else
			return(0);
	}
	else if (ch_kind == SERVICE_CHANNEL)
	{
		if (access == AC1)
		{
			free_len = read_wave_dsrc_reg32(WAVE_MAC_B_SCH_AC1_FREE_SPACE_H_REG_OFFSET);
		}
		else if (access == AC2)
		{
			free_len = read_wave_dsrc_reg32(WAVE_MAC_B_SCH_AC2_FREE_SPACE_H_REG_OFFSET);
		}
		else if (access == AC3)
		{
			free_len = read_wave_dsrc_reg32(WAVE_MAC_B_SCH_AC3_FREE_SPACE_H_REG_OFFSET);
		}
		else if (access == AC4)
		{
			free_len = read_wave_dsrc_reg32(WAVE_MAC_B_SCH_AC4_FREE_SPACE_H_REG_OFFSET);
		}
		else
			return(0);
	}
	else
		return(0);

	return(free_len);
}
#endif


#if 1	/* SHKO, Origin */
U4 Add_MAC_Header(U1 *mac_header, U1 from_to_ds, int frame_type)
{
	int i = 0;
	U1 order = 0;
	U1 ProtectedFrame = 0;
	U1 MoreData = 0;
	U1 PwrMgt = 0;
	U1 Retry = 0;
	U1 MoreFrag  = 0;
	U2 duration_id = 0;
	U4 high_mac_addr;
	U2 low_mac_addr;
	U2 seq_control = 0;
	U2 frag_num = 0;
	U2 QoS_control = 0;


	/* 하위 바이트가 먼저 나간다. */
	if (frame_type == DATA_FRAME)
		mac_header[i++] = WAVE_MAC_PROTOCOL_VER | WAVE_MAC_DATA_FRAME | QOS_DATA;
	else
		mac_header[i++] = WAVE_MAC_PROTOCOL_VER | WAVE_MAC_MGMT_FRAME | QOS_DATA;

	mac_header[i++] = (order << 7) |(ProtectedFrame << 6) |(MoreData << 5) |(PwrMgt << 4) 
					|(Retry << 3) |(MoreFrag << 2) |from_to_ds;

	if (etri_flag)
	{
		mac_header[i++] = 0x91;
	}
	else
	{
		mac_header[i++] = (duration_id >> 8) & 0xFF;		/* SHKO : ETRI는 Throughput 테스트 시 0x91로 보낸다. */
	}
	mac_header[i++] = duration_id  & 0xFF;

	switch(from_to_ds)
	{
		case IBSS_TO_DS_FROM_DS:
			/* address1 필드 */
			mac_header[i++] = wave_mac_dest_addr[0];
			mac_header[i++] = wave_mac_dest_addr[1];
			mac_header[i++] = wave_mac_dest_addr[2];
			mac_header[i++] = wave_mac_dest_addr[3];
			mac_header[i++] = wave_mac_dest_addr[4];
			mac_header[i++] = wave_mac_dest_addr[5];

			/* address2 필드 */
			mac_header[i++] = wave_mac_src_addr[0];
			mac_header[i++] = wave_mac_src_addr[1];
			mac_header[i++] = wave_mac_src_addr[2];
			mac_header[i++] = wave_mac_src_addr[3];
			mac_header[i++] = wave_mac_src_addr[4];
			mac_header[i++] = wave_mac_src_addr[5];

			/* address3 필드 *//* 원래는 Address3 필드에 BSSID가 들어가야 한다. */
		#if 0
			mac_header[i++] = wave_mac_dest_addr[0];
			mac_header[i++] = wave_mac_dest_addr[1];
			mac_header[i++] = wave_mac_dest_addr[2];
			mac_header[i++] = wave_mac_dest_addr[3];
			mac_header[i++] = wave_mac_dest_addr[4];
			mac_header[i++] = wave_mac_dest_addr[5];
		#else
			mac_header[i++] = 0xFF;
			mac_header[i++] = 0xFF;
			mac_header[i++] = 0xFF;
			mac_header[i++] = 0xFF;
			mac_header[i++] = 0xFF;
			mac_header[i++] = 0xFF;
		#endif
			break;

		case EXT_TO_DS_FROM_DS:		/* 원래는 Address1 필드에 BSSID가 들어가야 한다. */
			/* address1 필드 */
			mac_header[i++] = WSA_SRC_MAC_ADDR[0];
			mac_header[i++] = WSA_SRC_MAC_ADDR[1];
			mac_header[i++] = WSA_SRC_MAC_ADDR[2];
			mac_header[i++] = WSA_SRC_MAC_ADDR[3];
			mac_header[i++] = WSA_SRC_MAC_ADDR[4];
			mac_header[i++] = WSA_SRC_MAC_ADDR[5];

			/* address2 필드 */
			mac_header[i++] = wave_mac_src_addr[0];/* wave_mac_src_addr : 이 WAVE 단말기에 연결된 PC의 Ethernet MAC 주소 */
			mac_header[i++] = wave_mac_src_addr[1];
			mac_header[i++] = wave_mac_src_addr[2];
			mac_header[i++] = wave_mac_src_addr[3];
			mac_header[i++] = wave_mac_src_addr[4];
			mac_header[i++] = wave_mac_src_addr[5];

			/* address3 필드 */
		  #if 1
			mac_header[i++] = wave_mac_dest_addr[0];
			mac_header[i++] = wave_mac_dest_addr[1];
			mac_header[i++] = wave_mac_dest_addr[2];
			mac_header[i++] = wave_mac_dest_addr[3];
			mac_header[i++] = wave_mac_dest_addr[4];
			mac_header[i++] = wave_mac_dest_addr[5];
		  #else
		  	mac_header[i++] = 0xFF;
			mac_header[i++] = 0xFF;
			mac_header[i++] = 0xFF;
			mac_header[i++] = 0xFF;
			mac_header[i++] = 0xFF;
			mac_header[i++] = 0xFF;
		  #endif
			break;

		case TO_DS_EXT_FROM_DS:
			/* address1 필드 */
			mac_header[i++] = dest_mac[0];
			mac_header[i++] = dest_mac[1];
			mac_header[i++] = dest_mac[2];
			mac_header[i++] = dest_mac[3];
			mac_header[i++] = dest_mac[4];
			mac_header[i++] = dest_mac[5];

			/* address2 필드 *//* 원래는 Address2 필드에 BSSID가 들어가야 한다. */
			mac_header[i++] = wave_mac_src_addr[0];
			mac_header[i++] = wave_mac_src_addr[1];
			mac_header[i++] = wave_mac_src_addr[2];
			mac_header[i++] = wave_mac_src_addr[3];
			mac_header[i++] = wave_mac_src_addr[4];
			mac_header[i++] = wave_mac_src_addr[5];

			/* address3 필드 */
		  #if 0
			mac_header[i++] = wave_mac_src_addr[0];
			mac_header[i++] = wave_mac_src_addr[1];
			mac_header[i++] = wave_mac_src_addr[2];
			mac_header[i++] = wave_mac_src_addr[3];
			mac_header[i++] = wave_mac_src_addr[4];
			mac_header[i++] = wave_mac_src_addr[5];
		  #else
		  	mac_header[i++] = 0xFF;
			mac_header[i++] = 0xFF;
			mac_header[i++] = 0xFF;
			mac_header[i++] = 0xFF;
			mac_header[i++] = 0xFF;
			mac_header[i++] = 0xFF;
		  #endif
			break;

		case EXT_TO_DS_EXT_FROM_DS:		/* 원래는 Address1 필드에 BSSID가 들어가야 한다. */
			/* address1 필드 */
			mac_header[i++] = dest_mac[0];
			mac_header[i++] = dest_mac[1];
			mac_header[i++] = dest_mac[2];
			mac_header[i++] = dest_mac[3];
			mac_header[i++] = dest_mac[4];
			mac_header[i++] = dest_mac[5];

			/* address2 필드 *//* 원래는 Address2 필드에 BSSID가 들어가야 한다. */
			mac_header[i++] = wave_mac_src_addr[0];
			mac_header[i++] = wave_mac_src_addr[1];
			mac_header[i++] = wave_mac_src_addr[2];
			mac_header[i++] = wave_mac_src_addr[3];
			mac_header[i++] = wave_mac_src_addr[4];
			mac_header[i++] = wave_mac_src_addr[5];

			/* address3 필드 */
		  #if 0
			mac_header[i++] = wave_mac_src_addr[0];
			mac_header[i++] = wave_mac_src_addr[1];
			mac_header[i++] = wave_mac_src_addr[2];
			mac_header[i++] = wave_mac_src_addr[3];
			mac_header[i++] = wave_mac_src_addr[4];
			mac_header[i++] = wave_mac_src_addr[5];
		  #else
		  	mac_header[i++] = 0xFF;
			mac_header[i++] = 0xFF;
			mac_header[i++] = 0xFF;
			mac_header[i++] = 0xFF;
			mac_header[i++] = 0xFF;
			mac_header[i++] = 0xFF;
		  #endif
			break;

		default:
			/* address1 필드 */
			mac_header[i++] = dest_mac[0];
			mac_header[i++] = dest_mac[1];
			mac_header[i++] = dest_mac[2];
			mac_header[i++] = dest_mac[3];
			mac_header[i++] = dest_mac[4];
			mac_header[i++] = dest_mac[5];

			/* address2 필드 */
			mac_header[i++] = wave_mac_src_addr[0];
			mac_header[i++] = wave_mac_src_addr[1];
			mac_header[i++] = wave_mac_src_addr[2];
			mac_header[i++] = wave_mac_src_addr[3];
			mac_header[i++] = wave_mac_src_addr[4];
			mac_header[i++] = wave_mac_src_addr[5];

			/* address3 필드 */
			mac_header[i++] = wave_mac_dest_addr[0];
			mac_header[i++] = wave_mac_dest_addr[1];
			mac_header[i++] = wave_mac_dest_addr[2];
			mac_header[i++] = wave_mac_dest_addr[3];
			mac_header[i++] = wave_mac_dest_addr[4];
			mac_header[i++] = wave_mac_dest_addr[5];
			break;
	}


	frag_num = 0;
	seq_control = (data_seq_num << 4) | frag_num;
	
	mac_header[i++] = seq_control & 0xFF;
	mac_header[i++] = (seq_control >> 8) & 0xFF;

	/* address4 필드 */
  	if (from_to_ds == EXT_TO_DS_EXT_FROM_DS)
  	{
	  	mac_header[i++] = wave_mac_src_addr[0];
		mac_header[i++] = wave_mac_src_addr[1];
		mac_header[i++] = wave_mac_src_addr[2];
		mac_header[i++] = wave_mac_src_addr[3];
		mac_header[i++] = wave_mac_src_addr[4];
		mac_header[i++] = wave_mac_src_addr[5];
  	}

	if (etri_flag)
	{
		mac_header[i++] = 0x09;				/* SHKO : ETRI는 Throughput 테스트 시 0x09로 보낸다. */
	}
	else
	{
		mac_header[i++] = QoS_control & 0xFF;				/* SHKO : ETRI는 Throughput 테스트 시 0x09로 보낸다. */
	}
	
	mac_header[i++] = (QoS_control >> 8) & 0xFF;

	data_seq_num++;
	if (data_seq_num == SEQ_NUM_MODULO)
	{
		data_seq_num = 0;	
	}

	return(i);
	

	
}
#else
U4 Add_MAC_Header(U1 *sbuf, U1 from_to_ds, int frame_type)
{
	int i = 0;
	U1 order = 0;
	U1 ProtectedFrame = 0;
	U1 MoreData = 0;
	U1 PwrMgt = 0;
	U1 Retry = 0;
	U1 MoreFrag  = 0;
	U2 duration_id = 0;
	U4 high_mac_addr;
	U2 low_mac_addr;
	U2 seq_control = 0;
	U2 frag_num = 0;
	U2 QoS_control = 0;
	U4 mac_header_len = 0;

	if (frame_type == DATA_FRAME)
	{
		mac_header_len = 26;
		if (from_to_ds == EXT_TO_DS_EXT_FROM_DS)
		{
			mac_header_len = 32;
		}
	}
	else
	{
		mac_header_len = 24;
	}

	sbuf -= mac_header_len;
	


	/* 하위 바이트가 먼저 나간다. */
	if (frame_type == DATA_FRAME)
		sbuf[i++] = WAVE_MAC_PROTOCOL_VER | WAVE_MAC_DATA_FRAME | QOS_DATA;
	else
		sbuf[i++] = WAVE_MAC_PROTOCOL_VER | WAVE_MAC_MGMT_FRAME | QOS_DATA;

	sbuf[i++] = (order << 7) |(ProtectedFrame << 6) |(MoreData << 5) |(PwrMgt << 4) 
					|(Retry << 3) |(MoreFrag << 2) |from_to_ds;
					
	sbuf[i++] = (duration_id >> 8) & 0xFF;
	sbuf[i++] = duration_id  & 0xFF;

	switch(from_to_ds)
	{
		case IBSS_TO_DS_FROM_DS:
			/* address1 필드 */
			sbuf[i++] = wave_mac_dest_addr[0];
			sbuf[i++] = wave_mac_dest_addr[1];
			sbuf[i++] = wave_mac_dest_addr[2];
			sbuf[i++] = wave_mac_dest_addr[3];
			sbuf[i++] = wave_mac_dest_addr[4];
			sbuf[i++] = wave_mac_dest_addr[5];

			/* address2 필드 */
			sbuf[i++] = wave_mac_src_addr[0];
			sbuf[i++] = wave_mac_src_addr[1];
			sbuf[i++] = wave_mac_src_addr[2];
			sbuf[i++] = wave_mac_src_addr[3];
			sbuf[i++] = wave_mac_src_addr[4];
			sbuf[i++] = wave_mac_src_addr[5];

			/* address3 필드 *//* 원래는 Address3 필드에 BSSID가 들어가야 한다. */
		#if 0
			mac_header[i++] = wave_mac_dest_addr[0];
			mac_header[i++] = wave_mac_dest_addr[1];
			mac_header[i++] = wave_mac_dest_addr[2];
			mac_header[i++] = wave_mac_dest_addr[3];
			mac_header[i++] = wave_mac_dest_addr[4];
			mac_header[i++] = wave_mac_dest_addr[5];
		#else
			sbuf[i++] = 0xFF;
			sbuf[i++] = 0xFF;
			sbuf[i++] = 0xFF;
			sbuf[i++] = 0xFF;
			sbuf[i++] = 0xFF;
			sbuf[i++] = 0xFF;
		#endif
			break;

		case EXT_TO_DS_FROM_DS:		/* 원래는 Address1 필드에 BSSID가 들어가야 한다. */
			/* address1 필드 */
			sbuf[i++] = dest_mac[0];
			sbuf[i++] = dest_mac[1];
			sbuf[i++] = dest_mac[2];
			sbuf[i++] = dest_mac[3];
			sbuf[i++] = dest_mac[4];
			sbuf[i++] = dest_mac[5];

			/* address2 필드 */
			sbuf[i++] = wave_mac_src_addr[0];
			sbuf[i++] = wave_mac_src_addr[1];
			sbuf[i++] = wave_mac_src_addr[2];
			sbuf[i++] = wave_mac_src_addr[3];
			sbuf[i++] = wave_mac_src_addr[4];
			sbuf[i++] = wave_mac_src_addr[5];

			/* address3 필드 */
		  #if 0
			mac_header[i++] = wave_mac_dest_addr[0];
			mac_header[i++] = wave_mac_dest_addr[1];
			mac_header[i++] = wave_mac_dest_addr[2];
			mac_header[i++] = wave_mac_dest_addr[3];
			mac_header[i++] = wave_mac_dest_addr[4];
			mac_header[i++] = wave_mac_dest_addr[5];
		  #else
		  	sbuf[i++] = 0xFF;
			sbuf[i++] = 0xFF;
			sbuf[i++] = 0xFF;
			sbuf[i++] = 0xFF;
			sbuf[i++] = 0xFF;
			sbuf[i++] = 0xFF;
		  #endif
			break;

		case TO_DS_EXT_FROM_DS:
			/* address1 필드 */
			sbuf[i++] = dest_mac[0];
			sbuf[i++] = dest_mac[1];
			sbuf[i++] = dest_mac[2];
			sbuf[i++] = dest_mac[3];
			sbuf[i++] = dest_mac[4];
			sbuf[i++] = dest_mac[5];

			/* address2 필드 *//* 원래는 Address2 필드에 BSSID가 들어가야 한다. */
			sbuf[i++] = wave_mac_src_addr[0];
			sbuf[i++] = wave_mac_src_addr[1];
			sbuf[i++] = wave_mac_src_addr[2];
			sbuf[i++] = wave_mac_src_addr[3];
			sbuf[i++] = wave_mac_src_addr[4];
			sbuf[i++] = wave_mac_src_addr[5];

			/* address3 필드 */
		  #if 0
			mac_header[i++] = wave_mac_src_addr[0];
			mac_header[i++] = wave_mac_src_addr[1];
			mac_header[i++] = wave_mac_src_addr[2];
			mac_header[i++] = wave_mac_src_addr[3];
			mac_header[i++] = wave_mac_src_addr[4];
			mac_header[i++] = wave_mac_src_addr[5];
		  #else
		  	sbuf[i++] = 0xFF;
			sbuf[i++] = 0xFF;
			sbuf[i++] = 0xFF;
			sbuf[i++] = 0xFF;
			sbuf[i++] = 0xFF;
			sbuf[i++] = 0xFF;
		  #endif
			break;

		case EXT_TO_DS_EXT_FROM_DS:		/* 원래는 Address1 필드에 BSSID가 들어가야 한다. */
			/* address1 필드 */
			sbuf[i++] = dest_mac[0];
			sbuf[i++] = dest_mac[1];
			sbuf[i++] = dest_mac[2];
			sbuf[i++] = dest_mac[3];
			sbuf[i++] = dest_mac[4];
			sbuf[i++] = dest_mac[5];

			/* address2 필드 *//* 원래는 Address2 필드에 BSSID가 들어가야 한다. */
			sbuf[i++] = wave_mac_src_addr[0];
			sbuf[i++] = wave_mac_src_addr[1];
			sbuf[i++] = wave_mac_src_addr[2];
			sbuf[i++] = wave_mac_src_addr[3];
			sbuf[i++] = wave_mac_src_addr[4];
			sbuf[i++] = wave_mac_src_addr[5];

			/* address3 필드 */
		  #if 0
			mac_header[i++] = wave_mac_src_addr[0];
			mac_header[i++] = wave_mac_src_addr[1];
			mac_header[i++] = wave_mac_src_addr[2];
			mac_header[i++] = wave_mac_src_addr[3];
			mac_header[i++] = wave_mac_src_addr[4];
			mac_header[i++] = wave_mac_src_addr[5];
		  #else
		  	sbuf[i++] = 0xFF;
			sbuf[i++] = 0xFF;
			sbuf[i++] = 0xFF;
			sbuf[i++] = 0xFF;
			sbuf[i++] = 0xFF;
			sbuf[i++] = 0xFF;
		  #endif
			break;

		default:
			/* address1 필드 */
			sbuf[i++] = dest_mac[0];
			sbuf[i++] = dest_mac[1];
			sbuf[i++] = dest_mac[2];
			sbuf[i++] = dest_mac[3];
			sbuf[i++] = dest_mac[4];
			sbuf[i++] = dest_mac[5];

			/* address2 필드 */
			sbuf[i++] = wave_mac_src_addr[0];
			sbuf[i++] = wave_mac_src_addr[1];
			sbuf[i++] = wave_mac_src_addr[2];
			sbuf[i++] = wave_mac_src_addr[3];
			sbuf[i++] = wave_mac_src_addr[4];
			sbuf[i++] = wave_mac_src_addr[5];

			/* address3 필드 */
			sbuf[i++] = wave_mac_dest_addr[0];
			sbuf[i++] = wave_mac_dest_addr[1];
			sbuf[i++] = wave_mac_dest_addr[2];
			sbuf[i++] = wave_mac_dest_addr[3];
			sbuf[i++] = wave_mac_dest_addr[4];
			sbuf[i++] = wave_mac_dest_addr[5];
			break;
	}


	frag_num = 0;
	seq_control = (data_seq_num << 4) | frag_num;
	
	sbuf[i++] = seq_control & 0xFF;
	sbuf[i++] = (seq_control >> 8) & 0xFF;

	/* address4 필드 */
  	if (from_to_ds == EXT_TO_DS_EXT_FROM_DS)
  	{
	  	sbuf[i++] = wave_mac_src_addr[0];
		sbuf[i++] = wave_mac_src_addr[1];
		sbuf[i++] = wave_mac_src_addr[2];
		sbuf[i++] = wave_mac_src_addr[3];
		sbuf[i++] = wave_mac_src_addr[4];
		sbuf[i++] = wave_mac_src_addr[5];
  	}

	if (frame_type == DATA_FRAME)
	{
		sbuf[i++] = QoS_control & 0xFF;
		sbuf[i++] = (QoS_control >> 8) & 0xFF;
	}

	data_seq_num++;
	if (data_seq_num == SEQ_NUM_MODULO)
	{
		data_seq_num = 0;	
	}

	return(i);
	

	
}
#endif

int Store_Resend_WAVE_Tx_Queue(int frame_kind, int ch_kind, int access, int len, int tx_power, int modulation, U1 from_to_ds, U1 *send_buf)
{
	U4 free_len;
	U4 write_len;
	U4 total_len;
	int i=0;
	int j;
	int k;
	int mac_header_len = 0;
	U4 frame_info;
	U4 complete_time;
	U4 rts_rate;
	U4 sdata;
	//U1 sbuf[2080];
	U4 Frame_Content_Reg;
	U4 Frame_Info_Reg;
	int ret;
	


	if (multi_ac_channel_alloc_flag)
		access = cch_channel_access;

	if (frame_kind == DATA_FRAME)
	{
		if (from_to_ds == EXT_TO_DS_EXT_FROM_DS)
		{
			mac_header_len = 32;
		}
		else
		{
			mac_header_len = 26;
		}
	}
	else
	{
		mac_header_len = 24;
	}

	
	send_buf -= mac_header_len;
	Add_MAC_Header(send_buf, from_to_ds, frame_kind);

	total_len = len + mac_header_len;


	if ( total_len > WAVE_MAC_RX_QUEUE_SIZE )
	{
		printf("[Store_Resend_WAVE_Tx_Queue] Software Queue is Overflow : %d\n", total_len);
		return(-1);
	}

	wave_resend_cch_ac1_frame[wave_resend_cch1_ac1_frame_write_count].access_catagory = AC1;
	wave_resend_cch_ac1_frame[wave_resend_cch1_ac1_frame_write_count].ch_kind = CONTROL_CHANNEL;
	wave_resend_cch_ac1_frame[wave_resend_cch1_ac1_frame_write_count].mac_header_len = mac_header_len;
	wave_resend_cch_ac1_frame[wave_resend_cch1_ac1_frame_write_count].len = total_len;

	memcpy(wave_resend_cch_ac1_frame[wave_resend_cch1_ac1_frame_write_count].buf, send_buf, total_len);

	complete_time = 0x32;
	rts_rate = 0;

	switch(modulation)
	{
		case 3:
			wave_resend_cch_ac1_frame[wave_resend_cch1_ac1_frame_write_count].frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_3M_BPSK << 12)
						| (total_len & 0xFFF);
			break;

		case 4:
			wave_resend_cch_ac1_frame[wave_resend_cch1_ac1_frame_write_count].frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_4_5M_BPSK << 12)
						| (total_len & 0xFFF);
			break;

		case 6:
			wave_resend_cch_ac1_frame[wave_resend_cch1_ac1_frame_write_count].frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_6M_QPSK << 12)
						| (total_len & 0xFFF);
			break;

		case 9:
			wave_resend_cch_ac1_frame[wave_resend_cch1_ac1_frame_write_count].frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_9M_QPSK << 12)
						| (total_len & 0xFFF);
			break;

		case 12:
			wave_resend_cch_ac1_frame[wave_resend_cch1_ac1_frame_write_count].frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_12M_16QAM << 12)
						| (total_len & 0xFFF);
			break;

		case 18:
			wave_resend_cch_ac1_frame[wave_resend_cch1_ac1_frame_write_count].frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_18M_16QAM << 12)
						| (total_len & 0xFFF);
			break;

		case 24:
			wave_resend_cch_ac1_frame[wave_resend_cch1_ac1_frame_write_count].frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_24M_64QAM << 12)
						| (total_len & 0xFFF);
			break;

		case 27:
			wave_resend_cch_ac1_frame[wave_resend_cch1_ac1_frame_write_count].frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_27M_64QAM << 12)
						| (total_len & 0xFFF);
			break;

		default:
			break;
		
	}

	cch_channel_access++;

	if (cch_channel_access > AC4)
		cch_channel_access = AC1;

#if 0
	for ( i = 0; i < total_len; i++)
	{
		printf("[%02x]", wave_resend_cch_ac1_frame[wave_resend_cch1_ac1_frame_write_count].buf[i]);

		if ( ((i+1) % 10 == 0) )
		{
			printf("\n");
		}
	}
	printf("\n");
#endif

	ret = write(dev, &wave_resend_cch_ac1_frame[wave_resend_cch1_ac1_frame_write_count],(total_len + 12));
	if (ret < 0)
	{
		perror("[Store_Resend_WAVE_Tx_Queue] write:");
	}

	return(0);
}

U4 Tx_Time_Calc(U4 sdul, U4 mdcycle, U4 un32Datarate)
{
	U4	un32TotalFrameLengthBits;		// TX 되어지는 DATA FRAME의 Total bits 수 
	U4	un32ModSymbol;					
	U4	un32NumDataSymbol;					// DATA Symbol 수  
	U4	un32NumMidSymbol;					// Midamble Symbol 수  
	U4	un32NumACKSymbol;					// ACK Symbol 수  
	U4	un32TimeData;					// Total Data Time(Data + Midamble OFDM Symbol)
	U4	un32TimeACK;					// ACK Time  
	U4	un32NavData;					// DATA Time + SIFS + ACK Time
	U4  tx_time;
	U1	US_UNIT=8;						//8usec	
	U4	un32DBPS; 						//각각의  Modulation에 따른  DBPS
	U4	RTSCTStrlTime;
	
	//printf("[Tx_Time_Calc] SHKO1\n");

	/* SHKO : 802.11 규격의 17.3.2 참조 */
	un32TotalFrameLengthBits = sdul*8 + 16 + 6 + 32;	// Length of Frame(Data-Variable)*8(bits) + Service(16bits) + Tail(6bits) + FCS(32bits)

	//Added by jmp // data rate 으로 수정 해야함. 
	/* SHKO : 802.11 규격의 Table 17-3 참조 */
	switch(un32Datarate){
		case 3 :
			un32DBPS = DBPS_3M;
			break;
		case 4 :
			un32DBPS = DBPS_45M;			
			break;
		case 6 :
			un32DBPS = DBPS_6M;
			break;
		case 9 :
			un32DBPS = DBPS_9M;
			break;			
		case 12 :
			un32DBPS = DBPS_12M;
			break;
		case 18 :
			un32DBPS = DBPS_18M;
			break;
		case 24 :
			un32DBPS = DBPS_24M;
			break;			
		case 27 :
			un32DBPS = DBPS_27M;
			break;			
		default :
			un32DBPS = DBPS_3M;
	}

	//printf("[Tx_Time_Calc] SHKO2\n");

	switch(RTSCTStrl){
	case 3 :
		RTSCTStrlTime = 104 + 32 + 88 + 32; // RTS_3M + SIFS + CTS_3M + SIFS
		break;
	case 6 :
		RTSCTStrlTime = 72 + 32 + 64 + 32; // RTS_6M + SIFS + CTS_6M + SIFS		
		break;
	case 12 :
		RTSCTStrlTime = 56 + 32 + 56 + 32; // RTS_12M + SIFS + CTS_12M + SIFS		
		break;
//	case 27 :
//		RTSCTStrlTime = 48 + 32 + 48 + 32; // RTS_27M + SIFS + CTS_27M + SIFS	
//		break;
	default :
		RTSCTStrlTime = 0;		
	}
	
	// Number of Data OFDM Symbols	
	if(un32TotalFrameLengthBits >= un32DBPS)
	{
		un32ModSymbol = un32TotalFrameLengthBits % un32DBPS;
		
		if(un32ModSymbol == 0)
		{
			un32NumDataSymbol = un32TotalFrameLengthBits / un32DBPS;
		}
		else
		{
			un32NumDataSymbol = un32TotalFrameLengthBits / un32DBPS + 1;
		}
	}
	else
	{
		printf(" \n\r **** The packet is too short !!! ");
	}

	//printf("[Tx_Time_Calc] SHKO3\n");

	// Number of Ack OFDM Symbols
	un32ModSymbol = ACK_LENGTH % un32DBPS;
	
	if(un32ModSymbol == 0)
	{
		un32NumACKSymbol = ACK_LENGTH / un32DBPS;
	}
	else
	{
		un32NumACKSymbol = ACK_LENGTH / un32DBPS +1;
	}
	
	// Number of Midamble OFDM Symbols
	if (mdcycle > 0)
		un32NumMidSymbol = un32NumDataSymbol/mdcycle;
	
	//printf("[Tx_Time_Calc] SHKO4\n");

	// Duration of DATA	
	if(MIDCtrl)
	{
		un32TimeData = COMMON_TIME + un32NumDataSymbol*SYMBOL_TIME + un32NumMidSymbol*MIDAMBLE_SYMBOL_TIME;
	}
    	else
    	{
		un32TimeData = COMMON_TIME + un32NumDataSymbol*SYMBOL_TIME;
    	}
	
	// Duration of ACK
	un32TimeACK = COMMON_TIME + un32NumACKSymbol*SYMBOL_TIME;

	//TX Time of Frame
	un32NavData = un32TimeData + SIFS_TIME + un32TimeACK + RTSCTStrlTime;
	
	if((un32NavData%US_UNIT) == 0)
	{
		tx_time = un32NavData/US_UNIT;
	}
	else
	{
		tx_time = un32NavData/US_UNIT+1;
	}
	//printf("[Tx_Time_Calc] SHKO5\n");
	
	return tx_time;
	
}



#if 0	//SHKO, Origin
int Send_MPDU(int frame_kind, int ch_kind, int access, int len, int tx_power, int modulation, U1 from_to_ds, U1 *send_buf)
{
	U4 free_len;
	TX_FRAME_DATA tx_frame;
	U4 write_len;
	U4 total_len;
	int i=0;
	int ap_buf_position=0;
	U4 *mac_header_ptr;
	U4 *data_ptr;
	U4 frame_info;
	U4 complete_time;
	U4 rts_rate;
	U4 sdata;
	//U1 sbuf[2080];
	U4 Frame_Content_Reg;
	U4 Frame_Info_Reg;
	int mac_header_len = 0;

	if (multi_ac_channel_alloc_flag)
		access = cch_channel_access;
		
	if (frame_kind == DATA_FRAME)
	{
		if (from_to_ds == EXT_TO_DS_EXT_FROM_DS)
		{
			mac_header_len = 32;
		}
		else
		{
			mac_header_len = 26;
		}
	}
	else
	{
		mac_header_len = 24;
	}

	
	free_len = Get_Free_Len_Of_TX_Queue(ch_kind, access);
	/* 36 = MAC 헤더(32) + FCS(4) */
	if (free_len <(len + mac_header_len + 4))
	{
		printf("[Send_MPDU]Tx Queue is Unavailable, ch_access = %d, freelen = %d, tx_len = %d\n", access, free_len, len);

		cch_channel_access++;

		if (cch_channel_access > AC4)
			cch_channel_access = AC1;
		return(-1);
	}

	if (ch_kind == CONTROL_CHANNEL)
	{
		if (access == AC1)
		{
			Frame_Content_Reg = WAVE_MAC_A_CCH_AC1_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_A_CCH_AC1_FRAME_INFO_H_REG_OFFSET;
		}
		else if (access == AC2)
		{
			Frame_Content_Reg = WAVE_MAC_A_CCH_AC2_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_A_CCH_AC2_FRAME_INFO_H_REG_OFFSET;
		}
		else if (access == AC3)
		{
			Frame_Content_Reg = WAVE_MAC_A_CCH_AC3_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_A_CCH_AC3_FRAME_INFO_H_REG_OFFSET;
		}
		else if (access == AC4)
		{
			Frame_Content_Reg = WAVE_MAC_A_CCH_AC4_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_A_CCH_AC4_FRAME_INFO_H_REG_OFFSET;
		}
		else
			return(-1);
	}
	else if (ch_kind == SERVICE_CHANNEL)
	{
		if (access == AC1)
		{
			Frame_Content_Reg = WAVE_MAC_A_SCH_AC1_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_A_SCH_AC1_FRAME_INFO_H_REG_OFFSET;
		}
		else if (access == AC2)
		{
			Frame_Content_Reg = WAVE_MAC_A_SCH_AC2_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_A_SCH_AC2_FRAME_INFO_H_REG_OFFSET;
		}
		else if (access == AC3)
		{
			Frame_Content_Reg = WAVE_MAC_A_SCH_AC3_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_A_SCH_AC3_FRAME_INFO_H_REG_OFFSET;
		}
		else if (access == AC4)
		{
			Frame_Content_Reg = WAVE_MAC_A_SCH_AC4_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_A_SCH_AC4_FRAME_INFO_H_REG_OFFSET;
		}
		else
			return(-1);
	}

	//printf("[Send_MPDU]Tx Queue is Unavailable, freelen = %d, tx_len = %d\n", free_len, len);

	
	tx_frame.header_len = Add_MAC_Header(tx_frame.mac_header, from_to_ds, frame_kind);

	total_len = len + tx_frame.header_len;

	
	tx_frame.sbuf = send_buf;

	
	mac_header_ptr = (U4 *)tx_frame.mac_header;

	data_ptr = (U4 *)tx_frame.sbuf;

	if ( len > WAVE_MAC_RX_QUEUE_SIZE )
	{
		printf("[Send_MPDU] Software Queue is Overflow : %d\n", len);
		return(-1);
	}

	if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
	{
		print_dump_data(tx_frame.mac_header, tx_frame.header_len, "[Send_MPDU] MAC Header");
		print_dump_data(tx_frame.sbuf, len, "[Send_MPDU] MAC DATA");
	}


	if ( (tx_frame.header_len%4) == 0)
     	{
		write_len = tx_frame.header_len/4;
		for ( i = 0; i < write_len; i++)
		{
		#if WAVE_RX_TX_BUF_UPDATE
			if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
     				printf("[%08X]",mac_header_ptr[i]);
			write_wave_dsrc_reg32(Frame_Content_Reg, mac_header_ptr[i]);
     		#else
     			sdata = ENDIAN_SWAP32(mac_header_ptr[i]);
     			//if (print_flag)
			//	printf("[%08X]",sdata);
			write_wave_dsrc_reg32(Frame_Content_Reg, sdata);
     		#endif
     		}
     		//if (print_flag)
     		//	printf("\n");
     			
		if ( (len%4) == 0)
		{
			write_len = len/4;
		}
		else
		{
			write_len = (len/4) + 1;
		}

		for ( i = 0; i < write_len; i++)
		{
		#if WAVE_RX_TX_BUF_UPDATE
			if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
     				printf("[%08X]",data_ptr[i]);
			write_wave_dsrc_reg32(Frame_Content_Reg, data_ptr[i]);
     		#else
     			sdata = ENDIAN_SWAP32(data_ptr[i]);
     			//if (print_flag)
			//	printf("[%08X]",sdata);
			write_wave_dsrc_reg32(Frame_Content_Reg, sdata);
     		#endif
		}
		//if (print_flag)
     		//	printf("\n");
	}
	else
	{
		ap_buf_position = 4- (tx_frame.header_len%4);

		for ( i = 0; i < ap_buf_position; i++)
		{
			tx_frame.mac_header[tx_frame.header_len+i] = send_buf[i];
		}

		write_len = (tx_frame.header_len + ap_buf_position)/4;
		for ( i = 0; i < write_len; i++)
		{
		#if WAVE_RX_TX_BUF_UPDATE
			if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
     				printf("[%08X]",mac_header_ptr[i]);
			write_wave_dsrc_reg32(Frame_Content_Reg, mac_header_ptr[i]);
     		#else
     			sdata = ENDIAN_SWAP32(mac_header_ptr[i]);
     			//if (print_flag)
			//	printf("[%08X]",sdata);
			write_wave_dsrc_reg32(Frame_Content_Reg, sdata);
     		#endif
		}
		//if (print_flag)
     		//	printf("\n");

		//data_ptr = (U4 *)&tx_frame.sbuf[ap_buf_position];
		len = len - ap_buf_position;

		if ( (len%4) == 0)
		{
			write_len = len/4;
		}
		else
		{
			write_len = (len/4) + 1;
		}


		data_ptr = (U4 *)&send_buf[ap_buf_position];
		
		for ( i = 0; i < write_len; i++)
		{
		#if WAVE_RX_TX_BUF_UPDATE
			if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
     				printf("[%08X]",data_ptr[i]);
			write_wave_dsrc_reg32(Frame_Content_Reg, data_ptr[i]);
     		#else
     			sdata = ENDIAN_SWAP32(data_ptr[i]);
     			//if (print_flag)
			//	printf("[%08X]",sdata);
			write_wave_dsrc_reg32(Frame_Content_Reg, sdata);
     		#endif
		}
		//if (print_flag)
     		//	printf("\n");
     			
	}

	complete_time = 0x32;
	rts_rate = 0;

	if (tx_add_len)
	{
		total_len += tx_add_len;
	}
	//total_len = 0x52;

	switch(modulation)
	{
		case 3:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_3M_BPSK << 12)
						| (total_len & 0xFFF);
			break;

		case 4:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_4_5M_BPSK << 12)
						| (total_len & 0xFFF);
			break;

		case 6:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_6M_QPSK << 12)
						| (total_len & 0xFFF);
			break;

		case 9:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_9M_QPSK << 12)
						| (total_len & 0xFFF);
			break;

		case 12:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_12M_16QAM << 12)
						| (total_len & 0xFFF);
			break;

		case 18:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_18M_16QAM << 12)
						| (total_len & 0xFFF);
			break;

		case 24:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_24M_64QAM << 12)
						| (total_len & 0xFFF);
			break;

		case 27:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_27M_64QAM << 12)
						| (total_len & 0xFFF);
			break;

		default:
			break;
		
	}

	cch_channel_access++;

	if (cch_channel_access > AC4)
		cch_channel_access = AC1;

	if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
     		printf("frame_info = [%08X]",frame_info);
	write_wave_dsrc_reg32(Frame_Info_Reg, frame_info);

	return(0);
}
#else
int Send_MPDU(int frame_kind, int ch_kind, int access, int len, int tx_power, int modulation, U1 from_to_ds, U1 *send_buf)
{
	U4 free_len;
	U4 write_len;
	U4 total_len;
	U4 total_len_div_for;
	int i=0;
	int j;
	int k;
	U4 frame_info;
	U4 complete_time;
	U4 rts_rate;
	U4 sdata;
	//U1 sbuf[2080];
	U4 Frame_Content_Reg;
	U4 Frame_Info_Reg;
	int mac_header_len = 0;
	U4_T sbuf[520];
	int remain_len;
	int ret = 0;
	U4 *send_buf_ptr;

	if (multi_ac_channel_alloc_flag)
		access = cch_channel_access;
		
	if (frame_kind == DATA_FRAME)
	{
		if (from_to_ds == EXT_TO_DS_EXT_FROM_DS)
		{
			mac_header_len = 32;
		}
		else
		{
			mac_header_len = 26;
		}
	}
	else
	{
		mac_header_len = 24;
	}

	free_len = Get_Free_Len_Of_TX_Queue(ch_kind, access);
	/* 36 = MAC 헤더(32) + FCS(4) */
	if (free_len <(len + mac_header_len + 4))
	{
		//printf("[Send_MPDU]Tx Queue is Unavailable, ch_access = %d, freelen = %d, tx_len = %d\n", access, free_len, len);
		if (g_tx_reset_reg_test == 0)
		{
			cch_channel_access++;

			if (cch_channel_access > AC4)
				cch_channel_access = AC1;
			return(-1);
		}
	}

	if (ch_kind == CONTROL_CHANNEL)
	{
		if (access == AC1)
		{
			Frame_Content_Reg = WAVE_MAC_A_CCH_AC1_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_A_CCH_AC1_FRAME_INFO_H_REG_OFFSET;
		}
		else if (access == AC2)
		{
			Frame_Content_Reg = WAVE_MAC_A_CCH_AC2_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_A_CCH_AC2_FRAME_INFO_H_REG_OFFSET;
		}
		else if (access == AC3)
		{
			Frame_Content_Reg = WAVE_MAC_A_CCH_AC3_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_A_CCH_AC3_FRAME_INFO_H_REG_OFFSET;
		}
		else if (access == AC4)
		{
			Frame_Content_Reg = WAVE_MAC_A_CCH_AC4_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_A_CCH_AC4_FRAME_INFO_H_REG_OFFSET;
		}
		else
		{
			printf("[Send_MPDU]CCH Invalid Access Category = %d\n", access);
			return(-1);
		}
	}
	else if (ch_kind == SERVICE_CHANNEL)
	{
		if (access == AC1)
		{
			Frame_Content_Reg = WAVE_MAC_A_SCH_AC1_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_A_SCH_AC1_FRAME_INFO_H_REG_OFFSET;
		}
		else if (access == AC2)
		{
			Frame_Content_Reg = WAVE_MAC_A_SCH_AC2_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_A_SCH_AC2_FRAME_INFO_H_REG_OFFSET;
		}
		else if (access == AC3)
		{
			Frame_Content_Reg = WAVE_MAC_A_SCH_AC3_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_A_SCH_AC3_FRAME_INFO_H_REG_OFFSET;
		}
		else if (access == AC4)
		{
			Frame_Content_Reg = WAVE_MAC_A_SCH_AC4_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_A_SCH_AC4_FRAME_INFO_H_REG_OFFSET;
		}
		else
		{
			printf("[Send_MPDU]SCH Invalid Access Category = %d\n", access);
			return(-1);
		}
	}

	//printf("[Send_MPDU]Tx Queue is Unavailable, freelen = %d, tx_len = %d\n", free_len, len);
	

	send_buf -= mac_header_len;		/* SHKO : 주의 mac_heder_len 길이 만큼 뺀 값이 항상 4의 배수여야 한다. */
	Add_MAC_Header(send_buf, from_to_ds, frame_kind);

	total_len = len + mac_header_len;

	if ( total_len > WAVE_MAC_RX_QUEUE_SIZE )
	{
		printf("[Send_MPDU] Software Queue is Overflow : %d\n", total_len);
		return(-1);
	}

#if 0	//SHKO, Origin
	total_len_div_for = total_len/4;

	remain_len = total_len % 4;

	j = 0;
	for ( i = 0; i < total_len_div_for; i++ )
	{
		sbuf[i].b1[0] = send_buf[j++];
		sbuf[i].b1[1] = send_buf[j++];
		sbuf[i].b1[2] = send_buf[j++];
		sbuf[i].b1[3] = send_buf[j++];
	}

	if (remain_len)
	{
		for ( k = 0; k < remain_len; k++ )
		{
			sbuf[i].b1[k] = send_buf[j+k];
		}

		
		for ( k = remain_len; k < 4; k++ )
		{
			sbuf[i].b1[k] = 0;
		}
		i++;
	}

	write_len = i;
#else
	total_len_div_for = total_len/4;

	remain_len = total_len % 4;

	write_len = total_len_div_for;

	if (remain_len)
	{
		write_len++;	
	}
#endif

	if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
	{
		printf("Display Tx Data\n");
		for ( i = 0; i < total_len; i++)
		{
			printf("0x%02x, ", send_buf[i]);
			if ( ( (i+1) % 10 ) == 0 )
				printf("\n");
	     	}
	     	if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
	     		printf("\n");
	}

#if 0	//SHKO, Origin
	for ( i = 0; i < write_len; i++)
	{
	#if WAVE_RX_TX_BUF_UPDATE
		if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
     			printf("[%08X]",sbuf[i].b4);
		//write_wave_dsrc_reg32(Frame_Content_Reg, sbuf[i].b4);
     	#else
     		sdata = ENDIAN_SWAP32(sbuf[i].b4);
     		//if (print_flag)
		//	printf("[%08X]",sdata);
		write_wave_dsrc_reg32(Frame_Content_Reg, sdata);
     	#endif
     	}
     	if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
     		printf("\n");
#else
	send_buf_ptr = (U4 *)send_buf;
	for ( i = 0; i < write_len; i++)
	{
	#if WAVE_RX_TX_BUF_UPDATE
		if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
     			printf("[%08X]",send_buf_ptr[i]);
		write_wave_dsrc_reg32(Frame_Content_Reg, send_buf_ptr[i]);
     	#else
     		sdata = ENDIAN_SWAP32(send_buf_ptr[i]);
     		//if (print_flag)
		//	printf("[%08X]",sdata);
		write_wave_dsrc_reg32(Frame_Content_Reg, sdata);
     	#endif
     	}
     	if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
     		printf("\n");
#endif

#if 1	//SHKO, Origin
	if (etri_flag)
	{
		complete_time = 0xBB;
	}
	else
	{
		complete_time = 0x32;
	}
#else
	complete_time = Tx_Time_Calc((len + mac_header_len), 0, modulation);
#endif

#if 1	//SHKO, Origin
	rts_rate = 0;		/* SHKO, rts_rate의 값을 0이 아닌 다른 값을 사용하면 ping 메세지를 보낼 때 마다 CCH_AC1_RETX_LIMIT_OVERFLOW_INT!!인터럽트가 발생한다. */
#else
	if(memcmp(&send_buf[4], Broadcast_MAC_ADDR,ETH_MAC_ADDR_LEN)==0)
	{
		rts_rate = 0;
	}
	else
	{
		rts_rate = 0;
	}
#endif

	if (tx_add_len)
	{
		total_len += tx_add_len;
	}
	//total_len = 0x52;

	switch(modulation)
	{
		case 3:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_3M_BPSK << 12)
						| (total_len & 0xFFF);
			break;

		case 4:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_4_5M_BPSK << 12)
						| (total_len & 0xFFF);
			break;

		case 6:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_6M_QPSK << 12)
						| (total_len & 0xFFF);
			break;

		case 9:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_9M_QPSK << 12)
						| (total_len & 0xFFF);
			break;

		case 12:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_12M_16QAM << 12)
						| (total_len & 0xFFF);
			break;

		case 18:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_18M_16QAM << 12)
						| (total_len & 0xFFF);
			break;

		case 24:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_24M_64QAM << 12)
						| (total_len & 0xFFF);
			break;

		case 27:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_27M_64QAM << 12)
						| (total_len & 0xFFF);
			break;

		default:
			break;
		
	}

	cch_channel_access++;

	if (cch_channel_access > AC4)
		cch_channel_access = AC1;

	if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
     		printf("frame_info = [%08X]\n",frame_info);

     	//printf("g_tx_reset_reg_test = [%08X]\n",g_tx_reset_reg_test);

	if (g_tx_reset_reg_test == 0)
	{
     		//printf("frame_info = [%08X][%08X]\n",Frame_Info_Reg,frame_info);
		write_wave_dsrc_reg32(Frame_Info_Reg, frame_info);
	}

#if 0
	ret  = ioctl(dev, IOCTLWAVE_WAIT_TX);
	if (ret != 0)
	{
		perror("[Send_MPDU] ioctl:");
	}
	printf("[ether_rx_proc_thread]Not Resource\n");
#endif
	

	return(0);
}
#endif

#if WAVE_MERGE
int Send_MPDU_B(int frame_kind, int ch_kind, int access, int len, int tx_power, int modulation, U1 from_to_ds, U1 *send_buf)
{
	U4 free_len;
	U4 write_len;
	U4 total_len;
	U4 total_len_div_for;
	int i=0;
	int j;
	int k;
	U4 frame_info;
	U4 complete_time;
	U4 rts_rate;
	U4 sdata;
	//U1 sbuf[2080];
	U4 Frame_Content_Reg;
	U4 Frame_Info_Reg;
	int mac_header_len = 0;
	U4_T sbuf[520];
	int remain_len;
	int ret = 0;
	U4 *send_buf_ptr;

	if (multi_ac_channel_alloc_flag)
		access = cch_channel_access;
		
	if (frame_kind == DATA_FRAME)
	{
		if (from_to_ds == EXT_TO_DS_EXT_FROM_DS)
		{
			mac_header_len = 32;
		}
		else
		{
			mac_header_len = 26;
		}
	}
	else
	{
		mac_header_len = 24;
	}

	free_len = Get_Free_Len_Of_TX_Queue_B(ch_kind, access);
	/* 36 = MAC 헤더(32) + FCS(4) */
	if (free_len <(len + mac_header_len + 4))
	{
		printf("[Send_MPDU_B]Tx Queue is Unavailable, ch_access = %d, freelen = %d, tx_len = %d\n", access, free_len, len);

		cch_channel_access++;

		if (cch_channel_access > AC4)
			cch_channel_access = AC1;
		return(-1);
	}

	if (ch_kind == CONTROL_CHANNEL)
	{
		if (access == AC1)
		{
			Frame_Content_Reg = WAVE_MAC_B_CCH_AC1_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_B_CCH_AC1_FRAME_INFO_H_REG_OFFSET;
		}
		else if (access == AC2)
		{
			Frame_Content_Reg = WAVE_MAC_B_CCH_AC2_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_B_CCH_AC2_FRAME_INFO_H_REG_OFFSET;
		}
		else if (access == AC3)
		{
			Frame_Content_Reg = WAVE_MAC_B_CCH_AC3_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_B_CCH_AC3_FRAME_INFO_H_REG_OFFSET;
		}
		else if (access == AC4)
		{
			Frame_Content_Reg = WAVE_MAC_B_CCH_AC4_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_B_CCH_AC4_FRAME_INFO_H_REG_OFFSET;
		}
		else
			return(-1);
	}
	else if (ch_kind == SERVICE_CHANNEL)
	{
		if (access == AC1)
		{
			Frame_Content_Reg = WAVE_MAC_B_SCH_AC1_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_B_SCH_AC1_FRAME_INFO_H_REG_OFFSET;
		}
		else if (access == AC2)
		{
			Frame_Content_Reg = WAVE_MAC_B_SCH_AC2_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_B_SCH_AC2_FRAME_INFO_H_REG_OFFSET;
		}
		else if (access == AC3)
		{
			Frame_Content_Reg = WAVE_MAC_B_SCH_AC3_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_B_SCH_AC3_FRAME_INFO_H_REG_OFFSET;
		}
		else if (access == AC4)
		{
			Frame_Content_Reg = WAVE_MAC_B_SCH_AC4_FRAME_CONTENTS_H_REG_OFFSET;
			Frame_Info_Reg = WAVE_MAC_B_SCH_AC4_FRAME_INFO_H_REG_OFFSET;
		}
		else
			return(-1);
	}

	//printf("[Send_MPDU]Tx Queue is Unavailable, freelen = %d, tx_len = %d\n", free_len, len);
	

	send_buf -= mac_header_len;		/* SHKO : 주의 mac_heder_len 길이 만큼 뺀 값이 항상 4의 배수여야 한다. */
	Add_MAC_Header(send_buf, from_to_ds, frame_kind);

	total_len = len + mac_header_len;

	if ( total_len > WAVE_MAC_RX_QUEUE_SIZE )
	{
		printf("[Send_MPDU] Software Queue is Overflow : %d\n", total_len);
		return(-1);
	}

#if 0	//SHKO, Origin
	total_len_div_for = total_len/4;

	remain_len = total_len % 4;

	j = 0;
	for ( i = 0; i < total_len_div_for; i++ )
	{
		sbuf[i].b1[0] = send_buf[j++];
		sbuf[i].b1[1] = send_buf[j++];
		sbuf[i].b1[2] = send_buf[j++];
		sbuf[i].b1[3] = send_buf[j++];
	}

	if (remain_len)
	{
		for ( k = 0; k < remain_len; k++ )
		{
			sbuf[i].b1[k] = send_buf[j+k];
		}

		
		for ( k = remain_len; k < 4; k++ )
		{
			sbuf[i].b1[k] = 0;
		}
		i++;
	}

	write_len = i;
#else
	total_len_div_for = total_len/4;

	remain_len = total_len % 4;

	write_len = total_len_div_for;

	if (remain_len)
	{
		write_len++;	
	}
#endif

#if 0	//SHKO, Origin
	for ( i = 0; i < write_len; i++)
	{
	#if WAVE_RX_TX_BUF_UPDATE
		if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
     			printf("[%08X]",sbuf[i].b4);
		//write_wave_dsrc_reg32(Frame_Content_Reg, sbuf[i].b4);
     	#else
     		sdata = ENDIAN_SWAP32(sbuf[i].b4);
     		//if (print_flag)
		//	printf("[%08X]",sdata);
		write_wave_dsrc_reg32(Frame_Content_Reg, sdata);
     	#endif
     	}
     	if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
     		printf("\n");
#else
	send_buf_ptr = (U4 *)send_buf;
	for ( i = 0; i < write_len; i++)
	{
	#if WAVE_RX_TX_BUF_UPDATE
		if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
     			printf("[%08X]",send_buf_ptr[i]);
		write_wave_dsrc_reg32(Frame_Content_Reg, send_buf_ptr[i]);
     	#else
     		sdata = ENDIAN_SWAP32(send_buf_ptr[i]);
     		//if (print_flag)
		//	printf("[%08X]",sdata);
		write_wave_dsrc_reg32(Frame_Content_Reg, sdata);
     	#endif
     	}
     	if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
     		printf("\n");
#endif

#if 1	//SHKO, Origin
	if (etri_flag)
	{
		complete_time = 0xBB;
	}
	else
	{
		complete_time = 0x32;
	}
#else
	complete_time = Tx_Time_Calc((len + mac_header_len), 0, modulation);
#endif

#if 1	//SHKO, Origin
	rts_rate = 0;		/* SHKO, rts_rate의 값을 0이 아닌 다른 값을 사용하면 ping 메세지를 보낼 때 마다 CCH_AC1_RETX_LIMIT_OVERFLOW_INT!!인터럽트가 발생한다. */
#else
	if(memcmp(&send_buf[4], Broadcast_MAC_ADDR,ETH_MAC_ADDR_LEN)==0)
	{
		rts_rate = 0;
	}
	else
	{
		rts_rate = 0;
	}
#endif

	if (tx_add_len)
	{
		total_len += tx_add_len;
	}
	//total_len = 0x52;

	switch(modulation)
	{
		case 3:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_3M_BPSK << 12)
						| (total_len & 0xFFF);
			break;

		case 4:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_4_5M_BPSK << 12)
						| (total_len & 0xFFF);
			break;

		case 6:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_6M_QPSK << 12)
						| (total_len & 0xFFF);
			break;

		case 9:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_9M_QPSK << 12)
						| (total_len & 0xFFF);
			break;

		case 12:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_12M_16QAM << 12)
						| (total_len & 0xFFF);
			break;

		case 18:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_18M_16QAM << 12)
						| (total_len & 0xFFF);
			break;

		case 24:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_24M_64QAM << 12)
						| (total_len & 0xFFF);
			break;

		case 27:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_27M_64QAM << 12)
						| (total_len & 0xFFF);
			break;

		default:
			break;
		
	}

	cch_channel_access++;

	if (cch_channel_access > AC4)
		cch_channel_access = AC1;

	if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
     		printf("frame_info = [%08X]\n",frame_info);

     	
	write_wave_dsrc_reg32(Frame_Info_Reg, frame_info);

#if 0
	ret  = ioctl(dev, IOCTLWAVE_WAIT_TX);
	if (ret != 0)
	{
		perror("[Send_MPDU] ioctl:");
	}
	printf("[ether_rx_proc_thread]Not Resource\n");
#endif
	

	return(0);
}

#endif


int Store_Tx_Queue(int modem_id, int frame_kind, int ch_kind, int access, int len, int tx_power, int modulation, U1 from_to_ds, U1 *send_buf)
{
	U4 free_len;
	U4 write_len;
	U4 total_len;
	U4 total_len_div_for;
	int i=0;
	int j;
	int k;
	U4 frame_info;
	U4 complete_time;
	U4 rts_rate;
	U4 sdata;
	int mac_header_len = 0;
	int remain_len;
	int ret = 0;
	U4 *send_buf_ptr;
	U4 *send_buf_ptr_origin;
	IOCTLWAVE_INFO ctrl_info;
	U4 diff;
	
	
		
	if (frame_kind == DATA_FRAME)
	{
		if (from_to_ds == EXT_TO_DS_EXT_FROM_DS)
		{
			mac_header_len = 32;
		}
		else
		{
			mac_header_len = 26;
		}
	}
	else
	{
		mac_header_len = 24;
	}
	

	//printf("[Send_MPDU]Tx Queue is Unavailable, freelen = %d, tx_len = %d\n", free_len, len);
	
	/* 24 = modem_id(4) + write_len(4) + frame_kind(4) + ch_kind(4) + access_category(4) + frame_info(4) */
	send_buf -= (mac_header_len + 24);		/* SHKO : 주의 (mac_heder_len + 24) 길이 만큼 뺀 값이 항상 4의 배수여야 한다. */

	send_buf_ptr = (U4 *)send_buf;
	send_buf_ptr_origin = send_buf_ptr;

	total_len = len + mac_header_len;

	if ( total_len > WAVE_MAC_RX_QUEUE_SIZE )
	{
		printf("[Store_Tx_Queue] Software Queue is Overflow : %d\n", total_len);
		return(-1);
	}
	
	total_len_div_for = total_len/4;
	remain_len = total_len % 4;
	write_len = total_len_div_for;
	if (remain_len)
	{
		write_len++;	

	}

  #if 0	//SHKO, Origin
	if (etri_flag)
	{
		complete_time = 0xBB;
	}
	else
	{
		complete_time = 0x32;
	}
  #else
  	if (etri_flag)
  	{
		complete_time = Tx_Time_Calc((len + mac_header_len), 0, modulation);
		if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
			printf("[Store_Tx_Queue] complete_time=0x%02x\n", complete_time);
	}
	else
	{
		complete_time = 0x32;
	}
  #endif

  #if 1	//SHKO, Origin
	rts_rate = g_rts_rate;		/* SHKO, rts_rate의 값을 0이 아닌 다른 값을 사용하면,  ping 메세지를 보낼 때 마다 CCH_AC1_RETX_LIMIT_OVERFLOW_INT!!인터럽트가 발생한다. */
	complete_time = 0x32;
  #else
	if(memcmp(&send_buf[4], Broadcast_MAC_ADDR,ETH_MAC_ADDR_LEN) ==0)
	{
		rts_rate = 0;
	}
	else
	{
		rts_rate = 0;
	}
  #endif

	switch(modulation)
	{
		case 3:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_3M_BPSK << 12)
						| (total_len & 0xFFF);
			break;

		case 4:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_4_5M_BPSK << 12)
						| (total_len & 0xFFF);
			break;

		case 6:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_6M_QPSK << 12)
						| (total_len & 0xFFF);
			break;

		case 9:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_9M_QPSK << 12)
						| (total_len & 0xFFF);
			break;

		case 12:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_12M_16QAM << 12)
						| (total_len & 0xFFF);
			break;

		case 18:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_18M_16QAM << 12)
						| (total_len & 0xFFF);
			break;

		case 24:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_24M_64QAM << 12)
						| (total_len & 0xFFF);
			break;

		case 27:
			frame_info = (complete_time << 22) | (rts_rate << 20) | ((U4)tx_power << 16) | ((U4)DATA_RATE_27M_64QAM << 12)
						| (total_len & 0xFFF);
			break;

		default:
			break;
		
	}

	if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
     		printf("write_len = [%08X]\n",write_len);

     	if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
     		printf("frame_kind = [%08X]\n",frame_kind);

     	if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
     		printf("ch_kind = [%08X]\n",ch_kind);

     	if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
     		printf("access = [%08X]\n",access);

	if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
     		printf("frame_info = [%08X]\n",frame_info);


	*send_buf_ptr++ = modem_id;
	*send_buf_ptr++ = write_len;
	*send_buf_ptr++ = frame_kind;
	*send_buf_ptr++ = ch_kind;
	*send_buf_ptr++ = access;
	*send_buf_ptr++ = frame_info;

	send_buf = (U1 *)send_buf_ptr;
	
	
	Add_MAC_Header(send_buf, from_to_ds, frame_kind);

#if 1
	for ( i = 0; i < write_len; i++)
	{
	  #if WAVE_RX_TX_BUF_UPDATE

		if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
   			printf("[%08X]",send_buf_ptr[i]);
     	  #else
		sdata = ENDIAN_SWAP32(send_buf_ptr[i]);
    
 		//if (print_flag)
		//	printf("[%08X]",sdata);
	  #endif
   	}
  	if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
  		printf("\n");
 #endif


	if (tx_add_len)
	{
		total_len += tx_add_len;
	}
	//total_len = 0x52;

	if ( ioctl(dev, IOCTLWAVE_READ, &ctrl_info) == 0 )
	{
		if ( ctrl_info.wave_tx_queue_write_index > ctrl_info.wave_tx_queue_read_index )
		{
			diff = ctrl_info.wave_tx_queue_write_index - ctrl_info.wave_tx_queue_read_index;
		}
		else if ( ctrl_info.wave_tx_queue_write_index < ctrl_info.wave_tx_queue_read_index )
		{
			/* 255 = Kernel Driver Tx Queue Size - 1 */
			diff = (255 - ctrl_info.wave_tx_queue_read_index) + ctrl_info.wave_tx_queue_write_index;
		}
		else
		{
			diff = 0;
		}
		
	}
	else
	{
		perror("[Store_Tx_Queue]ioctl read:");
	}

	/* 24 = modem_id(4) + write_len(4) + frame_kind(4) + ch_kind(4) + access_category(4) + frame_info(4) */
#if 0	/* SHKO, Origin */
	if ( diff < tx_queue_pause_threshold )
	{
		ret = write(dev, send_buf_ptr_origin, (total_len + 24));	
		if (ret < 0)
		{
			if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
	   			printf("[Store_Tx_Queue] Send Fail!!= %d",ret);

	   		//printf("[Store_Tx_Queue] Send Fail : ret = %d\n", ret);
		}
	}
	else
	{
		printf("[Store_Tx_Queue] Tx Pause : windex=%d, rindex=%d\n", ctrl_info.wave_tx_queue_write_index, ctrl_info.wave_tx_queue_read_index);
	}
#else
	if ( (diff < tx_queue_pause_threshold) || (ctrl_info.wave_tx_queue_read_index == ctrl_info.wave_tx_write_success_index))
	{
		ret = write(dev, send_buf_ptr_origin, (total_len + 24));	
		if (ret < 0)
		{
			if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
	   			printf("[Store_Tx_Queue] Send Fail!!= %d",ret);

	   		//printf("[Store_Tx_Queue] Send Fail : ret = %d\n", ret);
		}
	}
	else
	{
		printf("[Store_Tx_Queue] Tx Pause : windex=%d, rindex=%d\n", ctrl_info.wave_tx_queue_write_index, ctrl_info.wave_tx_queue_read_index);
	}
#endif

	//stop_timer(0);
	if ( sr5500_rx_test_flag == 0 )
	{
		stop_timer(&wave_tx_timer_id);
	//start_timer(0);
	//if ( diff < 100 )
		start_timer(&wave_tx_timer_id, wave_tx_timer_handler, 1, 0);
	//else
	//	start_timer(&wave_tx_timer_id, 2, 0);
	}
		
	

	return(0);

	

}


int make_send_data_for_test (int length, int mac_header_len, U1 *send_buf, int modulation, int total_count, int current_count)
{
	int i;
	int j;
	U1 data_rate;
	U2 wsmp_header_len = 0;
	U1 start_end_flag;		/* 1이면 start, 0이면 End */
	int ap_len;

	ap_len = length;
	
	i = mac_header_len;						/* MAC Header를 위해 남겨 놓음. 26 = dataframe의 MAC 헤더의 길이 */
		
	send_buf[i++] = 0xAA;
	send_buf[i++] = 0xAA;
	send_buf[i++] = 0x03;
	send_buf[i++] = 0x00;
	send_buf[i++] = 0x00;
	send_buf[i++] = 0x00;
	send_buf[i++] = 0x88;
	send_buf[i++] = 0xdc;
	send_buf[i++] = WSMP_VERSION;	/* version */

	for ( j = 0; j < psid_len; j++)
	{
		send_buf[i++] = psid.b1[(psid_len-1-j)];		/* 1609.3 8.1.3 참조, ARADA 단말기가 0x20임.  */
	}

	send_buf[i++] = EXT_WAVE_TRANSMIT_POWER_USED_EID;
	send_buf[i++] = 1;		/* Tx Power Length */
	send_buf[i++] = 0x07;

	send_buf[i++] = EXT_WAVE_DATARATE_EID;
	send_buf[i++] = 1;		/* Data Rate Length */

	/* SHKO : IEEE 802.11 규격의 10.4.4.2를 참조하면 된다. */
	switch(modulation)
	{
		case 3:
			data_rate = 6;
			break;

		case 4:		/* 4.5Mbps */
			data_rate = 9;
			break;
				
		case 6:
			data_rate = 12;
			break;

		case 9:
			data_rate = 18;
			break;
				
		case 12:
			data_rate = 24;
			break;

		case 18:
			data_rate = 36;
			break;
				
		case 24:
			data_rate = 48;
			break;
				
		case 27:
			data_rate = 54;
			break;
				
		default:
			data_rate = 6;
			break;
				
	}
	send_buf[i++] = data_rate;

	send_buf[i++] = EXT_WAVE_CHANNEL_NUM_EID;
	send_buf[i++] = 1;		/* Channel Number Length */
	send_buf[i++] = 0xac;
		
	send_buf[i++] = WAVE_EID_WSM;/* WSMP WAVE element ID */

	wsmp_header_len = i + 2;		/* 2 = Length Field 길이 */

	send_buf[i++] = (length >> 8) & 0xFF;
	send_buf[i++] = length & 0xFF;

	length += wsmp_header_len;


	/* USER Defined Protocol */
	send_buf[i++] = SR5500_TEST_FRAME_ID;

	if ((total_count  - 1) == current_count )
	{
		start_end_flag = 0;
	}
	else
	{
		start_end_flag = 1;
	}
	
	send_buf[i++] = start_end_flag;
	
	send_buf[i++] = (total_count >> 8) & 0xFF;
	send_buf[i++] = total_count & 0xFF;

	send_buf[i++] = (current_count >> 8) & 0xFF;
	send_buf[i++] = current_count & 0xFF;

	send_buf[i++] = (ap_len >> 8) & 0xFF;
	send_buf[i++] = ap_len & 0xFF;

	send_buf[i++] = (U1) modulation;
	

	for ( ; i < length; i++)
	{
		send_buf[i] = 0x55;
	}
	return(i);
}

int Send_WAVE_Data_for_Test(U1 *send_buf, int modulation, int ap_len, int tx_power, int mac_header_len, int count)
{
	int i;
	int total_len;
	int interval = 2000;
	
	
	/* SHKO : IEEE 802.11 규격의 10.4.4.2를 참조하면 된다. */
	switch(modulation)
	{
		case 3:
			interval = 2000;
			break;

		case 4:		/* 4.5Mbps */
			interval = 2000;
			break;
				
		case 6:
			interval = 2000;
			break;

		case 9:
			interval = 1500;
			break;
				
		case 12:
			interval = 1500;
			break;

		case 18:
			interval = 1000;
			break;
				
		case 24:
			interval = 1000;
			break;
				
		case 27:
			interval = 1000;
			break;
				
		default:
			interval = 2000;
			break;
				
	}
	
	for ( i = 0; i < count; i++)
	{
		total_len = make_send_data_for_test (ap_len, mac_header_len, send_buf, modulation, count, i);
		
		/* 26 = MAC Header를 위해 남겨 놓음. */
		Send_MPDU(DATA_FRAME, CONTROL_CHANNEL, AC4, (total_len - mac_header_len), tx_power, modulation, IBSS_TO_DS_FROM_DS, &send_buf[mac_header_len]);
		
		time_delay(interval);
		
	}

	return(0);
}

int clear_wave_counter(void)
{
	U4 u4;
	U2 u2;
	
	u2 = reg_readw(WAVE_CONTROL_L_REG_OFFSET);
	u2 |= MAC_A_COUNTER_CLEAR_BIT;
	reg_writew(WAVE_CONTROL_L_REG_OFFSET, u2);

	u4 = read_wave_dsrc_reg32(WAVE_MODEM_A_ETC_REG_OFFSET);
	//printf("read u4=0x%08x\n", u4);
	u4 |= PHY_COUNTER_CLEAR_BIT;
	//printf("write u4=0x%08x\n", u4);
	write_wave_dsrc_reg32(WAVE_MODEM_A_ETC_REG_OFFSET, u4);

	printf("[clear_wave_counter]\n");

	mac_rx_count = 0;
	wave_mac_rx_retry_count = 0;
	wave_mac_rx_duplication_count = 0;
	wave_mac_rx_no_retry_duplication_count = 0;
}


int update_sr5500_test_data(U2 ap_len, U1 modulation, U2 total_count, int flag)
{
	/* SHKO : IEEE 802.11 규격의 10.4.4.2를 참조하면 된다. */
	switch(modulation)
	{
		case 3:
			if (ap_len == 100)
			{
				sr5500_test_info[0][0].tx_total_cnt = total_count;
				sr5500_test_info[0][0].wsmp_rx_cnt++; 
				//printf("[update_sr5500_test_data] sr5500_test_info[0][0].wsmp_rx_cnt=%d, mac_rx_count=%d\n", sr5500_test_info[0][0].wsmp_rx_cnt, mac_rx_count);
				if (flag)
				{
					sr5500_test_info[0][0].sw_mac_rx_cnt = mac_rx_count;
					printf("[update_sr5500_test_data] mac_rx_count=%d\n", mac_rx_count);
					sr5500_test_info[0][0].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[0][0].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[0][0].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else if (ap_len == 200)
			{
				sr5500_test_info[0][1].tx_total_cnt = total_count;
				sr5500_test_info[0][1].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[0][1].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[0][1].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[0][1].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[0][1].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else if (ap_len == 400)
			{
				sr5500_test_info[0][2].tx_total_cnt = total_count;
				sr5500_test_info[0][2].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[0][2].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[0][2].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[0][2].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[0][2].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else if (ap_len == 800)
			{
				sr5500_test_info[0][3].tx_total_cnt = total_count;
				sr5500_test_info[0][3].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[0][3].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[0][3].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[0][3].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[0][3].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else
			{
				sr5500_test_info[0][4].tx_total_cnt = total_count;
				sr5500_test_info[0][4].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[0][4].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[0][4].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[0][4].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[0][4].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			break;

		case 4:		/* 4.5Mbps */
			if (ap_len == 100)
			{
				sr5500_test_info[1][0].tx_total_cnt = total_count;
				sr5500_test_info[1][0].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[1][0].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[1][0].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[1][0].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[1][0].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else if (ap_len == 200)
			{
				sr5500_test_info[1][1].tx_total_cnt = total_count;
				sr5500_test_info[1][1].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[1][1].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[1][1].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[1][1].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[1][1].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else if (ap_len == 400)
			{
				sr5500_test_info[1][2].tx_total_cnt = total_count;
				sr5500_test_info[1][2].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[1][2].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[1][2].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[1][2].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[1][2].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else if (ap_len == 800)
			{
				sr5500_test_info[1][3].tx_total_cnt = total_count;
				sr5500_test_info[1][3].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[1][3].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[1][3].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[1][3].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[1][3].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else
			{
				sr5500_test_info[1][4].tx_total_cnt = total_count;
				sr5500_test_info[1][4].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[1][4].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[1][4].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[1][4].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[1][4].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			break;
				
		case 6:
			if (ap_len == 100)
			{
				sr5500_test_info[2][0].tx_total_cnt = total_count;
				sr5500_test_info[2][0].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[2][0].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[2][0].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[2][0].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[2][0].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else if (ap_len == 200)
			{
				sr5500_test_info[2][1].tx_total_cnt = total_count;
				sr5500_test_info[2][1].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[2][1].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[2][1].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[2][1].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[2][1].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else if (ap_len == 400)
			{
				sr5500_test_info[2][2].tx_total_cnt = total_count;
				sr5500_test_info[2][2].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[2][2].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[2][2].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[2][2].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[2][2].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else if (ap_len == 800)
			{
				sr5500_test_info[2][3].tx_total_cnt = total_count;
				sr5500_test_info[2][3].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[2][3].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[2][3].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[2][3].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[2][3].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else
			{
				sr5500_test_info[2][4].tx_total_cnt = total_count;
				sr5500_test_info[2][4].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[2][4].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[2][4].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[2][4].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[2][4].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			break;

		case 9:
			if (ap_len == 100)
			{
				sr5500_test_info[3][0].tx_total_cnt = total_count;
				sr5500_test_info[3][0].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[3][0].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[3][0].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[3][0].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[3][0].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else if (ap_len == 200)
			{
				sr5500_test_info[3][1].tx_total_cnt = total_count;
				sr5500_test_info[3][1].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[3][1].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[3][1].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[3][1].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[3][1].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else if (ap_len == 400)
			{
				sr5500_test_info[3][2].tx_total_cnt = total_count;
				sr5500_test_info[3][2].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[3][2].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[3][2].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[3][2].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[3][2].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else if (ap_len == 800)
			{
				sr5500_test_info[3][3].tx_total_cnt = total_count;
				sr5500_test_info[3][3].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[3][3].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[3][3].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[3][3].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[3][3].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else
			{
				sr5500_test_info[3][4].tx_total_cnt = total_count;
				sr5500_test_info[3][4].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[3][4].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[3][4].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[3][4].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[3][4].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			break;
				
		case 12:
			if (ap_len == 100)
			{
				sr5500_test_info[4][0].tx_total_cnt = total_count;
				sr5500_test_info[4][0].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[4][0].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[4][0].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[4][0].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[4][0].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else if (ap_len == 200)
			{
				sr5500_test_info[4][1].tx_total_cnt = total_count;
				sr5500_test_info[4][1].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[4][1].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[4][1].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[4][1].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[4][1].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else if (ap_len == 400)
			{
				sr5500_test_info[4][2].tx_total_cnt = total_count;
				sr5500_test_info[4][2].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[4][2].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[4][2].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[4][2].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[4][2].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else if (ap_len == 800)
			{
				sr5500_test_info[4][3].tx_total_cnt = total_count;
				sr5500_test_info[4][3].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[4][3].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[4][3].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[4][3].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[4][3].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else
			{
				sr5500_test_info[4][4].tx_total_cnt = total_count;
				sr5500_test_info[4][4].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[4][4].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[4][4].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[4][4].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[4][4].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			break;
				
		default:
			if (ap_len == 100)
			{
				sr5500_test_info[5][0].tx_total_cnt = total_count;
				sr5500_test_info[5][0].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[5][0].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[5][0].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[5][0].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[5][0].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else if (ap_len == 200)
			{
				sr5500_test_info[5][1].tx_total_cnt = total_count;
				sr5500_test_info[5][1].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[5][1].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[5][1].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[5][1].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[5][1].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else if (ap_len == 400)
			{
				sr5500_test_info[5][2].tx_total_cnt = total_count;
				sr5500_test_info[5][2].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[5][2].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[5][2].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[5][2].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[5][2].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else if (ap_len == 800)
			{
				sr5500_test_info[5][3].tx_total_cnt = total_count;
				sr5500_test_info[5][3].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[5][3].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[5][3].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[5][3].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[5][3].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			else
			{
				sr5500_test_info[5][4].tx_total_cnt = total_count;
				sr5500_test_info[5][4].wsmp_rx_cnt++; 
				if (flag)
				{
					sr5500_test_info[5][4].sw_mac_rx_cnt = mac_rx_count;
					sr5500_test_info[5][4].mac_rx_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET);
					sr5500_test_info[5][4].crc_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET);
					sr5500_test_info[5][4].physical_error_cnt = (int)read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET);
				}
			}
			break;
				
	}

	if (flag)
	{
		clear_wave_counter();
	}
}


int print_sr5500_test_data_rate_len(int i, int j)
{
	switch(i)
	{
		case 0:
			if ( j == 0 )
			{
				printf("===================================================================\n");
				printf("Display 3Mbps, Length 100Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 1)
			{
				printf("===================================================================\n");
				printf("Display 3Mbps, Length 200Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 2)
			{
				printf("===================================================================\n");
				printf("Display 3Mbps, Length 400Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 3)
			{
				printf("===================================================================\n");
				printf("Display 3Mbps, Length 800Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 4)
			{
				printf("===================================================================\n");
				printf("Display 3Mbps, Length 1000Byte\n");
				printf("===================================================================\n");
			}
			else
			{
				printf("[print_sr5500_test_data_rate_len] Invalid i=%d, j=%d\n", i, j);
			}
			break;
		case 1:
			if ( j == 0 )
			{
				printf("===================================================================\n");
				printf("Display 4.5Mbps, Length 100Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 1)
			{
				printf("===================================================================\n");
				printf("Display 4.5Mbps, Length 200Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 2)
			{
				printf("===================================================================\n");
				printf("Display 4.5Mbps, Length 400Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 3)
			{
				printf("===================================================================\n");
				printf("Display 4.5Mbps, Length 800Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 4)
			{
				printf("===================================================================\n");
				printf("Display 4.5Mbps, Length 1000Byte\n");
				printf("===================================================================\n");
			}
			else
			{
				printf("[print_sr5500_test_data_rate_len] Invalid i=%d, j=%d\n", i, j);
			}
			break;
		case 2:
			if ( j == 0 )
			{
				printf("===================================================================\n");
				printf("Display 6Mbps, Length 100Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 1)
			{
				printf("===================================================================\n");
				printf("Display 6Mbps, Length 200Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 2)
			{
				printf("===================================================================\n");
				printf("Display 6Mbps, Length 400Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 3)
			{
				printf("===================================================================\n");
				printf("Display 6Mbps, Length 800Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 4)
			{
				printf("===================================================================\n");
				printf("Display 6Mbps, Length 1000Byte\n");
				printf("===================================================================\n");
			}
			else
			{
				printf("[print_sr5500_test_data_rate_len] Invalid i=%d, j=%d\n", i, j);
			}
			break;
		case 3:
			if ( j == 0 )
			{
				printf("===================================================================\n");
				printf("Display 9Mbps, Length 100Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 1)
			{
				printf("===================================================================\n");
				printf("Display 9Mbps, Length 200Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 2)
			{
				printf("===================================================================\n");
				printf("Display 9Mbps, Length 400Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 3)
			{
				printf("===================================================================\n");
				printf("Display 9Mbps, Length 800Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 4)
			{
				printf("===================================================================\n");
				printf("Display 9Mbps, Length 1000Byte\n");
				printf("===================================================================\n");
			}
			else
			{
				printf("[print_sr5500_test_data_rate_len] Invalid i=%d, j=%d\n", i, j);
			}
			break;
		case 4:
			if ( j == 0 )
			{
				printf("===================================================================\n");
				printf("Display 12Mbps, Length 100Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 1)
			{
				printf("===================================================================\n");
				printf("Display 12Mbps, Length 200Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 2)
			{
				printf("===================================================================\n");
				printf("Display 12Mbps, Length 400Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 3)
			{
				printf("===================================================================\n");
				printf("Display 12Mbps, Length 800Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 4)
			{
				printf("===================================================================\n");
				printf("Display 12Mbps, Length 1000Byte\n");
				printf("===================================================================\n");
			}
			else
			{
				printf("[print_sr5500_test_data_rate_len] Invalid i=%d, j=%d\n", i, j);
			}
			break;
		case 5:
			if ( j == 0 )
			{
				printf("===================================================================\n");
				printf("Display 18Mbps, Length 100Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 1)
			{
				printf("===================================================================\n");
				printf("Display 18Mbps, Length 200Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 2)
			{
				printf("===================================================================\n");
				printf("Display 18Mbps, Length 400Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 3)
			{
				printf("===================================================================\n");
				printf("Display 18Mbps, Length 800Byte\n");
				printf("===================================================================\n");
			}
			else if ( j == 4)
			{
				printf("===================================================================\n");
				printf("Display 18Mbps, Length 1000Byte\n");
				printf("===================================================================\n");
			}
			else
			{
				printf("[print_sr5500_test_data_rate_len] Invalid i=%d, j=%d\n", i, j);
			}
			break;
		default:
			printf("[print_sr5500_test_data_rate_len] Invalid i=%d\n", i);
			break;
	}
	return(0);
}

int print_sr5500_test_result(void)
{
	int i, j;
	float rx_rate;

	for ( i = 0; i < 6; i++ )
	{
		for ( j = 0; j < 5; j++)
		{
			rx_rate = 0;
			print_sr5500_test_data_rate_len(i, j);
			printf("Total Tx Count = %d, MAC Rx Count = %d, SW_MAC_RX Count=%d, WSMP_RX Count=%d\n", 
			sr5500_test_info[i][j].tx_total_cnt, sr5500_test_info[i][j].mac_rx_cnt, 
			sr5500_test_info[i][j].sw_mac_rx_cnt, sr5500_test_info[i][j].wsmp_rx_cnt);

			if (sr5500_test_info[i][j].tx_total_cnt)
				rx_rate = ((float)sr5500_test_info[i][j].mac_rx_cnt * 100) / (float)sr5500_test_info[i][j].tx_total_cnt;
			printf("MAC Rx Rate = %f%%, \n", rx_rate);

			rx_rate = 0;
			if (sr5500_test_info[i][j].tx_total_cnt)
				rx_rate = ((float)sr5500_test_info[i][j].sw_mac_rx_cnt * 100)/ (float)sr5500_test_info[i][j].tx_total_cnt;
			printf("SW_MAC Rx Rate = %f%%, \n", rx_rate);

			rx_rate = 0;
			if (sr5500_test_info[i][j].tx_total_cnt)
				rx_rate = ((float)sr5500_test_info[i][j].wsmp_rx_cnt * 100) / (float)sr5500_test_info[i][j].tx_total_cnt;
			printf("WSMP Rx Rate = %f%%, \n", rx_rate);

			printf("Total Tx Count = %d, CRC Error Count = %d, Physical Error Count=%d\n", 
					sr5500_test_info[i][j].tx_total_cnt, sr5500_test_info[i][j].crc_error_cnt, 
					sr5500_test_info[i][j].physical_error_cnt);

			rx_rate = 0;
			if (sr5500_test_info[i][j].tx_total_cnt)
				rx_rate = ((float)sr5500_test_info[i][j].crc_error_cnt * 100) / (float)sr5500_test_info[i][j].tx_total_cnt;
			printf("CRC Error Rate = %f%%, \n", rx_rate);

			rx_rate = 0;
			if (sr5500_test_info[i][j].tx_total_cnt)
				rx_rate = ( (float)sr5500_test_info[i][j].physical_error_cnt * 100)/ (float)sr5500_test_info[i][j].tx_total_cnt;
			printf("Physical Error Rate = %f%%, \n", rx_rate);

			printf("\n");
		}
	}
}

int clear_sr5500_test_data(void)
{
	int i, j;


	for ( i = 0; i < 6; i++ )
	{
		for ( j = 0; j < 5; j++)
		{
			sr5500_test_info[i][j].tx_total_cnt = 0;
			sr5500_test_info[i][j].mac_rx_cnt = 0;
			sr5500_test_info[i][j].sw_mac_rx_cnt = 0;
			sr5500_test_info[i][j].wsmp_rx_cnt = 0;
			sr5500_test_info[i][j].crc_error_cnt = 0;
			sr5500_test_info[i][j].physical_error_cnt = 0;
		}
	}

}


/* 첫번째 인자 rx_wsmp_buf는 mac_header를 제외한 LLC, SNAP 헤더의 시작을 가리킨다. */
int proc_wsmp_data(U1 *rx_wsmp_buf)
{
	int i;
	U1 start_end_flag;
	U2 total_count;
	U2 current_count;
	U2 ap_len;
	U1 modulation;
	U2_T data;
	U1 end_flag = 0;

	i = 22;
	if (rx_wsmp_buf[i++] == SR5500_TEST_FRAME_ID)
	{
		start_end_flag = rx_wsmp_buf[i++];

		data.b1[1] = rx_wsmp_buf[i++];
		data.b1[0] = rx_wsmp_buf[i++];
		total_count = data.b2;

		data.b1[1] = rx_wsmp_buf[i++];
		data.b1[0] = rx_wsmp_buf[i++];
		current_count = data.b2;

		data.b1[1] = rx_wsmp_buf[i++];
		data.b1[0] = rx_wsmp_buf[i++];
		ap_len = data.b2;

		modulation = rx_wsmp_buf[i++];

#if 0
		if ((sr5500_prev_ap_len == 100) && (sr5500_prev_modulation == 3))
		{
			printf("[proc_wsmp_data]1. ap_len=%d, modulation=%d, start_end_flag=%d\n", ap_len, modulation, start_end_flag);
		}
		else if ((ap_len == 100) && (modulation == 3))
		{
			printf("[proc_wsmp_data]2. ap_len=%d, modulation=%d, start_end_flag=%d\n", sr5500_prev_ap_len, sr5500_prev_modulation, start_end_flag);
		}
#endif


		if ( (sr5500_prev_ap_len != ap_len) ||  ( sr5500_prev_modulation != modulation ))
		{
			if (start_end_flag)
			{
				update_sr5500_test_data(ap_len, modulation, total_count, 0);
			}
			else
			{
				printf("[proc_wsmp_data]1. ap_len=%d, modulation=%d, start_end_flag=%d\n", ap_len, modulation, start_end_flag);
				printf("[proc_wsmp_data]2. ap_len=%d, modulation=%d, start_end_flag=%d\n", sr5500_prev_ap_len, sr5500_prev_modulation, start_end_flag);
				update_sr5500_test_data(sr5500_prev_ap_len, sr5500_prev_modulation, sr5500_prev_total_cnt, 1);
				update_sr5500_test_data(ap_len, modulation, total_count, 0);
			}
		}
		else
		{
			if (start_end_flag)
			{
				update_sr5500_test_data(ap_len, modulation, total_count, 0);
			}
			else
			{
				update_sr5500_test_data(ap_len, modulation, total_count, 1);
				end_flag = 1;
			}
		}
		
		sr5500_prev_ap_len = ap_len;
		sr5500_prev_modulation = modulation;
		sr5500_prev_total_cnt = total_count;
		sr5500_prev_start_flag = start_end_flag;
		

		if ((modulation == 18) && (ap_len == 1000) && (end_flag == 1))
		{
			printf("[proc_wsmp_data] Normal SR5500 Rx Test End\n");
			sr5500_rx_test_end_flag = 1;
			print_sr5500_test_result();
		}
		else
		{
			sr5500_prev_mac_rx_cnt = total_wave_mac_rx_count;
			start_timer(&SR5500_TEST_RX_TIMER_ID, sr5500_rx_test_timer_handler, 5, 0);

		}
	}
}

int wave_mac_rx_proc(U1 *rx_buf, U4 rx_len)
{
	int i = 0;
	int j = 0;
	U1 frame_type;
	U1 frame_subtype;
	U1 wave_mac_version;
	U1 from_ds_to_ds;
	U2_T ether_type;
	U1 *tx_buf;
	U4 tx_len;
	int mac_table_index;
	U1 mac_addr1[ETH_MAC_ADDR_LEN];
	U1 mac_addr3[ETH_MAC_ADDR_LEN];
	U2 fragment;
	U2 seq_num;
	U2_T seq_ctrl;
	U1 retry_bit;
	U1 *rx_llc_snap_header_start_buf;
	U4_T iperf_seq_num;
	U2_T wsmp_len;

#if 0
	printf("[wave_mac_rx_proc]rx_len=%d\n", rx_len);
	print_dump_data(rx_buf, rx_len, "[wave_mac_rx_proc] Recv Data");
#endif
	iperf_seq_num.b4 = 0;

	i = 0;
	wave_mac_version = rx_buf[i] & 0x03;
	frame_type = (rx_buf[i] >> 2) & 0x03;
	frame_subtype = (rx_buf[i++] >> 4) & 0x0F;

	from_ds_to_ds = rx_buf[i] & 0x03;
	retry_bit = (rx_buf[i] & WAVE_MAC_RETRY_BIT) >> 3;

	
	if ( wave_mac_version !=WAVE_MAC_PROTOCOL_VER )
	{
		printf("[wave_mac_rx_proc] Invalid WAVE MAC Version = 0x%02x\n", wave_mac_version);
		return(-1);
	}

	//printf("[wave_mac_rx_proc]frame_type=0x%02x\n", frame_type);
	
	switch(frame_type)
	{
		case WAVE_MAC_MGMT_FRAME_TYPE:
			if( print_flag & WAVE_MAC_RX_MANAGE_DEBUG_MODE )
     				print_dump_data(rx_buf, rx_len, "[wave_mac_rx_proc] Recv Manage Frame");
			//printf("[wave_mac_rx_proc] Management Frame,  from_ds_to_ds= 0x%02x\n", from_ds_to_ds);
			i = 24;		/* WAVE MAC Management Frame의 길이는 24바이트 */
			break;

		case WAVE_MAC_CTRL_FRAME_TYPE:
			printf("[wave_mac_rx_proc] Invalid WAVE MAC Frame Type = 0x%02x\n", frame_type);
			return(-1);
			//break;

		case WAVE_MAC_DATA_FRAME_TYPE:

     			if( print_flag & WAVE_MAC_RX_DEBUG_MODE )
     				print_dump_data(rx_buf, rx_len, "[wave_mac_rx_proc] Recv Data Frame");

     			memcpy(mac_addr1, &rx_buf[4], 6);
     			memcpy(mac_addr3, &rx_buf[16], 6);

			if (from_ds_to_ds == EXT_TO_DS_EXT_FROM_DS)
			{
				i = 32;
			}
			else
			{
				i = 26;
			}
			
			break;

		default:
			printf("[wave_mac_rx_proc] Invalid WAVE MAC Frame Type = 0x%02x\n", frame_type);
			return(-1);
	}

	seq_ctrl.b1[0] = rx_buf[WAVE_MAC_SEQ_CTRL_OFFSET];
	seq_ctrl.b1[1] = rx_buf[(WAVE_MAC_SEQ_CTRL_OFFSET+1)];

	fragment = seq_ctrl.b2 & 0x000F;
	seq_num = (seq_ctrl.b2 >> 4) & 0x0FFF;

	//if( (frame_type == WAVE_MAC_DATA_FRAME_TYPE) && g_display_mac_rx_seq_num_flag )
	//	printf("[wave_mac_rx_proc] seq_num = %d\n", seq_num);
		//printf("[wave_mac_rx_proc] retry_bit = %d, fragment = %d, seq_num = %d\n", retry_bit, fragment, seq_num);

	/* MAC Source Address 저장 */
	mac_table_index = find_wave_rx_dest_mac_table_with_mac_addr(&rx_buf[10]);
	if (mac_table_index < 0)
	{
		if (add_mac_addr_to_wave_rx_dest_mac_table(&rx_buf[10], fragment, seq_num) < 0)
		{
			printf("[wave_mac_rx_proc] Add MAC Src Addr to MAC Table Fail !!\n");	
		}
	}
	else
	{
		/* Duplication Message 처리 루틴 */
		if (retry_bit)
		{
			wave_mac_rx_retry_count++;
			if ( (wave_rx_dest_mac_table[mac_table_index].fragment == fragment) && (wave_rx_dest_mac_table[mac_table_index].seq_num== seq_num) )
			{
				wave_mac_rx_duplication_count++;
				//printf("[wave_mac_rx_proc] Discard Duplication Message !!\n");
				return(-1);
			}
			else
			{
				wave_rx_dest_mac_table[mac_table_index].fragment = fragment;
				wave_rx_dest_mac_table[mac_table_index].seq_num = seq_num;
				
			}
		}
		else
		{
			if ( (wave_rx_dest_mac_table[mac_table_index].fragment == fragment) && (wave_rx_dest_mac_table[mac_table_index].seq_num== seq_num) )
			{
				wave_mac_rx_no_retry_duplication_count++;
				printf("[wave_mac_rx_proc] No Retry Discard Duplication Message !!\n");
				return(-1);
			}
			else
			{
				wave_rx_dest_mac_table[mac_table_index].fragment = fragment;
				wave_rx_dest_mac_table[mac_table_index].seq_num = seq_num;
				
			}
		}
	}

	rx_llc_snap_header_start_buf = &rx_buf[i];

	if (frame_type == WAVE_MAC_DATA_FRAME_TYPE)
	{
		if ((rx_buf[i] != 0xAA) || (rx_buf[(i+1)] != 0xAA) || (rx_buf[(i+2)] != 0x03))
		{
			//printf("[wave_mac_rx_proc] Invalid LLC Header = 0x%02x:0x%02x:0x%02x\n", rx_buf[i], rx_buf[(i+1)], rx_buf[(i+2)]);
			return(-1);
		}

		if ((rx_buf[(i+3)] != 0x00) || (rx_buf[(i+4)] != 0x00) || (rx_buf[(i+5)] != 0x00))
		{
			printf("[wave_mac_rx_proc] Protocol ID = 0x%02x:0x%02x:0x%02x\n", rx_buf[(i+3)], rx_buf[(i+4)], rx_buf[(i+5)]);
			return(-1);
		}

		
		ether_type.b1[1] = rx_buf[(i+6)];
		ether_type.b1[0] = rx_buf[(i+7)];

		i += 8;			/* 8 = LLC 헤더 + SNAP 헤더 */

		tx_buf = &rx_buf[i];
		tx_len = rx_len - i + 14;	/* 14 = 이더넷 헤더 */

		tx_buf -= 14;

		if (from_ds_to_ds == IBSS_TO_DS_FROM_DS)
		{
			memcpy(tx_buf, wave_mac_src_addr, 6);		/* wave_mac_src_addr : 이 WAVE 단말기에 연결된 PC의 Ethernet MAC 주소 */
			memcpy(&tx_buf[6], my_eth0_mac_addr, 6);		/* my_eth0_mac_addr : 이 WAVE 단말기의 Ethernet MAC 주소 */
		}
		else if (from_ds_to_ds == TO_DS_EXT_FROM_DS)		/* FromDS=1, ToDS=0 */
		{
			memcpy(tx_buf, mac_addr1, 6);					/* mac_addr1 : 이 WAVE 단말기의 무선 WAVE MAC 주소 */
			memcpy(&tx_buf[6], mac_addr3, 6);				/* mac_addr3 : 송신측 WAVE 단말기에 연결된 PC의 Ethernet MAC 주소 */

			//if (auto_dest_mac_flag)
			//	memcpy(WSA_DEST_MAC_ADDR, mac_addr3, 6);/* WSA를 송신한 기지국과 연결된 PC MAC 주소 */
		}

		tx_buf[12] = ether_type.b1[1];
		tx_buf[13] = ether_type.b1[0];

		
		switch(from_ds_to_ds)
		{
			case IBSS_TO_DS_FROM_DS:
				if (ether_type.b2 != ETHER_TYPE_WSMP)
				{
				#if 0
					iperf_seq_num.b1[3] = rx_buf[62];
					iperf_seq_num.b1[2] = rx_buf[63];
					iperf_seq_num.b1[1] = rx_buf[64];
					iperf_seq_num.b1[0] = rx_buf[65];

					if ((iperf_seq_num.b4 == g_prev_iperf_seq_num) && (g_prev_iperf_seq_num != 0))
					{
						if( g_display_mac_rx_seq_num_flag )
						{
							printf("[wave_mac_rx_proc] retry = %d\n", retry_bit);
							printf("[wave_mac_rx_proc] IBSS prev_seq = %d, cur_seq = %d\n", g_prev_iperf_seq_num, iperf_seq_num.b4);
						}
						//return(-1);
					}
					g_prev_iperf_seq_num = iperf_seq_num.b4;
					
					//if( g_display_mac_rx_seq_num_flag )
					//	printf("[wave_mac_rx_proc] IBSS iperf_seq_num = %d\n", iperf_seq_num.b4);
				#endif
					send_ethernet_raw_data(tx_buf, tx_len);
				}
				else
				{
					if (sr5500_rx_test_flag)
						proc_wsmp_data(rx_llc_snap_header_start_buf);


					if (rx_buf[i] == WAVE_SECURITY_VERSION)
					{
						i++;
						if (rx_buf[i] == MSG_TYPE_SIGNED)
						{
							i++;
							if (rx_buf[i] == WAVE_EID_WSM)
							{
								i++;
								wsmp_len.b1[1] = rx_buf[i++];
								wsmp_len.b1[0] = rx_buf[i++];

								if ( g_ecdsa_sw_proc_flag == 0 )
								{
									Verify_Signed_Message(&rx_buf[i], wsmp_len.b2);
								}
								else
								{
									SW_Verify_Signed_Message(&rx_buf[i], wsmp_len.b2);
								}
							}
							
						}
						else if (rx_buf[i] == MSG_TYPE_ENCRYPTED)
						{
							i++;
							if (rx_buf[i] == WAVE_EID_WSM)
							{
								i++;
								wsmp_len.b1[1] = rx_buf[i++];
								wsmp_len.b1[0] = rx_buf[i++];
								Decode_Encrypted_Message(&rx_buf[i], wsmp_len.b2);
							}
							
						}
					}
				}
				break;

			case EXT_TO_DS_FROM_DS:
				if (ether_type.b2 != ETHER_TYPE_WSMP)
				{
				#if 1
					iperf_seq_num.b1[3] = rx_buf[62];
					iperf_seq_num.b1[2] = rx_buf[63];
					iperf_seq_num.b1[1] = rx_buf[64];
					iperf_seq_num.b1[0] = rx_buf[65];

					if ((iperf_seq_num.b4 == g_prev_iperf_seq_num) && (g_prev_iperf_seq_num != 0))
					{
						if( g_display_mac_rx_seq_num_flag )
							printf("[wave_mac_rx_proc] ToDS prev_seq = %d, cur_seq = %d\n", g_prev_iperf_seq_num, iperf_seq_num.b4);
						//return(-1);
					}
					g_prev_iperf_seq_num = iperf_seq_num.b4;
					
					//if( g_display_mac_rx_seq_num_flag )
					//	printf("[wave_mac_rx_proc] ToDS iperf_seq_num = %d\n", iperf_seq_num.b4);
				#endif
					send_ethernet_raw_data(tx_buf, tx_len);
				}
				break;

			case TO_DS_EXT_FROM_DS:
				if (ether_type.b2 != ETHER_TYPE_WSMP)
				{
				#if 1
					iperf_seq_num.b1[3] = rx_buf[62];
					iperf_seq_num.b1[2] = rx_buf[63];
					iperf_seq_num.b1[1] = rx_buf[64];
					iperf_seq_num.b1[0] = rx_buf[65];

					if ((iperf_seq_num.b4 == g_prev_iperf_seq_num) && (g_prev_iperf_seq_num != 0))
					{
						if( g_display_mac_rx_seq_num_flag )
							printf("[wave_mac_rx_proc] FromDS prev_seq = %d, cur_seq = %d\n", g_prev_iperf_seq_num, iperf_seq_num.b4);
						//return(-1);
					}
					g_prev_iperf_seq_num = iperf_seq_num.b4;

					
					//if( g_display_mac_rx_seq_num_flag )
					//	printf("[wave_mac_rx_proc] FromDS iperf_seq_num = %d\n", iperf_seq_num.b4);
				#endif
					send_ethernet_raw_data(tx_buf, tx_len);
				}
				break;

			case EXT_TO_DS_EXT_FROM_DS:
				printf("[wave_mac_rx_proc] Invalid WAVE MAC EXT_TO_DS_EXT_FROM_DS = 0x%02x\n", from_ds_to_ds);
				break;

			default:
				printf("[wave_mac_rx_proc] Invalid WAVE MAC from_ds_to_ds = 0x%02x\n", from_ds_to_ds);
				return(-1);
		}
	}
	else if (frame_type == WAVE_MAC_MGMT_FRAME_TYPE)
	{
		proc_wave_mac_management_frame(rx_buf, rx_len);
	}
	
}


void *wave_mac_thread(void *data)   
{   
 	int n;
	int i;
	volatile unsigned int status;
	volatile unsigned int len;
	volatile unsigned int rx_info;
	U4_T rssi;
	U4_T data_rate;
	U1 *org_data_ptr;
 	
 	printf("[wave_mac_thread] Start\n");

 	while( 1 )
	{  
     		if (wave_mac_rx_queue_write_index != wave_mac_rx_queue_read_index)
     		{   
     			//pthread_mutex_lock(&ether_rx_mutex);
     			org_data_ptr = wave_mac_rx_queue[wave_mac_rx_queue_read_index].data_ptr;
     			//if( print_flag & WAVE_MAC_RX_DEBUG_MODE == WAVE_MAC_RX_DEBUG_MODE)
     			//	printf("[wave_rcv_thread]1\n");
			mac_rx_count++;

			if (sr5500_rx_test_flag)
				total_wave_mac_rx_count++;

        		rssi.b1[3] = wave_mac_rx_queue[wave_mac_rx_queue_read_index].data_ptr[0];
        		rssi.b1[2] = wave_mac_rx_queue[wave_mac_rx_queue_read_index].data_ptr[1];
        		rssi.b1[1] = wave_mac_rx_queue[wave_mac_rx_queue_read_index].data_ptr[2];
        		rssi.b1[0] = wave_mac_rx_queue[wave_mac_rx_queue_read_index].data_ptr[3];

        		wave_mac_rx_queue[wave_mac_rx_queue_read_index].rssi = rssi.b4;

        		data_rate.b1[3] = wave_mac_rx_queue[wave_mac_rx_queue_read_index].data_ptr[4];
        		data_rate.b1[2] = wave_mac_rx_queue[wave_mac_rx_queue_read_index].data_ptr[5];
        		data_rate.b1[1] = wave_mac_rx_queue[wave_mac_rx_queue_read_index].data_ptr[6];
        		data_rate.b1[0] = wave_mac_rx_queue[wave_mac_rx_queue_read_index].data_ptr[7];

        		wave_mac_rx_queue[wave_mac_rx_queue_read_index].data_rate= data_rate.b4;
        		wave_mac_rx_queue[wave_mac_rx_queue_read_index].data_ptr += 8;					/* 8 = rssi(4) + data_rate(4) */
        		wave_mac_rx_queue[wave_mac_rx_queue_read_index].data_len -= 8;
        		wave_mac_rx_queue[wave_mac_rx_queue_read_index].data_len -= 4;					/* 4 = MAC CRC */

#if 0
        		if( print_flag & WAVE_MAC_RX_DEBUG_MODE == WAVE_MAC_RX_DEBUG_MODE)
     				printf("[wave_rcv_thread]rssi=0x%x, data_rate=0x%x, n=%d\n", rssi.b4, data_rate.b4, n);

     			if( print_flag & WAVE_MAC_RX_DEBUG_MODE )
     				print_dump_data(wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr, wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_len, "[wave_rcv_thread] Recv Data");
#endif

        		wave_mac_rx_proc(wave_mac_rx_queue[wave_mac_rx_queue_read_index].data_ptr, wave_mac_rx_queue[wave_mac_rx_queue_read_index].data_len);

        		wave_mac_rx_queue[wave_mac_rx_queue_read_index].data_ptr = org_data_ptr;
        		

			wave_mac_rx_queue_read_index++;
			if (wave_mac_rx_queue_read_index == WAVE_MAC_RX_QUEUE_NUM)
			{
				wave_mac_rx_queue_read_index = 0;
			}

			//if( print_flag & WAVE_MAC_RX_DEBUG_MODE == WAVE_MAC_RX_DEBUG_MODE)
     			//	printf("[wave_rcv_thread]2\n");
     			//pthread_mutex_unlock(&ether_rx_mutex);

     			//print_dump_data((U1 *)message, 8, "[wave_rcv_thread] Recv Data");
			
		}
		else
		{
			//printf("[net_rcv_thread] n=%d\n", n);
			//my_nanosleep(0, 10000000);	// 10ms Sleep 	
			//my_nanosleep(0, 5000000);	// 5ms Sleep 	
			//if( print_flag & WAVE_MAC_RX_DEBUG_MODE == WAVE_MAC_RX_DEBUG_MODE)
     			//	printf("[wave_rcv_thread]3\n");
		}   
 	}   
 	return 0;   
}

