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

extern U1 *wave_dsrc_base;

void set_multi_ch_cch(U4 r0)
{

	switch(r0)
	{
		case RF_FREQ_5840:
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH1_ID_REG_OFFSET), 0x20E9);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH1_IF_REG_OFFSET), 0x2666);
			break;
		case RF_FREQ_5850:
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH1_ID_REG_OFFSET), 0x00EA);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH1_IF_REG_OFFSET), 0x0000);
			break;
		case RF_FREQ_5855:
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH1_ID_REG_OFFSET), 0x30EA);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH1_IF_REG_OFFSET), 0x0CCC);
			break;
		case RF_FREQ_5860:
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH1_ID_REG_OFFSET), 0x20EA);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH1_IF_REG_OFFSET), 0x1999);
			break;
		case RF_FREQ_5865:
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH1_ID_REG_OFFSET), 0x20EA);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH1_IF_REG_OFFSET), 0x2666);
			break;
		case RF_FREQ_5870:
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH1_ID_REG_OFFSET), 0x10EA);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH1_IF_REG_OFFSET), 0x3333);
			break;
		case RF_FREQ_5875:
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH1_ID_REG_OFFSET), 0x00EB);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH1_IF_REG_OFFSET), 0x0000);
			break;
		case RF_FREQ_5880:
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH1_ID_REG_OFFSET), 0x30EB);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH1_IF_REG_OFFSET), 0x0CCC);
			break;
		case RF_FREQ_5885:
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH1_ID_REG_OFFSET), 0x20EB);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH1_IF_REG_OFFSET), 0x1999);
			break;
		case RF_FREQ_5890:
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH1_ID_REG_OFFSET), 0x20EB);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH1_IF_REG_OFFSET), 0x2666);
			break;
		default:
			printf("\r\nError : Not available Input RF Freq. (%d)", r0);					
			break;
	}
}



void set_multi_ch_sch(U4 r0)
{
	switch(r0)
	{
		case RF_FREQ_5840:
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH2_ID_REG_OFFSET), 0x20E9);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH2_IF_REG_OFFSET), 0x2666);
			break;
		case RF_FREQ_5850:
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH2_ID_REG_OFFSET), 0x00EA);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH2_IF_REG_OFFSET), 0x0000);
			break;
		case RF_FREQ_5855:
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH2_ID_REG_OFFSET), 0x30EA);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH2_IF_REG_OFFSET), 0x0CCC);
			break;
		case RF_FREQ_5860:
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH2_ID_REG_OFFSET), 0x20EA);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH2_IF_REG_OFFSET), 0x1999);
			break;
		case RF_FREQ_5865:
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH2_ID_REG_OFFSET), 0x20EA);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH2_IF_REG_OFFSET), 0x2666);
			break;
		case RF_FREQ_5870:
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH2_ID_REG_OFFSET), 0x10EA);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH2_IF_REG_OFFSET), 0x3333);
			break;
		case RF_FREQ_5875:
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH2_ID_REG_OFFSET), 0x00EB);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH2_IF_REG_OFFSET), 0x0000);
			break;
		case RF_FREQ_5880:
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH2_ID_REG_OFFSET), 0x30EB);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH2_IF_REG_OFFSET), 0x0CCC);
			break;
		case RF_FREQ_5885:
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH2_ID_REG_OFFSET), 0x20EB);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH2_IF_REG_OFFSET), 0x1999);
			break;
		case RF_FREQ_5890:
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH2_ID_REG_OFFSET), 0x20EB);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_HANDOVER_RF_CH2_IF_REG_OFFSET), 0x2666);
			break;
		default:
			printf("\r\nError : Not available Input RF Freq. (%d)", r0);					
			break;
	}
}