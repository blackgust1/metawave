#include <pthread.h>
#include <stdio.h>
#include "type_def.h"
#include "wave_reg.h"
#include "linked_list.h"
#include "task.h"
#include "util.h"

extern U1 *wave_dsrc_base;


void wave_modem_init(void)
{
	/* reg_writel(WAVE_MODEM_TXPWR_SET1_REG, 0x0); */
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET1_2_REG_OFFSET), 0x0);

	reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET3_4_REG_OFFSET), 0x0);

	reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET5_6_REG_OFFSET), 0x0);

	reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET7_8_REG_OFFSET), 0x0);

	
	/* reg_writel(WAVE_MODEM_RF_STATUS_CMD_REG, 0x2002); */
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_RF_SPI_CTRL_REG_OFFSET), 0x2002);

	my_nanosleep(0, 20000);		/* 20usec delay */

	/* reg_writel(WAVE_MODEM_RF_STATUS_CMD_REG, 0x2002); */
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_RF_SPI_CTRL_REG_OFFSET), 0x2002);
	
#if WAVE_ASIC_VER
	/* [11] : 64QAM Must Burst On */
	/* [10] : 64QAM Must Filter Off */
	/* [9] : RSSI Must Burst */
	/* [8] : Rate Weight Mode On */
	/* [7:0] : RSSI Burst Threshold */
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_RE_ESTIMATION_MODE_REG_OFFSET), 0x0CBF);
#endif

	
	/* 아래와 같이 세팅을 해야 txpkt 명령의 txpower가 적용된다. */
#if 0	//SHKO, Origin
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET1_2_REG_OFFSET), 0x0180);
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET3_4_REG_OFFSET), 0x028C);
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET5_6_REG_OFFSET), 0x0798);
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET7_8_REG_OFFSET), 0x0AA4);
#else
#if WAVE_FPGA_VER
//#if 1
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET1_2_REG_OFFSET), 0x0600);
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET3_4_REG_OFFSET), 0x120C);
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET5_6_REG_OFFSET), 0x1E18);
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET7_8_REG_OFFSET), 0x2A3F);
#endif

#if WAVE_ASIC_VER
//#if 0
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET1_2_REG_OFFSET), 0x130c);
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET3_4_REG_OFFSET), 0x1d17);
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET5_6_REG_OFFSET), 0x2723);
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET7_8_REG_OFFSET), 0x302d);
#endif
#endif

#if 1
	/* ASIC SHKO, Added */
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_FTO_THRESHOLD_REG_OFFSET), 1);

	/* [8] : Tx Scale, [7] : Scrambler Initial Value, [6:0] : Tx Seed */
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_SCALE_SCRAMBLE_REG_OFFSET), 0x3dd);

	/* CCA Busy Threshold using RSSI Register */
	/* [15:8] : CCA Busy를 판단하는 기준값. */
	/* [7:0] : 입력 신호가 CCA Busy 기준 값 이상으로 시간적으로 유지되는 값을 의미한다. */
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_RSSI0_REG_OFFSET), 0xba80);

	/* AGC Operation Mode Set Register */
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_MODE_SELECT_REG_OFFSET), 0x8319);
#endif
	
}


#if WAVE_MERGE
void wave_modem_b_init(void)
{
	reg_writew((wave_dsrc_base + WAVE_MODEM_B_TX_PWR_SET1_2_REG_OFFSET), 0x0);

	reg_writew((wave_dsrc_base + WAVE_MODEM_B_TX_PWR_SET3_4_REG_OFFSET), 0x0);

	reg_writew((wave_dsrc_base + WAVE_MODEM_B_TX_PWR_SET5_6_REG_OFFSET), 0x0);

	reg_writew((wave_dsrc_base + WAVE_MODEM_B_TX_PWR_SET7_8_REG_OFFSET), 0x0);

	
	/* reg_writel(WAVE_MODEM_RF_STATUS_CMD_REG, 0x2002); */
	reg_writew((wave_dsrc_base + WAVE_MODEM_B_RF_SPI_CTRL_REG_OFFSET), 0x2002);

	my_nanosleep(0, 20000);		/* 20usec delay */

	/* reg_writel(WAVE_MODEM_RF_STATUS_CMD_REG, 0x2002); */
	reg_writew((wave_dsrc_base + WAVE_MODEM_B_RF_SPI_CTRL_REG_OFFSET), 0x2002);

#if WAVE_ASIC_VER
	/* [11] : 64QAM Must Burst On */
	/* [10] : 64QAM Must Filter Off */
	/* [9] : RSSI Must Burst */
	/* [8] : Rate Weight Mode On */
	/* [7:0] : RSSI Burst Threshold */
	reg_writew((wave_dsrc_base + WAVE_MODEM_B_RE_ESTIMATION_MODE_REG_OFFSET), 0x0CBF);
#endif

	
	/* 아래와 같이 세팅을 해야 txpkt 명령의 txpower가 적용된다. */
#if 0	//SHKO, Origin
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET1_2_REG_OFFSET), 0x0180);
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET3_4_REG_OFFSET), 0x028C);
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET5_6_REG_OFFSET), 0x0798);
	reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET7_8_REG_OFFSET), 0x0AA4);
#else
#if WAVE_FPGA_VER
//#if 1
	reg_writew((wave_dsrc_base + WAVE_MODEM_B_TX_PWR_SET1_2_REG_OFFSET), 0x0600);
	reg_writew((wave_dsrc_base + WAVE_MODEM_B_TX_PWR_SET3_4_REG_OFFSET), 0x120C);
	reg_writew((wave_dsrc_base + WAVE_MODEM_B_TX_PWR_SET5_6_REG_OFFSET), 0x1E18);
	reg_writew((wave_dsrc_base + WAVE_MODEM_B_TX_PWR_SET7_8_REG_OFFSET), 0x2A3F);
#endif

#if WAVE_ASIC_VER
//#if 0
	reg_writew((wave_dsrc_base + WAVE_MODEM_B_TX_PWR_SET1_2_REG_OFFSET), 0x130c);
	reg_writew((wave_dsrc_base + WAVE_MODEM_B_TX_PWR_SET3_4_REG_OFFSET), 0x1d17);
	reg_writew((wave_dsrc_base + WAVE_MODEM_B_TX_PWR_SET5_6_REG_OFFSET), 0x2723);
	reg_writew((wave_dsrc_base + WAVE_MODEM_B_TX_PWR_SET7_8_REG_OFFSET), 0x302d);
#endif
#endif


#if 1
	/* ASIC SHKO, Added */
	reg_writew((wave_dsrc_base + WAVE_MODEM_B_FTO_THRESHOLD_REG_OFFSET), 1);

	/* [8] : Tx Scale, [7] : Scrambler Initial Value, [6:0] : Tx Seed */
	reg_writew((wave_dsrc_base + WAVE_MODEM_B_TX_SCALE_SCRAMBLE_REG_OFFSET), 0x3dd);

	/* CCA Busy Threshold using RSSI Register */
	/* [15:8] : CCA Busy를 판단하는 기준값. */
	/* [7:0] : 입력 신호가 CCA Busy 기준 값 이상으로 시간적으로 유지되는 값을 의미한다. */
	reg_writew((wave_dsrc_base + WAVE_MODEM_B_RSSI0_REG_OFFSET), 0xba80);

	/* AGC Operation Mode Set Register */
	reg_writew((wave_dsrc_base + WAVE_MODEM_B_MODE_SELECT_REG_OFFSET), 0x8319);
#endif
	
}

#endif
