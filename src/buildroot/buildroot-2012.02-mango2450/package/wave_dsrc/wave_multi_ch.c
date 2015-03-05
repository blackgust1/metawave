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


void Multi_Ch_OnOff(U1 flag)
{
	U2 reg_data;
	if (flag)		/* Multi-CH On */
	{
		/* Sync time pulse on GPS (Channel A,B)*/
		reg_data = reg_readw((wave_dsrc_base + WAVE_MODE_SET_L_REG_OFFSET));
		reg_data |= 3;
		reg_writew((wave_dsrc_base + WAVE_MODE_SET_L_REG_OFFSET), reg_data);

		/* Turn on Multi-channel operation (Channel A,B)*/
		reg_data = reg_readw((wave_dsrc_base + WAVE_MULTICH_SET_L_REG_OFFSET));
		reg_data |= 3;
		reg_writew((wave_dsrc_base + WAVE_MULTICH_SET_L_REG_OFFSET), reg_data);

		
	}
	else			/* Multi-CH Off */
	{
		/* Sync time pulse on SW (Channel A,B)*/
		reg_data = reg_readw((wave_dsrc_base + WAVE_MODE_SET_L_REG_OFFSET));
		clear_bit(reg_data, 0);
		clear_bit(reg_data, 1);
		reg_writew((wave_dsrc_base + WAVE_MODE_SET_L_REG_OFFSET), reg_data);

		/* Turn off Multi-channel operation (Channel A,B)*/
		reg_data = reg_readw((wave_dsrc_base + WAVE_MULTICH_SET_L_REG_OFFSET));
		clear_bit(reg_data, 0);
		clear_bit(reg_data, 1);
		reg_writew((wave_dsrc_base + WAVE_MULTICH_SET_L_REG_OFFSET), reg_data);
	}
}
