
#include <stdio.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/ioctl.h>		/* ioctl */

#include "type_def.h"
#include "wave_reg.h"
#include "wave_mac.h"
#include "wave_int.h"
#include "fpga_aes.h"
#include "ecdsa_ecc.h"
#include "linked_list.h"
#include "task.h"
#include "util.h"
#include "gmp.h"
#include "aes.h"
#include "mode_hdr.h"		/* Added By SHKO */
#include "ccm.h"
#include "sha2.h"
#include "p1363.h"

extern U1 *wave_dsrc_base;

extern int sha_print_flag;

extern int dev;

int fsha256_test1(U1 *msg, volatile unsigned int len, int flag, U1 *sha_out);
int fsha256_interrupt_test1(U1 *msg, volatile unsigned int len, int flag, U1 *sha_out);

/* SHKO : fips180-2.pdf 파일의 Appendix B.1 참조 */
/* Block size = 512bit, */
/* flag가 1이면 256, 0이면 224 mode */
int fsha256_interrupt_test1(U1 *msg, volatile unsigned int len, int flag, U1 *sha_out)
{
	int i = 0, k, j = 0;
	unsigned char sha2sum[32];
	unsigned char plain_buf[4];
	volatile unsigned int data;
	volatile unsigned int block_count;
	volatile unsigned int control;
	volatile unsigned int status;
	unsigned int four_unit_len;
	unsigned int remain_len;
	unsigned long long total_bits;
	U8_T total_bits_num;
	U4_T rcv_buf[256];
	int time_out;
	unsigned int wave_ecc_interrupt_status;
	int ret = 0;

	four_unit_len = len / 4;
	remain_len = len % 4;

	total_bits = len * 8;

	total_bits_num.Lo = total_bits & 0xFFFFFFFF;
	total_bits_num.Hi = (total_bits >> 32) & 0xFFFFFFFF;

	block_count = 1;

	while(len)
	{
		if (len > 64)
		{
			block_count++;
			len -= 64;
		}
		else
		{
			if(len >= 56)
			{
				block_count++;
			}
			len = 0;
		}
		
		if (len < 0 )
			len = 0;
		
	}

	i = 0;
	for ( j = 0; j < four_unit_len; j++)
	{
		rcv_buf[j].b1[3] = msg[i++];
		rcv_buf[j].b1[2] = msg[i++];
		rcv_buf[j].b1[1] = msg[i++];
		rcv_buf[j].b1[0] = msg[i++];
		//if (sha_print_flag)
		//	printf("rcv_buf[%d].b4 = 0x%08x\n", j, rcv_buf[j].b4);
	}
	if (remain_len)
	{
		rcv_buf[j].b4 = 0;
		for (k = 0; k < remain_len; k++)
			rcv_buf[j].b1[3-k] = msg[i++];

		//if (sha_print_flag)
		//	printf("rcv_buf[%d].b4 = 0x%08x\n", j, rcv_buf[j].b4);
	}
	
	

	//printf("[fsha256_test1] SHKO1\n");
	j = 0;
	i = 0;
	k = 0;

	for ( k = 0; k < block_count; k++)
	{
		i = 0;
		if (four_unit_len)
		{
			if (four_unit_len > 16)
			{
				for ( i = 0; i < 16; i++)
				{
				#if WAVE_SECURITY_16BIT_ENABLE == 0
				  	reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
				 #else
				 	write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
				#endif
					j++;
				}
				four_unit_len -= 16;


				if  ( k == 0 )
				{
				#if WAVE_SECURITY_16BIT_ENABLE == 0
			  		reg_writel((wave_dsrc_base + ECDSA_SHA_DATA_LEN0_H_REG_OFFSET), 0);
					reg_writel((wave_dsrc_base + ECDSA_SHA_DATA_LEN1_H_REG_OFFSET), block_count);
				#else
					write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SHA_DATA_LEN0_H_REG_OFFSET, 0);
					write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SHA_DATA_LEN1_H_REG_OFFSET, block_count);
				#endif

					if (flag == 1)
						control = SHA_CONTROL_ISHA_START_BIT | SHA_CONTROL_ISHA_FIRST_BIT | SHA_CONTROL_ISHA_SELECT_BIT;
					else
						control = SHA_CONTROL_ISHA_START_BIT | SHA_CONTROL_ISHA_FIRST_BIT;
					
					write_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET, control);

				}
				else
				{
					//if (sha_print_flag)
					//	printf("block_count1 = %d\n", block_count);
					control = SHA_CONTROL_ISHA_START_BIT;
					write_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET, control);
				}
			}
			else
			{
				for ( i = 0; i < four_unit_len; i++)
				{
					//if (sha_print_flag)
					//	printf("i = %d, msg[%d].b4 = 0x%08x\n", i, j, rcv_buf[j].b4);
				  #if 0
					write_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
				  #else
				  	#if WAVE_SECURITY_16BIT_ENABLE == 0
				  		reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
				  	#else
						write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
					#endif
				  #endif
					j++;
				}
				four_unit_len = 0;

				if ( i < 14 )
				{
					switch(remain_len)
					{
						case 0:
							rcv_buf[j].b1[3] = 0x80;	/* 1bit padding */
							rcv_buf[j].b1[2] = 0x00;
							rcv_buf[j].b1[1] = 0x00;
							rcv_buf[j].b1[0] = 0x00;
							break;
						case 1:
							rcv_buf[j].b1[2] = 0x80;	/* 1bit padding */
							rcv_buf[j].b1[1] = 0x00;
							rcv_buf[j].b1[0] = 0x00;
							break;
						case 2:
							rcv_buf[j].b1[1] = 0x80;	/* 1bit padding */
							rcv_buf[j].b1[0] = 0x00;
							break;
						case 3:
							rcv_buf[j].b1[0] = 0x80;	/* 1bit padding */
							break;
						
					}

					remain_len = 0;
				
					//printf("i = %d, msg[%d].b4 = 0x%08x\n", i, j, msg[j].b4);
				  #if 0
					write_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
				  #else
				  	#if WAVE_SECURITY_16BIT_ENABLE == 0
				  		reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
				  	#else
				  		write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
				  	#endif
				  #endif

				  #if 0
					printf("i = %d, rcv_buf[%d].b4 = 0x%08x\n", i, j, read_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4))));
				  #else
				  	//if (sha_print_flag)
				  	//	printf("i = %d, rcv_buf[%d].b4 = 0x%08x\n", i, j, rcv_buf[j].b4);
				  #endif
					j++;
					i++;

					if ( i < 14)
					{
						for ( ; i < 14; i++)
						{
							//if (sha_print_flag)
							//	printf("i = %d\n", i);
						  #if 0
							write_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
						  #else
						  	#if WAVE_SECURITY_16BIT_ENABLE == 0
						  		reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
						  	#else
						  		write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
						  	#endif
						  #endif
						}
						//if (sha_print_flag)
						//{
						//	printf("total_bits_num.Hi = %d\n", total_bits_num.Hi);
						//	printf("total_bits_num.Lo = %d\n", total_bits_num.Lo);
						//}
					  #if 0
						write_wave_ecc_reg32(ECDSA_SHA_MESSAGE14_H_REG_OFFSET, total_bits_num.Hi);
						write_wave_ecc_reg32(ECDSA_SHA_MESSAGE15_H_REG_OFFSET, total_bits_num.Lo);
					  #else
					  	#if WAVE_SECURITY_16BIT_ENABLE == 0
					  		reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE14_H_REG_OFFSET), total_bits_num.Hi);
							reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE15_H_REG_OFFSET), total_bits_num.Lo);
						#else
							write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SHA_MESSAGE14_H_REG_OFFSET, total_bits_num.Hi);
							write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SHA_MESSAGE15_H_REG_OFFSET, total_bits_num.Lo);
						#endif
					  #endif
					}
					else
					{
						for ( ; i < 16; i++)
						{
							//if (sha_print_flag)
							//	printf("i = %d\n", i);
						  #if 0
							write_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
						  #else
						  	#if WAVE_SECURITY_16BIT_ENABLE == 0
						  		reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
						  	#else
						  		write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
						  	#endif
						  #endif
						}
					}

					if  ( k == 0 )
					{
						//if (sha_print_flag)
						//	printf("block_count = %d\n", block_count);
			  		#if 0
						write_wave_ecc_reg32(ECDSA_SHA_DATA_LEN0_H_REG_OFFSET, 0);
						write_wave_ecc_reg32(ECDSA_SHA_DATA_LEN1_H_REG_OFFSET, block_count);
			  		#else
			  			#if WAVE_SECURITY_16BIT_ENABLE == 0
			  				reg_writel((wave_dsrc_base + ECDSA_SHA_DATA_LEN0_H_REG_OFFSET), 0);
							reg_writel((wave_dsrc_base + ECDSA_SHA_DATA_LEN1_H_REG_OFFSET), block_count);
						#else
							write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SHA_DATA_LEN0_H_REG_OFFSET, 0);
							write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SHA_DATA_LEN1_H_REG_OFFSET, block_count);
						#endif
			  		#endif

						if (flag == 1)
							control = SHA_CONTROL_ISHA_START_BIT | SHA_CONTROL_ISHA_FIRST_BIT | SHA_CONTROL_ISHA_SELECT_BIT;
						else
							control = SHA_CONTROL_ISHA_START_BIT | SHA_CONTROL_ISHA_FIRST_BIT;
					
						write_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET, control);
						//if (sha_print_flag)
						//	printf("SHA_Control = 0x%08x\n", read_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET));

					}
					else
					{
						//if (sha_print_flag)
						//	printf("block_count1 = %d\n", block_count);
						control = SHA_CONTROL_ISHA_START_BIT;
						write_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET, control);
					}

				}	
				else if ( i < 16 )
				{
					switch(remain_len)
					{
						case 0:
							rcv_buf[j].b1[3] = 0x80;	/* 1bit padding */
							rcv_buf[j].b1[2] = 0x00;
							rcv_buf[j].b1[1] = 0x00;
							rcv_buf[j].b1[0] = 0x00;
							break;
						case 1:
							rcv_buf[j].b1[2] = 0x80;	/* 1bit padding */
							rcv_buf[j].b1[1] = 0x00;
							rcv_buf[j].b1[0] = 0x00;
							break;
						case 2:
							rcv_buf[j].b1[1] = 0x80;	/* 1bit padding */
							rcv_buf[j].b1[0] = 0x00;
							break;
						case 3:
							rcv_buf[j].b1[0] = 0x80;	/* 1bit padding */
							break;
						
					}
					remain_len = 0;
				
					//printf("i = %d, msg[%d].b4 = 0x%08x\n", i, j, msg[j].b4);
				#if WAVE_SECURITY_16BIT_ENABLE == 0
				  	reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
				  #else
				  	write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
				  #endif

				  #if 0
					printf("i = %d, rcv_buf[%d].b4 = 0x%08x\n", i, j, read_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4))));
				  #else
				  	//if (sha_print_flag)
				  	//	printf("i = %d, rcv_buf[%d].b4 = 0x%08x\n", i, j, reg_readl((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4))));
				  #endif
					j++;
					i++;

					for ( ; i < 16; i++)
					{
						//if (sha_print_flag)
						//	printf("i = %d\n", i);
					#if 0
						write_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
					#else
						#if WAVE_SECURITY_16BIT_ENABLE == 0
						 	reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
						 #else
						 	write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
						 #endif
					#endif
					}

					if  ( k == 0 )
					{
						//if (sha_print_flag)
						//	printf("block_count = %d\n", block_count);
			  		#if 0
						write_wave_ecc_reg32(ECDSA_SHA_DATA_LEN0_H_REG_OFFSET, 0);
						write_wave_ecc_reg32(ECDSA_SHA_DATA_LEN1_H_REG_OFFSET, block_count);
			  		#else
			  			#if WAVE_SECURITY_16BIT_ENABLE == 0
			  				reg_writel((wave_dsrc_base + ECDSA_SHA_DATA_LEN0_H_REG_OFFSET), 0);
							reg_writel((wave_dsrc_base + ECDSA_SHA_DATA_LEN1_H_REG_OFFSET), block_count);
						#else
							write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SHA_DATA_LEN0_H_REG_OFFSET, 0);
							write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SHA_DATA_LEN1_H_REG_OFFSET, block_count);
						#endif
			  		#endif

						if (flag == 1)
							control = SHA_CONTROL_ISHA_START_BIT | SHA_CONTROL_ISHA_FIRST_BIT | SHA_CONTROL_ISHA_SELECT_BIT;
						else
							control = SHA_CONTROL_ISHA_START_BIT | SHA_CONTROL_ISHA_FIRST_BIT;
					
						write_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET, control);
						//if (sha_print_flag)
						//	printf("SHA_Control = 0x%08x\n", read_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET));

					}
					else
					{
						//if (sha_print_flag)
						//	printf("block_count1 = %d\n", block_count);
						control = SHA_CONTROL_ISHA_START_BIT;
						write_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET, control);
					}

				}
			}
		}
		else
		{
			//if (sha_print_flag)
			//	printf("remain_len = %d, i = %d, j = %d\n", remain_len, i, j);
			switch(remain_len)
			{
				case 0:
					rcv_buf[j].b1[3] = 0x80;	/* 1bit padding */
					rcv_buf[j].b1[2] = 0x00;
					rcv_buf[j].b1[1] = 0x00;
					rcv_buf[j].b1[0] = 0x00;
					break;
				case 1:
					rcv_buf[j].b1[2] = 0x80;	/* 1bit padding */
					rcv_buf[j].b1[1] = 0x00;
					rcv_buf[j].b1[0] = 0x00;
					break;
				case 2:
					rcv_buf[j].b1[1] = 0x80;	/* 1bit padding */
					rcv_buf[j].b1[0] = 0x00;
					break;
				case 3:
					rcv_buf[j].b1[0] = 0x80;	/* 1bit padding */
					break;
					
			}

			//if (sha_print_flag)
			//	printf("i = %d, msg[%d].b4 = 0x%08x\n", i, j, rcv_buf[j].b4);
		  #if 0
			write_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), msg[j].b4);
		  #else
		  	if (remain_len)
		  	{
		  	#if WAVE_SECURITY_16BIT_ENABLE == 0
		  		reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
		  	#else
		  		write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
		  	#endif
		  		j++;
				i++;

				remain_len = 0;
		  	}
		  #endif
			
			if ( i < 14)
			{
				for ( ; i < 14; i++)
				{
					//if (sha_print_flag)
					//	printf("i = %d\n", i);
				  #if 0
					write_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
				  #else
				  	#if WAVE_SECURITY_16BIT_ENABLE == 0
				  		reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
				  	#else
		  				write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
		  			#endif
				  #endif
				}
				//if (sha_print_flag)
				//{
				//	printf("total_bits_num.Hi = %d\n", total_bits_num.Hi);
				//	printf("total_bits_num.Lo = %d\n", total_bits_num.Lo);
				//}
			  #if 0
				write_wave_ecc_reg32(ECDSA_SHA_MESSAGE14_H_REG_OFFSET, total_bits_num.Hi);
				write_wave_ecc_reg32(ECDSA_SHA_MESSAGE15_H_REG_OFFSET, total_bits_num.Lo);
			  #else
			 	 #if WAVE_SECURITY_16BIT_ENABLE == 0
			  		reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE14_H_REG_OFFSET), total_bits_num.Hi);
					reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE15_H_REG_OFFSET), total_bits_num.Lo);
				#else
					write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SHA_MESSAGE14_H_REG_OFFSET, total_bits_num.Hi);
					write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SHA_MESSAGE15_H_REG_OFFSET, total_bits_num.Lo);
				#endif
			  #endif
			}
			else
			{
				for ( ; i < 16; i++)
				{
					//if (sha_print_flag)
					//	printf("i = %d\n", i);
				  #if 0
					write_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
				  #else
				  	#if WAVE_SECURITY_16BIT_ENABLE == 0
				  		reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
				  	#else
				  		write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
				  	#endif
				  #endif
				}
			}

			if  ( k == 0 )
			{
				//if (sha_print_flag)
				//	printf("block_count = %d\n", block_count);
			  #if 0
				write_wave_ecc_reg32(ECDSA_SHA_DATA_LEN0_H_REG_OFFSET, 0);
				write_wave_ecc_reg32(ECDSA_SHA_DATA_LEN1_H_REG_OFFSET, block_count);
			  #else
			  	#if WAVE_SECURITY_16BIT_ENABLE == 0
			  		reg_writel((wave_dsrc_base + ECDSA_SHA_DATA_LEN0_H_REG_OFFSET), 0);
					reg_writel((wave_dsrc_base + ECDSA_SHA_DATA_LEN1_H_REG_OFFSET), block_count);
				#else
					write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SHA_DATA_LEN0_H_REG_OFFSET, 0);
					write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SHA_DATA_LEN1_H_REG_OFFSET, block_count);
				#endif
			  #endif

				if (flag == 1)
					control = SHA_CONTROL_ISHA_START_BIT | SHA_CONTROL_ISHA_FIRST_BIT | SHA_CONTROL_ISHA_SELECT_BIT;
				else
					control = SHA_CONTROL_ISHA_START_BIT | SHA_CONTROL_ISHA_FIRST_BIT;
					
				write_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET, control);
				//if (sha_print_flag)
				//	printf("SHA_Control = 0x%08x\n", read_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET));

			}
			else
			{
				//if (sha_print_flag)
				//	printf("block_count1 = %d\n", block_count);
				control = SHA_CONTROL_ISHA_START_BIT;
				write_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET, control);
			}

		}	
	}

	
	
	//printf("[fsha256_test1]SHKO2\n");
#if 0
	if (sha_print_flag)
	{
		for ( i = 0; i < 16; i++)
		{
#if 0
			printf("i = %d, 0x%08x\n", i, read_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4))));
#else
			printf("i = %d, 0x%08x\n", i, reg_readl((wave_dsrc_base + ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4))));
#endif
		}
		printf("\n");
	}
#endif

	//printf("[fsha256_test1]ECC STAT = 0x%08x\n", read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET));
#if 0
	time_out = 2000;
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		//if (sha_print_flag)
		//	printf("status=0x%08x\n", status);
		if (status & SHA_DONE_STATUS_BIT)	/* SHA Done */
			break;
	}
	if (time_out <= 0)
		printf("[fsha256_test] status=0x%08x\n", status);
		
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SHA_DONE_STATUS_BIT);

	if (time_out < 0)
	{
		printf("[fsha256_test1] Time Out!!=%d\n", time_out);
		return(-1);
	}
#endif

	time_out = 20000;
	while(time_out--)
	{	
		ret  = ioctl(dev, IOCTLWAVE_ECC_INT_READ, &wave_ecc_interrupt_status);
		if (ret != 0)
		{
			perror("[fsha256_interrupt_test1] ioctl:");
			break;
		}
		else
		{
			if (wave_ecc_interrupt_status == SHA_DONE)
			{
				break;
			}
		}
	}

	//if (sha_print_flag)
	//	printf("[fsha256_test1]time_out=%d\n", time_out);

	j = 0;

	/* SHA256 이므로 결과는 32바이트가 나온다. */
	for ( i = 0; i < 8; i++ )
	{
		sha_out[j++] = (reg_readl((wave_dsrc_base + ECDSA_SHA_OUT0_H_REG_OFFSET + (i*4))) >> 24) & 0xFF;
		sha_out[j++] = (reg_readl((wave_dsrc_base + ECDSA_SHA_OUT0_H_REG_OFFSET + (i*4))) >> 16) & 0xFF;
		sha_out[j++] = (reg_readl((wave_dsrc_base + ECDSA_SHA_OUT0_H_REG_OFFSET + (i*4))) >> 8) & 0xFF;
		sha_out[j++] = reg_readl((wave_dsrc_base + ECDSA_SHA_OUT0_H_REG_OFFSET + (i*4)))  & 0xFF;
	}
	//printf("\n");
	if (sha_print_flag)
	{
		printf("Display SHA Output Data\n");
		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", sha_out[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}

	return( 0 );
}

/* SHKO : fips180-2.pdf 파일의 Appendix B.1 참조 */
/* Block size = 512bit, */
/* flag가 1이면 256, 0이면 224 mode */
int fsha256_test1(U1 *msg, volatile unsigned int len, int flag, U1 *sha_out)
{
	int i = 0, k, j = 0;
	unsigned char sha2sum[32];
	unsigned char plain_buf[4];
	volatile unsigned int data;
	volatile unsigned int block_count;
	volatile unsigned int control;
	volatile unsigned int status;
	unsigned int four_unit_len;
	unsigned int remain_len;
	unsigned long long total_bits;
	U8_T total_bits_num;
	U4_T rcv_buf[256];
	int time_out;

	four_unit_len = len / 4;
	remain_len = len % 4;

	total_bits = len * 8;

	total_bits_num.Lo = total_bits & 0xFFFFFFFF;
	total_bits_num.Hi = (total_bits >> 32) & 0xFFFFFFFF;

	block_count = 1;

	while(len)
	{
		if (len > 64)
		{
			block_count++;
			len -= 64;
		}
		else
		{
			if(len >= 56)
			{
				block_count++;
			}
			len = 0;
		}
		
		if (len < 0 )
			len = 0;
		
	}

	i = 0;
	for ( j = 0; j < four_unit_len; j++)
	{
		rcv_buf[j].b1[3] = msg[i++];
		rcv_buf[j].b1[2] = msg[i++];
		rcv_buf[j].b1[1] = msg[i++];
		rcv_buf[j].b1[0] = msg[i++];
		//if (sha_print_flag)
		//	printf("rcv_buf[%d].b4 = 0x%08x\n", j, rcv_buf[j].b4);
	}
	if (remain_len)
	{
		rcv_buf[j].b4 = 0;
		for (k = 0; k < remain_len; k++)
			rcv_buf[j].b1[3-k] = msg[i++];

		//if (sha_print_flag)
		//	printf("rcv_buf[%d].b4 = 0x%08x\n", j, rcv_buf[j].b4);
	}
	
	

	//printf("[fsha256_test1] SHKO1\n");
	j = 0;
	i = 0;
	k = 0;

#if 1
	for ( k = 0; k < block_count; k++)
	{
		i = 0;
		if (four_unit_len)
		{
			if (four_unit_len > 16)
			{
				for ( i = 0; i < 16; i++)
				{
					//if (sha_print_flag)
					//	printf("i = %d, msg[%d].b4 = 0x%08x\n", i, j, rcv_buf[j].b4);
				  #if 0
					write_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
				  #else
				  #if WAVE_SECURITY_16BIT_ENABLE == 0
				  	reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
				  #else
				  	write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
				  #endif
				  #endif
					j++;
				}
				four_unit_len -= 16;


				if  ( k == 0 )
				{
					//if (sha_print_flag)
					//	printf("block_count = %d\n", block_count);
			  	  #if 0
					write_wave_ecc_reg32(ECDSA_SHA_DATA_LEN0_H_REG_OFFSET, 0);
					write_wave_ecc_reg32(ECDSA_SHA_DATA_LEN1_H_REG_OFFSET, block_count);
			  	  #else
			  	  #if WAVE_SECURITY_16BIT_ENABLE == 0
			  		reg_writel((wave_dsrc_base + ECDSA_SHA_DATA_LEN0_H_REG_OFFSET), 0);
					reg_writel((wave_dsrc_base + ECDSA_SHA_DATA_LEN1_H_REG_OFFSET), block_count);
				#else
					write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SHA_DATA_LEN0_H_REG_OFFSET, 0);
					write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SHA_DATA_LEN1_H_REG_OFFSET, block_count);
				#endif
			  	  #endif

					if (flag == 1)
						control = SHA_CONTROL_ISHA_START_BIT | SHA_CONTROL_ISHA_FIRST_BIT | SHA_CONTROL_ISHA_SELECT_BIT;
					else
						control = SHA_CONTROL_ISHA_START_BIT | SHA_CONTROL_ISHA_FIRST_BIT;
					
					write_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET, control);
					//if (sha_print_flag)
					//	printf("SHA_Control = 0x%08x\n", read_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET));

				}
				else
				{
					//if (sha_print_flag)
					//	printf("block_count1 = %d\n", block_count);
					control = SHA_CONTROL_ISHA_START_BIT;
					write_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET, control);
				}
			}
			else
			{
				for ( i = 0; i < four_unit_len; i++)
				{
					//if (sha_print_flag)
					//	printf("i = %d, msg[%d].b4 = 0x%08x\n", i, j, rcv_buf[j].b4);
				  #if 0
					write_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
				  #else
				  	#if WAVE_SECURITY_16BIT_ENABLE == 0
				  		reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
				  	#else
				  		write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
				  	#endif
				  #endif
					j++;
				}
				four_unit_len = 0;

				if ( i < 14 )
				{
					switch(remain_len)
					{
						case 0:
							rcv_buf[j].b1[3] = 0x80;	/* 1bit padding */
							rcv_buf[j].b1[2] = 0x00;
							rcv_buf[j].b1[1] = 0x00;
							rcv_buf[j].b1[0] = 0x00;
							break;
						case 1:
							rcv_buf[j].b1[2] = 0x80;	/* 1bit padding */
							rcv_buf[j].b1[1] = 0x00;
							rcv_buf[j].b1[0] = 0x00;
							break;
						case 2:
							rcv_buf[j].b1[1] = 0x80;	/* 1bit padding */
							rcv_buf[j].b1[0] = 0x00;
							break;
						case 3:
							rcv_buf[j].b1[0] = 0x80;	/* 1bit padding */
							break;
						
					}

					remain_len = 0;
				
					//printf("i = %d, msg[%d].b4 = 0x%08x\n", i, j, msg[j].b4);
				  #if 0
					write_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
				  #else
				  	#if WAVE_SECURITY_16BIT_ENABLE == 0
				  		reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
				  	#else
				  		write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
				  	#endif
				  #endif

				  #if 0
					printf("i = %d, rcv_buf[%d].b4 = 0x%08x\n", i, j, read_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4))));
				  #else
				  	//if (sha_print_flag)
				  	//	printf("i = %d, rcv_buf[%d].b4 = 0x%08x\n", i, j, rcv_buf[j].b4);
				  #endif
					j++;
					i++;

					if ( i < 14)
					{
						for ( ; i < 14; i++)
						{
							//if (sha_print_flag)
							//	printf("i = %d\n", i);
						  #if 0
							write_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
						  #else
						  	#if WAVE_SECURITY_16BIT_ENABLE == 0
						  		reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
						  	#else
						  		write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
						  	#endif
						  #endif
						}
						//if (sha_print_flag)
						//{
						//	printf("total_bits_num.Hi = %d\n", total_bits_num.Hi);
						//	printf("total_bits_num.Lo = %d\n", total_bits_num.Lo);
						//}
					  #if 0
						write_wave_ecc_reg32(ECDSA_SHA_MESSAGE14_H_REG_OFFSET, total_bits_num.Hi);
						write_wave_ecc_reg32(ECDSA_SHA_MESSAGE15_H_REG_OFFSET, total_bits_num.Lo);
					  #else
					  	#if WAVE_SECURITY_16BIT_ENABLE == 0
					  		reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE14_H_REG_OFFSET), total_bits_num.Hi);
							reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE15_H_REG_OFFSET), total_bits_num.Lo);
						#else
							write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SHA_MESSAGE14_H_REG_OFFSET, total_bits_num.Hi);
							write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SHA_MESSAGE15_H_REG_OFFSET, total_bits_num.Lo);
						#endif
					  #endif
					}
					else
					{
						for ( ; i < 16; i++)
						{
							//if (sha_print_flag)
							//	printf("i = %d\n", i);
						  #if 0
							write_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
						  #else
						  	#if WAVE_SECURITY_16BIT_ENABLE == 0
						  		reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
						  	#else
						  		write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
						  	#endif
						  #endif
						}
					}

					if  ( k == 0 )
					{
						//if (sha_print_flag)
						//	printf("block_count = %d\n", block_count);
			  		#if 0
						write_wave_ecc_reg32(ECDSA_SHA_DATA_LEN0_H_REG_OFFSET, 0);
						write_wave_ecc_reg32(ECDSA_SHA_DATA_LEN1_H_REG_OFFSET, block_count);
			  		#else
			  		#if WAVE_SECURITY_16BIT_ENABLE == 0
			  			reg_writel((wave_dsrc_base + ECDSA_SHA_DATA_LEN0_H_REG_OFFSET), 0);
						reg_writel((wave_dsrc_base + ECDSA_SHA_DATA_LEN1_H_REG_OFFSET), block_count);
					#else
						write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SHA_DATA_LEN0_H_REG_OFFSET, 0);
						write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SHA_DATA_LEN1_H_REG_OFFSET, block_count);
					#endif
			  		#endif

						if (flag == 1)
							control = SHA_CONTROL_ISHA_START_BIT | SHA_CONTROL_ISHA_FIRST_BIT | SHA_CONTROL_ISHA_SELECT_BIT;
						else
							control = SHA_CONTROL_ISHA_START_BIT | SHA_CONTROL_ISHA_FIRST_BIT;
					
						write_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET, control);
						//if (sha_print_flag)
						//	printf("SHA_Control = 0x%08x\n", read_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET));

					}
					else
					{
						//if (sha_print_flag)
						//	printf("block_count1 = %d\n", block_count);
						control = SHA_CONTROL_ISHA_START_BIT;
						write_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET, control);
					}

				}	
				else if ( i < 16 )
				{
					switch(remain_len)
					{
						case 0:
							rcv_buf[j].b1[3] = 0x80;	/* 1bit padding */
							rcv_buf[j].b1[2] = 0x00;
							rcv_buf[j].b1[1] = 0x00;
							rcv_buf[j].b1[0] = 0x00;
							break;
						case 1:
							rcv_buf[j].b1[2] = 0x80;	/* 1bit padding */
							rcv_buf[j].b1[1] = 0x00;
							rcv_buf[j].b1[0] = 0x00;
							break;
						case 2:
							rcv_buf[j].b1[1] = 0x80;	/* 1bit padding */
							rcv_buf[j].b1[0] = 0x00;
							break;
						case 3:
							rcv_buf[j].b1[0] = 0x80;	/* 1bit padding */
							break;
						
					}
					remain_len = 0;
				
					//printf("i = %d, msg[%d].b4 = 0x%08x\n", i, j, msg[j].b4);
				  #if 0
					write_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
				  #else
				  	#if WAVE_SECURITY_16BIT_ENABLE == 0
				  		reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
				  	#else
				  		write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
				  	#endif
				  #endif

				  #if 0
					printf("i = %d, rcv_buf[%d].b4 = 0x%08x\n", i, j, read_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4))));
				  #else
				  	//if (sha_print_flag)
				  	//	printf("i = %d, rcv_buf[%d].b4 = 0x%08x\n", i, j, reg_readl((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4))));
				  #endif
					j++;
					i++;

					for ( ; i < 16; i++)
					{
						//if (sha_print_flag)
						//	printf("i = %d\n", i);
					#if 0
						write_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
					#else
						#if WAVE_SECURITY_16BIT_ENABLE == 0
						 	reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
						 #else
						 	write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
						 #endif
					#endif
					}

					if  ( k == 0 )
					{
						//if (sha_print_flag)
						//	printf("block_count = %d\n", block_count);
			  		#if 0
						write_wave_ecc_reg32(ECDSA_SHA_DATA_LEN0_H_REG_OFFSET, 0);
						write_wave_ecc_reg32(ECDSA_SHA_DATA_LEN1_H_REG_OFFSET, block_count);
			  		#else
			  			#if WAVE_SECURITY_16BIT_ENABLE == 0
			  				reg_writel((wave_dsrc_base + ECDSA_SHA_DATA_LEN0_H_REG_OFFSET), 0);
							reg_writel((wave_dsrc_base + ECDSA_SHA_DATA_LEN1_H_REG_OFFSET), block_count);
						#else
							write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SHA_DATA_LEN0_H_REG_OFFSET), 0);
							write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SHA_DATA_LEN1_H_REG_OFFSET), block_count);
						#endif
			  		#endif

						if (flag == 1)
							control = SHA_CONTROL_ISHA_START_BIT | SHA_CONTROL_ISHA_FIRST_BIT | SHA_CONTROL_ISHA_SELECT_BIT;
						else
							control = SHA_CONTROL_ISHA_START_BIT | SHA_CONTROL_ISHA_FIRST_BIT;
					
						write_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET, control);
						//if (sha_print_flag)
						//	printf("SHA_Control = 0x%08x\n", read_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET));

					}
					else
					{
						//if (sha_print_flag)
						//	printf("block_count1 = %d\n", block_count);
						control = SHA_CONTROL_ISHA_START_BIT;
						write_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET, control);
					}

				}
			}
		}
		else
		{
			//if (sha_print_flag)
			//	printf("remain_len = %d, i = %d, j = %d\n", remain_len, i, j);
			switch(remain_len)
			{
				case 0:
					rcv_buf[j].b1[3] = 0x80;	/* 1bit padding */
					rcv_buf[j].b1[2] = 0x00;
					rcv_buf[j].b1[1] = 0x00;
					rcv_buf[j].b1[0] = 0x00;
					break;
				case 1:
					rcv_buf[j].b1[2] = 0x80;	/* 1bit padding */
					rcv_buf[j].b1[1] = 0x00;
					rcv_buf[j].b1[0] = 0x00;
					break;
				case 2:
					rcv_buf[j].b1[1] = 0x80;	/* 1bit padding */
					rcv_buf[j].b1[0] = 0x00;
					break;
				case 3:
					rcv_buf[j].b1[0] = 0x80;	/* 1bit padding */
					break;
					
			}

			//if (sha_print_flag)
			//	printf("i = %d, msg[%d].b4 = 0x%08x\n", i, j, rcv_buf[j].b4);
		  #if 0
			write_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), msg[j].b4);
		  #else
		  	if (remain_len)
		  	{
		  		#if WAVE_SECURITY_16BIT_ENABLE == 0
		  			reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
		  		#else
		  			write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), rcv_buf[j].b4);
		  		#endif
		  		j++;
				i++;

				remain_len = 0;
		  	}
		  #endif
			
			if ( i < 14)
			{
				for ( ; i < 14; i++)
				{
					//if (sha_print_flag)
					//	printf("i = %d\n", i);
				  #if 0
					write_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
				  #else
				  	#if WAVE_SECURITY_16BIT_ENABLE == 0
				  		reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
				  	#else
		  				write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
		  			#endif
				  #endif
				}
				//if (sha_print_flag)
				//{
				//	printf("total_bits_num.Hi = %d\n", total_bits_num.Hi);
				//	printf("total_bits_num.Lo = %d\n", total_bits_num.Lo);
				//}
			  #if 0
				write_wave_ecc_reg32(ECDSA_SHA_MESSAGE14_H_REG_OFFSET, total_bits_num.Hi);
				write_wave_ecc_reg32(ECDSA_SHA_MESSAGE15_H_REG_OFFSET, total_bits_num.Lo);
			  #else
			  #if WAVE_SECURITY_16BIT_ENABLE == 0
			  	reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE14_H_REG_OFFSET), total_bits_num.Hi);
				reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE15_H_REG_OFFSET), total_bits_num.Lo);
			 #else
			 	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SHA_MESSAGE14_H_REG_OFFSET, total_bits_num.Hi);
				write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SHA_MESSAGE15_H_REG_OFFSET, total_bits_num.Lo);
			 #endif
			  #endif
			}
			else
			{
				for ( ; i < 16; i++)
				{
					//if (sha_print_flag)
					//	printf("i = %d\n", i);
				  #if 0
					write_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
				  #else
				  	#if WAVE_SECURITY_16BIT_ENABLE == 0
				  	reg_writel((wave_dsrc_base + ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
				  	#else
				  	write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4)), 0);
				  	#endif
				  #endif
				}
			}

			if  ( k == 0 )
			{
				//if (sha_print_flag)
				//	printf("block_count = %d\n", block_count);
			  #if 0
				write_wave_ecc_reg32(ECDSA_SHA_DATA_LEN0_H_REG_OFFSET, 0);
				write_wave_ecc_reg32(ECDSA_SHA_DATA_LEN1_H_REG_OFFSET, block_count);
			  #else
			  	#if WAVE_SECURITY_16BIT_ENABLE == 0
			  	reg_writel((wave_dsrc_base + ECDSA_SHA_DATA_LEN0_H_REG_OFFSET), 0);
				reg_writel((wave_dsrc_base + ECDSA_SHA_DATA_LEN1_H_REG_OFFSET), block_count);
				#else
					write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SHA_DATA_LEN0_H_REG_OFFSET, 0);
				write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SHA_DATA_LEN1_H_REG_OFFSET, block_count);
				#endif
			  #endif

				if (flag == 1)
					control = SHA_CONTROL_ISHA_START_BIT | SHA_CONTROL_ISHA_FIRST_BIT | SHA_CONTROL_ISHA_SELECT_BIT;
				else
					control = SHA_CONTROL_ISHA_START_BIT | SHA_CONTROL_ISHA_FIRST_BIT;
					
				write_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET, control);
				//if (sha_print_flag)
				//	printf("SHA_Control = 0x%08x\n", read_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET));

			}
			else
			{
				//if (sha_print_flag)
				//	printf("block_count1 = %d\n", block_count);
				control = SHA_CONTROL_ISHA_START_BIT;
				write_wave_ecc_reg32(ECDSA_SHA_CONT_H_REG_OFFSET, control);
			}

		}	
	}

	
	
	//printf("[fsha256_test1]SHKO2\n");
#if 0
	if (sha_print_flag)
	{
		for ( i = 0; i < 16; i++)
		{
#if 0
			printf("i = %d, 0x%08x\n", i, read_wave_ecc_reg32((ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4))));
#else
			printf("i = %d, 0x%08x\n", i, reg_readl((wave_dsrc_base + ECDSA_SHA_MESSAGE0_H_REG_OFFSET + (i*4))));
#endif
		}
		printf("\n");
	}
#endif

	//printf("[fsha256_test1]ECC STAT = 0x%08x\n", read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET));

	time_out = 20000;
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		//if (sha_print_flag)
		//	printf("status=0x%08x\n", status);
		if (status & SHA_DONE_STATUS_BIT)	/* SHA Done */
			break;
	}
	if (time_out <= 0)
		printf("[fsha256_test] status=0x%08x\n", status);
		
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SHA_DONE_STATUS_BIT);

	if (time_out < 0)
	{
		printf("[fsha256_test1] Time Out!!=%d\n", time_out);
		return(-1);
	}

	//if (sha_print_flag)
	//	printf("[fsha256_test1]time_out=%d\n", time_out);

	j = 0;

	/* SHA256 이므로 결과는 32바이트가 나온다. */
	for ( i = 0; i < 8; i++ )
	{
#if 0
		sha_out[i] = read_wave_ecc_reg32((ECDSA_SHA_OUT0_H_REG_OFFSET + (i*4)));
#else
		sha_out[j++] = (reg_readl((wave_dsrc_base + ECDSA_SHA_OUT0_H_REG_OFFSET + (i*4))) >> 24) & 0xFF;
		sha_out[j++] = (reg_readl((wave_dsrc_base + ECDSA_SHA_OUT0_H_REG_OFFSET + (i*4))) >> 16) & 0xFF;
		sha_out[j++] = (reg_readl((wave_dsrc_base + ECDSA_SHA_OUT0_H_REG_OFFSET + (i*4))) >> 8) & 0xFF;
		sha_out[j++] = reg_readl((wave_dsrc_base + ECDSA_SHA_OUT0_H_REG_OFFSET + (i*4)))  & 0xFF;
		
#endif
	}
	//printf("\n");
#if 1
	if (sha_print_flag)
	{
		printf("Display SHA Output Data\n");
		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", sha_out[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}
#endif
	
#endif
    return( 0 );
}

