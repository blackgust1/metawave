
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
#include "wsmp.h"

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
extern int aes_print_flag;
extern U1 g_aes_key[10][16];
extern int ecies_print_flag;

int g_aes_cmsg_falut_flag;
extern int g_aes_key_index;
extern int g_security_printf_flag;


extern int dev;

int fpga_ccm_test(int test_mode, int flag);
extern int Soft_Make_VCT(U1 *pub_key, U1 *cipher, U1 *atag);
extern int Soft_Decrypt_Ecies(U1 *pub_key, U1 *cipher, U1 *atag, U1 *plain_key);
int Decode_Encrypted_Message(U1 *rx_buf, U2 len);



int fpga_aes_key_setting(unsigned char *key)
{
	U4_T key_buf[4];
	int i, j;

	i = 0;
	j = 0;

	for ( i = 0; i < 4; i++)
	{
		key_buf[i].b1[3] = key[j++];
		key_buf[i].b1[2] = key[j++];
		key_buf[i].b1[1] = key[j++];
		key_buf[i].b1[0] = key[j++];
	}

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + AES_KEY0_H_REG_OFFSET), key_buf[0].b4);
	reg_writel((wave_dsrc_base + AES_KEY1_H_REG_OFFSET), key_buf[1].b4);
	reg_writel((wave_dsrc_base + AES_KEY2_H_REG_OFFSET), key_buf[2].b4);
	reg_writel((wave_dsrc_base + AES_KEY3_H_REG_OFFSET), key_buf[3].b4);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(AES_KEY0_H_REG_OFFSET, key_buf[0].b4);
	write_wave_ecc_reg32_by_16bit_or_32bit(AES_KEY1_H_REG_OFFSET, key_buf[1].b4);
	write_wave_ecc_reg32_by_16bit_or_32bit(AES_KEY2_H_REG_OFFSET, key_buf[2].b4);
	write_wave_ecc_reg32_by_16bit_or_32bit(AES_KEY3_H_REG_OFFSET, key_buf[3].b4);
#endif

	return(0);
}

/* SHKO, Added */
/* flag가 1이면 인터럽트 방식, flag가 0이면 폴링 방식 */
int fpga_aes_encrypt(const unsigned char *in, unsigned char *out, int flag)
{   
	U4_T in_buf[4];
	U4_T out_buf[4];
	int i, j;
	volatile U4 status;
	int time_out;
	U4 wave_ecc_interrupt_status;
	int ret = 0;
	//double operating_time;
    	//struct timeval start_point, end_point;

	//gettimeofday(&start_point, NULL);

	i = 0;
	j = 0;

	for ( i = 0; i < 4; i++)
	{
		in_buf[i].b1[3] = in[j++];
		in_buf[i].b1[2] = in[j++];
		in_buf[i].b1[1] = in[j++];
		in_buf[i].b1[0] = in[j++];
	}

	//printf("AES_KEY0_H_REG_OFFSET = 0x%08x\n", read_wave_ecc_reg32(AES_KEY0_H_REG_OFFSET));
	//printf("AES_KEY1_H_REG_OFFSET = 0x%08x\n", read_wave_ecc_reg32(AES_KEY1_H_REG_OFFSET));
	//printf("AES_KEY2_H_REG_OFFSET = 0x%08x\n", read_wave_ecc_reg32(AES_KEY2_H_REG_OFFSET));
	//printf("AES_KEY3_H_REG_OFFSET = 0x%08x\n", read_wave_ecc_reg32(AES_KEY3_H_REG_OFFSET));

	/* 평문 : 00112233445566778899aabbccddeeff */
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + AES_DATA0_H_REG_OFFSET), in_buf[0].b4);
	reg_writel((wave_dsrc_base + AES_DATA1_H_REG_OFFSET), in_buf[1].b4);
	reg_writel((wave_dsrc_base + AES_DATA2_H_REG_OFFSET), in_buf[2].b4);
	reg_writel((wave_dsrc_base + AES_DATA3_H_REG_OFFSET), in_buf[3].b4);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(AES_DATA0_H_REG_OFFSET, in_buf[0].b4);
	write_wave_ecc_reg32_by_16bit_or_32bit(AES_DATA1_H_REG_OFFSET, in_buf[1].b4);
	write_wave_ecc_reg32_by_16bit_or_32bit(AES_DATA2_H_REG_OFFSET, in_buf[2].b4);
	write_wave_ecc_reg32_by_16bit_or_32bit(AES_DATA3_H_REG_OFFSET, in_buf[3].b4);
#endif
	

	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, AES_ENABLE_BIT);

	//printf("AES_DATA0_H_REG_OFFSET = 0x%08x\n", read_wave_ecc_reg32(AES_DATA0_H_REG_OFFSET));
	//printf("AES_DATA1_H_REG_OFFSET = 0x%08x\n", read_wave_ecc_reg32(AES_DATA1_H_REG_OFFSET));
	//printf("AES_DATA2_H_REG_OFFSET = 0x%08x\n", read_wave_ecc_reg32(AES_DATA2_H_REG_OFFSET));
	//printf("AES_DATA3_H_REG_OFFSET = 0x%08x\n", read_wave_ecc_reg32(AES_DATA3_H_REG_OFFSET));
	if (flag)
	{
		time_out = 20000;
		while(time_out--)
		{	
			ret  = ioctl(dev, IOCTLWAVE_ECC_INT_READ, &wave_ecc_interrupt_status);
			if (ret != 0)
			{
				perror("[fpga_aes_encrypt] ioctl:");
				break;
			}
			else
			{
				if (wave_ecc_interrupt_status == AES_DONE)
				{
					break;
				}
			}
		}
	}
	else
	{
		time_out = 2000;
		while(time_out--)
		{
			status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
			
			if (status & AES_DONE_BIT)	/* AES Done */
				break;
		}
		//printf("[fpga_aes_encrypt] status=0x%08x\n", status);
		
		write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, AES_DONE_BIT);
	}

	//printf("[fpga_aes_encrypt] status=0x%08x\n", read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET));

	if (time_out < 0)
		printf("[fpga_aes_encrypt] Time Out!!\n");
	//sleep(1);
	//if (aes_print_flag)
	//	printf("[fpga_aes_encrypt]status=0x%08x, time_out=%d\n",status, time_out);
	

	//printf("AES_DATA0_H_REG_OFFSET = 0x%08x\n", read_wave_ecc_reg32(AES_DATA0_H_REG_OFFSET));
	//printf("AES_DATA1_H_REG_OFFSET = 0x%08x\n", read_wave_ecc_reg32(AES_DATA1_H_REG_OFFSET));
	//printf("AES_DATA2_H_REG_OFFSET = 0x%08x\n", read_wave_ecc_reg32(AES_DATA2_H_REG_OFFSET));
	//printf("AES_DATA3_H_REG_OFFSET = 0x%08x\n", read_wave_ecc_reg32(AES_DATA3_H_REG_OFFSET));

	/* result = 69c4e0d86a7b0430d8cdb78070b4c55a */
#if 0
	out_buf[0].b4 = read_wave_ecc_reg32(AES_OUT0_H_REG_OFFSET);
	out_buf[1].b4 = read_wave_ecc_reg32(AES_OUT1_H_REG_OFFSET);
	out_buf[2].b4 = read_wave_ecc_reg32(AES_OUT2_H_REG_OFFSET);
	out_buf[3].b4 = read_wave_ecc_reg32(AES_OUT3_H_REG_OFFSET);
#else
	out_buf[0].b4 = reg_readl((wave_dsrc_base + AES_OUT0_H_REG_OFFSET));
	out_buf[1].b4 = reg_readl((wave_dsrc_base + AES_OUT1_H_REG_OFFSET));
	out_buf[2].b4 = reg_readl((wave_dsrc_base + AES_OUT2_H_REG_OFFSET));
	out_buf[3].b4 = reg_readl((wave_dsrc_base + AES_OUT3_H_REG_OFFSET));
#endif

	//if (aes_print_flag)
	//	printf("[fpga_aes_encrypt]status=0x%08x, time_out=%d\n",status, time_out);
	
	i = 0;
#if 0
	for ( j = 0; j < 4; j++)
	{
		out[i++]=out_buf[j].b1[1];
		out[i++]=out_buf[j].b1[0];
		out[i++]=out_buf[j].b1[3];
		out[i++]=out_buf[j].b1[2];
		
	}
#else
	for ( j = 0; j < 4; j++)
	{
		out[i++]=out_buf[j].b1[3];
		out[i++]=out_buf[j].b1[2];
		out[i++]=out_buf[j].b1[1];
		out[i++]=out_buf[j].b1[0];
		
	}
#endif
#if 0
	printf("AES_OUT0_H_REG_OFFSET = 0x%02x, 0x%02x, 0x%02x, 0x%02x\n", out_buf[0].b1[0], out_buf[0].b1[1], out_buf[0].b1[2], out_buf[0].b1[3]);
	printf("AES_OUT1_H_REG_OFFSET = 0x%02x, 0x%02x, 0x%02x, 0x%02x\n", out_buf[1].b1[0], out_buf[1].b1[1], out_buf[1].b1[2], out_buf[1].b1[3]);
	printf("AES_OUT2_H_REG_OFFSET = 0x%02x, 0x%02x, 0x%02x, 0x%02x\n", out_buf[2].b1[0], out_buf[2].b1[1], out_buf[2].b1[2], out_buf[2].b1[3]);
	printf("AES_OUT3_H_REG_OFFSET = 0x%02x, 0x%02x, 0x%02x, 0x%02x\n", out_buf[3].b1[0], out_buf[3].b1[1], out_buf[3].b1[2], out_buf[3].b1[3]);

	for ( i = 0; i < 16; i++)
		printf("[%02x]", out[i]);

	printf("\n");
#endif
	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("%f\n",operating_time);
	return(0);
}


/* SHKO : NIST SP 800-38C 규격 A.2.1 참조 */
int formatting_block0(unsigned int nounce_len, unsigned char *nounce, unsigned int associate_data_len, unsigned int payload_len, 
					 unsigned int mac_len, unsigned char *block)
{
	unsigned char mac_field;
	unsigned char q_field;
	unsigned char adata_field;
	int i,j,k;
	unsigned char q;
	unsigned char Q[256];
	U4_T	len;

	mac_field = (mac_len-2)/2;
	q_field = (15-nounce_len) - 1;

	if ( associate_data_len )
		adata_field = 1;
	else
		adata_field = 0;
	
	i = 0;
	block[i++] = (adata_field << 6) | (mac_field << 3) | q_field;

	q = 15 - nounce_len;
	j = 0;
	for ( ; i <= (15-q); i++)
	{
		block[i] = nounce[j++];
	}

	len.b4 = payload_len;

	j = 0;

	for ( k = (q-1); k >= 0; k--)
	{
		if ( j < 4 )	/* 4는 길이 필드의 최대 길이 */
			Q[k] = len.b1[j++];
		else
			Q[k] = 0;
	}

	j = 0;
	for ( ; i <= 15; i++)
	{
		block[i] = Q[j++];
	}

	

	return(i);
}

/* SHKO : NIST SP 800-38C 규격 A.2.2 참조 */
int formatting_associated_data(U8 associate_data_len, unsigned char *associate_data, unsigned char *block)
{
	int i = 0;
	int j, k;
	int n;
	int associate_len_field_len;
	U4_T	len;
	int remain;

	if (associate_data_len <= 0)
	{
		//printf("[formatting_associated_data] invalid associate_data_len = %d\n", associate_data_len);
		return(0);
	}

	len.b4 = associate_data_len;

	if (associate_data_len < 0xFF00) /* 0xFF00 = 2^16 - 2^8 */
	{
		associate_len_field_len = 2;
	}
	else if (associate_data_len < 0x100000000) /* 0x100000000 = 2^32 */
	{
		associate_len_field_len = 4;
		block[i++] = 0xFF;
		block[i++] = 0xFE;

	}
	else if (associate_data_len < 0x1999999999999999) /* 0x1999999999999999 = 2^64 */
	{
		associate_len_field_len = 8;
		block[i++] = 0xFF;
		block[i++] = 0xFF;
	}

	if ( associate_len_field_len > 4 )	/* 4는 길이 필드의 최대 길이 */
		n = associate_len_field_len - 4;	/* 4는 길이 필드의 최대 길이 */
	else
		n = 4 - associate_len_field_len;

	j = 0;

	for ( k = (associate_len_field_len-1); k >= 0; k--)
	{
		if ( k < 4 )	/* 4는 길이 필드의 최대 길이 */
			block[i++] = len.b1[k];
		else
			block[i++] = 0;
	}

	for ( j = 0; j < associate_data_len; j++)
	{
		block[i++] = associate_data[j];
	}

	remain = i % AES_BLOCK_SIZE;
	if(remain)
	{
		for ( j = remain; j < AES_BLOCK_SIZE; j++ )
			block[i++] = 0;
	}
	return(i);
}

/* SHKO : NIST SP 800-38C 규격 A.2.3 참조 */
int formatting_payload_data(unsigned int payload_len, unsigned char *payload, unsigned char *block)
{
	int i = 0;
	int j = 0;
	int remain;

	if (payload_len <= 0)
	{
		printf("[formatting_payload_data] invalid payload_len = %d\n", payload_len);
		return(-1);
	}

	for ( i = 0; i < payload_len; i++)
	{
		block[i] = payload[i];
	}

	remain = i % AES_BLOCK_SIZE;
	if(remain)
	{
		for ( j = remain; j < AES_BLOCK_SIZE; j++ )
			block[i++] = 0;
	}
	return(i);
}

/* SHKO : NIST SP 800-38C 규격 A.3 참조 */
int formatting_counter_blocks(unsigned int nounce_len, unsigned char *nounce, int counter_block_cnt, unsigned char *counter_block)
{
	unsigned char q_field;
	unsigned char adata_field;
	int i,j,k,n,m;
	unsigned char q;
	unsigned char Q[256];
	U4_T	count;

	q_field = (15-nounce_len) - 1;
	
	i = 0;
	q = 15 - nounce_len;


	for ( k = 0; k < counter_block_cnt; k++ )
	{
		count.b4 = k;
		counter_block[i++] = q_field;
		n = 0;
		m = 0;

		for ( j = 0 ; j < nounce_len; j++)
		{
			counter_block[i++] = nounce[j];
		}

		for ( ; j < 15; j++)
		{
			if ((q - n) > 4) 	/* 4는 길이 필드의 최대 길이 */
			{
				counter_block[i++] = 0;
				n++;
			}
			else
			{
				if (q < 4)		/* 4는 길이 필드의 최대 길이 */
					counter_block[i++] = count.b1[q-1-m];
				else
					counter_block[i++] = count.b1[3-m];

				n++;
				m++;
			}
		}
	}

	return(i);
}


/* SHKO : NIST SP 800-38C 규격 A.2.1 참조 */
int formatting_block(unsigned int nounce_len, unsigned char *nounce, U8 associate_data_len, unsigned char *associate_data, unsigned int payload_len, 
					 unsigned char *payload, unsigned int mac_len, unsigned char *block)
{
	int index = 0;
	int i;

	index = formatting_block0(nounce_len, nounce, associate_data_len, payload_len,mac_len, block);
	index += formatting_associated_data(associate_data_len, associate_data, &block[index]);
	index += formatting_payload_data(payload_len, payload, &block[index]);

#if 0
	printf("index=%d\n", index);

	for ( i = 0; i < index; i++)
	{
		printf("[%02x]", block[i]);
		if ( (i+1) % 16 == 0 )
			printf("\n");
	}
	printf("\n");
#endif

	return(index);

}

/* flag가 1이면 인터럽트 방식, flag가 0이면 폴링 방식 */
int fpga_ccm_test(int test_mode, int flag)
{
	int    i, j;
	int k;
	unsigned char *kp;
	unsigned char *ip;
	unsigned char *hp;
	unsigned char *tp;
	int mac_len;
	unsigned char plain_text[32];
	unsigned char ctr[AES_BLOCK_SIZE*5120];
	unsigned char z[AES_BLOCK_SIZE];
	unsigned char s[AES_BLOCK_SIZE*5120];
	int payload_len;
	/* 아래 a, b, c, p, t 배열의 크기는 최소한 payload_len 만큼의 크기는 가져야 한다. */
	unsigned char a[AES_BLOCK_SIZE*2], b[AES_BLOCK_SIZE*2], c[AES_BLOCK_SIZE*2];
	unsigned char p[AES_BLOCK_SIZE*2], t[AES_BLOCK_SIZE*2];
	int c_len;
	unsigned char block[AES_BLOCK_SIZE*5120];
	int total_len;
	int block_cnt;
	unsigned char y[AES_BLOCK_SIZE*5120];
	int count_block_cnt;
	int count_block_total_len;
	int remain;
	int key_len;
	int iv_len;
	U8 hdr_len;
	//volatile unsigned int reg_value;
	struct timeval start_point, end_point;
	volatile double operating_time;
	int index0, index1;
	unsigned char expected_payload[32];
	unsigned char expected_cipher_text[46];
	unsigned char expected_mac[32];
	int cipher_text_len;

	//reg_value = reg_readl((gpio_base + 0x14));
	//reg_value |= 0x200;
	//reg_writel((gpio_base + 0x14), reg_value);	/* GPB9 OutputData Setting, CON1의 48번 핀 */

	if (aes_print_flag)
	{
		printf("=================================\n");
		printf("[fpga_ccm_test] Transmit Part!!\n");
		printf("=================================\n");
	}
	gettimeofday(&start_point, NULL);

	switch(test_mode)
	{
		case 1:	/* SHKO : NIST SP 800-38C 규격 Appendix C.1 참조 */
			key_len = 16;
			iv_len = 7;			/* Nounce 길이 */
			hdr_len = 8;			/* Associate Data 길이 */
			mac_len = 4;			/* Message Authentication Code 길이 */
			payload_len = 4;		/* 평문의 길이 */
			cipher_text_len = 8;

			i = 0;
			expected_payload[i++] = 0x20;
			expected_payload[i++] = 0x21;
			expected_payload[i++] = 0x22;
			expected_payload[i++] = 0x23;

			i = 0;
			expected_cipher_text[i++] = 0x71;
			expected_cipher_text[i++] = 0x62;
			expected_cipher_text[i++] = 0x01;
			expected_cipher_text[i++] = 0x5B;
			expected_cipher_text[i++] = 0x4D;
			expected_cipher_text[i++] = 0xAC;
			expected_cipher_text[i++] = 0x25;
			expected_cipher_text[i++] = 0x5D;

			i = 0;
			expected_mac[i++] = 0x60;
			expected_mac[i++] = 0x84;
			expected_mac[i++] = 0x34;
			expected_mac[i++] = 0x1B;
			break;

		case 2:	/* SHKO : NIST SP 800-38C 규격 Appendix C.2 참조 */
			key_len = 16;
			mac_len = 6;
			iv_len = 8;
			hdr_len = 16;
			payload_len = 16;
			cipher_text_len = 22;

			i = 0;
			expected_payload[i++] = 0x20;
			expected_payload[i++] = 0x21;
			expected_payload[i++] = 0x22;
			expected_payload[i++] = 0x23;
			expected_payload[i++] = 0x24;
			expected_payload[i++] = 0x25;
			expected_payload[i++] = 0x26;
			expected_payload[i++] = 0x27;
			expected_payload[i++] = 0x28;
			expected_payload[i++] = 0x29;
			expected_payload[i++] = 0x2A;
			expected_payload[i++] = 0x2B;
			expected_payload[i++] = 0x2C;
			expected_payload[i++] = 0x2D;
			expected_payload[i++] = 0x2E;
			expected_payload[i++] = 0x2F;

			i = 0;
			expected_cipher_text[i++] = 0xD2;
			expected_cipher_text[i++] = 0xA1;
			expected_cipher_text[i++] = 0xF0;
			expected_cipher_text[i++] = 0xE0;
			expected_cipher_text[i++] = 0x51;
			expected_cipher_text[i++] = 0xEA;
			expected_cipher_text[i++] = 0x5F;
			expected_cipher_text[i++] = 0x62;

			expected_cipher_text[i++] = 0x08;
			expected_cipher_text[i++] = 0x1A;
			expected_cipher_text[i++] = 0x77;
			expected_cipher_text[i++] = 0x92;
			expected_cipher_text[i++] = 0x07;
			expected_cipher_text[i++] = 0x3D;
			expected_cipher_text[i++] = 0x59;
			expected_cipher_text[i++] = 0x3D;

			expected_cipher_text[i++] = 0x1F;
			expected_cipher_text[i++] = 0xC6;
			expected_cipher_text[i++] = 0x4F;
			expected_cipher_text[i++] = 0xBF;
			expected_cipher_text[i++] = 0xAC;
			expected_cipher_text[i++] = 0xCD;

			i = 0;
			expected_mac[i++] = 0x7F;
			expected_mac[i++] = 0x47;
			expected_mac[i++] = 0x9F;
			expected_mac[i++] = 0xFC;
			expected_mac[i++] = 0xA4;
			expected_mac[i++] = 0x64;
			break;

		case 3:	/* SHKO : NIST SP 800-38C 규격 Appendix C.3 참조 */
			key_len = 16;
			mac_len = 8;
			iv_len = 12;
			hdr_len = 20;
			payload_len = 24;
			cipher_text_len = 32;

			i = 0;
			expected_payload[i++] = 0x20;
			expected_payload[i++] = 0x21;
			expected_payload[i++] = 0x22;
			expected_payload[i++] = 0x23;
			expected_payload[i++] = 0x24;
			expected_payload[i++] = 0x25;
			expected_payload[i++] = 0x26;
			expected_payload[i++] = 0x27;
			
			expected_payload[i++] = 0x28;
			expected_payload[i++] = 0x29;
			expected_payload[i++] = 0x2A;
			expected_payload[i++] = 0x2B;
			expected_payload[i++] = 0x2C;
			expected_payload[i++] = 0x2D;
			expected_payload[i++] = 0x2E;
			expected_payload[i++] = 0x2F;

			expected_payload[i++] = 0x30;
			expected_payload[i++] = 0x31;
			expected_payload[i++] = 0x32;
			expected_payload[i++] = 0x33;
			expected_payload[i++] = 0x34;
			expected_payload[i++] = 0x35;
			expected_payload[i++] = 0x36;
			expected_payload[i++] = 0x37;

			i = 0;
			expected_cipher_text[i++] = 0xE3;
			expected_cipher_text[i++] = 0xB2;
			expected_cipher_text[i++] = 0x01;
			expected_cipher_text[i++] = 0xA9;
			expected_cipher_text[i++] = 0xF5;
			expected_cipher_text[i++] = 0xB7;
			expected_cipher_text[i++] = 0x1A;
			expected_cipher_text[i++] = 0x7A;

			expected_cipher_text[i++] = 0x9B;
			expected_cipher_text[i++] = 0x1C;
			expected_cipher_text[i++] = 0xEA;
			expected_cipher_text[i++] = 0xEC;
			expected_cipher_text[i++] = 0xCD;
			expected_cipher_text[i++] = 0x97;
			expected_cipher_text[i++] = 0xE7;
			expected_cipher_text[i++] = 0x0B;

			expected_cipher_text[i++] = 0x61;
			expected_cipher_text[i++] = 0x76;
			expected_cipher_text[i++] = 0xAA;
			expected_cipher_text[i++] = 0xD9;
			expected_cipher_text[i++] = 0xA4;
			expected_cipher_text[i++] = 0x42;
			expected_cipher_text[i++] = 0x8A;
			expected_cipher_text[i++] = 0xA5;

			expected_cipher_text[i++] = 0x48;
			expected_cipher_text[i++] = 0x43;
			expected_cipher_text[i++] = 0x92;
			expected_cipher_text[i++] = 0xFB;
			expected_cipher_text[i++] = 0xC1;
			expected_cipher_text[i++] = 0xB0;
			expected_cipher_text[i++] = 0x99;
			expected_cipher_text[i++] = 0x51;

			i = 0;
			expected_mac[i++] = 0x67;
			expected_mac[i++] = 0xC9;
			expected_mac[i++] = 0x92;
			expected_mac[i++] = 0x40;
			expected_mac[i++] = 0xC7;
			expected_mac[i++] = 0xD5;
			expected_mac[i++] = 0x10;
			expected_mac[i++] = 0x48;
			break;

		case 4:	/* SHKO : NIST SP 800-38C 규격 Appendix C.4 참조 */
			key_len = 16;
			mac_len = 14;
			iv_len = 13;
			hdr_len = 65536;
			payload_len = 32;
			cipher_text_len = 46;

			i = 0;
			expected_payload[i++] = 0x20;
			expected_payload[i++] = 0x21;
			expected_payload[i++] = 0x22;
			expected_payload[i++] = 0x23;
			expected_payload[i++] = 0x24;
			expected_payload[i++] = 0x25;
			expected_payload[i++] = 0x26;
			expected_payload[i++] = 0x27;
			
			expected_payload[i++] = 0x28;
			expected_payload[i++] = 0x29;
			expected_payload[i++] = 0x2A;
			expected_payload[i++] = 0x2B;
			expected_payload[i++] = 0x2C;
			expected_payload[i++] = 0x2D;
			expected_payload[i++] = 0x2E;
			expected_payload[i++] = 0x2F;

			expected_payload[i++] = 0x30;
			expected_payload[i++] = 0x31;
			expected_payload[i++] = 0x32;
			expected_payload[i++] = 0x33;
			expected_payload[i++] = 0x34;
			expected_payload[i++] = 0x35;
			expected_payload[i++] = 0x36;
			expected_payload[i++] = 0x37;

			expected_payload[i++] = 0x38;
			expected_payload[i++] = 0x39;
			expected_payload[i++] = 0x3A;
			expected_payload[i++] = 0x3B;
			expected_payload[i++] = 0x3C;
			expected_payload[i++] = 0x3D;
			expected_payload[i++] = 0x3E;
			expected_payload[i++] = 0x3F;

			i = 0;
			expected_cipher_text[i++] = 0x69;
			expected_cipher_text[i++] = 0x91;
			expected_cipher_text[i++] = 0x5D;
			expected_cipher_text[i++] = 0xAD;
			expected_cipher_text[i++] = 0x1E;
			expected_cipher_text[i++] = 0x84;
			expected_cipher_text[i++] = 0xC6;
			expected_cipher_text[i++] = 0x37;

			expected_cipher_text[i++] = 0x6A;
			expected_cipher_text[i++] = 0x68;
			expected_cipher_text[i++] = 0xC2;
			expected_cipher_text[i++] = 0x96;
			expected_cipher_text[i++] = 0x7E;
			expected_cipher_text[i++] = 0x4D;
			expected_cipher_text[i++] = 0xAB;
			expected_cipher_text[i++] = 0x61;

			expected_cipher_text[i++] = 0x5A;
			expected_cipher_text[i++] = 0xE0;
			expected_cipher_text[i++] = 0xFD;
			expected_cipher_text[i++] = 0x1F;
			expected_cipher_text[i++] = 0xAE;
			expected_cipher_text[i++] = 0xC4;
			expected_cipher_text[i++] = 0x4C;
			expected_cipher_text[i++] = 0xC4;

			expected_cipher_text[i++] = 0x84;
			expected_cipher_text[i++] = 0x82;
			expected_cipher_text[i++] = 0x85;
			expected_cipher_text[i++] = 0x29;
			expected_cipher_text[i++] = 0x46;
			expected_cipher_text[i++] = 0x3C;
			expected_cipher_text[i++] = 0xCF;
			expected_cipher_text[i++] = 0x72;

			expected_cipher_text[i++] = 0xB4;
			expected_cipher_text[i++] = 0xAC;
			expected_cipher_text[i++] = 0x6B;
			expected_cipher_text[i++] = 0xEC;
			expected_cipher_text[i++] = 0x93;
			expected_cipher_text[i++] = 0xE8;
			expected_cipher_text[i++] = 0x59;
			expected_cipher_text[i++] = 0x8E;

			expected_cipher_text[i++] = 0x7F;
			expected_cipher_text[i++] = 0x0D;
			expected_cipher_text[i++] = 0xAD;
			expected_cipher_text[i++] = 0xBC;
			expected_cipher_text[i++] = 0xEA;
			expected_cipher_text[i++] = 0x5B;

			i = 0;
			expected_mac[i++] = 0xF4;
			expected_mac[i++] = 0xDD;
			expected_mac[i++] = 0x5D;
			expected_mac[i++] = 0x0E;
			expected_mac[i++] = 0xE4;
			expected_mac[i++] = 0x04;
			expected_mac[i++] = 0x61;
			expected_mac[i++] = 0x72;

			expected_mac[i++] = 0x25;
			expected_mac[i++] = 0xFF;
			expected_mac[i++] = 0xE3;
			expected_mac[i++] = 0x4F;
			expected_mac[i++] = 0xCE;
			expected_mac[i++] = 0x91;
			break;
	}
	
	c_len = payload_len + mac_len;

	kp = malloc(key_len);
	ip = malloc(iv_len);
	hp = malloc(hdr_len);

	for (i = 0; i < key_len; i++)
		kp[i] = 0x40 + i;
	
	for (i = 0; i < iv_len; i++)
		ip[i] = 0x10 + i;

	for (i = 0; i < hdr_len; i++)
		hp[i] = i;

	for (i = 0; i < payload_len; i++)
		plain_text[i] = 0x20 + i;


	fpga_aes_key_setting(kp);
		

	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("1. %f\n",operating_time);


	//gettimeofday(&start_point, NULL);

	total_len = formatting_block(iv_len, ip, hdr_len, hp, payload_len, plain_text, mac_len, block);

	block_cnt = total_len / AES_BLOCK_SIZE;

	remain = payload_len % AES_BLOCK_SIZE;
	if (remain)
	{
		count_block_cnt = (payload_len / AES_BLOCK_SIZE) + 2;
	}
	else
	{
		count_block_cnt = (payload_len / AES_BLOCK_SIZE) + 1;
	}

	
	/* SHKO : NIST SP 800-38C 규격 6.1 참조 */
	fpga_aes_encrypt(&block[AES_BLOCK_SIZE*0], &y[AES_BLOCK_SIZE*0], flag);	/* Y0 = CIPHk(B0) */

	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("2.%f\n",operating_time);
#if 0	//SHKO
	if (aes_print_flag)
	{
		printf("Display y\n");
		for(i = 0; i < AES_BLOCK_SIZE; i++)
		{
			printf("[%02x]", y[(AES_BLOCK_SIZE*0)+i]);
		}
		printf("\n");
	}
#endif

	operating_time = 0;
	//block_cnt = 50;
	//gettimeofday(&start_point, NULL);
	/* For i=1 to r, do Yi = CIPHK(Bi^Yi-1) */
	for ( i = 1; i < block_cnt; i++ )
	{
		//gettimeofday(&start_point, NULL);

		index0 = AES_BLOCK_SIZE*i;
		index1 = AES_BLOCK_SIZE*(i-1);
		
		for ( k = 0; k < AES_BLOCK_SIZE; k++)
		{
			z[k] = block[index0 + k] ^ y[index1 + k];
		}

		fpga_aes_encrypt(z, &y[index0], flag);

#if 0	//SHKO
		if (aes_print_flag)
		{
			printf("Display y%d\n",index0);
			for(j = 0; j < AES_BLOCK_SIZE; j++)
			{
				printf("[%02x]", y[index0+j]);
			}
			printf("\n");
		}
#endif

		//gettimeofday(&end_point, NULL);

		//operating_time += (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
		//if ( i == (block_cnt - 1) )
		//	printf("3.%f\n",operating_time);
	}
	//printf("4.%f\n",operating_time);
	

	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("3.%f, block_cnt=%d\n",operating_time, block_cnt);

	//gettimeofday(&start_point, NULL);

	if (aes_print_flag)
	{
		printf("\nDisplay T, block_cnt=%d\n", block_cnt);
		for(i = 0; i < mac_len; i++)
		{
			printf("[%02x]", y[(AES_BLOCK_SIZE*(block_cnt-1)) + i]);
		}
		printf("\n");
	}

	

	count_block_total_len = formatting_counter_blocks(iv_len, ip, count_block_cnt, ctr);

	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("4.%f\n",operating_time);

	//gettimeofday(&start_point, NULL);

	if (aes_print_flag)
	{
		printf("count_block_total_len=%d\n", count_block_total_len);

		for ( i = 0; i < count_block_total_len; i++)
		{
			printf("[%02x]", ctr[i]);
			if ( (i+1) % 16 == 0 )
				printf("\n");
		}
		printf("\n");
	}

	for ( i = 0; i < count_block_cnt; i++)
	{
		fpga_aes_encrypt(&ctr[(AES_BLOCK_SIZE*i)], &s[(AES_BLOCK_SIZE*i)], flag);
	}

	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("5.%f\n",operating_time);

	//gettimeofday(&start_point, NULL);

	if (aes_print_flag)
	{
		printf("Display S0\n");
		for(i = 0; i < AES_BLOCK_SIZE; i++)
		{
			printf("[%02x]", s[(AES_BLOCK_SIZE*0)+i]);
		}
		printf("\n");

		printf("Display S1\n");
		for(i = 0; i < AES_BLOCK_SIZE; i++)
		{
			printf("[%02x]", s[(AES_BLOCK_SIZE*1)+i]);
		}
		printf("\n");
	}

#if 0	//SHKO
	if (aes_print_flag)
	{
		printf("Display a\n");
	}
#endif
	for(i = 0; i < payload_len; i++)
	{
		a[i] = plain_text[i] ^ s[(AES_BLOCK_SIZE*1)+i];
	#if 0	//SHKO
		if (aes_print_flag)
			printf("[%02x]", a[i]);
	#endif
	}
#if 0
	if (aes_print_flag)
		printf("\n");
	
	if (aes_print_flag)
		printf("Display b\n");
#endif
	
	for(i = 0; i < mac_len; i++)
	{
		//b[i] = y2[i] ^ s0[i];
		b[i] = y[(AES_BLOCK_SIZE*(block_cnt-1)) + i] ^ s[(AES_BLOCK_SIZE*0)+i];
	#if 0	//SHKO
		if (aes_print_flag)
			printf("[%02x]", b[i]);
	#endif
	}
#if 0	//SHKO
	if (aes_print_flag)
		printf("\n");
#endif

	k = 0;
	for(i = 0; i < (payload_len); i++)
	{
		c[k++] = a[i];
		
	}

	for(i = 0; i < (mac_len); i++)
	{
		c[k++] = b[i];
	}

	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("6.%f\n",operating_time);

	//gettimeofday(&start_point, NULL);

	if (aes_print_flag)
	{
		printf("\nDisplay C\n");
		for(i = 0; i < (payload_len + mac_len); i++)
		{
			printf("[%02x]", c[i]);
		}
		printf("\n");
	}

	if (aes_print_flag)
	{
		printf("\n\n=================================\n");
		printf("[fpga_ccm_test] Receive Part!!\n");
		printf("=================================\n");
	}

#if 0
	if (aes_print_flag)
		printf("AEC CCM Decryption Start\n");
#endif

	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("7.%f\n",operating_time);

	//gettimeofday(&start_point, NULL);
	for ( i = 0; i < count_block_cnt; i++)
	{
		fpga_aes_encrypt(&ctr[(AES_BLOCK_SIZE*i)], &s[(AES_BLOCK_SIZE*i)], flag);
	}

	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("8.%f\n",operating_time);

	//gettimeofday(&start_point, NULL);

	if (aes_print_flag)
		printf("Display Plain Text\n");
	for(i = 0; i < payload_len; i++)
	{
		p[i] = c[i] ^ s[(AES_BLOCK_SIZE*1)+i];
		if (aes_print_flag)
			printf("[%02x]", p[i]);
	}
	if (aes_print_flag)
		printf("\n");

	if (aes_print_flag)
		printf("Display T\n");
	for(i = 0; i < mac_len; i++)
	{
		t[i] = c[(c_len - mac_len + i)] ^ s[(AES_BLOCK_SIZE*0)+i];
		if (aes_print_flag)
			printf("[%02x]", t[i]);
	}
	if (aes_print_flag)
		printf("\n");

	fpga_aes_encrypt(&block[AES_BLOCK_SIZE*0], &y[AES_BLOCK_SIZE*0], flag);
		
	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("9.%f\n",operating_time);

	//gettimeofday(&start_point, NULL);
#if 0	/* SHKO, Origin */
	for ( i = 1; i < block_cnt; i++ )
	{
		for ( k = 0; k < AES_BLOCK_SIZE; k++)
		{
			z[k] = block[(AES_BLOCK_SIZE*i) + k] ^ y[(AES_BLOCK_SIZE*(i-1)) + k];
		}
	
		fpga_aes_encrypt(z, &y[AES_BLOCK_SIZE*i], flag);
			
	}
#else
	total_len = formatting_block(iv_len, ip, hdr_len, hp, payload_len, p, mac_len, block);

	block_cnt = total_len / AES_BLOCK_SIZE;

	remain = payload_len % AES_BLOCK_SIZE;
	if (remain)
	{
		count_block_cnt = (payload_len / AES_BLOCK_SIZE) + 2;
	}
	else
	{
		count_block_cnt = (payload_len / AES_BLOCK_SIZE) + 1;
	}

	/* SHKO : NIST SP 800-38C 규격 6.1 참조 */
	fpga_aes_encrypt(&block[AES_BLOCK_SIZE*0], &y[AES_BLOCK_SIZE*0], flag);	/* Y0 = CIPHk(B0) */

	/* For i=1 to r, do Yi = CIPHK(Bi^Yi-1) */
	for ( i = 1; i < block_cnt; i++ )
	{
		//gettimeofday(&start_point, NULL);

		index0 = AES_BLOCK_SIZE*i;
		index1 = AES_BLOCK_SIZE*(i-1);
		
		for ( k = 0; k < AES_BLOCK_SIZE; k++)
		{
			z[k] = block[index0 + k] ^ y[index1 + k];
		}

		fpga_aes_encrypt(z, &y[index0], flag);

	}
	
	if (aes_print_flag)
	{
		printf("\nDisplay T, block_cnt=%d\n", block_cnt);
		for(i = 0; i < mac_len; i++)
		{
			printf("[%02x]", y[(AES_BLOCK_SIZE*(block_cnt-1)) + i]);
		}
		printf("\n");
	}

#endif
	

	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("10.%f\n",operating_time);

	//gettimeofday(&start_point, NULL);

    	free(kp); 
	free(ip);
    	free(hp); 

	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("Operation Time : %f\n",operating_time);
	//reg_value = reg_readl((gpio_base + 0x14));
	//reg_value &= ~((unsigned int)0x200);
	//reg_writel((gpio_base + 0x14), reg_value);	/* GPB9 OutputData Setting, CON1의 48번 핀 */

	if( memcmp( &y[(AES_BLOCK_SIZE*(block_cnt-1))], expected_mac, mac_len ) == 0) 
	{
		printf("AES Encryption/Decryption MAC Success!!\n");
	}
	else
	{
		printf("AES Encryption/Decryption MAC Fail!!\n");
	}

	if( memcmp( p, expected_payload, payload_len ) == 0)
	{
		printf("AES Encryption/Decryption Payload Success!!\n");
	}
	else
	{
		printf("AES Encryption/Decryption Payload Fail!!\n");

		printf("Display Plain Text\n");
		for(i = 0; i < payload_len; i++)
		{
			printf("[%02x]", p[i]);
		}
		printf("\n");

		printf("Display expected payload\n");
		for(i = 0; i < payload_len; i++)
		{
			printf("[%02x]", expected_payload[i]);
		}
		printf("\n");
	}

	if( memcmp( c, expected_cipher_text, cipher_text_len ) == 0 )
	{
		printf("AES Encryption/Decryption Cipher Success!!\n");
	}
	else
	{
		printf("AES Encryption/Decryption Cipher Fail!!\n");
	}
	

    	return (0);
}


int fpga_aes_ccm_encryped(U1 *encrypt_msg, U1 *plain_msg, int plain_msg_len, U1 *nonce)
{
	int    i, j;
	int k;
	unsigned char *kp;
	//unsigned char ip[12];	/* nonce */
	unsigned char *hp;
	unsigned char *tp;
	int mac_len;
	unsigned char ctr[AES_BLOCK_SIZE*5120];
	unsigned char z[AES_BLOCK_SIZE];
	unsigned char s[AES_BLOCK_SIZE*5120];
	int payload_len;
	/* 아래 a, b, c, p, t 배열의 크기는 최소한 payload_len 만큼의 크기는 가져야 한다. */
	unsigned char a[AES_BLOCK_SIZE*128], b[AES_BLOCK_SIZE*128], c[AES_BLOCK_SIZE*128];
	unsigned char p[AES_BLOCK_SIZE*128], t[AES_BLOCK_SIZE*128];
	int c_len;
	unsigned char block[AES_BLOCK_SIZE*5120];
	int total_len;
	int block_cnt;
	unsigned char y[AES_BLOCK_SIZE*5120];
	int count_block_cnt;
	int count_block_total_len;
	int remain;
	int key_len;
	int iv_len;
	U8 hdr_len;
	//volatile unsigned int reg_value;
	struct timeval start_point, end_point;
	volatile double operating_time;
	int index0, index1;
	int cipher_text_len;
	int flag = 0;

	//reg_value = reg_readl((gpio_base + 0x14));
	//reg_value |= 0x200;
	//reg_writel((gpio_base + 0x14), reg_value);	/* GPB9 OutputData Setting, CON1의 48번 핀 */

	if (aes_print_flag)
	{
		printf("=================================\n");
		printf("[fpga_ccm_test] Transmit Part!!\n");
		printf("=================================\n");
	}

	if (aes_print_flag || g_security_printf_flag)
	{
		printf("Display Plain Message len:%d\n",plain_msg_len);
		for( i = 0; i < plain_msg_len; i++)
		{
			printf("[%02x]", plain_msg[i]);
			if ( ((i+1)%10) == 0 )
				printf("\n");
		}
		printf("\n");
	}

	if (aes_print_flag )
	{
		printf("\nDisplay nonce\n");
		for( i = 0; i < 12; i++)
		{
			printf("[%02x]", nonce[i]);
			if ( ((i+1)%10) == 0 )
				printf("\n");
		}
		printf("\n");
	}

	
	gettimeofday(&start_point, NULL);

	key_len = 16;
	iv_len = 12;	/* nonce */
	mac_len = 16;
	payload_len = plain_msg_len;
	cipher_text_len = payload_len + mac_len;
	hdr_len = 0;		/* Associate Len */
	
	c_len = payload_len + mac_len;

	kp = g_aes_key[g_aes_key_index];

	if (aes_print_flag )
	{
		printf("\nDisplay AES_KEY\n");
		for( i = 0; i < 16; i++)
		{
			printf("[%02x]", kp[i]);
			if ( ((i+1)%10) == 0 )
				printf("\n");
		}
		printf("\n");
	}
	
	//for (i = 0; i < iv_len; i++)
	//	ip[i] = 0x10 + i;

	hp = NULL;

	fpga_aes_key_setting(kp);
		

	total_len = formatting_block(iv_len, nonce, hdr_len, hp, payload_len, plain_msg, mac_len, block);

	block_cnt = total_len / AES_BLOCK_SIZE;

	remain = payload_len % AES_BLOCK_SIZE;
	if (remain)
	{
		count_block_cnt = (payload_len / AES_BLOCK_SIZE) + 2;
	}
	else
	{
		count_block_cnt = (payload_len / AES_BLOCK_SIZE) + 1;
	}

	
	/* SHKO : NIST SP 800-38C 규격 6.1 참조 */
	fpga_aes_encrypt(&block[AES_BLOCK_SIZE*0], &y[AES_BLOCK_SIZE*0], flag);	/* Y0 = CIPHk(B0) */

#if 0	//SHKO
	if (aes_print_flag)
	{
		printf("Display y\n");
		for(i = 0; i < AES_BLOCK_SIZE; i++)
		{
			printf("[%02x]", y[(AES_BLOCK_SIZE*0)+i]);
		}
		printf("\n");
	}
#endif

	operating_time = 0;
	//block_cnt = 50;
	//gettimeofday(&start_point, NULL);
	/* For i=1 to r, do Yi = CIPHK(Bi^Yi-1) */
	for ( i = 1; i < block_cnt; i++ )
	{
		//gettimeofday(&start_point, NULL);

		index0 = AES_BLOCK_SIZE*i;
		index1 = AES_BLOCK_SIZE*(i-1);
		
		for ( k = 0; k < AES_BLOCK_SIZE; k++)
		{
			z[k] = block[index0 + k] ^ y[index1 + k];
		}

		fpga_aes_encrypt(z, &y[index0], flag);

#if 0	//SHKO
		if (aes_print_flag)
		{
			printf("Display y%d\n",index0);
			for(j = 0; j < AES_BLOCK_SIZE; j++)
			{
				printf("[%02x]", y[index0+j]);
			}
			printf("\n");
		}
#endif

		//gettimeofday(&end_point, NULL);

		//operating_time += (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
		//if ( i == (block_cnt - 1) )
		//	printf("3.%f\n",operating_time);
	}
	//printf("4.%f\n",operating_time);
	

	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("3.%f, block_cnt=%d\n",operating_time, block_cnt);

	//gettimeofday(&start_point, NULL);

	if (aes_print_flag)
	{
		printf("\nDisplay T, block_cnt=%d\n", block_cnt);
		for(i = 0; i < mac_len; i++)
		{
			printf("[%02x]", y[(AES_BLOCK_SIZE*(block_cnt-1)) + i]);
		}
		printf("\n");
	}

	

	count_block_total_len = formatting_counter_blocks(iv_len, nonce, count_block_cnt, ctr);

	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("4.%f\n",operating_time);

	//gettimeofday(&start_point, NULL);
#if 0
	if (aes_print_flag)
	{
		printf("count_block_total_len=%d\n", count_block_total_len);

		for ( i = 0; i < count_block_total_len; i++)
		{
			printf("[%02x]", ctr[i]);
			if ( (i+1) % 16 == 0 )
				printf("\n");
		}
		printf("\n");
	}
#endif

	for ( i = 0; i < count_block_cnt; i++)
	{
		fpga_aes_encrypt(&ctr[(AES_BLOCK_SIZE*i)], &s[(AES_BLOCK_SIZE*i)], flag);
	}

#if 0
	if (aes_print_flag)
	{
		printf("Display S0\n");
		for(i = 0; i < AES_BLOCK_SIZE; i++)
		{
			printf("[%02x]", s[(AES_BLOCK_SIZE*0)+i]);
		}
		printf("\n");

		printf("Display S1\n");
		for(i = 0; i < AES_BLOCK_SIZE; i++)
		{
			printf("[%02x]", s[(AES_BLOCK_SIZE*1)+i]);
		}
		printf("\n");
	}
#endif

#if 0	//SHKO
	if (aes_print_flag)
	{
		printf("Display a\n");
	}
#endif
	for(i = 0; i < payload_len; i++)
	{
		a[i] = plain_msg[i] ^ s[(AES_BLOCK_SIZE*1)+i];
	#if 0	//SHKO
		if (aes_print_flag)
			printf("[%02x]", a[i]);
	#endif
	}
#if 0
	if (aes_print_flag)
		printf("\n");
	
	if (aes_print_flag)
		printf("Display b\n");
#endif
	
	for(i = 0; i < mac_len; i++)
	{
		//b[i] = y2[i] ^ s0[i];
		b[i] = y[(AES_BLOCK_SIZE*(block_cnt-1)) + i] ^ s[(AES_BLOCK_SIZE*0)+i];
	#if 0	//SHKO
		if (aes_print_flag)
			printf("[%02x]", b[i]);
	#endif
	}
#if 0	//SHKO
	if (aes_print_flag)
		printf("\n");
#endif

	k = 0;
	for(i = 0; i < (payload_len); i++)
	{
		encrypt_msg[k++] = a[i];
		
	}

	for(i = 0; i < (mac_len); i++)
	{
		encrypt_msg[k++] = b[i];
	}

	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("6.%f\n",operating_time);

	//gettimeofday(&start_point, NULL);

	if (aes_print_flag || g_security_printf_flag)
	{
		printf("\nDisplay C len:%d\n",(payload_len + mac_len));
		for(i = 0; i < (payload_len + mac_len); i++)
		{
			printf("[%02x]", encrypt_msg[i]);
			if (((i+1)%10) == 0)
				printf("\n");
		}
		printf("\n");
	}


	if (g_aes_cmsg_falut_flag)
	{
		if (encrypt_msg[k-1] == 0xFF)
			encrypt_msg[k-1] = 0;
		else
			encrypt_msg[k-1] = 0xFF;
	}
	

	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("AES Encryption Operation Time : %f\n",operating_time);
	//reg_value = reg_readl((gpio_base + 0x14));
	//reg_value &= ~((unsigned int)0x200);
	//reg_writel((gpio_base + 0x14), reg_value);	/* GPB9 OutputData Setting, CON1의 48번 핀 */

	
	

    	return (0);
}


int fpga_aes_ccm_decryped(U1 *plain_msg, U1 *aes_key, U1 *encrypt_msg, int encrypt_msg_len, U1 *nonce)
{
	int    i, j;
	int k;
	unsigned char *kp;
	unsigned char *hp;
	unsigned char *tp;
	int mac_len;
	unsigned char ctr[AES_BLOCK_SIZE*5120];
	unsigned char z[AES_BLOCK_SIZE];
	unsigned char s[AES_BLOCK_SIZE*5120];
	int payload_len;
	/* 아래 a, b, c, p, t 배열의 크기는 최소한 payload_len 만큼의 크기는 가져야 한다. */
	unsigned char a[AES_BLOCK_SIZE*128], b[AES_BLOCK_SIZE*128], c[AES_BLOCK_SIZE*128];
	unsigned char p[AES_BLOCK_SIZE*128], t[AES_BLOCK_SIZE*128];
	int c_len;
	unsigned char block[AES_BLOCK_SIZE*5120];
	int total_len;
	int block_cnt;
	unsigned char y[AES_BLOCK_SIZE*5120];
	int count_block_cnt;
	int count_block_total_len;
	int remain;
	int key_len;
	int iv_len;
	U8 hdr_len;
	//volatile unsigned int reg_value;
	struct timeval start_point, end_point;
	volatile double operating_time;
	int index0, index1;
	int cipher_text_len;
	int flag = 0;
	unsigned char plain_t[AES_BLOCK_SIZE*128];

	//reg_value = reg_readl((gpio_base + 0x14));
	//reg_value |= 0x200;
	//reg_writel((gpio_base + 0x14), reg_value);	/* GPB9 OutputData Setting, CON1의 48번 핀 */

	if (aes_print_flag)
	{
		printf("=================================\n");
		printf("[fpga_ccm_test] Receiver Part!!\n");
		printf("=================================\n");
	}

	if (aes_print_flag || g_security_printf_flag)
	{
		printf("Display Encrypted Message len:%d\n",encrypt_msg_len);
		for( i = 0; i < encrypt_msg_len; i++)
		{
			printf("[%02x]", encrypt_msg[i]);
			if ( ((i+1)%10) == 0 )
				printf("\n");
		}
		printf("\n");
	}

	if (aes_print_flag || g_security_printf_flag)
	{
		printf("\nDisplay AES_KEY\n");
		for( i = 0; i < 16; i++)
		{
			printf("[%02x]", aes_key[i]);
			if ( ((i+1)%10) == 0 )
				printf("\n");
		}
		printf("\n");
	}

	if (aes_print_flag )
	{
		printf("\nDisplay nonce\n");
		for( i = 0; i < 12; i++)
		{
			printf("[%02x]", nonce[i]);
			if ( ((i+1)%10) == 0 )
				printf("\n");
		}
		printf("\n");
	}
	
	gettimeofday(&start_point, NULL);

	

	key_len = 16;
	iv_len = 12;	/* nonce */
	mac_len = 16;
	payload_len = encrypt_msg_len - mac_len;
	cipher_text_len = payload_len + mac_len;
	hdr_len = 0;		/* Associate Len */
	
	c_len = payload_len + mac_len;

	kp = aes_key;
	
	//for (i = 0; i < iv_len; i++)
	//	ip[i] = 0x10 + i;

	hp = NULL;

	fpga_aes_key_setting(kp);
		

	total_len = formatting_block(iv_len, nonce, hdr_len, hp, payload_len, plain_msg, mac_len, block);

	block_cnt = total_len / AES_BLOCK_SIZE;

	remain = payload_len % AES_BLOCK_SIZE;
	if (remain)
	{
		count_block_cnt = (payload_len / AES_BLOCK_SIZE) + 2;
	}
	else
	{
		count_block_cnt = (payload_len / AES_BLOCK_SIZE) + 1;
	}


	count_block_total_len = formatting_counter_blocks(iv_len, nonce, count_block_cnt, ctr);

	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("4.%f\n",operating_time);

	//gettimeofday(&start_point, NULL);
#if 0
	if (aes_print_flag)
	{
		printf("count_block_total_len=%d\n", count_block_total_len);

		for ( i = 0; i < count_block_total_len; i++)
		{
			printf("[%02x]", ctr[i]);
			if ( (i+1) % 16 == 0 )
				printf("\n");
		}
		printf("\n");
	}
#endif


	if (aes_print_flag)
		printf("\nAEC CCM Decryption Start\n");

	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("7.%f\n",operating_time);

	//gettimeofday(&start_point, NULL);
	for ( i = 0; i < count_block_cnt; i++)
	{
		fpga_aes_encrypt(&ctr[(AES_BLOCK_SIZE*i)], &s[(AES_BLOCK_SIZE*i)], flag);
	}

	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("8.%f\n",operating_time);

	//gettimeofday(&start_point, NULL);

	if (aes_print_flag || g_security_printf_flag)
		printf("Display Plain Text len:%d\n", payload_len);
	for(i = 0; i < payload_len; i++)
	{
		p[i] = encrypt_msg[i] ^ s[(AES_BLOCK_SIZE*1)+i];
		if (aes_print_flag || g_security_printf_flag)
		{
			printf("[%02x]", p[i]);
			if ( (i+1) % 10 == 0 )
				printf("\n");
		}
	}
	if (aes_print_flag || g_security_printf_flag)
		printf("\n");

	

	if (aes_print_flag)
		printf("Display T\n");
	for(i = 0; i < mac_len; i++)
	{
		t[i] = encrypt_msg[(c_len - mac_len + i)] ^ s[(AES_BLOCK_SIZE*0)+i];
		if (aes_print_flag)
			printf("[%02x]", t[i]);
	}
	if (aes_print_flag)
		printf("\n");

	fpga_aes_encrypt(&block[AES_BLOCK_SIZE*0], &y[AES_BLOCK_SIZE*0], flag);
		
	
#if 0	//SHKO, Origin
	for ( i = 1; i < block_cnt; i++ )
	{
		for ( k = 0; k < AES_BLOCK_SIZE; k++)
		{
			z[k] = block[(AES_BLOCK_SIZE*i) + k] ^ y[(AES_BLOCK_SIZE*(i-1)) + k];
		}
	
		fpga_aes_encrypt(z, &y[AES_BLOCK_SIZE*i], flag);
			
	}
#else
	total_len = formatting_block(iv_len, nonce, hdr_len, hp, payload_len, p, mac_len, block);

	block_cnt = total_len / AES_BLOCK_SIZE;

	remain = payload_len % AES_BLOCK_SIZE;
	if (remain)
	{
		count_block_cnt = (payload_len / AES_BLOCK_SIZE) + 2;
	}
	else
	{
		count_block_cnt = (payload_len / AES_BLOCK_SIZE) + 1;
	}

	/* SHKO : NIST SP 800-38C 규격 6.1 참조 */
	fpga_aes_encrypt(&block[AES_BLOCK_SIZE*0], &y[AES_BLOCK_SIZE*0], flag);	/* Y0 = CIPHk(B0) */

	/* For i=1 to r, do Yi = CIPHK(Bi^Yi-1) */
	for ( i = 1; i < block_cnt; i++ )
	{
		//gettimeofday(&start_point, NULL);

		index0 = AES_BLOCK_SIZE*i;
		index1 = AES_BLOCK_SIZE*(i-1);
		
		for ( k = 0; k < AES_BLOCK_SIZE; k++)
		{
			z[k] = block[index0 + k] ^ y[index1 + k];
		}

		fpga_aes_encrypt(z, &y[index0], flag);

	}

	for(i = 0; i < mac_len; i++)
	{
		plain_t[i] = y[(AES_BLOCK_SIZE*(block_cnt-1)) + i];
	}
	
	if (aes_print_flag)
	{
		printf("\nDisplay PLAIN T, block_cnt=%d\n", block_cnt);
		for(i = 0; i < mac_len; i++)
		{
			printf("[%02x]", y[(AES_BLOCK_SIZE*(block_cnt-1)) + i]);
		}
		printf("\n");
	}

	if( memcmp( (U1 *)t, (U1 *)plain_t, mac_len ) == 0)
	{
		gettimeofday(&end_point, NULL);

		operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
		printf("AES Decryption Operation Time : %f\n",operating_time);
		//if (aes_print_flag)
		//{
			printf("===============================================\n");
			printf("[fpga_aes_ccm_decryped] AES Decryption Success!!\n");
			printf("===============================================\n");
		//}
	}
	else
	{
		gettimeofday(&end_point, NULL);

		operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
		printf("AES Decryption Operation Time : %f\n",operating_time);
		printf("===============================================\n");
		printf("[fpga_aes_ccm_decryped] AES Decryption Fail!!\n");
		printf("===============================================\n");
		return(-1);
	}

#endif

	
	

	
	//reg_value = reg_readl((gpio_base + 0x14));
	//reg_value &= ~((unsigned int)0x200);
	//reg_writel((gpio_base + 0x14), reg_value);	/* GPB9 OutputData Setting, CON1의 48번 핀 */

	
	

    	return (0);
}

int MakeEncryptedMsg(U1 *encryped_msg, U1 *plain_msg, int plain_msg_len)
{
	U1 pdata[1024];
	U1 v[33];
	U1 c[16];
	U1 t[16];
	U1 nonce[12];
	int i = 0;
	int j;
	time_t ran;
	U2 cipher_text_len = 0;
	U2 RecipientInfo_Len = 0;
	int ret;
	int ret_len = 0;

	time((time_t *)&ran);

	for ( j = 0 ; j < 8; j++ )
	{
		nonce[j] = j;
	}
	nonce[j++] = (ran >> 24) % 0xFF;
	nonce[j++] = (ran >> 16) % 0xFF;
	nonce[j++] = (ran >> 8) % 0xFF;
	nonce[j++] = ran % 0xFF;

	/* 1609.2의 EncryptedMessage 구조체 */
	encryped_msg[i++] = ENCRYPTE_CONTENT_APP_DATA;
	encryped_msg[i++] = SYMM_ALGORITHM_AES_128_CCM;

	RecipientInfo_Len = plain_msg_len + 96;
	
	encryped_msg[i++] = (RecipientInfo_Len >> 8) & 0xFF;
	encryped_msg[i++] = RecipientInfo_Len  & 0xFF;
	encryped_msg[i++] = ECIES_NISTP256;

	//Make_VCT(v, c, t);
	Soft_Make_VCT(v, c, t);

#if 1
	for ( j = 0; j < 33; j++ )
		encryped_msg[i++] = v[j];

	for ( j = 0; j < 16; j++ )
		encryped_msg[i++] = c[j];

	for ( j = 0; j < 16; j++ )
		encryped_msg[i++] = t[j];

	for ( j = 0; j < 12; j++ )
		encryped_msg[i++] = nonce[j];

	cipher_text_len = plain_msg_len + 16;		/* 16 = Message Authentication Code */

	encryped_msg[i++] = (cipher_text_len >> 8) & 0xFF;
	encryped_msg[i++] = cipher_text_len  & 0xFF;

	ret_len = i + cipher_text_len;

	
	ret = fpga_aes_ccm_encryped(&encryped_msg[i], plain_msg, plain_msg_len, nonce);
#endif

	return(ret_len);
}


int Decode_Encrypted_Message(U1 *rx_buf, U2 len)
{
	int i, j;
	U1 data;
	U2_T RecipientInfo_Len;
	U2_T cipher_text_len;
	U1 pdata[1024];
	U1 v[33];
	U1 c[16];
	U1 t[16];
	U1 nonce[12];
	U1 plain_aes_key[16];

	i = 0;
	data = rx_buf[i++];	/* ENCRYPTE_CONTENT_TYPE, 1609.2의 EncryptedMessage 구조체 참조  */
	data = rx_buf[i++];	/* SYMM_ALGORITHM Type, 1609.2의 EncryptedMessage 구조체 참조  */

	RecipientInfo_Len.b1[1] = rx_buf[i++];
	RecipientInfo_Len.b1[0]  = rx_buf[i++];
	data = rx_buf[i++];	/* ECIES_NISTP256 : PKAlgorithm Type */

	for ( j = 0; j < 33; j++ )
		v[j] = rx_buf[i++];

	for ( j = 0; j < 16; j++ )
		c[j] = rx_buf[i++];

	for ( j = 0; j < 16; j++ )
		t[j] = rx_buf[i++];

	for ( j = 0; j < 12; j++ )
		nonce[j] = rx_buf[i++];

	cipher_text_len.b1[1] = rx_buf[i++];
	cipher_text_len.b1[0]  = rx_buf[i++];

	Soft_Decrypt_Ecies(v, c, t, plain_aes_key);

	if ( ecies_print_flag )
	{
		printf("[Decode_Encrypted_Message]Display Decrypted AES_KEY\n");
		for ( j = 0; j < 16; j++ )
		{
			printf("[%02x]", plain_aes_key[j]);
			if ( ((j+1)%10) == 10 )
				printf("\n");
		}
		printf("\n");
	}

	fpga_aes_ccm_decryped(pdata, plain_aes_key, &rx_buf[i], cipher_text_len.b2, nonce);
}



