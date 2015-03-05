
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

extern int ecdsa_print_flag;
extern int ecdsa_test_flag;
int g_ecdsa_msg_falut_flag;
int g_ecdsa_public_key_falut_flag;
extern int dev;
extern int ecdsa_sw_test_fix_flag;	/* SHKO : 이 변수를 1로 하면 ANSI X9.62 규격에 있는 테스트 벡터를 그래로 사용한다. */
extern int g_security_printf_flag;


int fpga_ecdsa_test(int flag);
int fpga_ecdsa_interrupt_test(int flag);
void fpga_ecdsa_random_test(int flag);
extern int fsha256_interrupt_test1(U1 *msg, volatile unsigned int len, int flag, U1 *sha_out);
int MakeSignedMsg(int flag, U1 *signed_msg, U1 *unsigned_msg, int unsigned_msg_len);
int SW_Verify_Signed_Message(U1 *rx_buf, U2 len);
void ecdsa_random_generator_test(void);


U1 ecdsa256_public_key[10][33] = {
									{ 0x03, 0x59, 0x63, 0x75, 0xe6, 0xce, 0x57, 0xe0, 0xf2, 0x02,
									   0x94, 0xfc, 0x46, 0xbd, 0xfc, 0xfd, 0x19, 0xa3, 0x9f, 0x81,
									   0x61, 0xb5, 0x86, 0x95, 0xb3, 0xec, 0x5b, 0x3d, 0x16, 0x42,
									   0x7c, 0x27, 0x4d },
									
								};
U1 ecdsa224_public_key[10][29] = {
									{ 0x03, 0xfd, 0x44, 0xec, 0x11, 0xf9, 0xd4, 0x3d, 0x9d, 0x23,
									   0xb1, 0xe1, 0xd1, 0xc9, 0xed, 0x65, 0x19, 0xb4, 0x0e, 0xcf,
									   0x0c, 0x79, 0xf4, 0x8c, 0xf4, 0x76, 0xcc, 0x43, 0xf1},
									
								};

U1 ecdsa256_private_key[10][32] = {
									{ 0x2C, 0xA1, 0x41, 0x1A, 0x41, 0xB1, 0x7B, 0x24, 0xCC, 0x8C, 
									   0x3B, 0x08, 0x9C, 0xFD, 0x03, 0x3F, 0x19, 0x20, 0x20, 0x2A, 
									   0x6C, 0x0D, 0xE8, 0xAB, 0xB9, 0x7D, 0xF1, 0x49, 0x8D, 0x50,
									   0xD2,0xC8},
									
								};
U1 ecdsa224_private_key[10][32] = {
									{ 0x00, 0x00, 0x00, 0x00, 0x39, 0xC0, 0x1D, 0x09, 0x23, 0x67,
									   0xBC, 0x5D, 0xC4, 0xE9, 0xDE, 0xF0, 0x35, 0x10, 0xD0, 0x27,
									   0x2C, 0x77, 0xDA, 0xBA, 0x7C, 0x15, 0x29, 0x30, 0xAA, 0x83, 
									   0x19, 0xAB},
									
								};
								

/* flag가 1이면 256 mode, 2이면 224 mode */
int fpga_ecdsa_interrupt_test(int flag)
{
	U1		message[256];
	U4		r[8];
	U4		s[8];
	volatile unsigned int status;
	int 		i;
	int		msg_len;
	int		time_out;
	U1 sha_out[32];
	U4 		expected_r[8];
	U4		expected_s[8];
	volatile unsigned int control;
	struct timeval start_point, end_point;
	volatile double operating_time;
	mpz_t	hex_p;
	char		decimal_p[64];
	int ret = 0;
	U4 wave_ecc_interrupt_status;

	gettimeofday(&start_point, NULL);

#if 0
	if (flag == 2)
	{
		write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, SHA_INITIAL_BIT);	/* Clear */
		write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, SIGNATURE_GEN_INITIAL_BIT);	/* Clear */
		write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, SIGNATURE_VERIFICATION_INITIAL_BIT);	/* Clear */
		write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, ECIES_INITIAL_BIT);	/* Clear */
		write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, IKEY_RECOVERY_INITIAL_BIT);	/* Clear */
	}
#endif
	
	
	//write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, 0x7);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */
	//write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, 0x0);

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_ECC_ENABLE_H_REG_OFFSET), 0x0);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ECC_ENABLE_H_REG_OFFSET, 0);
#endif
	
	if (flag == 1)
	{
		/* Test Mode로 세팅 : 2를 write하면 Private Key를 고정 */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA256_RANDOM_DISABLE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA256_RANDOM_DISABLE);
	#endif
	}
	else if (flag == 2)
	{
		/* Test Mode로 세팅 : 2를 write하면 Private Key를 고정 */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA224_RANDOM_DISABLE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA224_RANDOM_DISABLE);
	#endif
	}
	
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), SIGNATURE_GEN_RANDOM_SEL_BIT);
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), TRANSFER_PRIVATE_RANDOM_SEL_BIT);
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), RECEIVER_PRIVATE_RANDOM_SEL_BIT);

	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00000000);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, SIGNATURE_GEN_RANDOM_SEL_BIT);
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, TRANSFER_PRIVATE_RANDOM_SEL_BIT);
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, RECEIVER_PRIVATE_RANDOM_SEL_BIT);
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, 0x00000000);
#endif
	
	/* Prime Number Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM1_H_REG_OFFSET), 0x1);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM2_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM3_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM4_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM6_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM7_H_REG_OFFSET), 0xFFFFFFFF);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM1_H_REG_OFFSET, 0x1);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM2_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM3_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM4_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM6_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM7_H_REG_OFFSET, 0xFFFFFFFF);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM1_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM3_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM4_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM5_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM6_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM7_H_REG_OFFSET), 0x00000001);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM1_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM3_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM4_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM5_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM6_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM7_H_REG_OFFSET, 0x00000001);
	#endif
	}

	/* test N Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER1_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER3_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER4_H_REG_OFFSET), 0xBCE6FAAD);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER5_H_REG_OFFSET), 0xA7179E84);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER6_H_REG_OFFSET), 0xF3B9CAC2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER7_H_REG_OFFSET), 0xFC632551);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER1_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER3_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER4_H_REG_OFFSET, 0xBCE6FAAD);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER5_H_REG_OFFSET, 0xA7179E84);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER6_H_REG_OFFSET, 0xF3B9CAC2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER7_H_REG_OFFSET, 0xFC632551);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER1_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER3_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER4_H_REG_OFFSET), 0xFFFF16A2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER5_H_REG_OFFSET), 0xE0B8F03E);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER6_H_REG_OFFSET), 0x13DD2945);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER7_H_REG_OFFSET), 0x5C5C2A3D);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER1_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER3_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER4_H_REG_OFFSET, 0xFFFF16A2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER5_H_REG_OFFSET, 0xE0B8F03E);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER6_H_REG_OFFSET, 0x13DD2945);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER7_H_REG_OFFSET, 0x5C5C2A3D);
	#endif
	}
	

	/* iArith_Base_Gx Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX0_H_REG_OFFSET), 0x6B17D1F2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX1_H_REG_OFFSET), 0xE12C4247);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX2_H_REG_OFFSET), 0xF8BCE6E5);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX3_H_REG_OFFSET), 0x63A440F2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX4_H_REG_OFFSET), 0x77037D81);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX5_H_REG_OFFSET), 0x2DEB33A0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX6_H_REG_OFFSET), 0xF4A13945);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX7_H_REG_OFFSET), 0xD898C296);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX0_H_REG_OFFSET, 0x6B17D1F2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX1_H_REG_OFFSET, 0xE12C4247);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX2_H_REG_OFFSET, 0xF8BCE6E5);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX3_H_REG_OFFSET, 0x63A440F2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX4_H_REG_OFFSET, 0x77037D81);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX5_H_REG_OFFSET, 0x2DEB33A0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX6_H_REG_OFFSET, 0xF4A13945);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX7_H_REG_OFFSET, 0xD898C296);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX1_H_REG_OFFSET), 0xB70E0CBD);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX2_H_REG_OFFSET), 0x6BB4BF7F);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX3_H_REG_OFFSET), 0x321390B9);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX4_H_REG_OFFSET), 0x4A03C1D3);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX5_H_REG_OFFSET), 0x56C21122);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX6_H_REG_OFFSET), 0x343280D6);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX7_H_REG_OFFSET), 0x115C1D21);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX1_H_REG_OFFSET, 0xB70E0CBD);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX2_H_REG_OFFSET, 0x6BB4BF7F);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX3_H_REG_OFFSET, 0x321390B9);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX4_H_REG_OFFSET, 0x4A03C1D3);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX5_H_REG_OFFSET, 0x56C21122);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX6_H_REG_OFFSET, 0x343280D6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX7_H_REG_OFFSET, 0x115C1D21);
	#endif
	}

	/* iArith_Base_Gy Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY0_H_REG_OFFSET), 0x4FE342E2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY1_H_REG_OFFSET), 0xFE1A7F9B);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY2_H_REG_OFFSET), 0x8EE7EB4A);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY3_H_REG_OFFSET), 0x7C0F9E16);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY4_H_REG_OFFSET), 0x2BCE3357);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY5_H_REG_OFFSET), 0x6B315ECE);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY6_H_REG_OFFSET), 0xCBB64068);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY7_H_REG_OFFSET), 0x37BF51F5);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY0_H_REG_OFFSET, 0x4FE342E2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY1_H_REG_OFFSET, 0xFE1A7F9B);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY2_H_REG_OFFSET, 0x8EE7EB4A);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY3_H_REG_OFFSET, 0x7C0F9E16);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY4_H_REG_OFFSET, 0x2BCE3357);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY5_H_REG_OFFSET, 0x6B315ECE);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY6_H_REG_OFFSET, 0xCBB64068);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY7_H_REG_OFFSET, 0x37BF51F5);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY1_H_REG_OFFSET), 0xBD376388);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY2_H_REG_OFFSET), 0xB5F723FB);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY3_H_REG_OFFSET), 0x4C22DFE6);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY4_H_REG_OFFSET), 0xCD4375A0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY5_H_REG_OFFSET), 0x5A074764);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY6_H_REG_OFFSET), 0x44D58199);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY7_H_REG_OFFSET), 0x85007E34);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY1_H_REG_OFFSET, 0xBD376388);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY2_H_REG_OFFSET, 0xB5F723FB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY3_H_REG_OFFSET, 0x4C22DFE6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY4_H_REG_OFFSET, 0xCD4375A0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY5_H_REG_OFFSET, 0x5A074764);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY6_H_REG_OFFSET, 0x44D58199);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY7_H_REG_OFFSET, 0x85007E34);
	#endif
	}

	/* Private Key Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY0_H_REG_OFFSET), 0x2CA1411A);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY1_H_REG_OFFSET), 0x41B17B24);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY2_H_REG_OFFSET), 0xCC8C3B08);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY3_H_REG_OFFSET), 0x9CFD033F);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY4_H_REG_OFFSET), 0x1920202A);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY5_H_REG_OFFSET), 0x6C0DE8AB);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY6_H_REG_OFFSET), 0xB97DF149);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY7_H_REG_OFFSET), 0x8D50D2C8);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY0_H_REG_OFFSET, 0x2CA1411A);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY1_H_REG_OFFSET, 0x41B17B24);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY2_H_REG_OFFSET, 0xCC8C3B08);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY3_H_REG_OFFSET, 0x9CFD033F);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY4_H_REG_OFFSET, 0x1920202A);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY5_H_REG_OFFSET, 0x6C0DE8AB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY6_H_REG_OFFSET, 0xB97DF149);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY7_H_REG_OFFSET, 0x8D50D2C8);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY1_H_REG_OFFSET), 0x39C01D09);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY2_H_REG_OFFSET), 0x2367BC5D);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY3_H_REG_OFFSET), 0xC4E9DEF0);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY4_H_REG_OFFSET), 0x3510D027);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY5_H_REG_OFFSET), 0x2C77DABA);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY6_H_REG_OFFSET), 0x7C152930);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY7_H_REG_OFFSET), 0xAA8319AB);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY1_H_REG_OFFSET, 0x39C01D09);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY2_H_REG_OFFSET, 0x2367BC5D);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY3_H_REG_OFFSET, 0xC4E9DEF0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY4_H_REG_OFFSET, 0x3510D027);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY5_H_REG_OFFSET, 0x2C77DABA);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY6_H_REG_OFFSET, 0x7C152930);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY7_H_REG_OFFSET, 0xAA8319AB);
	#endif
	}

	if (ecdsa_print_flag)
	{
		printf("=================================\n");
		printf("[fpag_ecdsa_test] Transmit Part!!\n");
		printf("=================================\n");
	}

	if (ecdsa_print_flag)
	{
		printf("Display Private Key!!\n");
	
		for ( i = 0; i < 8; i++ )
		{
			printf("[%08x]", read_wave_ecc_reg32(((ECDSA_PRIVATE_KEY0_H_REG_OFFSET) + (i*4))));
			if ( ( (i+1) % 10 ) == 0 )
				printf("\n");
		}
		printf("\n");


		printf("\nDisplay Random Key!!\n");
		for ( i = 0; i < 8; i++ )
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base + ECDSA_RANDOM_NUMBER0_H_REG_OFFSET) + (i*4))));
			if ( ( (i+1) % 10 ) == 0 )
				printf("\n");
		}
		printf("\n");
	}

	/* A at Equation E */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A1_H_REG_OFFSET), 0x00000001);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A2_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A3_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A4_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A6_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A7_H_REG_OFFSET), 0xFFFFFFFC);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A1_H_REG_OFFSET, 0x00000001);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A2_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A3_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A4_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A6_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A7_H_REG_OFFSET, 0xFFFFFFFC);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A1_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A3_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A4_H_REG_OFFSET), 0xFFFFFFFE);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A6_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A7_H_REG_OFFSET), 0xFFFFFFFE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A1_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A3_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A4_H_REG_OFFSET, 0xFFFFFFFE);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A6_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A7_H_REG_OFFSET, 0xFFFFFFFE);
	#endif
	}

	/* B at Equation E */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B0_H_REG_OFFSET), 0x5AC635D8);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B1_H_REG_OFFSET), 0xAA3A93E7);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B2_H_REG_OFFSET), 0xB3EBBD55);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B3_H_REG_OFFSET), 0x769886BC);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B4_H_REG_OFFSET), 0x651D06B0);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B5_H_REG_OFFSET), 0xCC53B0F6);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B6_H_REG_OFFSET), 0x3BCE3C3E);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B7_H_REG_OFFSET), 0x27D2604B);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B0_H_REG_OFFSET, 0x5AC635D8);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B1_H_REG_OFFSET, 0xAA3A93E7);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B2_H_REG_OFFSET, 0xB3EBBD55);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B3_H_REG_OFFSET, 0x769886BC);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B4_H_REG_OFFSET, 0x651D06B0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B5_H_REG_OFFSET, 0xCC53B0F6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B6_H_REG_OFFSET, 0x3BCE3C3E);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B7_H_REG_OFFSET, 0x27D2604B);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B0_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B1_H_REG_OFFSET), 0xB4050A85);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B2_H_REG_OFFSET), 0x0C04B3AB);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B3_H_REG_OFFSET), 0xF5413256);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B4_H_REG_OFFSET), 0x5044B0B7);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B5_H_REG_OFFSET), 0xD7BFD8BA);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B6_H_REG_OFFSET), 0x270B3943);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B7_H_REG_OFFSET), 0x2355FFB4);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B0_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B1_H_REG_OFFSET, 0xB4050A85);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B2_H_REG_OFFSET, 0x0C04B3AB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B3_H_REG_OFFSET, 0xF5413256);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B4_H_REG_OFFSET, 0x5044B0B7);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B5_H_REG_OFFSET, 0xD7BFD8BA);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B6_H_REG_OFFSET, 0x270B3943);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B7_H_REG_OFFSET, 0x2355FFB4);
	#endif
	}
	

	/* PNP Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_PNP0_H_REG_OFFSET), 0xCCD1C8AA);
		reg_writel((wave_dsrc_base + ECDSA_MONT_PNP1_H_REG_OFFSET), 0xEE00BC4F);
		reg_writel((wave_dsrc_base + ECDSA_MONT_QNQ0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_MONT_QNQ1_H_REG_OFFSET), 0x1);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_PNP0_H_REG_OFFSET, 0xCCD1C8AA);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_PNP1_H_REG_OFFSET, 0xEE00BC4F);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_QNQ0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_QNQ1_H_REG_OFFSET, 0x1);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_PNP0_H_REG_OFFSET), 0xD6E24270);
		reg_writel((wave_dsrc_base + ECDSA_MONT_PNP1_H_REG_OFFSET), 0x6A1FC2EB);
		reg_writel((wave_dsrc_base + ECDSA_MONT_QNQ0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_QNQ1_H_REG_OFFSET), 0xFFFFFFFF);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_PNP0_H_REG_OFFSET, 0xD6E24270);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_PNP1_H_REG_OFFSET, 0x6A1FC2EB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_QNQ0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_QNQ1_H_REG_OFFSET, 0xFFFFFFFF);
	#endif
	}

	/* R2 Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_R20_H_REG_OFFSET), 0x66E12D94);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R21_H_REG_OFFSET), 0xF3D95620);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R22_H_REG_OFFSET), 0x2845B239);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R23_H_REG_OFFSET), 0x2B6BEC59);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R24_H_REG_OFFSET), 0x4699799C);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R25_H_REG_OFFSET), 0x49BD6FA6);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R26_H_REG_OFFSET), 0x83244C95);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R27_H_REG_OFFSET), 0xBE79EEA2);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R20_H_REG_OFFSET, 0x66E12D94);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R21_H_REG_OFFSET, 0xF3D95620);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R22_H_REG_OFFSET, 0x2845B239);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R23_H_REG_OFFSET, 0x2B6BEC59);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R24_H_REG_OFFSET, 0x4699799C);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R25_H_REG_OFFSET, 0x49BD6FA6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R26_H_REG_OFFSET, 0x83244C95);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R27_H_REG_OFFSET, 0xBE79EEA2);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_R20_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R21_H_REG_OFFSET), 0xB1E97961);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R22_H_REG_OFFSET), 0x6AD15F7C);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R23_H_REG_OFFSET), 0xD9714856);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R24_H_REG_OFFSET), 0xABC8FF59);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R25_H_REG_OFFSET), 0x31D63F4B);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R26_H_REG_OFFSET), 0x29947A69);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R27_H_REG_OFFSET), 0x5F517D15);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R20_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R21_H_REG_OFFSET, 0xB1E97961);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R22_H_REG_OFFSET, 0x6AD15F7C);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R23_H_REG_OFFSET, 0xD9714856);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R24_H_REG_OFFSET, 0xABC8FF59);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R25_H_REG_OFFSET, 0x31D63F4B);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R26_H_REG_OFFSET, 0x29947A69);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R27_H_REG_OFFSET, 0x5F517D15);
	#endif
	}

	/* test R Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q0_H_REG_OFFSET), 0x00000004);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q1_H_REG_OFFSET), 0xFFFFFFFD);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q3_H_REG_OFFSET), 0xFFFFFFFE);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q4_H_REG_OFFSET), 0xFFFFFFFB);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q6_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q7_H_REG_OFFSET), 0x00000003);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q0_H_REG_OFFSET, 0x00000004);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q1_H_REG_OFFSET, 0xFFFFFFFD);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q3_H_REG_OFFSET, 0xFFFFFFFE);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q4_H_REG_OFFSET, 0xFFFFFFFB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q6_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q7_H_REG_OFFSET, 0x00000003);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q0_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q1_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q2_H_REG_OFFSET), 0xFFFFFFFE);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q3_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q4_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q5_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q6_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q7_H_REG_OFFSET), 0x00000001);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q0_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q1_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q2_H_REG_OFFSET, 0xFFFFFFFE);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q3_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q4_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q5_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q6_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q7_H_REG_OFFSET, 0x00000001);
	#endif
	}

	/* SIGVERIFY Setting */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R0_H_REG_OFFSET), 0xD73CD372);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R1_H_REG_OFFSET), 0x2BAE6CC0);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R2_H_REG_OFFSET), 0xB39065BB);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R3_H_REG_OFFSET), 0x4003D8EC);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R4_H_REG_OFFSET), 0xE1EF2F7A);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R5_H_REG_OFFSET), 0x8A55BFD6);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R6_H_REG_OFFSET), 0x77234B0B);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R7_H_REG_OFFSET), 0x3B902650);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R0_H_REG_OFFSET, 0xD73CD372);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R1_H_REG_OFFSET, 0x2BAE6CC0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R2_H_REG_OFFSET, 0xB39065BB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R3_H_REG_OFFSET, 0x4003D8EC);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R4_H_REG_OFFSET, 0xE1EF2F7A);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R5_H_REG_OFFSET, 0x8A55BFD6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R6_H_REG_OFFSET, 0x77234B0B);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R7_H_REG_OFFSET, 0x3B902650);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R0_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R1_H_REG_OFFSET), 0xFB6B02AD);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R2_H_REG_OFFSET), 0x1857422D);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R3_H_REG_OFFSET), 0xD0560D70);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R4_H_REG_OFFSET), 0x9D4FA60E);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R5_H_REG_OFFSET), 0xAB6E698C);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R6_H_REG_OFFSET), 0xCE964B2A);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R7_H_REG_OFFSET), 0xB82C39EE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R0_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R1_H_REG_OFFSET, 0xFB6B02AD);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R2_H_REG_OFFSET, 0x1857422D);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R3_H_REG_OFFSET, 0xD0560D70);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R4_H_REG_OFFSET, 0x9D4FA60E);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R5_H_REG_OFFSET, 0xAB6E698C);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R6_H_REG_OFFSET, 0xCE964B2A);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R7_H_REG_OFFSET, 0xB82C39EE);
	#endif
	}


	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S0_H_REG_OFFSET), 0xD9C88297);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S1_H_REG_OFFSET), 0xFEFED844);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S2_H_REG_OFFSET), 0x1E08DDA6);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S3_H_REG_OFFSET), 0x9554A645);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S4_H_REG_OFFSET), 0x2B8A0BD4);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S5_H_REG_OFFSET), 0xA0EA1DDB);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S6_H_REG_OFFSET), 0x750499F0);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S7_H_REG_OFFSET), 0xC2298C2F);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S0_H_REG_OFFSET, 0xD9C88297);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S1_H_REG_OFFSET, 0xFEFED844);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S2_H_REG_OFFSET, 0x1E08DDA6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S3_H_REG_OFFSET, 0x9554A645);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S4_H_REG_OFFSET, 0x2B8A0BD4);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S5_H_REG_OFFSET, 0xA0EA1DDB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S6_H_REG_OFFSET, 0x750499F0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S7_H_REG_OFFSET, 0xC2298C2F);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S0_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S1_H_REG_OFFSET), 0xA8060F8A);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S2_H_REG_OFFSET), 0xE5FDD132);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S3_H_REG_OFFSET), 0x6DE60A55);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S4_H_REG_OFFSET), 0x500EDCEA);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S5_H_REG_OFFSET), 0x763F1E82);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S6_H_REG_OFFSET), 0x0DA794A9);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S7_H_REG_OFFSET), 0x5B3C8F1A);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S0_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S1_H_REG_OFFSET, 0xA8060F8A);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S2_H_REG_OFFSET, 0xE5FDD132);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S3_H_REG_OFFSET, 0x6DE60A55);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S4_H_REG_OFFSET, 0x500EDCEA);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S5_H_REG_OFFSET, 0x763F1E82);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S6_H_REG_OFFSET, 0x0DA794A9);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S7_H_REG_OFFSET, 0x5B3C8F1A);
	#endif
	}

	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), 0x596375E6);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), 0xCE57E0F2);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), 0x0294FC46);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), 0xBDFCFD19);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), 0xA39F8161);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), 0xB58695B3);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), 0xEC5B3D16);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), 0x427C274D);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET, 0x596375E6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET, 0xCE57E0F2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET, 0x0294FC46);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET, 0xBDFCFD19);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET, 0xA39F8161);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET, 0xB58695B3);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET, 0xEC5B3D16);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET, 0x427C274D);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), 0xFD44EC11);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), 0xF9D43D9D);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), 0x23B1E1D1);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), 0xC9ED6519);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), 0xB40ECF0C);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), 0x79F48CF4);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), 0x76CC43F1);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET, 0xFD44EC11);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET, 0xF9D43D9D);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET, 0x23B1E1D1);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET, 0xC9ED6519);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET, 0xB40ECF0C);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET, 0x79F48CF4);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET, 0x76CC43F1);
	#endif
	}
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x1);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET, 0x1);
#endif



	/* test Hash Settings */
	i = 0;
	if (flag == 1)
	{
		message[i++] = 0x45;
		message[i++] = 0x78;
		message[i++] = 0x61;
		message[i++] = 0x6D;
		message[i++] = 0x70;
		message[i++] = 0x6C;
		message[i++] = 0x65;
		message[i++] = 0x20;

		message[i++] = 0x6F;
		message[i++] = 0x66;
		message[i++] = 0x20;
		message[i++] = 0x45;
		message[i++] = 0x43;
		message[i++] = 0x44;
		message[i++] = 0x53;
		message[i++] = 0x41;

		message[i++] = 0x20;
		message[i++] = 0x77;
		message[i++] = 0x69;
		message[i++] = 0x74;
		message[i++] = 0x68;
		message[i++] = 0x20;
		message[i++] = 0x61;
		message[i++] = 0x6E;

		message[i++] = 0x73;
		message[i++] = 0x69;
		message[i++] = 0x70;
		message[i++] = 0x32;
		message[i++] = 0x35;
		message[i++] = 0x36;
		message[i++] = 0x72;
		message[i++] = 0x31;

		message[i++] = 0x20;
		message[i++] = 0x61;
		message[i++] = 0x6E;
		message[i++] = 0x64;
		message[i++] = 0x20;
		message[i++] = 0x53;
		message[i++] = 0x48;
		message[i++] = 0x41;

		message[i++] = 0x2D;
		message[i++] = 0x32;
		message[i++] = 0x35;
		message[i++] = 0x36;
	}
	else if (flag == 2)
	{
		message[i++] = 0x45;
		message[i++] = 0x78;
		message[i++] = 0x61;
		message[i++] = 0x6D;
		message[i++] = 0x70;
		message[i++] = 0x6C;
		message[i++] = 0x65;
		message[i++] = 0x20;

		message[i++] = 0x6F;
		message[i++] = 0x66;
		message[i++] = 0x20;
		message[i++] = 0x45;
		message[i++] = 0x43;
		message[i++] = 0x44;
		message[i++] = 0x53;
		message[i++] = 0x41;

		message[i++] = 0x20;
		message[i++] = 0x77;
		message[i++] = 0x69;
		message[i++] = 0x74;
		message[i++] = 0x68;
		message[i++] = 0x20;
		message[i++] = 0x61;
		message[i++] = 0x6E;

		message[i++] = 0x73;
		message[i++] = 0x69;
		message[i++] = 0x70;
		message[i++] = 0x32;
		message[i++] = 0x32;
		message[i++] = 0x34;
		message[i++] = 0x72;
		message[i++] = 0x31;

		message[i++] = 0x20;
		message[i++] = 0x61;
		message[i++] = 0x6E;
		message[i++] = 0x64;
		message[i++] = 0x20;
		message[i++] = 0x53;
		message[i++] = 0x48;
		message[i++] = 0x41;

		message[i++] = 0x2D;
		message[i++] = 0x32;
		message[i++] = 0x32;
		message[i++] = 0x34;
	}
	msg_len = i;

	if(ecdsa_print_flag)
	{
		printf("Display Message M\n");

		for ( i = 0; i < msg_len; i++)
		{
			printf("[%02x]", message[i]);
			if ( ((i+1) % 10) == 0 )
			{
				printf("\n");
			}
		}
		printf("\n");
	}
	
	ret = fsha256_interrupt_test1(message, msg_len, flag, sha_out);
	if (ret < 0)
	{
		return(ret);
	}

#if 0
	if(ecdsa_print_flag)
	{
		printf("\nDisplay HASH Value is\n");
		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", sha_out[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}
#endif

	//printf("End fsha256_test1\n");

	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, SIGNATURE_GEN_ENABLE_BIT);

	if (flag == 1)	/* 256 mode */
	{
		i = 0;
		/* ANSI_X9.62문서의 L.4.2 참조 */
		expected_r[i++] = 0xd73cd372;
		expected_r[i++] = 0x2bae6cc0;
		expected_r[i++] = 0xb39065bb;
		expected_r[i++] = 0x4003d8ec;
		expected_r[i++] = 0xe1ef2f7a;
		expected_r[i++] = 0x8a55bfd6;
		expected_r[i++] = 0x77234b0b;
		expected_r[i++] = 0x3b902650;

		i = 0;
		expected_s[i++] = 0xd9c88297;
		expected_s[i++] = 0xfefed844;
		expected_s[i++] = 0x1e08dda6;
		expected_s[i++] = 0x9554a645;
		expected_s[i++] = 0x2b8a0bd4;
		expected_s[i++] = 0xa0ea1ddb;
		expected_s[i++] = 0x750499f0;
		expected_s[i++] = 0xc2298c2f;
	}
	else if(flag ==2)	/* 224 mode */
	{
		/* ANSI_X9.62문서의 L.4.1 참조 */
		i = 0;
		expected_r[i++] = 0x0;
		expected_r[i++] = 0xfb6b02ad;
		expected_r[i++] = 0x1857422d;
		expected_r[i++] = 0xd0560d70;
		expected_r[i++] = 0x9d4fa60e;
		expected_r[i++] = 0xab6e698c;
		expected_r[i++] = 0xce964b2a;
		expected_r[i++] = 0xb82c39ee;

		i = 0;
		expected_s[i++] = 0x0;
		expected_s[i++] = 0xa8060f8a;
		expected_s[i++] = 0xe5fdd132;
		expected_s[i++] = 0x6de60a55;
		expected_s[i++] = 0x500edcea;
		expected_s[i++] = 0x763f1e82;
		expected_s[i++] = 0x0da794a9;
		expected_s[i++] = 0x5b3c8f1a;
	}

#if 1
	time_out = 20000;
	while(time_out--)
	{	
		ret  = ioctl(dev, IOCTLWAVE_ECC_INT_READ, &wave_ecc_interrupt_status);
		if (ret != 0)
		{
			perror("[fpga_ecdsa_interrupt_test] ioctl:");
			break;
		}
		else
		{
			if (wave_ecc_interrupt_status == ECDSA_SIGNATURE_GEN_DONE)
			{
				break;
			}
		}
	}

	if (time_out < 0)
	{
		printf("[fpga_ecdsa_interrupt_test] Signature Generation Time Out!!\n");
		printf("SIGGEN status = 0x%08x, time_out = %d\n", status, time_out);
		return(-1);
	}

	if (ecdsa_print_flag)
	{
		//printf("SIGGEN status = 0x%08x, time_out = %d\n", status, time_out);

		printf("\n[fpga_ecdsa_interrupt_test]Display Signature Generation R\n");
	}



	for ( i = 0; i < 8; i++ )
	{
		r[i] = reg_readl(((wave_dsrc_base + ECDSA_SIGGEN_KEYPAIR_R0_H_REG_OFFSET) + (i*4)));
		if (ecdsa_print_flag)
		{
			printf("[%08x]", r[i]);
			if ( ( (i+1) % 10 ) == 0 )
				printf("\n");
		}
	}
	if (ecdsa_print_flag)
		printf("\n");

	if (ecdsa_print_flag)
	{
		if (flag == 1)	/* 256 mode */
		{
			mpz_init(hex_p);
			mpz_set_str(hex_p, "d73cd3722bae6cc0b39065bb4003d8ece1ef2f7a8a55bfd677234b0b3b902650", 16);
			mpz_get_str(decimal_p, 10, hex_p);
			printf("decimal R=%s\n", decimal_p);
		}
		else if (flag == 2)	/* 224 mode */
		{
			mpz_init(hex_p);
			mpz_set_str(hex_p, "fb6b02ad1857422dd0560d709d4fa60eab6e698cce964b2ab82c39ee", 16);
			mpz_get_str(decimal_p, 10, hex_p);
			printf("decimal R=%s\n", decimal_p);
		}
	}
	

	if (ecdsa_print_flag)
	{
		printf("\n[fpga_ecdsa_test]Display Signature Generation S\n");
	}


	for ( i = 0; i < 8; i++ )
	{
		s[i] = reg_readl(((wave_dsrc_base + ECDSA_SIGGEN_KEYPAIR_S0_H_REG_OFFSET) + (i*4)));
		if (ecdsa_print_flag)
		{
			printf("[%08x]", s[i]);
			if ( ( (i+1) % 10 ) == 0 )
				printf("\n");
		}
	}
	if (ecdsa_print_flag)
		printf("\n");

	if (ecdsa_print_flag)
	{
		if (flag == 1)	/* 256 mode */
		{
			mpz_init(hex_p);
			mpz_set_str(hex_p, "d9c88297fefed8441e08dda69554a6452b8a0bd4a0ea1ddb750499f0c2298c2f", 16);
			mpz_get_str(decimal_p, 10, hex_p);
			printf("decimal S=%s\n", decimal_p);
		}
		else if (flag == 2)	/* 224 mode */
		{
			mpz_init(hex_p);
			mpz_set_str(hex_p, "a8060f8ae5fdd1326de60a55500edcea763f1e820da794a95b3c8f1a", 16);
			mpz_get_str(decimal_p, 10, hex_p);
			printf("decimal S=%s\n", decimal_p);
		}
	}
#endif

	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("\nSignature Generation Operation Time : %f\n",operating_time);


	//write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, 0x7);	/* Clear */
	//write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, 0x0);
	if( (memcmp( (U1 *)r, (U1 *)expected_r, 32 ) == 0) && (memcmp( (U1 *)s, (U1 *)expected_s, 32 ) == 0) )
	{
		printf("===============================================\n");
		printf("[fpag_ecdsa_test] Signature Generation Success!!\n");
		printf("===============================================\n");
	}
	else
	{
		printf("===============================================\n");
		printf("[fpag_ecdsa_test] Signature Generation Fail!!\n");
		printf("===============================================\n");
		return(-1);
	}


	if (ecdsa_print_flag)
	{
		printf("\n\n\n=================================\n");
		printf("[fpag_ecdsa_test] Receive Part!!\n");
		printf("=================================\n");
	}
	gettimeofday(&start_point, NULL);
	
	ret = fsha256_interrupt_test1(message, msg_len, flag, sha_out);

	if (ret < 0)
	{
		return(ret);
	}

	if (ecdsa_test_flag == 0)
	{
		if (flag == 1)
		{
		#if WAVE_SECURITY_16BIT_ENABLE == 0
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), 0x596375E6);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), 0xCE57E0F2);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), 0x0294FC46);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), 0xBDFCFD19);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), 0xA39F8161);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), 0xB58695B3);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), 0xEC5B3D16);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), 0x427C274D);

			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x1);
		#else
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET, 0x596375E6);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET, 0xCE57E0F2);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET, 0x0294FC46);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET, 0xBDFCFD19);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET, 0xA39F8161);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET, 0xB58695B3);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET, 0xEC5B3D16);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET, 0x427C274D);

			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET, 0x1);
		#endif
		}
		else if (flag == 2)
		{
		#if WAVE_SECURITY_16BIT_ENABLE == 0
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), 0x00000000);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), 0xFD44EC11);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), 0xF9D43D9D);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), 0x23B1E1D1);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), 0xC9ED6519);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), 0xB40ECF0C);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), 0x79F48CF4);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), 0x76CC43F1);

			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x1);
		#else
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET, 0x00000000);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET, 0xFD44EC11);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET, 0xF9D43D9D);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET, 0x23B1E1D1);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET, 0xC9ED6519);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET, 0xB40ECF0C);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET, 0x79F48CF4);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET, 0x76CC43F1);

			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET, 0x1);
		#endif
		}
	}
	else
	{
		if (flag == 1)
		{
		#if WAVE_SECURITY_16BIT_ENABLE == 0
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), 0x12345678);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), 0x9abcdef1);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), 0x23456789);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), 0xabcdef12);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), 0x3456789a);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), 0xbcdef123);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), 0x456789ab);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), 0xcdef1234);

			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x1);
		#else
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET, 0x12345678);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET, 0x9abcdef1);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET, 0x23456789);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET, 0xabcdef12);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET, 0x3456789a);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET, 0xbcdef123);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET, 0x456789ab);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET, 0xcdef1234);

			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET, 0x1);
		#endif
		}
		else if (flag == 2)
		{
		#if WAVE_SECURITY_16BIT_ENABLE == 0
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), 0x00000000);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), 0x12345678);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), 0x9abcdef1);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), 0x23456789);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), 0xabcdef12);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), 0x3456789a);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), 0xbcdef123);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), 0x456789ab);

			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x1);
		#else
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET, 0x00000000);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET, 0x12345678);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET, 0x9abcdef1);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET, 0x23456789);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET, 0xabcdef12);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET, 0x3456789a);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET, 0xbcdef123);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET, 0x456789ab);

			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET, 0x1);
		#endif
		}
	}

	if (ecdsa_print_flag)
	{
		printf("Display Public KEY\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", read_wave_ecc_reg32(((ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}

	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA256_RANDOM_DISABLE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA256_RANDOM_DISABLE);
	#endif
	}
	else
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA224_RANDOM_DISABLE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA224_RANDOM_DISABLE);
	#endif
	}


	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, ECDSA_KEY_RECOVERY_ENABLE_BIT);

#if 0
	time_out = 20000;
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & ECDSA_RECOVERY_DONE_BIT)
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, ECDSA_RECOVERY_DONE_BIT);/* Clear */
	if (time_out < 0)
	{
		printf("[fpga_ecdsa_test] Key Recovery Done Time Out!!\n");
		printf("TRANS_PUBLIC_KEY_Y_RECOVERY status = 0x%08x, time_out = %d\n", status, time_out);
		return(-1);
	}
	
	//if (ecdsa_print_flag)
	//	printf("TRANS_PUBLIC_KEY_Y_RECOVERY status = 0x%08x, time_out = %d\n", status, time_out);

	if (ecdsa_print_flag)
	{
		printf("\nDisplay Recovery Sender Public Key Y\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECDSA_TRANS_RECEIVE_RECOVERY_Y0_H_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}
#endif

	//reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0);

	//write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, SIGNATURE_VERIFY_ENABLE_BIT);

#if 1
	time_out = 20000;
	while(time_out--)
	{	
		ret  = ioctl(dev, IOCTLWAVE_ECC_INT_READ, &wave_ecc_interrupt_status);
		if (ret != 0)
		{
			perror("[fpga_ecdsa_interrupt_test] ioctl:");
			break;
		}
		else
		{
			if (wave_ecc_interrupt_status == ECDSA_SIGNATURE_VERIFY_DONE)
			{
				break;
			}
		}
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);/* Clear */
#endif

	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("Signature Validation Operation Time : %f\n",operating_time);

#if 1
	if (time_out <= 0)
	{
		printf("[fpga_ecdsa_test] Signature Verify Valid Time Out!!\n");
		printf("SIGVERIFY Valid status = 0x%08x, time_out = %d\n", status, time_out);
		return(-1);
	}
	else
	{
		printf("===============================================\n");
		printf("[fpag_ecdsa_test] Signature Verification Success!!\n");
		printf("===============================================\n");
	}
		
	
	if (ecdsa_print_flag)
		printf("SIGVERIFY Valid status = 0x%08x, time_out = %d\n", status, time_out);

	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */
#endif


	
}

/* flag가 1이면 256 mode, 2이면 224 mode */
int fpga_ecdsa_test(int flag)
{
	U1		message[256];
	U4		r[8];
	U4		s[8];
	volatile unsigned int status;
	int 		i;
	int		msg_len;
	int		time_out;
	U1 sha_out[32];
	U4 		expected_r[8];
	U4		expected_s[8];
	volatile unsigned int control;
	struct timeval start_point, end_point;
	volatile double operating_time;
	mpz_t	hex_p;
	char		decimal_p[64];
	int ret = 0;

	gettimeofday(&start_point, NULL);

#if 0
	if (flag == 2)
	{
		write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, SHA_INITIAL_BIT);	/* Clear */
		write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, SIGNATURE_GEN_INITIAL_BIT);	/* Clear */
		write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, SIGNATURE_VERIFICATION_INITIAL_BIT);	/* Clear */
		write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, ECIES_INITIAL_BIT);	/* Clear */
		write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, IKEY_RECOVERY_INITIAL_BIT);	/* Clear */
	}
#endif
	
	//write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, 0x7);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */
	//write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, 0x0);

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_ECC_ENABLE_H_REG_OFFSET), 0x0);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ECC_ENABLE_H_REG_OFFSET, 0);
#endif
	
	if (flag == 1)
	{
		/* Test Mode로 세팅 : 2를 write하면 Private Key를 고정 */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA256_RANDOM_DISABLE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA256_RANDOM_DISABLE);
	#endif
	}
	else if (flag == 2)
	{
		/* Test Mode로 세팅 : 2를 write하면 Private Key를 고정 */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA224_RANDOM_DISABLE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA224_RANDOM_DISABLE);
	#endif
	}
	
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), SIGNATURE_GEN_RANDOM_SEL_BIT);
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), TRANSFER_PRIVATE_RANDOM_SEL_BIT);
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), RECEIVER_PRIVATE_RANDOM_SEL_BIT);

	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00000000);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, SIGNATURE_GEN_RANDOM_SEL_BIT);
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, TRANSFER_PRIVATE_RANDOM_SEL_BIT);
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, RECEIVER_PRIVATE_RANDOM_SEL_BIT);
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, 0x00000000);
#endif
	
	/* Prime Number Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM1_H_REG_OFFSET), 0x1);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM2_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM3_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM4_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM6_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM7_H_REG_OFFSET), 0xFFFFFFFF);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM1_H_REG_OFFSET, 0x1);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM2_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM3_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM4_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM6_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM7_H_REG_OFFSET, 0xFFFFFFFF);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM1_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM3_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM4_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM5_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM6_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM7_H_REG_OFFSET), 0x00000001);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM1_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM3_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM4_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM5_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM6_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM7_H_REG_OFFSET, 0x00000001);
	#endif
	}

	/* test N Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER1_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER3_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER4_H_REG_OFFSET), 0xBCE6FAAD);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER5_H_REG_OFFSET), 0xA7179E84);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER6_H_REG_OFFSET), 0xF3B9CAC2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER7_H_REG_OFFSET), 0xFC632551);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER1_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER3_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER4_H_REG_OFFSET, 0xBCE6FAAD);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER5_H_REG_OFFSET, 0xA7179E84);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER6_H_REG_OFFSET, 0xF3B9CAC2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER7_H_REG_OFFSET, 0xFC632551);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER1_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER3_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER4_H_REG_OFFSET), 0xFFFF16A2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER5_H_REG_OFFSET), 0xE0B8F03E);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER6_H_REG_OFFSET), 0x13DD2945);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER7_H_REG_OFFSET), 0x5C5C2A3D);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER1_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER3_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER4_H_REG_OFFSET, 0xFFFF16A2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER5_H_REG_OFFSET, 0xE0B8F03E);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER6_H_REG_OFFSET, 0x13DD2945);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER7_H_REG_OFFSET, 0x5C5C2A3D);
	#endif
	}
	

	/* iArith_Base_Gx Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX0_H_REG_OFFSET), 0x6B17D1F2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX1_H_REG_OFFSET), 0xE12C4247);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX2_H_REG_OFFSET), 0xF8BCE6E5);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX3_H_REG_OFFSET), 0x63A440F2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX4_H_REG_OFFSET), 0x77037D81);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX5_H_REG_OFFSET), 0x2DEB33A0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX6_H_REG_OFFSET), 0xF4A13945);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX7_H_REG_OFFSET), 0xD898C296);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX0_H_REG_OFFSET, 0x6B17D1F2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX1_H_REG_OFFSET, 0xE12C4247);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX2_H_REG_OFFSET, 0xF8BCE6E5);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX3_H_REG_OFFSET, 0x63A440F2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX4_H_REG_OFFSET, 0x77037D81);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX5_H_REG_OFFSET, 0x2DEB33A0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX6_H_REG_OFFSET, 0xF4A13945);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX7_H_REG_OFFSET, 0xD898C296);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX1_H_REG_OFFSET), 0xB70E0CBD);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX2_H_REG_OFFSET), 0x6BB4BF7F);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX3_H_REG_OFFSET), 0x321390B9);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX4_H_REG_OFFSET), 0x4A03C1D3);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX5_H_REG_OFFSET), 0x56C21122);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX6_H_REG_OFFSET), 0x343280D6);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX7_H_REG_OFFSET), 0x115C1D21);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX1_H_REG_OFFSET, 0xB70E0CBD);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX2_H_REG_OFFSET, 0x6BB4BF7F);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX3_H_REG_OFFSET, 0x321390B9);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX4_H_REG_OFFSET, 0x4A03C1D3);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX5_H_REG_OFFSET, 0x56C21122);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX6_H_REG_OFFSET, 0x343280D6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX7_H_REG_OFFSET, 0x115C1D21);
	#endif
	}

	/* iArith_Base_Gy Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY0_H_REG_OFFSET), 0x4FE342E2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY1_H_REG_OFFSET), 0xFE1A7F9B);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY2_H_REG_OFFSET), 0x8EE7EB4A);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY3_H_REG_OFFSET), 0x7C0F9E16);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY4_H_REG_OFFSET), 0x2BCE3357);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY5_H_REG_OFFSET), 0x6B315ECE);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY6_H_REG_OFFSET), 0xCBB64068);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY7_H_REG_OFFSET), 0x37BF51F5);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY0_H_REG_OFFSET, 0x4FE342E2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY1_H_REG_OFFSET, 0xFE1A7F9B);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY2_H_REG_OFFSET, 0x8EE7EB4A);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY3_H_REG_OFFSET, 0x7C0F9E16);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY4_H_REG_OFFSET, 0x2BCE3357);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY5_H_REG_OFFSET, 0x6B315ECE);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY6_H_REG_OFFSET, 0xCBB64068);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY7_H_REG_OFFSET, 0x37BF51F5);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY1_H_REG_OFFSET), 0xBD376388);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY2_H_REG_OFFSET), 0xB5F723FB);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY3_H_REG_OFFSET), 0x4C22DFE6);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY4_H_REG_OFFSET), 0xCD4375A0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY5_H_REG_OFFSET), 0x5A074764);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY6_H_REG_OFFSET), 0x44D58199);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY7_H_REG_OFFSET), 0x85007E34);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY1_H_REG_OFFSET, 0xBD376388);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY2_H_REG_OFFSET, 0xB5F723FB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY3_H_REG_OFFSET, 0x4C22DFE6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY4_H_REG_OFFSET, 0xCD4375A0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY5_H_REG_OFFSET, 0x5A074764);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY6_H_REG_OFFSET, 0x44D58199);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY7_H_REG_OFFSET, 0x85007E34);
	#endif
	}

	/* Private Key Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY0_H_REG_OFFSET), 0x2CA1411A);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY1_H_REG_OFFSET), 0x41B17B24);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY2_H_REG_OFFSET), 0xCC8C3B08);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY3_H_REG_OFFSET), 0x9CFD033F);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY4_H_REG_OFFSET), 0x1920202A);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY5_H_REG_OFFSET), 0x6C0DE8AB);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY6_H_REG_OFFSET), 0xB97DF149);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY7_H_REG_OFFSET), 0x8D50D2C8);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY0_H_REG_OFFSET, 0x2CA1411A);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY1_H_REG_OFFSET, 0x41B17B24);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY2_H_REG_OFFSET, 0xCC8C3B08);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY3_H_REG_OFFSET, 0x9CFD033F);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY4_H_REG_OFFSET, 0x1920202A);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY5_H_REG_OFFSET, 0x6C0DE8AB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY6_H_REG_OFFSET, 0xB97DF149);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY7_H_REG_OFFSET, 0x8D50D2C8);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY1_H_REG_OFFSET), 0x39C01D09);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY2_H_REG_OFFSET), 0x2367BC5D);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY3_H_REG_OFFSET), 0xC4E9DEF0);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY4_H_REG_OFFSET), 0x3510D027);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY5_H_REG_OFFSET), 0x2C77DABA);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY6_H_REG_OFFSET), 0x7C152930);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY7_H_REG_OFFSET), 0xAA8319AB);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY1_H_REG_OFFSET, 0x39C01D09);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY2_H_REG_OFFSET, 0x2367BC5D);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY3_H_REG_OFFSET, 0xC4E9DEF0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY4_H_REG_OFFSET, 0x3510D027);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY5_H_REG_OFFSET, 0x2C77DABA);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY6_H_REG_OFFSET, 0x7C152930);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY7_H_REG_OFFSET, 0xAA8319AB);
	#endif
	}

	if (ecdsa_print_flag)
	{
		printf("=================================\n");
		printf("[fpag_ecdsa_test] Transmit Part!!\n");
		printf("=================================\n");
	}

	if (ecdsa_print_flag)
	{
		printf("Display Private Key!!\n");

		for ( i = 0; i < 8; i++ )
		{
			printf("[%08x]", read_wave_ecc_reg32(((ECDSA_PRIVATE_KEY0_H_REG_OFFSET) + (i*4))));
			if ( ( (i+1) % 10 ) == 0 )
				printf("\n");
		}
		printf("\n");


		printf("\nDisplay Random Key!!\n");
		for ( i = 0; i < 8; i++ )
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base + ECDSA_RANDOM_NUMBER0_H_REG_OFFSET) + (i*4))));
			if ( ( (i+1) % 10 ) == 0 )
				printf("\n");
		}
		printf("\n");
	}

	/* A at Equation E */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A1_H_REG_OFFSET), 0x00000001);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A2_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A3_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A4_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A6_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A7_H_REG_OFFSET), 0xFFFFFFFC);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A1_H_REG_OFFSET, 0x00000001);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A2_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A3_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A4_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A6_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A7_H_REG_OFFSET, 0xFFFFFFFC);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A1_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A3_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A4_H_REG_OFFSET), 0xFFFFFFFE);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A6_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A7_H_REG_OFFSET), 0xFFFFFFFE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A1_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A3_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A4_H_REG_OFFSET, 0xFFFFFFFE);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A6_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A7_H_REG_OFFSET, 0xFFFFFFFE);
	#endif
	}

	/* B at Equation E */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B0_H_REG_OFFSET), 0x5AC635D8);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B1_H_REG_OFFSET), 0xAA3A93E7);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B2_H_REG_OFFSET), 0xB3EBBD55);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B3_H_REG_OFFSET), 0x769886BC);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B4_H_REG_OFFSET), 0x651D06B0);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B5_H_REG_OFFSET), 0xCC53B0F6);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B6_H_REG_OFFSET), 0x3BCE3C3E);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B7_H_REG_OFFSET), 0x27D2604B);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B0_H_REG_OFFSET, 0x5AC635D8);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B1_H_REG_OFFSET, 0xAA3A93E7);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B2_H_REG_OFFSET, 0xB3EBBD55);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B3_H_REG_OFFSET, 0x769886BC);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B4_H_REG_OFFSET, 0x651D06B0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B5_H_REG_OFFSET, 0xCC53B0F6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B6_H_REG_OFFSET, 0x3BCE3C3E);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B7_H_REG_OFFSET, 0x27D2604B);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B0_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B1_H_REG_OFFSET), 0xB4050A85);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B2_H_REG_OFFSET), 0x0C04B3AB);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B3_H_REG_OFFSET), 0xF5413256);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B4_H_REG_OFFSET), 0x5044B0B7);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B5_H_REG_OFFSET), 0xD7BFD8BA);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B6_H_REG_OFFSET), 0x270B3943);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B7_H_REG_OFFSET), 0x2355FFB4);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B0_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B1_H_REG_OFFSET, 0xB4050A85);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B2_H_REG_OFFSET, 0x0C04B3AB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B3_H_REG_OFFSET, 0xF5413256);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B4_H_REG_OFFSET, 0x5044B0B7);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B5_H_REG_OFFSET, 0xD7BFD8BA);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B6_H_REG_OFFSET, 0x270B3943);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B7_H_REG_OFFSET, 0x2355FFB4);
	#endif
	}
	

	/* PNP Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_PNP0_H_REG_OFFSET), 0xCCD1C8AA);
		reg_writel((wave_dsrc_base + ECDSA_MONT_PNP1_H_REG_OFFSET), 0xEE00BC4F);
		reg_writel((wave_dsrc_base + ECDSA_MONT_QNQ0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_MONT_QNQ1_H_REG_OFFSET), 0x1);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_PNP0_H_REG_OFFSET, 0xCCD1C8AA);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_PNP1_H_REG_OFFSET, 0xEE00BC4F);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_QNQ0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_QNQ1_H_REG_OFFSET, 0x1);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_PNP0_H_REG_OFFSET), 0xD6E24270);
		reg_writel((wave_dsrc_base + ECDSA_MONT_PNP1_H_REG_OFFSET), 0x6A1FC2EB);
		reg_writel((wave_dsrc_base + ECDSA_MONT_QNQ0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_QNQ1_H_REG_OFFSET), 0xFFFFFFFF);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_PNP0_H_REG_OFFSET, 0xD6E24270);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_PNP1_H_REG_OFFSET, 0x6A1FC2EB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_QNQ0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_QNQ1_H_REG_OFFSET, 0xFFFFFFFF);
	#endif
	}

	/* R2 Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_R20_H_REG_OFFSET), 0x66E12D94);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R21_H_REG_OFFSET), 0xF3D95620);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R22_H_REG_OFFSET), 0x2845B239);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R23_H_REG_OFFSET), 0x2B6BEC59);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R24_H_REG_OFFSET), 0x4699799C);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R25_H_REG_OFFSET), 0x49BD6FA6);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R26_H_REG_OFFSET), 0x83244C95);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R27_H_REG_OFFSET), 0xBE79EEA2);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R20_H_REG_OFFSET, 0x66E12D94);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R21_H_REG_OFFSET, 0xF3D95620);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R22_H_REG_OFFSET, 0x2845B239);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R23_H_REG_OFFSET, 0x2B6BEC59);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R24_H_REG_OFFSET, 0x4699799C);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R25_H_REG_OFFSET, 0x49BD6FA6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R26_H_REG_OFFSET, 0x83244C95);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R27_H_REG_OFFSET, 0xBE79EEA2);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_R20_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R21_H_REG_OFFSET), 0xB1E97961);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R22_H_REG_OFFSET), 0x6AD15F7C);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R23_H_REG_OFFSET), 0xD9714856);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R24_H_REG_OFFSET), 0xABC8FF59);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R25_H_REG_OFFSET), 0x31D63F4B);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R26_H_REG_OFFSET), 0x29947A69);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R27_H_REG_OFFSET), 0x5F517D15);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R20_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R21_H_REG_OFFSET, 0xB1E97961);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R22_H_REG_OFFSET, 0x6AD15F7C);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R23_H_REG_OFFSET, 0xD9714856);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R24_H_REG_OFFSET, 0xABC8FF59);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R25_H_REG_OFFSET, 0x31D63F4B);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R26_H_REG_OFFSET, 0x29947A69);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R27_H_REG_OFFSET, 0x5F517D15);
	#endif
	}

	/* test R Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q0_H_REG_OFFSET), 0x00000004);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q1_H_REG_OFFSET), 0xFFFFFFFD);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q3_H_REG_OFFSET), 0xFFFFFFFE);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q4_H_REG_OFFSET), 0xFFFFFFFB);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q6_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q7_H_REG_OFFSET), 0x00000003);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q0_H_REG_OFFSET, 0x00000004);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q1_H_REG_OFFSET, 0xFFFFFFFD);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q3_H_REG_OFFSET, 0xFFFFFFFE);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q4_H_REG_OFFSET, 0xFFFFFFFB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q6_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q7_H_REG_OFFSET, 0x00000003);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q0_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q1_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q2_H_REG_OFFSET), 0xFFFFFFFE);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q3_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q4_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q5_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q6_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q7_H_REG_OFFSET), 0x00000001);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q0_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q1_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q2_H_REG_OFFSET, 0xFFFFFFFE);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q3_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q4_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q5_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q6_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q7_H_REG_OFFSET, 0x00000001);
	#endif
	}

	/* SIGVERIFY Setting */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R0_H_REG_OFFSET), 0xD73CD372);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R1_H_REG_OFFSET), 0x2BAE6CC0);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R2_H_REG_OFFSET), 0xB39065BB);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R3_H_REG_OFFSET), 0x4003D8EC);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R4_H_REG_OFFSET), 0xE1EF2F7A);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R5_H_REG_OFFSET), 0x8A55BFD6);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R6_H_REG_OFFSET), 0x77234B0B);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R7_H_REG_OFFSET), 0x3B902650);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R0_H_REG_OFFSET, 0xD73CD372);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R1_H_REG_OFFSET, 0x2BAE6CC0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R2_H_REG_OFFSET, 0xB39065BB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R3_H_REG_OFFSET, 0x4003D8EC);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R4_H_REG_OFFSET, 0xE1EF2F7A);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R5_H_REG_OFFSET, 0x8A55BFD6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R6_H_REG_OFFSET, 0x77234B0B);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R7_H_REG_OFFSET, 0x3B902650);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R0_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R1_H_REG_OFFSET), 0xFB6B02AD);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R2_H_REG_OFFSET), 0x1857422D);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R3_H_REG_OFFSET), 0xD0560D70);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R4_H_REG_OFFSET), 0x9D4FA60E);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R5_H_REG_OFFSET), 0xAB6E698C);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R6_H_REG_OFFSET), 0xCE964B2A);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R7_H_REG_OFFSET), 0xB82C39EE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R0_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R1_H_REG_OFFSET, 0xFB6B02AD);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R2_H_REG_OFFSET, 0x1857422D);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R3_H_REG_OFFSET, 0xD0560D70);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R4_H_REG_OFFSET, 0x9D4FA60E);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R5_H_REG_OFFSET, 0xAB6E698C);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R6_H_REG_OFFSET, 0xCE964B2A);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_R7_H_REG_OFFSET, 0xB82C39EE);
	#endif
	}


	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S0_H_REG_OFFSET), 0xD9C88297);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S1_H_REG_OFFSET), 0xFEFED844);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S2_H_REG_OFFSET), 0x1E08DDA6);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S3_H_REG_OFFSET), 0x9554A645);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S4_H_REG_OFFSET), 0x2B8A0BD4);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S5_H_REG_OFFSET), 0xA0EA1DDB);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S6_H_REG_OFFSET), 0x750499F0);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S7_H_REG_OFFSET), 0xC2298C2F);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S0_H_REG_OFFSET, 0xD9C88297);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S1_H_REG_OFFSET, 0xFEFED844);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S2_H_REG_OFFSET, 0x1E08DDA6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S3_H_REG_OFFSET, 0x9554A645);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S4_H_REG_OFFSET, 0x2B8A0BD4);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S5_H_REG_OFFSET, 0xA0EA1DDB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S6_H_REG_OFFSET, 0x750499F0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S7_H_REG_OFFSET, 0xC2298C2F);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S0_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S1_H_REG_OFFSET), 0xA8060F8A);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S2_H_REG_OFFSET), 0xE5FDD132);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S3_H_REG_OFFSET), 0x6DE60A55);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S4_H_REG_OFFSET), 0x500EDCEA);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S5_H_REG_OFFSET), 0x763F1E82);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S6_H_REG_OFFSET), 0x0DA794A9);
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S7_H_REG_OFFSET), 0x5B3C8F1A);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S0_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S1_H_REG_OFFSET, 0xA8060F8A);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S2_H_REG_OFFSET, 0xE5FDD132);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S3_H_REG_OFFSET, 0x6DE60A55);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S4_H_REG_OFFSET, 0x500EDCEA);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S5_H_REG_OFFSET, 0x763F1E82);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S6_H_REG_OFFSET, 0x0DA794A9);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_SIGVERIFY_KEYPAIR_S7_H_REG_OFFSET, 0x5B3C8F1A);
	#endif
	}

	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), 0x596375E6);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), 0xCE57E0F2);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), 0x0294FC46);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), 0xBDFCFD19);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), 0xA39F8161);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), 0xB58695B3);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), 0xEC5B3D16);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), 0x427C274D);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET, 0x596375E6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET, 0xCE57E0F2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET, 0x0294FC46);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET, 0xBDFCFD19);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET, 0xA39F8161);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET, 0xB58695B3);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET, 0xEC5B3D16);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET, 0x427C274D);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), 0xFD44EC11);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), 0xF9D43D9D);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), 0x23B1E1D1);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), 0xC9ED6519);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), 0xB40ECF0C);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), 0x79F48CF4);
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), 0x76CC43F1);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET, 0xFD44EC11);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET, 0xF9D43D9D);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET, 0x23B1E1D1);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET, 0xC9ED6519);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET, 0xB40ECF0C);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET, 0x79F48CF4);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET, 0x76CC43F1);
	#endif
	}

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x1);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET, 0x1);
#endif

#if 0
	if (flag == 1)
	{
		reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), 0x3BD87E39);
		reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), 0x6DA09C7E);
		reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), 0x5C13B38F);
		reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), 0x69448A94);
		reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), 0x13499463);
		reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), 0xA5BA8D06);
		reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), 0xA92B10CE);
		reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), 0x3AE91E3B);
		
		reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x1);
	}
	

	

	/* 수신측 공개키 X좌표 값*/
	if (flag == 1)
	{
		reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R0_REG_OFFSET), 0xD8CE32C0);
		reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R1_REG_OFFSET), 0x96C0EAD1);
		reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R2_REG_OFFSET), 0xA9B4AB0F);
		reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R3_REG_OFFSET), 0xD6312459);
		reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R4_REG_OFFSET), 0x55FEC361);
		reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R5_REG_OFFSET), 0x33B97633);
		reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R6_REG_OFFSET), 0x4A2B5AA2);
		reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R7_REG_OFFSET), 0x10592977);
	}
	

	/* 수신측 공개키 Y좌표 값*/
	if (flag == 1)
	{
		reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S0_REG_OFFSET), 0x349714AE);
		reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S1_REG_OFFSET), 0x5FE2DAAE);
		reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S2_REG_OFFSET), 0x514769E6);
		reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S3_REG_OFFSET), 0x0D2E8343);
		reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S4_REG_OFFSET), 0x37F9569F);
		reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S5_REG_OFFSET), 0xA1D55DD3);
		reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S6_REG_OFFSET), 0x7B28A9CF);
		reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S7_REG_OFFSET), 0x3CB175BA);
	}
#endif
	
	



	/* test Hash Settings */
	i = 0;
	if (flag == 1)
	{
		message[i++] = 0x45;
		message[i++] = 0x78;
		message[i++] = 0x61;
		message[i++] = 0x6D;
		message[i++] = 0x70;
		message[i++] = 0x6C;
		message[i++] = 0x65;
		message[i++] = 0x20;

		message[i++] = 0x6F;
		message[i++] = 0x66;
		message[i++] = 0x20;
		message[i++] = 0x45;
		message[i++] = 0x43;
		message[i++] = 0x44;
		message[i++] = 0x53;
		message[i++] = 0x41;

		message[i++] = 0x20;
		message[i++] = 0x77;
		message[i++] = 0x69;
		message[i++] = 0x74;
		message[i++] = 0x68;
		message[i++] = 0x20;
		message[i++] = 0x61;
		message[i++] = 0x6E;

		message[i++] = 0x73;
		message[i++] = 0x69;
		message[i++] = 0x70;
		message[i++] = 0x32;
		message[i++] = 0x35;
		message[i++] = 0x36;
		message[i++] = 0x72;
		message[i++] = 0x31;

		message[i++] = 0x20;
		message[i++] = 0x61;
		message[i++] = 0x6E;
		message[i++] = 0x64;
		message[i++] = 0x20;
		message[i++] = 0x53;
		message[i++] = 0x48;
		message[i++] = 0x41;

		message[i++] = 0x2D;
		message[i++] = 0x32;
		message[i++] = 0x35;
		message[i++] = 0x36;
	}
	else if (flag == 2)
	{
		message[i++] = 0x45;
		message[i++] = 0x78;
		message[i++] = 0x61;
		message[i++] = 0x6D;
		message[i++] = 0x70;
		message[i++] = 0x6C;
		message[i++] = 0x65;
		message[i++] = 0x20;

		message[i++] = 0x6F;
		message[i++] = 0x66;
		message[i++] = 0x20;
		message[i++] = 0x45;
		message[i++] = 0x43;
		message[i++] = 0x44;
		message[i++] = 0x53;
		message[i++] = 0x41;

		message[i++] = 0x20;
		message[i++] = 0x77;
		message[i++] = 0x69;
		message[i++] = 0x74;
		message[i++] = 0x68;
		message[i++] = 0x20;
		message[i++] = 0x61;
		message[i++] = 0x6E;

		message[i++] = 0x73;
		message[i++] = 0x69;
		message[i++] = 0x70;
		message[i++] = 0x32;
		message[i++] = 0x32;
		message[i++] = 0x34;
		message[i++] = 0x72;
		message[i++] = 0x31;

		message[i++] = 0x20;
		message[i++] = 0x61;
		message[i++] = 0x6E;
		message[i++] = 0x64;
		message[i++] = 0x20;
		message[i++] = 0x53;
		message[i++] = 0x48;
		message[i++] = 0x41;

		message[i++] = 0x2D;
		message[i++] = 0x32;
		message[i++] = 0x32;
		message[i++] = 0x34;
	}
	msg_len = i;

	if(ecdsa_print_flag)
	{
		printf("Display Message M\n");

		for ( i = 0; i < msg_len; i++)
		{
			printf("[%02x]", message[i]);
			if ( ((i+1) % 10) == 0 )
			{
				printf("\n");
			}
		}
		printf("\n");
	}
	
	ret = fsha256_test1(message, msg_len, flag, sha_out);
	if (ret < 0)
	{
		return(ret);
	}

	if(ecdsa_print_flag)
	{
		printf("\nDisplay HASH Value is\n");
		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", sha_out[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}

	//printf("End fsha256_test1\n");

	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, SIGNATURE_GEN_ENABLE_BIT);

	if (flag == 1)	/* 256 mode */
	{
		i = 0;
		/* ANSI_X9.62문서의 L.4.2 참조 */
		expected_r[i++] = 0xd73cd372;
		expected_r[i++] = 0x2bae6cc0;
		expected_r[i++] = 0xb39065bb;
		expected_r[i++] = 0x4003d8ec;
		expected_r[i++] = 0xe1ef2f7a;
		expected_r[i++] = 0x8a55bfd6;
		expected_r[i++] = 0x77234b0b;
		expected_r[i++] = 0x3b902650;

		i = 0;
		expected_s[i++] = 0xd9c88297;
		expected_s[i++] = 0xfefed844;
		expected_s[i++] = 0x1e08dda6;
		expected_s[i++] = 0x9554a645;
		expected_s[i++] = 0x2b8a0bd4;
		expected_s[i++] = 0xa0ea1ddb;
		expected_s[i++] = 0x750499f0;
		expected_s[i++] = 0xc2298c2f;
	}
	else if(flag ==2)	/* 224 mode */
	{
		/* ANSI_X9.62문서의 L.4.1 참조 */
		i = 0;
		expected_r[i++] = 0x0;
		expected_r[i++] = 0xfb6b02ad;
		expected_r[i++] = 0x1857422d;
		expected_r[i++] = 0xd0560d70;
		expected_r[i++] = 0x9d4fa60e;
		expected_r[i++] = 0xab6e698c;
		expected_r[i++] = 0xce964b2a;
		expected_r[i++] = 0xb82c39ee;

		i = 0;
		expected_s[i++] = 0x0;
		expected_s[i++] = 0xa8060f8a;
		expected_s[i++] = 0xe5fdd132;
		expected_s[i++] = 0x6de60a55;
		expected_s[i++] = 0x500edcea;
		expected_s[i++] = 0x763f1e82;
		expected_s[i++] = 0x0da794a9;
		expected_s[i++] = 0x5b3c8f1a;
	}

	time_out = 20000;
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & SIGGEN_DONE_STATUS_BIT)	/* Signature Generation Done */
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);/* Clear */

	if (time_out < 0)
	{
		printf("[fpga_ecdsa_test] Signature Generation Time Out!!\n");
		printf("SIGGEN status = 0x%08x, time_out = %d\n", status, time_out);
		return(-1);
	}
	if (ecdsa_print_flag)
	{
		//printf("SIGGEN status = 0x%08x, time_out = %d\n", status, time_out);

		printf("\n[fpga_ecdsa_test]Display Signature Generation R\n");
	}


	for ( i = 0; i < 8; i++ )
	{
		r[i] = reg_readl(((wave_dsrc_base + ECDSA_SIGGEN_KEYPAIR_R0_H_REG_OFFSET) + (i*4)));
		if (ecdsa_print_flag)
		{
			printf("[%08x]", r[i]);
			if ( ( (i+1) % 10 ) == 0 )
				printf("\n");
		}
	}
	if (ecdsa_print_flag)
		printf("\n");

	if (ecdsa_print_flag)
	{
		if (flag == 1)	/* 256 mode */
		{
			mpz_init(hex_p);
			mpz_set_str(hex_p, "d73cd3722bae6cc0b39065bb4003d8ece1ef2f7a8a55bfd677234b0b3b902650", 16);
			mpz_get_str(decimal_p, 10, hex_p);
			printf("decimal R=%s\n", decimal_p);
		}
		else if (flag == 2)	/* 224 mode */
		{
			mpz_init(hex_p);
			mpz_set_str(hex_p, "fb6b02ad1857422dd0560d709d4fa60eab6e698cce964b2ab82c39ee", 16);
			mpz_get_str(decimal_p, 10, hex_p);
			printf("decimal R=%s\n", decimal_p);
		}
	}
	

	if (ecdsa_print_flag)
	{
		printf("\n[fpga_ecdsa_test]Display Signature Generation S\n");
	}


	for ( i = 0; i < 8; i++ )
	{
		s[i] = reg_readl(((wave_dsrc_base + ECDSA_SIGGEN_KEYPAIR_S0_H_REG_OFFSET) + (i*4)));
		if (ecdsa_print_flag)
		{
			printf("[%08x]", s[i]);
			if ( ( (i+1) % 10 ) == 0 )
				printf("\n");
		}
	}
	if (ecdsa_print_flag)
		printf("\n");

	if (ecdsa_print_flag)
	{
		if (flag == 1)	/* 256 mode */
		{
			mpz_init(hex_p);
			mpz_set_str(hex_p, "d9c88297fefed8441e08dda69554a6452b8a0bd4a0ea1ddb750499f0c2298c2f", 16);
			mpz_get_str(decimal_p, 10, hex_p);
			printf("decimal S=%s\n", decimal_p);
		}
		else if (flag == 2)	/* 224 mode */
		{
			mpz_init(hex_p);
			mpz_set_str(hex_p, "a8060f8ae5fdd1326de60a55500edcea763f1e820da794a95b3c8f1a", 16);
			mpz_get_str(decimal_p, 10, hex_p);
			printf("decimal S=%s\n", decimal_p);
		}
	}

	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("\nSignature Generation Operation Time : %f\n",operating_time);
	//write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, 0x7);	/* Clear */
	//write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, 0x0);
	if( (memcmp( (U1 *)r, (U1 *)expected_r, 32 ) == 0) && (memcmp( (U1 *)s, (U1 *)expected_s, 32 ) == 0) )
	{
		printf("===============================================\n");
		printf("[fpag_ecdsa_test] Signature Generation Success!!\n");
		printf("===============================================\n");
	}
	else
	{
		printf("===============================================\n");
		printf("[fpag_ecdsa_test] Signature Generation Fail!!\n");
		printf("===============================================\n");
		return(-1);
	}

#if 0	/* SHKO, Origin */
	gettimeofday(&start_point, NULL);
	
	fsha256_test1(message, msg_len, flag, sha_out);

	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, SIGNATURE_VERIFY_ENABLE_BIT);

	time_out = 20000;

	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & SIGVERIFY_DONE_STATUS_BIT)	/* Signature Generation Done */
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);/* Clear */

	if (time_out < 0)
		printf("[fpga_ecdsa_test] Signature Verify Done Time Out!!\n");
		
	if (ecdsa_print_flag)
		printf("SIGVERIFY Done status = 0x%08x, time_out = %d\n", status, time_out);

	time_out = 20000;

	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & SIGVERIFY_VALID_STATUS_BIT)	/* Signature Generation Done */
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);/* Clear */

	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("Signature Validation Operation Time : %f\n",operating_time);

	if (time_out < 0)
		printf("[fpga_ecdsa_test] Signature Verify Valid Time Out!!\n");
	
	if (ecdsa_print_flag)
		printf("SIGVERIFY Valid status = 0x%08x, time_out = %d\n", status, time_out);
#else
	if (ecdsa_print_flag)
	{
		printf("\n\n\n=================================\n");
		printf("[fpag_ecdsa_test] Receive Part!!\n");
		printf("=================================\n");
	}
	gettimeofday(&start_point, NULL);
	
	ret = fsha256_test1(message, msg_len, flag, sha_out);

	if (ret < 0)
	{
		return(ret);
	}

	if (ecdsa_test_flag == 0)
	{
		if (flag == 1)
		{
		#if WAVE_SECURITY_16BIT_ENABLE == 0
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), 0x596375E6);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), 0xCE57E0F2);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), 0x0294FC46);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), 0xBDFCFD19);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), 0xA39F8161);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), 0xB58695B3);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), 0xEC5B3D16);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), 0x427C274D);

			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x1);
		#else
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET, 0x596375E6);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET, 0xCE57E0F2);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET, 0x0294FC46);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET, 0xBDFCFD19);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET, 0xA39F8161);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET, 0xB58695B3);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET, 0xEC5B3D16);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET, 0x427C274D);

			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET, 0x1);
		#endif
		}
		else if (flag == 2)
		{
		#if WAVE_SECURITY_16BIT_ENABLE == 0
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), 0x00000000);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), 0xFD44EC11);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), 0xF9D43D9D);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), 0x23B1E1D1);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), 0xC9ED6519);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), 0xB40ECF0C);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), 0x79F48CF4);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), 0x76CC43F1);

			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x1);
		#else
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET, 0x00000000);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET, 0xFD44EC11);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET, 0xF9D43D9D);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET, 0x23B1E1D1);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET, 0xC9ED6519);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET, 0xB40ECF0C);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET, 0x79F48CF4);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET, 0x76CC43F1);

			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET, 0x1);
		#endif
		}
	}
	else
	{
		if (flag == 1)
		{
		#if WAVE_SECURITY_16BIT_ENABLE == 0
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), 0x12345678);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), 0x9abcdef1);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), 0x23456789);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), 0xabcdef12);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), 0x3456789a);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), 0xbcdef123);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), 0x456789ab);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), 0xcdef1234);

			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x1);
		#else
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET, 0x12345678);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET, 0x9abcdef1);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET, 0x23456789);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET, 0xabcdef12);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET, 0x3456789a);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET, 0xbcdef123);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET, 0x456789ab);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET, 0xcdef1234);

			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET, 0x1);
		#endif
		}
		else if (flag == 2)
		{
		#if WAVE_SECURITY_16BIT_ENABLE == 0
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), 0x00000000);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), 0x12345678);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), 0x9abcdef1);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), 0x23456789);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), 0xabcdef12);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), 0x3456789a);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), 0xbcdef123);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), 0x456789ab);

			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x1);
		#else
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET, 0x00000000);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET, 0x12345678);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET, 0x9abcdef1);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET, 0x23456789);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET, 0xabcdef12);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET, 0x3456789a);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET, 0xbcdef123);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET, 0x456789ab);

			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET, 0x1);
		#endif
		}
	}

	if (ecdsa_print_flag)
	{
		printf("Display Public KEY\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", read_wave_ecc_reg32(((ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}

	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA256_RANDOM_DISABLE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA256_RANDOM_DISABLE);
	#endif
	}
	else
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA224_RANDOM_DISABLE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA224_RANDOM_DISABLE);
	#endif
	}


	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, ECDSA_KEY_RECOVERY_ENABLE_BIT);
	
	time_out = 20000;
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & ECDSA_RECOVERY_DONE_BIT)
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, ECDSA_RECOVERY_DONE_BIT);/* Clear */
	if (time_out < 0)
	{
		printf("[fpga_ecdsa_test] Key Recovery Done Time Out!!\n");
		printf("TRANS_PUBLIC_KEY_Y_RECOVERY status = 0x%08x, time_out = %d\n", status, time_out);
		return(-1);
	}
	
	//if (ecdsa_print_flag)
	//	printf("TRANS_PUBLIC_KEY_Y_RECOVERY status = 0x%08x, time_out = %d\n", status, time_out);

	if (ecdsa_print_flag)
	{
		printf("\nDisplay Recovery Sender Public Key Y\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECDSA_TRANS_RECEIVE_RECOVERY_Y0_H_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, 0);
#endif


	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, SIGNATURE_VERIFY_ENABLE_BIT);

	time_out = 20000;

	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if ((status & SIGVERIFY_DONE_STATUS_BIT) && (status & SIGVERIFY_VALID_STATUS_BIT))	/* Signature Generation Done */
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);/* Clear */


	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("Signature Validation Operation Time : %f\n",operating_time);

	if (time_out <= 0)
	{
		printf("[fpga_ecdsa_test] Signature Verify Valid Time Out!!\n");
		printf("SIGVERIFY Valid status = 0x%08x, time_out = %d\n", status, time_out);
		return(-1);
	}
	else
	{
		printf("===============================================\n");
		printf("[fpag_ecdsa_test] Signature Verification Success!!\n");
		printf("===============================================\n");
	}
		
	
	if (ecdsa_print_flag)
		printf("SIGVERIFY Valid status = 0x%08x, time_out = %d\n", status, time_out);
#endif

	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */
	


	
}

/* flag가 1이면 256 mode, 2이면 224 mode */
void fpga_ecdsa_random_test(int flag)
{
	U1		message[256];
	U4		r[8];
	U4		s[8];
	volatile unsigned int status;
	int 		i;
	int		msg_len;
	int		time_out;
	U1 sha_out[32];
	volatile unsigned int control;
	struct timeval start_point, end_point;
	volatile double operating_time;
	U4 reg_data;

	gettimeofday(&start_point, NULL);
	
	//write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, 0x7);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */
	//write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, 0x0);

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_ECC_ENABLE_H_REG_OFFSET), 0x0);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ECC_ENABLE_H_REG_OFFSET, 0);
#endif
	
	if (flag == 1)
	{
		/* Test Mode로 세팅 : 2를 write하면 Private Key를 고정 */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA256_RANDOM_ENABLE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA256_RANDOM_ENABLE);
	#endif
	}
	else if (flag == 2)
	{
		/* Test Mode로 세팅 : 2를 write하면 Private Key를 고정 */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA224_RANDOM_ENABLE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA224_RANDOM_ENABLE);
	#endif
	}
	
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), SIGNATURE_GEN_RANDOM_SEL_BIT);
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), TRANSFER_PRIVATE_RANDOM_SEL_BIT);
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), RECEIVER_PRIVATE_RANDOM_SEL_BIT);

	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00000000);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, SIGNATURE_GEN_RANDOM_SEL_BIT);
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, TRANSFER_PRIVATE_RANDOM_SEL_BIT);
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, RECEIVER_PRIVATE_RANDOM_SEL_BIT);
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, 0x00000000);
#endif
	/* Prime Number Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM1_H_REG_OFFSET), 0x1);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM2_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM3_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM4_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM6_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM7_H_REG_OFFSET), 0xFFFFFFFF);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM1_H_REG_OFFSET, 0x1);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM2_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM3_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM4_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM6_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM7_H_REG_OFFSET, 0xFFFFFFFF);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM1_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM3_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM4_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM5_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM6_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM7_H_REG_OFFSET), 0x00000001);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM1_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM3_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM4_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM5_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM6_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM7_H_REG_OFFSET, 0x00000001);
	#endif
	}

	/* test N Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER1_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER3_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER4_H_REG_OFFSET), 0xBCE6FAAD);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER5_H_REG_OFFSET), 0xA7179E84);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER6_H_REG_OFFSET), 0xF3B9CAC2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER7_H_REG_OFFSET), 0xFC632551);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER1_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER3_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER4_H_REG_OFFSET, 0xBCE6FAAD);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER5_H_REG_OFFSET, 0xA7179E84);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER6_H_REG_OFFSET, 0xF3B9CAC2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER7_H_REG_OFFSET, 0xFC632551);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER1_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER3_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER4_H_REG_OFFSET), 0xFFFF16A2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER5_H_REG_OFFSET), 0xE0B8F03E);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER6_H_REG_OFFSET), 0x13DD2945);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER7_H_REG_OFFSET), 0x5C5C2A3D);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER1_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER3_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER4_H_REG_OFFSET, 0xFFFF16A2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER5_H_REG_OFFSET, 0xE0B8F03E);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER6_H_REG_OFFSET, 0x13DD2945);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER7_H_REG_OFFSET, 0x5C5C2A3D);
	#endif
	}
	

	/* iArith_Base_Gx Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX0_H_REG_OFFSET), 0x6B17D1F2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX1_H_REG_OFFSET), 0xE12C4247);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX2_H_REG_OFFSET), 0xF8BCE6E5);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX3_H_REG_OFFSET), 0x63A440F2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX4_H_REG_OFFSET), 0x77037D81);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX5_H_REG_OFFSET), 0x2DEB33A0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX6_H_REG_OFFSET), 0xF4A13945);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX7_H_REG_OFFSET), 0xD898C296);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX0_H_REG_OFFSET, 0x6B17D1F2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX1_H_REG_OFFSET, 0xE12C4247);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX2_H_REG_OFFSET, 0xF8BCE6E5);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX3_H_REG_OFFSET, 0x63A440F2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX4_H_REG_OFFSET, 0x77037D81);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX5_H_REG_OFFSET, 0x2DEB33A0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX6_H_REG_OFFSET, 0xF4A13945);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX7_H_REG_OFFSET, 0xD898C296);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX1_H_REG_OFFSET), 0xB70E0CBD);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX2_H_REG_OFFSET), 0x6BB4BF7F);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX3_H_REG_OFFSET), 0x321390B9);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX4_H_REG_OFFSET), 0x4A03C1D3);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX5_H_REG_OFFSET), 0x56C21122);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX6_H_REG_OFFSET), 0x343280D6);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX7_H_REG_OFFSET), 0x115C1D21);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX1_H_REG_OFFSET, 0xB70E0CBD);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX2_H_REG_OFFSET, 0x6BB4BF7F);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX3_H_REG_OFFSET, 0x321390B9);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX4_H_REG_OFFSET, 0x4A03C1D3);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX5_H_REG_OFFSET, 0x56C21122);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX6_H_REG_OFFSET, 0x343280D6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX7_H_REG_OFFSET, 0x115C1D21);
	#endif
	}

	/* iArith_Base_Gy Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY0_H_REG_OFFSET), 0x4FE342E2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY1_H_REG_OFFSET), 0xFE1A7F9B);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY2_H_REG_OFFSET), 0x8EE7EB4A);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY3_H_REG_OFFSET), 0x7C0F9E16);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY4_H_REG_OFFSET), 0x2BCE3357);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY5_H_REG_OFFSET), 0x6B315ECE);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY6_H_REG_OFFSET), 0xCBB64068);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY7_H_REG_OFFSET), 0x37BF51F5);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY0_H_REG_OFFSET, 0x4FE342E2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY1_H_REG_OFFSET, 0xFE1A7F9B);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY2_H_REG_OFFSET, 0x8EE7EB4A);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY3_H_REG_OFFSET, 0x7C0F9E16);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY4_H_REG_OFFSET, 0x2BCE3357);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY5_H_REG_OFFSET, 0x6B315ECE);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY6_H_REG_OFFSET, 0xCBB64068);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY7_H_REG_OFFSET, 0x37BF51F5);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY1_H_REG_OFFSET), 0xBD376388);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY2_H_REG_OFFSET), 0xB5F723FB);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY3_H_REG_OFFSET), 0x4C22DFE6);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY4_H_REG_OFFSET), 0xCD4375A0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY5_H_REG_OFFSET), 0x5A074764);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY6_H_REG_OFFSET), 0x44D58199);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY7_H_REG_OFFSET), 0x85007E34);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY1_H_REG_OFFSET, 0xBD376388);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY2_H_REG_OFFSET, 0xB5F723FB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY3_H_REG_OFFSET, 0x4C22DFE6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY4_H_REG_OFFSET, 0xCD4375A0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY5_H_REG_OFFSET, 0x5A074764);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY6_H_REG_OFFSET, 0x44D58199);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY7_H_REG_OFFSET, 0x85007E34);
	#endif
	}

	/* Private Key Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY0_H_REG_OFFSET), 0x2CA1411A);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY1_H_REG_OFFSET), 0x41B17B24);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY2_H_REG_OFFSET), 0xCC8C3B08);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY3_H_REG_OFFSET), 0x9CFD033F);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY4_H_REG_OFFSET), 0x1920202A);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY5_H_REG_OFFSET), 0x6C0DE8AB);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY6_H_REG_OFFSET), 0xB97DF149);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY7_H_REG_OFFSET), 0x8D50D2C8);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY0_H_REG_OFFSET, 0x2CA1411A);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY1_H_REG_OFFSET, 0x41B17B24);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY2_H_REG_OFFSET, 0xCC8C3B08);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY3_H_REG_OFFSET, 0x9CFD033F);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY4_H_REG_OFFSET, 0x1920202A);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY5_H_REG_OFFSET, 0x6C0DE8AB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY6_H_REG_OFFSET, 0xB97DF149);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY7_H_REG_OFFSET, 0x8D50D2C8);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY1_H_REG_OFFSET), 0x39C01D09);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY2_H_REG_OFFSET), 0x2367BC5D);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY3_H_REG_OFFSET), 0xC4E9DEF0);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY4_H_REG_OFFSET), 0x3510D027);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY5_H_REG_OFFSET), 0x2C77DABA);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY6_H_REG_OFFSET), 0x7C152930);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY7_H_REG_OFFSET), 0xAA8319AB);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY1_H_REG_OFFSET, 0x39C01D09);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY2_H_REG_OFFSET, 0x2367BC5D);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY3_H_REG_OFFSET, 0xC4E9DEF0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY4_H_REG_OFFSET, 0x3510D027);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY5_H_REG_OFFSET, 0x2C77DABA);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY6_H_REG_OFFSET, 0x7C152930);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY7_H_REG_OFFSET, 0xAA8319AB);
	#endif
	}

	if (ecdsa_print_flag)
	{
		printf("=================================\n");
		printf("[fpag_ecdsa_test] Transmit Part!!\n");
		printf("=================================\n");
	}

	if (ecdsa_print_flag)
	{
		printf("Display Private Key!!\n");
	}
	for ( i = 0; i < 8; i++ )
	{
		if (ecdsa_print_flag)
		{
			printf("[%08x]", read_wave_ecc_reg32(((ECDSA_PRIVATE_KEY0_H_REG_OFFSET) + (i*4))));
			if ( ( (i+1) % 10 ) == 0 )
				printf("\n");
		}
	}
	printf("\n");


	/* A at Equation E */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A1_H_REG_OFFSET), 0x00000001);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A2_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A3_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A4_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A6_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A7_H_REG_OFFSET), 0xFFFFFFFC);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A1_H_REG_OFFSET, 0x00000001);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A2_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A3_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A4_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A6_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A7_H_REG_OFFSET, 0xFFFFFFFC);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A1_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A3_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A4_H_REG_OFFSET), 0xFFFFFFFE);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A6_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A7_H_REG_OFFSET), 0xFFFFFFFE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A1_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A3_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A4_H_REG_OFFSET, 0xFFFFFFFE);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A6_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A7_H_REG_OFFSET, 0xFFFFFFFE);
	#endif
	}

	/* B at Equation E */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B0_H_REG_OFFSET), 0x5AC635D8);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B1_H_REG_OFFSET), 0xAA3A93E7);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B2_H_REG_OFFSET), 0xB3EBBD55);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B3_H_REG_OFFSET), 0x769886BC);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B4_H_REG_OFFSET), 0x651D06B0);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B5_H_REG_OFFSET), 0xCC53B0F6);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B6_H_REG_OFFSET), 0x3BCE3C3E);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B7_H_REG_OFFSET), 0x27D2604B);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B0_H_REG_OFFSET, 0x5AC635D8);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B1_H_REG_OFFSET, 0xAA3A93E7);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B2_H_REG_OFFSET, 0xB3EBBD55);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B3_H_REG_OFFSET, 0x769886BC);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B4_H_REG_OFFSET, 0x651D06B0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B5_H_REG_OFFSET, 0xCC53B0F6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B6_H_REG_OFFSET, 0x3BCE3C3E);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B7_H_REG_OFFSET, 0x27D2604B);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B0_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B1_H_REG_OFFSET), 0xB4050A85);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B2_H_REG_OFFSET), 0x0C04B3AB);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B3_H_REG_OFFSET), 0xF5413256);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B4_H_REG_OFFSET), 0x5044B0B7);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B5_H_REG_OFFSET), 0xD7BFD8BA);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B6_H_REG_OFFSET), 0x270B3943);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B7_H_REG_OFFSET), 0x2355FFB4);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B0_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B1_H_REG_OFFSET, 0xB4050A85);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B2_H_REG_OFFSET, 0x0C04B3AB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B3_H_REG_OFFSET, 0xF5413256);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B4_H_REG_OFFSET, 0x5044B0B7);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B5_H_REG_OFFSET, 0xD7BFD8BA);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B6_H_REG_OFFSET, 0x270B3943);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B7_H_REG_OFFSET, 0x2355FFB4);
	#endif
	}
	

	/* PNP Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_PNP0_H_REG_OFFSET), 0xCCD1C8AA);
		reg_writel((wave_dsrc_base + ECDSA_MONT_PNP1_H_REG_OFFSET), 0xEE00BC4F);
		reg_writel((wave_dsrc_base + ECDSA_MONT_QNQ0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_MONT_QNQ1_H_REG_OFFSET), 0x1);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_PNP0_H_REG_OFFSET, 0xCCD1C8AA);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_PNP1_H_REG_OFFSET, 0xEE00BC4F);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_QNQ0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_QNQ1_H_REG_OFFSET, 0x1);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_PNP0_H_REG_OFFSET), 0xD6E24270);
		reg_writel((wave_dsrc_base + ECDSA_MONT_PNP1_H_REG_OFFSET), 0x6A1FC2EB);
		reg_writel((wave_dsrc_base + ECDSA_MONT_QNQ0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_QNQ1_H_REG_OFFSET), 0xFFFFFFFF);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_PNP0_H_REG_OFFSET, 0xD6E24270);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_PNP1_H_REG_OFFSET, 0x6A1FC2EB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_QNQ0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_QNQ1_H_REG_OFFSET, 0xFFFFFFFF);
	#endif
	}

	/* R2 Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_R20_H_REG_OFFSET), 0x66E12D94);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R21_H_REG_OFFSET), 0xF3D95620);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R22_H_REG_OFFSET), 0x2845B239);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R23_H_REG_OFFSET), 0x2B6BEC59);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R24_H_REG_OFFSET), 0x4699799C);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R25_H_REG_OFFSET), 0x49BD6FA6);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R26_H_REG_OFFSET), 0x83244C95);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R27_H_REG_OFFSET), 0xBE79EEA2);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R20_H_REG_OFFSET, 0x66E12D94);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R21_H_REG_OFFSET, 0xF3D95620);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R22_H_REG_OFFSET, 0x2845B239);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R23_H_REG_OFFSET, 0x2B6BEC59);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R24_H_REG_OFFSET, 0x4699799C);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R25_H_REG_OFFSET, 0x49BD6FA6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R26_H_REG_OFFSET, 0x83244C95);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R27_H_REG_OFFSET, 0xBE79EEA2);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_R20_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R21_H_REG_OFFSET), 0xB1E97961);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R22_H_REG_OFFSET), 0x6AD15F7C);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R23_H_REG_OFFSET), 0xD9714856);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R24_H_REG_OFFSET), 0xABC8FF59);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R25_H_REG_OFFSET), 0x31D63F4B);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R26_H_REG_OFFSET), 0x29947A69);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R27_H_REG_OFFSET), 0x5F517D15);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R20_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R21_H_REG_OFFSET, 0xB1E97961);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R22_H_REG_OFFSET, 0x6AD15F7C);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R23_H_REG_OFFSET, 0xD9714856);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R24_H_REG_OFFSET, 0xABC8FF59);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R25_H_REG_OFFSET, 0x31D63F4B);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R26_H_REG_OFFSET, 0x29947A69);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R27_H_REG_OFFSET, 0x5F517D15);
	#endif
	}

	/* test R Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q0_H_REG_OFFSET), 0x00000004);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q1_H_REG_OFFSET), 0xFFFFFFFD);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q3_H_REG_OFFSET), 0xFFFFFFFE);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q4_H_REG_OFFSET), 0xFFFFFFFB);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q6_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q7_H_REG_OFFSET), 0x00000003);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q0_H_REG_OFFSET, 0x00000004);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q1_H_REG_OFFSET, 0xFFFFFFFD);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q3_H_REG_OFFSET, 0xFFFFFFFE);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q4_H_REG_OFFSET, 0xFFFFFFFB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q6_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q7_H_REG_OFFSET, 0x00000003);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q0_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q1_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q2_H_REG_OFFSET), 0xFFFFFFFE);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q3_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q4_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q5_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q6_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q7_H_REG_OFFSET), 0x00000001);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q0_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q1_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q2_H_REG_OFFSET, 0xFFFFFFFE);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q3_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q4_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q5_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q6_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q7_H_REG_OFFSET, 0x00000001);
	#endif
	}

#if 1
	if (flag == 1)
	{
		/* 1를 Write하면 Random 모드 */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA256_RANDOM_ENABLE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA256_RANDOM_ENABLE);
	#endif
	}
	else if (flag == 2)
	{
		/* 1를 Write하면 Random 모드 */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA224_RANDOM_ENABLE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA224_RANDOM_ENABLE);
	#endif
	}
#endif

	//reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x1);

	//reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), SIGNATURE_GEN_RANDOM_SEL_BIT);
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), TRANSFER_PRIVATE_RANDOM_SEL_BIT);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, TRANSFER_PRIVATE_RANDOM_SEL_BIT);
#endif

	if (ecdsa_print_flag)
	{
		printf("Display Sender Random Key!!\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECDSA_RANDOM_NUMBER0_H_REG_OFFSET)+(i*4))));
		}
		
		printf("\n");
	}


#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00000000); /* RANDOM Number 동작을 멈춘다.*/
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, 0x00000000);/* RANDOM Number 동작을 멈춘다.*/
#endif


	/* test Hash Settings */
	i = 0;
	if (flag == 1)
	{
		message[i++] = 0x45;
		message[i++] = 0x78;
		message[i++] = 0x61;
		message[i++] = 0x6D;
		message[i++] = 0x70;
		message[i++] = 0x6C;
		message[i++] = 0x65;
		message[i++] = 0x20;

		message[i++] = 0x6F;
		message[i++] = 0x66;
		message[i++] = 0x20;
		message[i++] = 0x45;
		message[i++] = 0x43;
		message[i++] = 0x44;
		message[i++] = 0x53;
		message[i++] = 0x41;

		message[i++] = 0x20;
		message[i++] = 0x77;
		message[i++] = 0x69;
		message[i++] = 0x74;
		message[i++] = 0x68;
		message[i++] = 0x20;
		message[i++] = 0x61;
		message[i++] = 0x6E;

		message[i++] = 0x73;
		message[i++] = 0x69;
		message[i++] = 0x70;
		message[i++] = 0x32;
		message[i++] = 0x35;
		message[i++] = 0x36;
		message[i++] = 0x72;
		message[i++] = 0x31;

		message[i++] = 0x20;
		message[i++] = 0x61;
		message[i++] = 0x6E;
		message[i++] = 0x64;
		message[i++] = 0x20;
		message[i++] = 0x53;
		message[i++] = 0x48;
		message[i++] = 0x41;

		message[i++] = 0x2D;
		message[i++] = 0x32;
		message[i++] = 0x35;
		message[i++] = 0x36;
	}
	else if (flag == 2)
	{
		message[i++] = 0x45;
		message[i++] = 0x78;
		message[i++] = 0x61;
		message[i++] = 0x6D;
		message[i++] = 0x70;
		message[i++] = 0x6C;
		message[i++] = 0x65;
		message[i++] = 0x20;

		message[i++] = 0x6F;
		message[i++] = 0x66;
		message[i++] = 0x20;
		message[i++] = 0x45;
		message[i++] = 0x43;
		message[i++] = 0x44;
		message[i++] = 0x53;
		message[i++] = 0x41;

		message[i++] = 0x20;
		message[i++] = 0x77;
		message[i++] = 0x69;
		message[i++] = 0x74;
		message[i++] = 0x68;
		message[i++] = 0x20;
		message[i++] = 0x61;
		message[i++] = 0x6E;

		message[i++] = 0x73;
		message[i++] = 0x69;
		message[i++] = 0x70;
		message[i++] = 0x32;
		message[i++] = 0x32;
		message[i++] = 0x34;
		message[i++] = 0x72;
		message[i++] = 0x31;

		message[i++] = 0x20;
		message[i++] = 0x61;
		message[i++] = 0x6E;
		message[i++] = 0x64;
		message[i++] = 0x20;
		message[i++] = 0x53;
		message[i++] = 0x48;
		message[i++] = 0x41;

		message[i++] = 0x2D;
		message[i++] = 0x32;
		message[i++] = 0x32;
		message[i++] = 0x34;
	}
	msg_len = i;
	fsha256_test1(message, msg_len, flag, sha_out);

	//printf("End fsha256_test1\n");

	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, SIGNATURE_GEN_ENABLE_BIT);

	

	time_out = 20000;
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & SIGGEN_DONE_STATUS_BIT)	/* Signature Generation Done */
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);/* Clear */

	if (time_out < 0)
		printf("[fpga_ecdsa_test] Signature Generation Time Out!!\n");
	if (ecdsa_print_flag)
	{
		//printf("SIGGEN status = 0x%08x, time_out = %d\n", status, time_out);

		printf("\n[fpga_ecdsa_test]Display Signature Generation R\n");
	}


	for ( i = 0; i < 8; i++ )
	{
		r[i] = reg_readl(((wave_dsrc_base + ECDSA_SIGGEN_KEYPAIR_R0_H_REG_OFFSET) + (i*4)));
		if (ecdsa_print_flag)
		{
			printf("[%08x]", r[i]);
			if ( ( (i+1) % 10 ) == 0 )
				printf("\n");
		}
	}

	if (ecdsa_print_flag)
		printf("\n");

	if (ecdsa_print_flag)
	{
		printf("\n[fpga_ecdsa_test]Display Signature Generation S\n");
	}


	for ( i = 0; i < 8; i++ )
	{
		s[i] = reg_readl(((wave_dsrc_base + ECDSA_SIGGEN_KEYPAIR_S0_H_REG_OFFSET) + (i*4)));
		if (ecdsa_print_flag)
		{
			printf("[%08x]", s[i]);
			if ( ( (i+1) % 10 ) == 0 )
				printf("\n");
		}
	}
	if (ecdsa_print_flag)
		printf("\n");

	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("Signature Generation Operation Time : %f\n",operating_time);

	if(time_out)
	{
		printf("================================================\n");
		printf("[fpag_ecdsa_random_test] Signature Generation Success!!\n");
		printf("================================================\n");
	}
	else
	{
		printf("================================================\n");
		printf("[fpag_ecdsa_random_test] Signature Generation Fail!!\n");
		printf("================================================\n");
	}
	//write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, 0x7);	/* Clear */
	//write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, 0x0);
	

	if (ecdsa_print_flag)
	{
		printf("\n\n\n=================================\n");
		printf("[fpag_ecdsa_test] Receive Part!!\n");
		printf("=================================\n");
	}
	
	gettimeofday(&start_point, NULL);

	if (flag == 1)
	{
		/* Test Mode로 세팅 : 2를 write하면 Private Key를 고정 */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA256_RANDOM_ENABLE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA256_RANDOM_ENABLE);
	#endif
	}
	else if (flag == 2)
	{
		/* Test Mode로 세팅 : 2를 write하면 Private Key를 고정 */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA224_RANDOM_ENABLE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA224_RANDOM_ENABLE);
	#endif
	}
	
	fsha256_test1(message, msg_len, flag, sha_out);

	if (ecdsa_test_flag == 0)
	{
		if (flag == 1)
		{
		#if WAVE_SECURITY_16BIT_ENABLE == 0
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), 0x596375E6);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), 0xCE57E0F2);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), 0x0294FC46);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), 0xBDFCFD19);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), 0xA39F8161);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), 0xB58695B3);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), 0xEC5B3D16);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), 0x427C274D);
		#else
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET, 0x596375E6);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET, 0xCE57E0F2);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET, 0x0294FC46);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET, 0xBDFCFD19);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET, 0xA39F8161);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET, 0xB58695B3);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET, 0xEC5B3D16);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET, 0x427C274D);
		#endif
		}
		else if (flag == 2)
		{
		#if WAVE_SECURITY_16BIT_ENABLE == 0
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), 0x00000000);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), 0xFD44EC11);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), 0xF9D43D9D);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), 0x23B1E1D1);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), 0xC9ED6519);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), 0xB40ECF0C);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), 0x79F48CF4);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), 0x76CC43F1);
		#else
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET, 0x00000000);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET, 0xFD44EC11);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET, 0xF9D43D9D);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET, 0x23B1E1D1);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET, 0xC9ED6519);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET, 0xB40ECF0C);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET, 0x79F48CF4);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET, 0x76CC43F1);
		#endif
		}
	}
	else
	{
		if (flag == 1)
		{
		#if WAVE_SECURITY_16BIT_ENABLE == 0
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), 0x12345678);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), 0x9abcdef1);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), 0x23456789);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), 0xabcdef12);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), 0x3456789a);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), 0xbcdef123);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), 0x456789ab);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), 0xcdef1234);
		#else
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET, 0x12345678);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET, 0x9abcdef1);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET, 0x23456789);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET, 0xabcdef12);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET, 0x3456789a);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET, 0xbcdef123);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET, 0x456789ab);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET, 0xcdef1234);
		#endif
		}
		else if (flag == 2)
		{
		#if WAVE_SECURITY_16BIT_ENABLE == 0
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), 0x00000000);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), 0x12345678);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), 0x9abcdef1);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), 0x23456789);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), 0xabcdef12);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), 0x3456789a);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), 0xbcdef123);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), 0x456789ab);
		#else
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET, 0x00000000);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET, 0x12345678);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET, 0x9abcdef1);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET, 0x23456789);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET, 0xabcdef12);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET, 0x3456789a);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET, 0xbcdef123);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET, 0x456789ab);
		#endif
		}
	}

	if (ecdsa_print_flag)
	{
		printf("Display Public KEY\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", read_wave_ecc_reg32(((ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x1);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET, 0x1);
#endif

	/* 수신된 R, S값을 세팅한다. */
	for ( i = 0; i < 8; i++ )
	{
		/* SIGVERIFY Setting */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R0_H_REG_OFFSET + (i*4)), r[i]);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SIGVERIFY_KEYPAIR_R0_H_REG_OFFSET + (i*4)), r[i]);
	#endif
	}

	for ( i = 0; i < 8; i++ )
	{
		/* SIGVERIFY Setting */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S0_H_REG_OFFSET + (i*4)), s[i]);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SIGVERIFY_KEYPAIR_S0_H_REG_OFFSET + (i*4)), s[i]);
	#endif
	}

	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, ECDSA_KEY_RECOVERY_ENABLE_BIT);
	time_out = 20000;
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & ECDSA_RECOVERY_DONE_BIT)
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, ECDSA_RECOVERY_DONE_BIT);/* Clear */
	if (time_out < 0)
		printf("[fpga_ecdsa_test] Key Recovery Done Time Out!!\n");
	
	//if (ecdsa_print_flag)
	//	printf("TRANS_PUBLIC_KEY_Y_RECOVERY status = 0x%08x, time_out = %d\n", status, time_out);

	if (ecdsa_print_flag)
	{
		printf("\nDisplay Recovery Sender Public Key Y\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECDSA_TRANS_RECEIVE_RECOVERY_Y0_H_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, 0);
#endif


	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, SIGNATURE_VERIFY_ENABLE_BIT);

	time_out = 20000;

	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if ((status & SIGVERIFY_DONE_STATUS_BIT) && (status & SIGVERIFY_VALID_STATUS_BIT))	/* Signature Generation Done */
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);/* Clear */

	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("Signature Validation Operation Time : %f\n",operating_time);

	if (time_out < 0)
	{
		printf("================================================\n");
		printf("[fpag_ecdsa_random_test] Signature Verification Fail!!\n");
		printf("================================================\n");
	}
	else
	{
		printf("================================================\n");
		printf("[fpag_ecdsa_random_test] Signature Verification Success!!\n");
		printf("================================================\n");
	}
		
	if (ecdsa_print_flag)
		printf("SIGVERIFY Done status = 0x%08x, time_out = %d\n", status, time_out);

	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */
	


	
}

void ecdsa_random_generator_test(void)
{
	U4		r[8];
	U4		s[8];
	volatile unsigned int status;
	int 		i;
	int		msg_len;
	int		time_out;
	U1 sha_out[32];
	volatile unsigned int control;
	struct timeval start_point, end_point;
	volatile double operating_time;
	U4 reg_data;

	gettimeofday(&start_point, NULL);
	
	//write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, 0x7);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */
	//write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, 0x0);

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_ECC_ENABLE_H_REG_OFFSET), 0x0);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ECC_ENABLE_H_REG_OFFSET, 0);
#endif
	
	
		/* Test Mode로 세팅 : 2를 write하면 Private Key를 고정 */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA256_RANDOM_ENABLE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA256_RANDOM_ENABLE);
	#endif
	
	
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), SIGNATURE_GEN_RANDOM_SEL_BIT);
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), TRANSFER_PRIVATE_RANDOM_SEL_BIT);
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), RECEIVER_PRIVATE_RANDOM_SEL_BIT);

	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00000000);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, SIGNATURE_GEN_RANDOM_SEL_BIT);
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, TRANSFER_PRIVATE_RANDOM_SEL_BIT);
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, RECEIVER_PRIVATE_RANDOM_SEL_BIT);
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, 0x00000000);
#endif
	/* Prime Number Settings */
	
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM1_H_REG_OFFSET), 0x1);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM2_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM3_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM4_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM6_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM7_H_REG_OFFSET), 0xFFFFFFFF);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM1_H_REG_OFFSET, 0x1);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM2_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM3_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM4_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM6_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM7_H_REG_OFFSET, 0xFFFFFFFF);
	#endif
	

	/* test N Settings */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER1_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER3_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER4_H_REG_OFFSET), 0xBCE6FAAD);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER5_H_REG_OFFSET), 0xA7179E84);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER6_H_REG_OFFSET), 0xF3B9CAC2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER7_H_REG_OFFSET), 0xFC632551);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER1_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER3_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER4_H_REG_OFFSET, 0xBCE6FAAD);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER5_H_REG_OFFSET, 0xA7179E84);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER6_H_REG_OFFSET, 0xF3B9CAC2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER7_H_REG_OFFSET, 0xFC632551);
	#endif
	

	/* iArith_Base_Gx Settings */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX0_H_REG_OFFSET), 0x6B17D1F2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX1_H_REG_OFFSET), 0xE12C4247);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX2_H_REG_OFFSET), 0xF8BCE6E5);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX3_H_REG_OFFSET), 0x63A440F2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX4_H_REG_OFFSET), 0x77037D81);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX5_H_REG_OFFSET), 0x2DEB33A0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX6_H_REG_OFFSET), 0xF4A13945);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX7_H_REG_OFFSET), 0xD898C296);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX0_H_REG_OFFSET, 0x6B17D1F2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX1_H_REG_OFFSET, 0xE12C4247);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX2_H_REG_OFFSET, 0xF8BCE6E5);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX3_H_REG_OFFSET, 0x63A440F2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX4_H_REG_OFFSET, 0x77037D81);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX5_H_REG_OFFSET, 0x2DEB33A0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX6_H_REG_OFFSET, 0xF4A13945);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX7_H_REG_OFFSET, 0xD898C296);
	#endif
	

	/* iArith_Base_Gy Settings */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY0_H_REG_OFFSET), 0x4FE342E2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY1_H_REG_OFFSET), 0xFE1A7F9B);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY2_H_REG_OFFSET), 0x8EE7EB4A);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY3_H_REG_OFFSET), 0x7C0F9E16);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY4_H_REG_OFFSET), 0x2BCE3357);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY5_H_REG_OFFSET), 0x6B315ECE);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY6_H_REG_OFFSET), 0xCBB64068);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY7_H_REG_OFFSET), 0x37BF51F5);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY0_H_REG_OFFSET, 0x4FE342E2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY1_H_REG_OFFSET, 0xFE1A7F9B);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY2_H_REG_OFFSET, 0x8EE7EB4A);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY3_H_REG_OFFSET, 0x7C0F9E16);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY4_H_REG_OFFSET, 0x2BCE3357);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY5_H_REG_OFFSET, 0x6B315ECE);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY6_H_REG_OFFSET, 0xCBB64068);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY7_H_REG_OFFSET, 0x37BF51F5);
	#endif
	

	/* Private Key Settings */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY0_H_REG_OFFSET), 0x2CA1411A);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY1_H_REG_OFFSET), 0x41B17B24);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY2_H_REG_OFFSET), 0xCC8C3B08);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY3_H_REG_OFFSET), 0x9CFD033F);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY4_H_REG_OFFSET), 0x1920202A);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY5_H_REG_OFFSET), 0x6C0DE8AB);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY6_H_REG_OFFSET), 0xB97DF149);
		reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY7_H_REG_OFFSET), 0x8D50D2C8);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY0_H_REG_OFFSET, 0x2CA1411A);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY1_H_REG_OFFSET, 0x41B17B24);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY2_H_REG_OFFSET, 0xCC8C3B08);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY3_H_REG_OFFSET, 0x9CFD033F);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY4_H_REG_OFFSET, 0x1920202A);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY5_H_REG_OFFSET, 0x6C0DE8AB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY6_H_REG_OFFSET, 0xB97DF149);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY7_H_REG_OFFSET, 0x8D50D2C8);
	#endif

	if (ecdsa_print_flag)
	{
		printf("=================================\n");
		printf("[fpag_ecdsa_test] Transmit Part!!\n");
		printf("=================================\n");
	}

	if (ecdsa_print_flag)
	{
		printf("Display Private Key!!\n");
	}
	for ( i = 0; i < 8; i++ )
	{
		if (ecdsa_print_flag)
		{
			printf("[%08x]", read_wave_ecc_reg32(((ECDSA_PRIVATE_KEY0_H_REG_OFFSET) + (i*4))));
			if ( ( (i+1) % 10 ) == 0 )
				printf("\n");
		}
	}
	printf("\n");


	/* A at Equation E */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A1_H_REG_OFFSET), 0x00000001);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A2_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A3_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A4_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A6_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A7_H_REG_OFFSET), 0xFFFFFFFC);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A1_H_REG_OFFSET, 0x00000001);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A2_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A3_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A4_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A6_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A7_H_REG_OFFSET, 0xFFFFFFFC);
	#endif
	

	/* B at Equation E */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B0_H_REG_OFFSET), 0x5AC635D8);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B1_H_REG_OFFSET), 0xAA3A93E7);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B2_H_REG_OFFSET), 0xB3EBBD55);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B3_H_REG_OFFSET), 0x769886BC);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B4_H_REG_OFFSET), 0x651D06B0);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B5_H_REG_OFFSET), 0xCC53B0F6);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B6_H_REG_OFFSET), 0x3BCE3C3E);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B7_H_REG_OFFSET), 0x27D2604B);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B0_H_REG_OFFSET, 0x5AC635D8);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B1_H_REG_OFFSET, 0xAA3A93E7);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B2_H_REG_OFFSET, 0xB3EBBD55);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B3_H_REG_OFFSET, 0x769886BC);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B4_H_REG_OFFSET, 0x651D06B0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B5_H_REG_OFFSET, 0xCC53B0F6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B6_H_REG_OFFSET, 0x3BCE3C3E);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B7_H_REG_OFFSET, 0x27D2604B);
	#endif
	

	/* PNP Settings */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_PNP0_H_REG_OFFSET), 0xCCD1C8AA);
		reg_writel((wave_dsrc_base + ECDSA_MONT_PNP1_H_REG_OFFSET), 0xEE00BC4F);
		reg_writel((wave_dsrc_base + ECDSA_MONT_QNQ0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_MONT_QNQ1_H_REG_OFFSET), 0x1);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_PNP0_H_REG_OFFSET, 0xCCD1C8AA);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_PNP1_H_REG_OFFSET, 0xEE00BC4F);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_QNQ0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_QNQ1_H_REG_OFFSET, 0x1);
	#endif
	

	/* R2 Settings */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_R20_H_REG_OFFSET), 0x66E12D94);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R21_H_REG_OFFSET), 0xF3D95620);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R22_H_REG_OFFSET), 0x2845B239);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R23_H_REG_OFFSET), 0x2B6BEC59);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R24_H_REG_OFFSET), 0x4699799C);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R25_H_REG_OFFSET), 0x49BD6FA6);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R26_H_REG_OFFSET), 0x83244C95);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R27_H_REG_OFFSET), 0xBE79EEA2);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R20_H_REG_OFFSET, 0x66E12D94);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R21_H_REG_OFFSET, 0xF3D95620);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R22_H_REG_OFFSET, 0x2845B239);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R23_H_REG_OFFSET, 0x2B6BEC59);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R24_H_REG_OFFSET, 0x4699799C);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R25_H_REG_OFFSET, 0x49BD6FA6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R26_H_REG_OFFSET, 0x83244C95);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R27_H_REG_OFFSET, 0xBE79EEA2);
	#endif
	

	/* test R Settings */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q0_H_REG_OFFSET), 0x00000004);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q1_H_REG_OFFSET), 0xFFFFFFFD);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q3_H_REG_OFFSET), 0xFFFFFFFE);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q4_H_REG_OFFSET), 0xFFFFFFFB);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q6_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q7_H_REG_OFFSET), 0x00000003);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q0_H_REG_OFFSET, 0x00000004);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q1_H_REG_OFFSET, 0xFFFFFFFD);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q3_H_REG_OFFSET, 0xFFFFFFFE);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q4_H_REG_OFFSET, 0xFFFFFFFB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q6_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q7_H_REG_OFFSET, 0x00000003);
	#endif
	
	/* 1를 Write하면 Random 모드 */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA256_RANDOM_ENABLE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA256_RANDOM_ENABLE);
	#endif

	//reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x1);

	//reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), SIGNATURE_GEN_RANDOM_SEL_BIT);
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), TRANSFER_PRIVATE_RANDOM_SEL_BIT);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, TRANSFER_PRIVATE_RANDOM_SEL_BIT);
#endif

	printf("Display Sender Random Key!!\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECDSA_RANDOM_NUMBER0_H_REG_OFFSET)+(i*4))));

			//printf("[%s]\n", uintToBinary(reg_readl(((wave_dsrc_base+ECDSA_RANDOM_NUMBER0_H_REG_OFFSET)+(i*4)))));
		}
		
		printf("\n");
	


#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00000000); /* RANDOM Number 동작을 멈춘다.*/
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, 0x00000000);/* RANDOM Number 동작을 멈춘다.*/
#endif

	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */
	

}



/* flag가 1이면 256 mode, 2이면 224 mode */
int MakeSignedMsg(int flag, U1 *signed_msg, U1 *unsigned_msg, int unsigned_msg_len)
{
	U4		r[8];
	U4		s[8];
	volatile unsigned int status;
	int 		i, j, k;
	int		time_out;
	U1 sha_out[32];
	struct timeval start_point, end_point;
	volatile double operating_time;
	U1 public_key_len;
	U4_T private_key;

	gettimeofday(&start_point, NULL);

	if (ecdsa_print_flag)
	{
		if ( flag == 1 )
		{
			printf("ECDSA 256 Mode\n");
		}
		else
		{
			printf("ECDSA 224 Mode\n");
		}
	}


	//write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, 0x7);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */
	//write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SHA_DONE_STATUS_BIT);
	//write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, 0x0);

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_ECC_ENABLE_H_REG_OFFSET), 0x0);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ECC_ENABLE_H_REG_OFFSET, 0);
#endif
	
	if (flag == 1)
	{
		if (ecdsa_sw_test_fix_flag == 0)
		{
			/* Test Mode로 세팅 : 2를 write하면 Private Key를 고정 */
		#if WAVE_SECURITY_16BIT_ENABLE == 0
			reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA256_RANDOM_ENABLE);
		#else
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA256_RANDOM_ENABLE);
		#endif
		}
		else
		{
			/* Test Mode로 세팅 : 2를 write하면 Private Key를 고정 */
		#if WAVE_SECURITY_16BIT_ENABLE == 0
			reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA256_RANDOM_DISABLE);
		#else
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA256_RANDOM_DISABLE);
		#endif
		}
	}
	else if (flag == 2)
	{
		if (ecdsa_sw_test_fix_flag == 0)
		{
			/* Test Mode로 세팅 : 2를 write하면 Private Key를 고정 */
		#if WAVE_SECURITY_16BIT_ENABLE == 0
			reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA224_RANDOM_ENABLE);
		#else
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA224_RANDOM_ENABLE);
		#endif
		}
		else
		{
			/* Test Mode로 세팅 : 2를 write하면 Private Key를 고정 */
		#if WAVE_SECURITY_16BIT_ENABLE == 0
			reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA224_RANDOM_DISABLE);
		#else
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA224_RANDOM_DISABLE);
		#endif
		}
	}
	
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), SIGNATURE_GEN_RANDOM_SEL_BIT);
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), TRANSFER_PRIVATE_RANDOM_SEL_BIT);
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), RECEIVER_PRIVATE_RANDOM_SEL_BIT);

	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00000000);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, SIGNATURE_GEN_RANDOM_SEL_BIT);
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, TRANSFER_PRIVATE_RANDOM_SEL_BIT);
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, RECEIVER_PRIVATE_RANDOM_SEL_BIT);
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, 0x00000000);
#endif
	/* Prime Number Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM1_H_REG_OFFSET), 0x1);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM2_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM3_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM4_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM6_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM7_H_REG_OFFSET), 0xFFFFFFFF);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM1_H_REG_OFFSET, 0x1);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM2_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM3_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM4_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM6_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM7_H_REG_OFFSET, 0xFFFFFFFF);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM1_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM3_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM4_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM5_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM6_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM7_H_REG_OFFSET), 0x00000001);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM1_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM3_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM4_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM5_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM6_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM7_H_REG_OFFSET, 0x00000001);
	#endif
	}

	/* test N Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER1_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER3_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER4_H_REG_OFFSET), 0xBCE6FAAD);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER5_H_REG_OFFSET), 0xA7179E84);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER6_H_REG_OFFSET), 0xF3B9CAC2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER7_H_REG_OFFSET), 0xFC632551);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER1_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER3_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER4_H_REG_OFFSET, 0xBCE6FAAD);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER5_H_REG_OFFSET, 0xA7179E84);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER6_H_REG_OFFSET, 0xF3B9CAC2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER7_H_REG_OFFSET, 0xFC632551);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER1_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER3_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER4_H_REG_OFFSET), 0xFFFF16A2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER5_H_REG_OFFSET), 0xE0B8F03E);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER6_H_REG_OFFSET), 0x13DD2945);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER7_H_REG_OFFSET), 0x5C5C2A3D);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER1_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER3_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER4_H_REG_OFFSET, 0xFFFF16A2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER5_H_REG_OFFSET, 0xE0B8F03E);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER6_H_REG_OFFSET, 0x13DD2945);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER7_H_REG_OFFSET, 0x5C5C2A3D);
	#endif
	}
	

	/* iArith_Base_Gx Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX0_H_REG_OFFSET), 0x6B17D1F2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX1_H_REG_OFFSET), 0xE12C4247);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX2_H_REG_OFFSET), 0xF8BCE6E5);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX3_H_REG_OFFSET), 0x63A440F2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX4_H_REG_OFFSET), 0x77037D81);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX5_H_REG_OFFSET), 0x2DEB33A0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX6_H_REG_OFFSET), 0xF4A13945);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX7_H_REG_OFFSET), 0xD898C296);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX0_H_REG_OFFSET, 0x6B17D1F2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX1_H_REG_OFFSET, 0xE12C4247);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX2_H_REG_OFFSET, 0xF8BCE6E5);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX3_H_REG_OFFSET, 0x63A440F2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX4_H_REG_OFFSET, 0x77037D81);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX5_H_REG_OFFSET, 0x2DEB33A0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX6_H_REG_OFFSET, 0xF4A13945);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX7_H_REG_OFFSET, 0xD898C296);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX1_H_REG_OFFSET), 0xB70E0CBD);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX2_H_REG_OFFSET), 0x6BB4BF7F);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX3_H_REG_OFFSET), 0x321390B9);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX4_H_REG_OFFSET), 0x4A03C1D3);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX5_H_REG_OFFSET), 0x56C21122);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX6_H_REG_OFFSET), 0x343280D6);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX7_H_REG_OFFSET), 0x115C1D21);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX1_H_REG_OFFSET, 0xB70E0CBD);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX2_H_REG_OFFSET, 0x6BB4BF7F);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX3_H_REG_OFFSET, 0x321390B9);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX4_H_REG_OFFSET, 0x4A03C1D3);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX5_H_REG_OFFSET, 0x56C21122);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX6_H_REG_OFFSET, 0x343280D6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX7_H_REG_OFFSET, 0x115C1D21);
	#endif
	}

	/* iArith_Base_Gy Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY0_H_REG_OFFSET), 0x4FE342E2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY1_H_REG_OFFSET), 0xFE1A7F9B);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY2_H_REG_OFFSET), 0x8EE7EB4A);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY3_H_REG_OFFSET), 0x7C0F9E16);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY4_H_REG_OFFSET), 0x2BCE3357);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY5_H_REG_OFFSET), 0x6B315ECE);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY6_H_REG_OFFSET), 0xCBB64068);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY7_H_REG_OFFSET), 0x37BF51F5);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY0_H_REG_OFFSET, 0x4FE342E2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY1_H_REG_OFFSET, 0xFE1A7F9B);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY2_H_REG_OFFSET, 0x8EE7EB4A);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY3_H_REG_OFFSET, 0x7C0F9E16);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY4_H_REG_OFFSET, 0x2BCE3357);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY5_H_REG_OFFSET, 0x6B315ECE);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY6_H_REG_OFFSET, 0xCBB64068);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY7_H_REG_OFFSET, 0x37BF51F5);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY1_H_REG_OFFSET), 0xBD376388);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY2_H_REG_OFFSET), 0xB5F723FB);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY3_H_REG_OFFSET), 0x4C22DFE6);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY4_H_REG_OFFSET), 0xCD4375A0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY5_H_REG_OFFSET), 0x5A074764);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY6_H_REG_OFFSET), 0x44D58199);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY7_H_REG_OFFSET), 0x85007E34);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY1_H_REG_OFFSET, 0xBD376388);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY2_H_REG_OFFSET, 0xB5F723FB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY3_H_REG_OFFSET, 0x4C22DFE6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY4_H_REG_OFFSET, 0xCD4375A0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY5_H_REG_OFFSET, 0x5A074764);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY6_H_REG_OFFSET, 0x44D58199);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY7_H_REG_OFFSET, 0x85007E34);
	#endif
	}

	/* Private Key Settings */
	if (flag == 1)
	{
		j = 0;
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		for ( k = 0; k < 8; k++)
		{
			private_key.b1[3] = ecdsa256_private_key[0][j++];
			private_key.b1[2] = ecdsa256_private_key[0][j++];
			private_key.b1[1] = ecdsa256_private_key[0][j++];
			private_key.b1[0] = ecdsa256_private_key[0][j++];
			reg_writel((((wave_dsrc_base + ECDSA_PRIVATE_KEY0_H_REG_OFFSET) + (k*4))), private_key.b4);
		}
		//reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY0_H_REG_OFFSET), 0x2CA1411A);
		//reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY1_H_REG_OFFSET), 0x41B17B24);
		//reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY2_H_REG_OFFSET), 0xCC8C3B08);
		//reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY3_H_REG_OFFSET), 0x9CFD033F);
		//reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY4_H_REG_OFFSET), 0x1920202A);
		//reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY5_H_REG_OFFSET), 0x6C0DE8AB);
		//reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY6_H_REG_OFFSET), 0xB97DF149);
		//reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY7_H_REG_OFFSET), 0x8D50D2C8);
	#else
		for ( k = 0; k < 8; k++)
		{
			private_key.b1[3] = ecdsa256_private_key[0][j++];
			private_key.b1[2] = ecdsa256_private_key[0][j++];
			private_key.b1[1] = ecdsa256_private_key[0][j++];
			private_key.b1[0] = ecdsa256_private_key[0][j++];
			write_wave_ecc_reg32_by_16bit_or_32bit(((ECDSA_PRIVATE_KEY0_H_REG_OFFSET + (k*4))), private_key.b4);
		}
		//write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY0_H_REG_OFFSET, 0x2CA1411A);
		//write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY1_H_REG_OFFSET, 0x41B17B24);
		//write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY2_H_REG_OFFSET, 0xCC8C3B08);
		//write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY3_H_REG_OFFSET, 0x9CFD033F);
		//write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY4_H_REG_OFFSET, 0x1920202A);
		//write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY5_H_REG_OFFSET, 0x6C0DE8AB);
		//write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY6_H_REG_OFFSET, 0xB97DF149);
		//write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY7_H_REG_OFFSET, 0x8D50D2C8);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
		j = 0;
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		for ( k = 0; k < 8; k++)
		{
			private_key.b1[3] = ecdsa224_private_key[0][j++];
			private_key.b1[2] = ecdsa224_private_key[0][j++];
			private_key.b1[1] = ecdsa224_private_key[0][j++];
			private_key.b1[0] = ecdsa224_private_key[0][j++];
			reg_writel((((wave_dsrc_base + ECDSA_PRIVATE_KEY0_H_REG_OFFSET) + (k*4))), private_key.b4);
		}
		//reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY0_H_REG_OFFSET), 0x0);
		//reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY1_H_REG_OFFSET), 0x39C01D09);
		//reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY2_H_REG_OFFSET), 0x2367BC5D);
		//reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY3_H_REG_OFFSET), 0xC4E9DEF0);
		//reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY4_H_REG_OFFSET), 0x3510D027);
		//reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY5_H_REG_OFFSET), 0x2C77DABA);
		//reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY6_H_REG_OFFSET), 0x7C152930);
		//reg_writel((wave_dsrc_base + ECDSA_PRIVATE_KEY7_H_REG_OFFSET), 0xAA8319AB);
	#else
		for ( k = 0; k < 8; k++)
		{
			private_key.b1[3] = ecdsa224_private_key[0][j++];
			private_key.b1[2] = ecdsa224_private_key[0][j++];
			private_key.b1[1] = ecdsa224_private_key[0][j++];
			private_key.b1[0] = ecdsa224_private_key[0][j++];
			write_wave_ecc_reg32_by_16bit_or_32bit(((ECDSA_PRIVATE_KEY0_H_REG_OFFSET + (k*4))), private_key.b4);
		}
		//write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY0_H_REG_OFFSET, 0x0);
		//write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY1_H_REG_OFFSET, 0x39C01D09);
		//write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY2_H_REG_OFFSET, 0x2367BC5D);
		//write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY3_H_REG_OFFSET, 0xC4E9DEF0);
		//write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY4_H_REG_OFFSET, 0x3510D027);
		//write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY5_H_REG_OFFSET, 0x2C77DABA);
		//write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY6_H_REG_OFFSET, 0x7C152930);
		//write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_PRIVATE_KEY7_H_REG_OFFSET, 0xAA8319AB);
	#endif
	}

	if (ecdsa_print_flag)
	{
		printf("=================================\n");
		printf("[fpag_ecdsa_test] Transmit Part!!\n");
		printf("=================================\n");
	}

	if (ecdsa_print_flag)
	{
		printf("Display Private Key!!\n");
	}
	for ( i = 0; i < 8; i++ )
	{
		if (ecdsa_print_flag)
		{
			printf("[%08x]", read_wave_ecc_reg32(((ECDSA_PRIVATE_KEY0_H_REG_OFFSET) + (i*4))));
			if ( ( (i+1) % 10 ) == 0 )
				printf("\n");
		}
	}
	if (ecdsa_print_flag)
		printf("\n");


	/* A at Equation E */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A1_H_REG_OFFSET), 0x00000001);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A2_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A3_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A4_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A6_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A7_H_REG_OFFSET), 0xFFFFFFFC);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A1_H_REG_OFFSET, 0x00000001);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A2_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A3_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A4_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A6_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A7_H_REG_OFFSET, 0xFFFFFFFC);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A1_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A3_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A4_H_REG_OFFSET), 0xFFFFFFFE);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A6_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A7_H_REG_OFFSET), 0xFFFFFFFE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A1_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A3_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A4_H_REG_OFFSET, 0xFFFFFFFE);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A6_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A7_H_REG_OFFSET, 0xFFFFFFFE);
	#endif
	}

	/* B at Equation E */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B0_H_REG_OFFSET), 0x5AC635D8);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B1_H_REG_OFFSET), 0xAA3A93E7);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B2_H_REG_OFFSET), 0xB3EBBD55);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B3_H_REG_OFFSET), 0x769886BC);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B4_H_REG_OFFSET), 0x651D06B0);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B5_H_REG_OFFSET), 0xCC53B0F6);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B6_H_REG_OFFSET), 0x3BCE3C3E);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B7_H_REG_OFFSET), 0x27D2604B);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B0_H_REG_OFFSET, 0x5AC635D8);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B1_H_REG_OFFSET, 0xAA3A93E7);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B2_H_REG_OFFSET, 0xB3EBBD55);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B3_H_REG_OFFSET, 0x769886BC);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B4_H_REG_OFFSET, 0x651D06B0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B5_H_REG_OFFSET, 0xCC53B0F6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B6_H_REG_OFFSET, 0x3BCE3C3E);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B7_H_REG_OFFSET, 0x27D2604B);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B0_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B1_H_REG_OFFSET), 0xB4050A85);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B2_H_REG_OFFSET), 0x0C04B3AB);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B3_H_REG_OFFSET), 0xF5413256);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B4_H_REG_OFFSET), 0x5044B0B7);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B5_H_REG_OFFSET), 0xD7BFD8BA);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B6_H_REG_OFFSET), 0x270B3943);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B7_H_REG_OFFSET), 0x2355FFB4);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B0_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B1_H_REG_OFFSET, 0xB4050A85);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B2_H_REG_OFFSET, 0x0C04B3AB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B3_H_REG_OFFSET, 0xF5413256);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B4_H_REG_OFFSET, 0x5044B0B7);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B5_H_REG_OFFSET, 0xD7BFD8BA);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B6_H_REG_OFFSET, 0x270B3943);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B7_H_REG_OFFSET, 0x2355FFB4);
	#endif
	}
	

	/* PNP Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_PNP0_H_REG_OFFSET), 0xCCD1C8AA);
		reg_writel((wave_dsrc_base + ECDSA_MONT_PNP1_H_REG_OFFSET), 0xEE00BC4F);
		reg_writel((wave_dsrc_base + ECDSA_MONT_QNQ0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_MONT_QNQ1_H_REG_OFFSET), 0x1);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_PNP0_H_REG_OFFSET, 0xCCD1C8AA);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_PNP1_H_REG_OFFSET, 0xEE00BC4F);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_QNQ0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_QNQ1_H_REG_OFFSET, 0x1);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_PNP0_H_REG_OFFSET), 0xD6E24270);
		reg_writel((wave_dsrc_base + ECDSA_MONT_PNP1_H_REG_OFFSET), 0x6A1FC2EB);
		reg_writel((wave_dsrc_base + ECDSA_MONT_QNQ0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_QNQ1_H_REG_OFFSET), 0xFFFFFFFF);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_PNP0_H_REG_OFFSET, 0xD6E24270);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_PNP1_H_REG_OFFSET, 0x6A1FC2EB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_QNQ0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_QNQ1_H_REG_OFFSET, 0xFFFFFFFF);
	#endif
	}

	/* R2 Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_R20_H_REG_OFFSET), 0x66E12D94);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R21_H_REG_OFFSET), 0xF3D95620);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R22_H_REG_OFFSET), 0x2845B239);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R23_H_REG_OFFSET), 0x2B6BEC59);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R24_H_REG_OFFSET), 0x4699799C);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R25_H_REG_OFFSET), 0x49BD6FA6);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R26_H_REG_OFFSET), 0x83244C95);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R27_H_REG_OFFSET), 0xBE79EEA2);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R20_H_REG_OFFSET, 0x66E12D94);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R21_H_REG_OFFSET, 0xF3D95620);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R22_H_REG_OFFSET, 0x2845B239);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R23_H_REG_OFFSET, 0x2B6BEC59);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R24_H_REG_OFFSET, 0x4699799C);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R25_H_REG_OFFSET, 0x49BD6FA6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R26_H_REG_OFFSET, 0x83244C95);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R27_H_REG_OFFSET, 0xBE79EEA2);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_R20_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R21_H_REG_OFFSET), 0xB1E97961);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R22_H_REG_OFFSET), 0x6AD15F7C);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R23_H_REG_OFFSET), 0xD9714856);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R24_H_REG_OFFSET), 0xABC8FF59);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R25_H_REG_OFFSET), 0x31D63F4B);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R26_H_REG_OFFSET), 0x29947A69);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R27_H_REG_OFFSET), 0x5F517D15);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R20_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R21_H_REG_OFFSET, 0xB1E97961);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R22_H_REG_OFFSET, 0x6AD15F7C);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R23_H_REG_OFFSET, 0xD9714856);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R24_H_REG_OFFSET, 0xABC8FF59);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R25_H_REG_OFFSET, 0x31D63F4B);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R26_H_REG_OFFSET, 0x29947A69);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R27_H_REG_OFFSET, 0x5F517D15);
	#endif
	}

	/* test R Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q0_H_REG_OFFSET), 0x00000004);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q1_H_REG_OFFSET), 0xFFFFFFFD);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q3_H_REG_OFFSET), 0xFFFFFFFE);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q4_H_REG_OFFSET), 0xFFFFFFFB);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q6_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q7_H_REG_OFFSET), 0x00000003);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q0_H_REG_OFFSET, 0x00000004);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q1_H_REG_OFFSET, 0xFFFFFFFD);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q3_H_REG_OFFSET, 0xFFFFFFFE);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q4_H_REG_OFFSET, 0xFFFFFFFB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q6_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q7_H_REG_OFFSET, 0x00000003);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q0_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q1_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q2_H_REG_OFFSET), 0xFFFFFFFE);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q3_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q4_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q5_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q6_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q7_H_REG_OFFSET), 0x00000001);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q0_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q1_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q2_H_REG_OFFSET, 0xFFFFFFFE);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q3_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q4_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q5_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q6_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q7_H_REG_OFFSET, 0x00000001);
	#endif
	}

	if (ecdsa_sw_test_fix_flag == 0)
	{
		if (flag == 1)
		{
			/* 1를 Write하면 Random 모드 */
		#if WAVE_SECURITY_16BIT_ENABLE == 0
			reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA256_RANDOM_ENABLE);
		#else
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA256_RANDOM_ENABLE);
		#endif
		}
		else if (flag == 2)
		{
			/* 1를 Write하면 Random 모드 */
		#if WAVE_SECURITY_16BIT_ENABLE == 0
			reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA224_RANDOM_ENABLE);
		#else
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA224_RANDOM_ENABLE);
		#endif
		}

		//reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x1);

		//reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), SIGNATURE_GEN_RANDOM_SEL_BIT);
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), TRANSFER_PRIVATE_RANDOM_SEL_BIT);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, TRANSFER_PRIVATE_RANDOM_SEL_BIT);
	#endif

		
	}

	if (ecdsa_print_flag)
	{
		printf("Display Sender Random Key!!\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECDSA_RANDOM_NUMBER0_H_REG_OFFSET)+(i*4))));
		}
			
		printf("\n");
	}


	if (ecdsa_print_flag)
	{
		printf("Display Sender Public Key!!\n");
		if (flag == 1)		/* 256 mode */
		{
			public_key_len = 33;
		}
		else
		{
			public_key_len = 29;
		}
		
		for ( i = 0; i < public_key_len; i++ )
		{
			if (flag == 1)
			{
				printf("[%02x]", ecdsa256_public_key[0][i]);
			}
			else
			{
				printf("[%02x]", ecdsa224_public_key[0][i]);
			}
			if ( ( (i+1) % 10 ) == 0 )
				printf("\n");
		}
		printf("\n");
	}


#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00000000); /* RANDOM Number 동작을 멈춘다.*/
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, 0x00000000);/* RANDOM Number 동작을 멈춘다.*/
#endif


	if (ecdsa_print_flag || g_security_printf_flag)
	{
		printf("Display Unsigned Message len:%d\n", unsigned_msg_len);
		for ( i = 0; i < unsigned_msg_len; i++ )
		{
			printf("[%02x]", unsigned_msg[i]);
			if ( ( (i+1) % 10 ) == 0 )
				printf("\n");
		}
		printf("\n");
	}
	fsha256_test1(unsigned_msg, unsigned_msg_len, flag, sha_out);


	//printf("End fsha256_test1\n");

	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, SIGNATURE_GEN_ENABLE_BIT);

	

	time_out = 20000;
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & SIGGEN_DONE_STATUS_BIT)	/* Signature Generation Done */
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);/* Clear */

	if (time_out < 0)
		printf("[fpga_ecdsa_test] Signature Generation Time Out!!\n");
	if (ecdsa_print_flag || g_security_printf_flag)
	{
		//printf("SIGGEN status = 0x%08x, time_out = %d\n", status, time_out);

		printf("\n[fpga_ecdsa_test]Display Signature Generation R\n");
	}


	for ( i = 0; i < 8; i++ )
	{
		r[i] = reg_readl(((wave_dsrc_base + ECDSA_SIGGEN_KEYPAIR_R0_H_REG_OFFSET) + (i*4)));
		if (ecdsa_print_flag || g_security_printf_flag)
		{
			printf("[%08x]", r[i]);
			if ( ( (i+1) % 10 ) == 0 )
				printf("\n");
		}
	}

	if (ecdsa_print_flag || g_security_printf_flag)
		printf("\n");

	if (ecdsa_print_flag || g_security_printf_flag)
	{
		printf("\n[fpga_ecdsa_test]Display Signature Generation S\n");
	}


	for ( i = 0; i < 8; i++ )
	{
		s[i] = reg_readl(((wave_dsrc_base + ECDSA_SIGGEN_KEYPAIR_S0_H_REG_OFFSET) + (i*4)));
		if (ecdsa_print_flag || g_security_printf_flag)
		{
			printf("[%08x]", s[i]);
			if ( ( (i+1) % 10 ) == 0 )
				printf("\n");
		}
	}
	if (ecdsa_print_flag || g_security_printf_flag)
		printf("\n");

	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("Signature Generation Operation Time : %f\n",operating_time);

	if(time_out)
	{
		printf("================================================\n");
		printf("[fpag_ecdsa_random_test] Signature Generation Success!!\n");
		printf("================================================\n");

		i = 0;

		if (flag == 1)		/* 256 mode */
		{
			public_key_len = 33;
			signed_msg[i++]  = public_key_len;

			for ( j = 0; j < public_key_len; j++ )
				signed_msg[i++] = ecdsa256_public_key[0][j];
		
		}
		else
		{
			public_key_len = 29;
			signed_msg[i++]  = public_key_len;

			for ( j = 0; j < public_key_len; j++ )
				signed_msg[i++] = ecdsa224_public_key[0][j];
		}

		if (g_ecdsa_public_key_falut_flag)
		{
			if (signed_msg[i-1] == 0xFF)
				signed_msg[i-1] = 0;
			else
				signed_msg[i-1] = 0xFF;
		}

		for ( j = 0; j < unsigned_msg_len; j++)
		{
			signed_msg[i++] = unsigned_msg[j];
			
		}

		if (g_ecdsa_msg_falut_flag)
			signed_msg[i-1] = 0xFF;

		if (flag == 1)		/* 256 mode */
		{
			/* Signature Type */
			signed_msg[i++] = ECDSA_NISTP256_WITH_SHA256;
			signed_msg[i++] = 32;
			for ( j = 0; j < 8; j++ )
			{
				signed_msg[i++] = (r[j] >> 24) & 0xFF;
				signed_msg[i++] = (r[j] >> 16) & 0xFF;
				signed_msg[i++] = (r[j] >> 8) & 0xFF;
				signed_msg[i++] = r[j]  & 0xFF;
			}

			for ( j = 0; j < 8; j++ )
			{
				signed_msg[i++] = (s[j] >> 24) & 0xFF;
				signed_msg[i++] = (s[j] >> 16) & 0xFF;
				signed_msg[i++] = (s[j] >> 8) & 0xFF;
				signed_msg[i++] = s[j] & 0xFF;
			}
		}
		else
		{
			/* Signature Type */
			signed_msg[i++] = ECDSA_NISTP224_WITH_SHA224;
			signed_msg[i++] = 28;
			for ( j = 1; j < 8; j++ )
			{
				signed_msg[i++] = (r[j] >> 24) & 0xFF;
				signed_msg[i++] = (r[j] >> 16) & 0xFF;
				signed_msg[i++] = (r[j] >> 8) & 0xFF;
				signed_msg[i++] = r[j] & 0xFF;
			}
			
			for ( j = 1; j < 8; j++ )
			{
				signed_msg[i++] = (s[j] >> 24) & 0xFF;
				signed_msg[i++] = (s[j] >> 16) & 0xFF;
				signed_msg[i++] = (s[j] >> 8) & 0xFF;
				signed_msg[i++] = s[j] & 0xFF;
			}
		}
		
	}
	else
	{
		printf("================================================\n");
		printf("[fpag_ecdsa_random_test] Signature Generation Fail!!\n");
		printf("================================================\n");

		i = 0;
	}
	//write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, 0x7);	/* Clear */
	//write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, 0x0);
	

	
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */
	//write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SHA_DONE_STATUS_BIT);
	return(i);


	
}

int SW_Verify_Signed_Message(U1 *rx_buf, U2 len)
{
	char* argv[128];
	int argc;
	U1 public_key_len;
	int i;
	int flag;

	//struct timeval start_point, end_point;
	//volatile double operating_time;


	//gettimeofday(&start_point, NULL);

	i = 0;
	public_key_len = rx_buf[i++];

	if ( public_key_len == 33 )	/* Public Key Len 이 33이면 256 mode이다. */
	{
		flag = 1;

		argc = 5;
		argv[0] = "ecdsa";
		argv[1] = "--verify";
		argv[2] = "03596375e6ce57e0f20294fc46bdfcfd19a39f8161b58695b3ec5b3d16427c274d";
		argv[3] = "-c";
		argv[4] = "10";
		
	}
	else
	{
		flag = 2;

		argc = 5;
		argv[0] = "ecdsa";
		argv[1] = "--verify";
		argv[2] = "03fd44ec11f9d43d9d23b1e1d1c9ed6519b40ecf0c79f48cf476cc43f1";
		argv[3] = "-c";
		argv[4] = "8";
	}

	command_verify(argc, argv);


	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("Signature Validation Operation Time : %f\n",operating_time);

	
}


int Verify_Signed_Message(U1 *rx_buf, U2 len)
{
	U1		message[256];
	U4_T	r[8];
	U4_T	s[8];
	volatile unsigned int status;
	int 		i, j, k, m;
	int		time_out;
	U1 sha_out[32];
	volatile unsigned int control;
	struct timeval start_point, end_point;
	volatile double operating_time;
	U4 reg_data;
	int flag;
	U4_T public_key_x[8];
	U1 public_key_y_odd;
	U1 public_key_len;
	U2 unsinged_msg_len;
	U1 PkAlgorithm;
	U1 r_len;
	int ret = 0;

	if (ecdsa_print_flag)
	{
		printf("\n\n\n=================================\n");
		printf("[Verify_Signed_Message] Receive Part!!\n");
		printf("=================================\n");
	}

	if (g_security_printf_flag)
		printf("WAVE Data Received\n");

	gettimeofday(&start_point, NULL);
	
	//write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, 0x7);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */
	//write_wave_ecc_reg32(ECDSA_SHA_GEN_VERIFY_INITIAL_H_REG_OFFSET, 0x0);

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_ECC_ENABLE_H_REG_OFFSET), 0x0);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ECC_ENABLE_H_REG_OFFSET, 0);
#endif
	if (ecdsa_print_flag)
	{
		printf("[Verify_Signed_Message] Display rx_buf\n");
		for ( j = 0; j < len; j++)
		{
			printf("[%02x]", rx_buf[j]);
			if (((j+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}


	i = 0;
	public_key_len = rx_buf[i++];

	if (ecdsa_print_flag)
		printf("[Verify_Signed_Message] public_key_len=%d\n", public_key_len);
	
	if ( public_key_len == 33 )	/* Public Key Len 이 33이면 256 mode이다. */
	{
		flag = 1;
	}
	else
	{
		flag = 2;
	}

	public_key_y_odd = rx_buf[i++];

	if (ecdsa_print_flag)
		printf("[Verify_Signed_Message] public_key_y_odd=%d\n", public_key_y_odd);

	if (flag == 1 )
	{
		/* 1 : public_key_len length field */
		/* 64 : r 서명자 + s 서명자 */
		/* 2 : PKAlgorithm Kind(1) + r 서명자 길이 필드 (1) */
		unsinged_msg_len = len - ( public_key_len + 1 ) - (64 + 2);
		for ( k = 0; k < 8; k++)
		{
			public_key_x[k].b1[3] = rx_buf[i++];
			public_key_x[k].b1[2] = rx_buf[i++];
			public_key_x[k].b1[1] = rx_buf[i++];
			public_key_x[k].b1[0] = rx_buf[i++];
		}
	}
	else
	{
		/* 1 : public_key_len length field */
		/* 56 : r 서명자 + s 서명자 */
		/* 2 : PKAlgorithm Kind(1) + r 서명자 길이 필드 (1) */
		unsinged_msg_len = len - ( public_key_len + 1 ) - (56 + 2);
		
		for ( k = 0; k < 8; k++)
		{
			if ( k == 0 )
			{
				public_key_x[k].b4 = 0;
			}
			else
			{
				public_key_x[k].b1[3] = rx_buf[i++];
				public_key_x[k].b1[2] = rx_buf[i++];
				public_key_x[k].b1[1] = rx_buf[i++];
				public_key_x[k].b1[0] = rx_buf[i++];
			}
		}
	}

	if (flag == 1)
	{
		/* Test Mode로 세팅 : 2를 write하면 Private Key를 고정 */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA256_RANDOM_ENABLE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA256_RANDOM_ENABLE);
	#endif
	}
	else if (flag == 2)
	{
		/* Test Mode로 세팅 : 2를 write하면 Private Key를 고정 */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA224_RANDOM_ENABLE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA224_RANDOM_ENABLE);
	#endif
	}

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), SIGNATURE_GEN_RANDOM_SEL_BIT);
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), TRANSFER_PRIVATE_RANDOM_SEL_BIT);
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), RECEIVER_PRIVATE_RANDOM_SEL_BIT);

	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00000000);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, SIGNATURE_GEN_RANDOM_SEL_BIT);
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, TRANSFER_PRIVATE_RANDOM_SEL_BIT);
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, RECEIVER_PRIVATE_RANDOM_SEL_BIT);
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, 0x00000000);
#endif

	/* Prime Number Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM1_H_REG_OFFSET), 0x1);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM2_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM3_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM4_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM6_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM7_H_REG_OFFSET), 0xFFFFFFFF);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM1_H_REG_OFFSET, 0x1);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM2_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM3_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM4_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM6_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM7_H_REG_OFFSET, 0xFFFFFFFF);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM1_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM3_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM4_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM5_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM6_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_PRIME_NUM7_H_REG_OFFSET), 0x00000001);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM1_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM3_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM4_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM5_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM6_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_PRIME_NUM7_H_REG_OFFSET, 0x00000001);
	#endif
	}

	/* test N Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER1_H_REG_OFFSET), 0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER3_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER4_H_REG_OFFSET), 0xBCE6FAAD);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER5_H_REG_OFFSET), 0xA7179E84);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER6_H_REG_OFFSET), 0xF3B9CAC2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER7_H_REG_OFFSET), 0xFC632551);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER1_H_REG_OFFSET, 0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER3_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER4_H_REG_OFFSET, 0xBCE6FAAD);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER5_H_REG_OFFSET, 0xA7179E84);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER6_H_REG_OFFSET, 0xF3B9CAC2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER7_H_REG_OFFSET, 0xFC632551);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER1_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER3_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER4_H_REG_OFFSET), 0xFFFF16A2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER5_H_REG_OFFSET), 0xE0B8F03E);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER6_H_REG_OFFSET), 0x13DD2945);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_ORDER7_H_REG_OFFSET), 0x5C5C2A3D);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER1_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER3_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER4_H_REG_OFFSET, 0xFFFF16A2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER5_H_REG_OFFSET, 0xE0B8F03E);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER6_H_REG_OFFSET, 0x13DD2945);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_ORDER7_H_REG_OFFSET, 0x5C5C2A3D);
	#endif
	}
	

	/* iArith_Base_Gx Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX0_H_REG_OFFSET), 0x6B17D1F2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX1_H_REG_OFFSET), 0xE12C4247);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX2_H_REG_OFFSET), 0xF8BCE6E5);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX3_H_REG_OFFSET), 0x63A440F2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX4_H_REG_OFFSET), 0x77037D81);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX5_H_REG_OFFSET), 0x2DEB33A0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX6_H_REG_OFFSET), 0xF4A13945);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX7_H_REG_OFFSET), 0xD898C296);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX0_H_REG_OFFSET, 0x6B17D1F2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX1_H_REG_OFFSET, 0xE12C4247);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX2_H_REG_OFFSET, 0xF8BCE6E5);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX3_H_REG_OFFSET, 0x63A440F2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX4_H_REG_OFFSET, 0x77037D81);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX5_H_REG_OFFSET, 0x2DEB33A0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX6_H_REG_OFFSET, 0xF4A13945);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX7_H_REG_OFFSET, 0xD898C296);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX1_H_REG_OFFSET), 0xB70E0CBD);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX2_H_REG_OFFSET), 0x6BB4BF7F);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX3_H_REG_OFFSET), 0x321390B9);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX4_H_REG_OFFSET), 0x4A03C1D3);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX5_H_REG_OFFSET), 0x56C21122);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX6_H_REG_OFFSET), 0x343280D6);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PX7_H_REG_OFFSET), 0x115C1D21);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX1_H_REG_OFFSET, 0xB70E0CBD);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX2_H_REG_OFFSET, 0x6BB4BF7F);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX3_H_REG_OFFSET, 0x321390B9);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX4_H_REG_OFFSET, 0x4A03C1D3);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX5_H_REG_OFFSET, 0x56C21122);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX6_H_REG_OFFSET, 0x343280D6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PX7_H_REG_OFFSET, 0x115C1D21);
	#endif
	}

	/* iArith_Base_Gy Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY0_H_REG_OFFSET), 0x4FE342E2);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY1_H_REG_OFFSET), 0xFE1A7F9B);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY2_H_REG_OFFSET), 0x8EE7EB4A);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY3_H_REG_OFFSET), 0x7C0F9E16);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY4_H_REG_OFFSET), 0x2BCE3357);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY5_H_REG_OFFSET), 0x6B315ECE);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY6_H_REG_OFFSET), 0xCBB64068);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY7_H_REG_OFFSET), 0x37BF51F5);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY0_H_REG_OFFSET, 0x4FE342E2);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY1_H_REG_OFFSET, 0xFE1A7F9B);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY2_H_REG_OFFSET, 0x8EE7EB4A);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY3_H_REG_OFFSET, 0x7C0F9E16);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY4_H_REG_OFFSET, 0x2BCE3357);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY5_H_REG_OFFSET, 0x6B315ECE);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY6_H_REG_OFFSET, 0xCBB64068);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY7_H_REG_OFFSET, 0x37BF51F5);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY1_H_REG_OFFSET), 0xBD376388);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY2_H_REG_OFFSET), 0xB5F723FB);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY3_H_REG_OFFSET), 0x4C22DFE6);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY4_H_REG_OFFSET), 0xCD4375A0);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY5_H_REG_OFFSET), 0x5A074764);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY6_H_REG_OFFSET), 0x44D58199);
		reg_writel((wave_dsrc_base + ECDSA_ARITH_BASE_PY7_H_REG_OFFSET), 0x85007E34);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY1_H_REG_OFFSET, 0xBD376388);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY2_H_REG_OFFSET, 0xB5F723FB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY3_H_REG_OFFSET, 0x4C22DFE6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY4_H_REG_OFFSET, 0xCD4375A0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY5_H_REG_OFFSET, 0x5A074764);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY6_H_REG_OFFSET, 0x44D58199);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ARITH_BASE_PY7_H_REG_OFFSET, 0x85007E34);
	#endif
	}

	/* A at Equation E */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A1_H_REG_OFFSET), 0x00000001);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A2_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A3_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A4_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A6_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A7_H_REG_OFFSET), 0xFFFFFFFC);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A1_H_REG_OFFSET, 0x00000001);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A2_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A3_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A4_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A6_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A7_H_REG_OFFSET, 0xFFFFFFFC);
	#endif
	}
	else if (flag == 2)	/* 224 mode : ANSI X9.62 문서의 L6.3.3 참조 */
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A1_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A3_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A4_H_REG_OFFSET), 0xFFFFFFFE);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A6_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_A7_H_REG_OFFSET), 0xFFFFFFFE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A1_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A3_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A4_H_REG_OFFSET, 0xFFFFFFFE);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A6_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_A7_H_REG_OFFSET, 0xFFFFFFFE);
	#endif
	}

	/* B at Equation E */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B0_H_REG_OFFSET), 0x5AC635D8);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B1_H_REG_OFFSET), 0xAA3A93E7);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B2_H_REG_OFFSET), 0xB3EBBD55);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B3_H_REG_OFFSET), 0x769886BC);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B4_H_REG_OFFSET), 0x651D06B0);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B5_H_REG_OFFSET), 0xCC53B0F6);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B6_H_REG_OFFSET), 0x3BCE3C3E);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B7_H_REG_OFFSET), 0x27D2604B);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B0_H_REG_OFFSET, 0x5AC635D8);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B1_H_REG_OFFSET, 0xAA3A93E7);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B2_H_REG_OFFSET, 0xB3EBBD55);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B3_H_REG_OFFSET, 0x769886BC);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B4_H_REG_OFFSET, 0x651D06B0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B5_H_REG_OFFSET, 0xCC53B0F6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B6_H_REG_OFFSET, 0x3BCE3C3E);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B7_H_REG_OFFSET, 0x27D2604B);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B0_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B1_H_REG_OFFSET), 0xB4050A85);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B2_H_REG_OFFSET), 0x0C04B3AB);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B3_H_REG_OFFSET), 0xF5413256);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B4_H_REG_OFFSET), 0x5044B0B7);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B5_H_REG_OFFSET), 0xD7BFD8BA);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B6_H_REG_OFFSET), 0x270B3943);
		reg_writel((wave_dsrc_base + ECDSA_EQUATION_B7_H_REG_OFFSET), 0x2355FFB4);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B0_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B1_H_REG_OFFSET, 0xB4050A85);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B2_H_REG_OFFSET, 0x0C04B3AB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B3_H_REG_OFFSET, 0xF5413256);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B4_H_REG_OFFSET, 0x5044B0B7);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B5_H_REG_OFFSET, 0xD7BFD8BA);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B6_H_REG_OFFSET, 0x270B3943);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_EQUATION_B7_H_REG_OFFSET, 0x2355FFB4);
	#endif
	}
	

	/* PNP Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_PNP0_H_REG_OFFSET), 0xCCD1C8AA);
		reg_writel((wave_dsrc_base + ECDSA_MONT_PNP1_H_REG_OFFSET), 0xEE00BC4F);
		reg_writel((wave_dsrc_base + ECDSA_MONT_QNQ0_H_REG_OFFSET), 0x0);
		reg_writel((wave_dsrc_base + ECDSA_MONT_QNQ1_H_REG_OFFSET), 0x1);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_PNP0_H_REG_OFFSET, 0xCCD1C8AA);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_PNP1_H_REG_OFFSET, 0xEE00BC4F);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_QNQ0_H_REG_OFFSET, 0x0);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_QNQ1_H_REG_OFFSET, 0x1);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_PNP0_H_REG_OFFSET), 0xD6E24270);
		reg_writel((wave_dsrc_base + ECDSA_MONT_PNP1_H_REG_OFFSET), 0x6A1FC2EB);
		reg_writel((wave_dsrc_base + ECDSA_MONT_QNQ0_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_QNQ1_H_REG_OFFSET), 0xFFFFFFFF);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_PNP0_H_REG_OFFSET, 0xD6E24270);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_PNP1_H_REG_OFFSET, 0x6A1FC2EB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_QNQ0_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_QNQ1_H_REG_OFFSET, 0xFFFFFFFF);
	#endif
	}

	/* R2 Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_R20_H_REG_OFFSET), 0x66E12D94);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R21_H_REG_OFFSET), 0xF3D95620);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R22_H_REG_OFFSET), 0x2845B239);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R23_H_REG_OFFSET), 0x2B6BEC59);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R24_H_REG_OFFSET), 0x4699799C);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R25_H_REG_OFFSET), 0x49BD6FA6);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R26_H_REG_OFFSET), 0x83244C95);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R27_H_REG_OFFSET), 0xBE79EEA2);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R20_H_REG_OFFSET, 0x66E12D94);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R21_H_REG_OFFSET, 0xF3D95620);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R22_H_REG_OFFSET, 0x2845B239);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R23_H_REG_OFFSET, 0x2B6BEC59);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R24_H_REG_OFFSET, 0x4699799C);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R25_H_REG_OFFSET, 0x49BD6FA6);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R26_H_REG_OFFSET, 0x83244C95);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R27_H_REG_OFFSET, 0xBE79EEA2);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_R20_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R21_H_REG_OFFSET), 0xB1E97961);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R22_H_REG_OFFSET), 0x6AD15F7C);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R23_H_REG_OFFSET), 0xD9714856);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R24_H_REG_OFFSET), 0xABC8FF59);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R25_H_REG_OFFSET), 0x31D63F4B);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R26_H_REG_OFFSET), 0x29947A69);
		reg_writel((wave_dsrc_base + ECDSA_MONT_R27_H_REG_OFFSET), 0x5F517D15);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R20_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R21_H_REG_OFFSET, 0xB1E97961);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R22_H_REG_OFFSET, 0x6AD15F7C);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R23_H_REG_OFFSET, 0xD9714856);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R24_H_REG_OFFSET, 0xABC8FF59);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R25_H_REG_OFFSET, 0x31D63F4B);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R26_H_REG_OFFSET, 0x29947A69);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_R27_H_REG_OFFSET, 0x5F517D15);
	#endif
	}

	/* test R Settings */
	if (flag == 1)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q0_H_REG_OFFSET), 0x00000004);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q1_H_REG_OFFSET), 0xFFFFFFFD);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q2_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q3_H_REG_OFFSET), 0xFFFFFFFE);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q4_H_REG_OFFSET), 0xFFFFFFFB);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q5_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q6_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q7_H_REG_OFFSET), 0x00000003);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q0_H_REG_OFFSET, 0x00000004);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q1_H_REG_OFFSET, 0xFFFFFFFD);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q2_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q3_H_REG_OFFSET, 0xFFFFFFFE);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q4_H_REG_OFFSET, 0xFFFFFFFB);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q5_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q6_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q7_H_REG_OFFSET, 0x00000003);
	#endif
	}
	else if (flag == 2)
	{
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q0_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q1_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q2_H_REG_OFFSET), 0xFFFFFFFE);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q3_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q4_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q5_H_REG_OFFSET), 0x00000000);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q6_H_REG_OFFSET), 0xFFFFFFFF);
		reg_writel((wave_dsrc_base + ECDSA_MONT_Q7_H_REG_OFFSET), 0x00000001);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q0_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q1_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q2_H_REG_OFFSET, 0xFFFFFFFE);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q3_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q4_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q5_H_REG_OFFSET, 0x00000000);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q6_H_REG_OFFSET, 0xFFFFFFFF);
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_MONT_Q7_H_REG_OFFSET, 0x00000001);
	#endif
	}

	
	if ( ecdsa_print_flag || g_security_printf_flag)
	{
		printf("[Verify_Signed_Message] len:%d\n", unsinged_msg_len);

		for ( j = 0; j < unsinged_msg_len; j++)
		{
			printf("[%02x]", rx_buf[i+j]);
			if (((j+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}

	/* SHKO : PUBLIC KEY Recovery 하기 전에 반드시 Random Enable해야 한다. */
	if (flag == 1)
	{
		/* Test Mode로 세팅 : 2를 write하면 Private Key를 고정 */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA256_RANDOM_ENABLE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA256_RANDOM_ENABLE);
	#endif
	}
	else if (flag == 2)
	{
		/* Test Mode로 세팅 : 2를 write하면 Private Key를 고정 */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA224_RANDOM_ENABLE);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA224_RANDOM_ENABLE);
	#endif
	}
	
	fsha256_test1(&rx_buf[i], unsinged_msg_len, flag, sha_out);
	i = i + unsinged_msg_len;


	if (ecdsa_test_flag == 0)
	{
		if (flag == 1)
		{
		#if WAVE_SECURITY_16BIT_ENABLE == 0
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), public_key_x[0].b4);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), public_key_x[1].b4);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), public_key_x[2].b4);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), public_key_x[3].b4);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), public_key_x[4].b4);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), public_key_x[5].b4);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), public_key_x[6].b4);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), public_key_x[7].b4);
		#else
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET, public_key_x[0].b4);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET, public_key_x[1].b4);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET, public_key_x[2].b4);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET, public_key_x[3].b4);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET, public_key_x[4].b4);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET, public_key_x[5].b4);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET, public_key_x[6].b4);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET, public_key_x[7].b4);
		#endif
		}
		else if (flag == 2)
		{
		#if WAVE_SECURITY_16BIT_ENABLE == 0
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), public_key_x[0].b4);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), public_key_x[1].b4);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), public_key_x[2].b4);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), public_key_x[3].b4);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), public_key_x[4].b4);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), public_key_x[5].b4);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), public_key_x[6].b4);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), public_key_x[7].b4);
		#else
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET, public_key_x[0].b4);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET, public_key_x[1].b4);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET, public_key_x[2].b4);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET, public_key_x[3].b4);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET, public_key_x[4].b4);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET, public_key_x[5].b4);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET, public_key_x[6].b4);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET, public_key_x[7].b4);
		#endif
		}
	}
	else
	{
		if (flag == 1)
		{
		#if WAVE_SECURITY_16BIT_ENABLE == 0
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), 0x12345678);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), 0x9abcdef1);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), 0x23456789);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), 0xabcdef12);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), 0x3456789a);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), 0xbcdef123);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), 0x456789ab);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), 0xcdef1234);
		#else
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET, 0x12345678);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET, 0x9abcdef1);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET, 0x23456789);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET, 0xabcdef12);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET, 0x3456789a);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET, 0xbcdef123);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET, 0x456789ab);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET, 0xcdef1234);
		#endif
		}
		else if (flag == 2)
		{
		#if WAVE_SECURITY_16BIT_ENABLE == 0
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), 0x00000000);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), 0x12345678);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), 0x9abcdef1);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), 0x23456789);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), 0xabcdef12);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), 0x3456789a);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), 0xbcdef123);
			reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), 0x456789ab);
		#else
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET, 0x00000000);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET, 0x12345678);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET, 0x9abcdef1);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET, 0x23456789);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET, 0xabcdef12);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET, 0x3456789a);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET, 0xbcdef123);
			write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET, 0x456789ab);
		#endif
		}
	}

	if (ecdsa_print_flag)
	{
		printf("Display Public KEY\n");
		for ( k = 0; k < 8; k++)
		{
			printf("[%08x]", read_wave_ecc_reg32(((ECDSA_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET)+(k*4))));
		}
		printf("\n");
	}

#if WAVE_SECURITY_16BIT_ENABLE == 0
	if ( public_key_y_odd == 0x03 )
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x1);
	else
		reg_writel((wave_dsrc_base + ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x0);
#else
	if ( public_key_y_odd == 0x03 )
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET, 0x1);
	else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET, 0x0);
#endif
	PkAlgorithm = rx_buf[i++];
	r_len = rx_buf[i++];

	if (ecdsa_print_flag || g_security_printf_flag)
	{
		//printf("SIGGEN status = 0x%08x, time_out = %d\n", status, time_out);

		printf("[Verify_Signed_Message]Display Signature Generation R\n");
	}

	if (flag == 1 )
	{
		for ( k = 0; k < 8; k++)
		{
			r[k].b1[3] = rx_buf[i++];
			r[k].b1[2] = rx_buf[i++];
			r[k].b1[1] = rx_buf[i++];
			r[k].b1[0] = rx_buf[i++];
			if (ecdsa_print_flag || g_security_printf_flag)
				printf("[%08x]", r[k].b4);
		}
	}
	else
	{
		for ( k = 0; k < 8; k++)
		{
			if ( k == 0 )
			{
				r[k].b4 = 0;
			}
			else
			{
				r[k].b1[3] = rx_buf[i++];
				r[k].b1[2] = rx_buf[i++];
				r[k].b1[1] = rx_buf[i++];
				r[k].b1[0] = rx_buf[i++];
			}
			if (ecdsa_print_flag || g_security_printf_flag)
				printf("[%08x]", r[k].b4);
		}
	}
	if (ecdsa_print_flag || g_security_printf_flag)
		printf("\n");

	if (ecdsa_print_flag || g_security_printf_flag)
	{
		//printf("SIGGEN status = 0x%08x, time_out = %d\n", status, time_out);

		printf("[Verify_Signed_Message]Display Signature Generation S\n");
	}

	if (flag == 1 )
	{
		for ( k = 0; k < 8; k++)
		{
			s[k].b1[3] = rx_buf[i++];
			s[k].b1[2] = rx_buf[i++];
			s[k].b1[1] = rx_buf[i++];
			s[k].b1[0] = rx_buf[i++];

			if (ecdsa_print_flag || g_security_printf_flag)
				printf("[%08x]", s[k].b4);
		}
	}
	else
	{
		for ( k = 0; k < 8; k++)
		{
			if ( k == 0 )
			{
				s[k].b4 = 0;
			}
			else
			{
				s[k].b1[3] = rx_buf[i++];
				s[k].b1[2] = rx_buf[i++];
				s[k].b1[1] = rx_buf[i++];
				s[k].b1[0] = rx_buf[i++];
			}
			if (ecdsa_print_flag || g_security_printf_flag)
				printf("[%08x]", s[k].b4);
		}
	}
	if (ecdsa_print_flag || g_security_printf_flag)
		printf("\n");

	

	/* 수신된 R, S값을 세팅한다. */
	for ( k = 0; k < 8; k++ )
	{
		/* SIGVERIFY Setting */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R0_H_REG_OFFSET + (k*4)), r[k].b4);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SIGVERIFY_KEYPAIR_R0_H_REG_OFFSET + (k*4)), r[k].b4);
	#endif
	}

	for ( k = 0; k < 8; k++ )
	{
		/* SIGVERIFY Setting */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S0_H_REG_OFFSET + (k*4)), s[k].b4);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit((ECDSA_SIGVERIFY_KEYPAIR_S0_H_REG_OFFSET + (k*4)), s[k].b4);
	#endif
	}

	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, ECDSA_KEY_RECOVERY_ENABLE_BIT);
	time_out = 20000;
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & ECDSA_RECOVERY_DONE_BIT)
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, ECDSA_RECOVERY_DONE_BIT);/* Clear */
	if (time_out < 0)
	{
		printf("[Verify_Signed_Message] Key Recovery Done Time Out!!\n");
#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0);
#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, 0);
#endif
		gettimeofday(&end_point, NULL);

		operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
		printf("Signature Validation Operation Time : %f\n",operating_time);

	
		printf("================================================\n");
		printf("[Verify_Signed_Message] Signature Verification Fail!!\n");
		printf("================================================\n");
	
		
		//if (ecdsa_print_flag)
		//	printf("SIGVERIFY Done status = 0x%08x, time_out = %d\n", status, time_out);

		write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
		write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
		write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */
		return(-1);
		
	}
	
	//if (ecdsa_print_flag)
	//	printf("TRANS_PUBLIC_KEY_Y_RECOVERY status = 0x%08x, time_out = %d\n", status, time_out);

	if (ecdsa_print_flag)
	{
		printf("\nDisplay Recovery Sender Public Key Y\n");
		for ( k = 0; k < 8; k++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECDSA_TRANS_RECEIVE_RECOVERY_Y0_H_REG_OFFSET)+(k*4))));
		}
		printf("\n");
	}
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, 0);
#endif


	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, SIGNATURE_VERIFY_ENABLE_BIT);

	time_out = 20000;

	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if ((status & SIGVERIFY_DONE_STATUS_BIT) && (status & SIGVERIFY_VALID_STATUS_BIT))	/* Signature Generation Done */
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);/* Clear */

	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("Signature Validation Operation Time : %f\n",operating_time);

	if (time_out < 0)
	{
		printf("================================================\n");
		printf("[Verify_Signed_Message] Signature Verification Fail!!\n");
		printf("================================================\n");
	}
	else
	{
		printf("================================================\n");
		printf("[Verify_Signed_Message] Signature Verification Success!!\n");
		printf("================================================\n");
	}
		
	//if (ecdsa_print_flag)
	//	printf("SIGVERIFY Done status = 0x%08x, time_out = %d\n", status, time_out);

	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */

	return(0);
}


