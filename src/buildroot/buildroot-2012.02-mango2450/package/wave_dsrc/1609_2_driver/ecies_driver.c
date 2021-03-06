
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

extern int ecies_print_flag;

extern int g_security_printf_flag;

extern int dev;

int g_aes_key_index;

void fpga_ecies_test(void);

BOOL FPGA_KDF2(U1 *z, octet *p, int olen, U1 *k);
BOOL FPGA_KDF2_Interrupt(U1 *z, octet *p, int olen, U1 *k);
BOOL FPGA_MAC1(U1 *m, int m_len, U1 *k, int k_len, int olen, U1 *tag);

extern int fsha256_interrupt_test1(U1 *msg, volatile unsigned int len, int flag, U1 *sha_out);
int Soft_Make_VCT(U1 *pub_key, U1 *cipher, U1 *atag);
int Soft_Decrypt_Ecies(U1 *pub_key, U1 *cipher, U1 *atag, U1 *plain_key);


U1 g_aes_key[10][16] = {
						{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 
						   0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
						{ 0x00, 0x01, 0x00, 0x02, 0x04, 0x03, 0x04, 0x02, 0x00, 0x09, 
						   0x01, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
					};

#if 0	/* SHKO, Origin */
U1 g_ecies_recv_public_key[10][33] = {
										{ 0x03, 0x5a, 0x57, 0xca, 0x08, 0x7e, 0x58, 0x70, 0x39, 0xd1, 
										   0x45, 0xc7, 0x2a, 0xd1, 0xe1, 0x9f, 0xfa, 0xe7, 0x6b, 0xbe, 
										   0xc6, 0x6a, 0x03, 0xe0, 0x34, 0x4b, 0x1e, 0x8d, 0x36, 0x43, 
										   0xf6, 0xa3, 0x38 },
										   
					};

U1 g_ecies_recv_private_key[10][32] = {
										{ 0xaa, 0xe2, 0x65, 0x0c, 0x40, 0x50, 0x06, 0x0d, 0x48, 0x8d, 
   										   0x88, 0xc0, 0xfe, 0xfe, 0x73, 0xf4, 0x2c, 0xd4, 0xe7, 0x99, 
   										   0x02, 0xd7, 0x63, 0x82, 0xba, 0x6e, 0xb5, 0xd3, 0xc8, 0x42, 
   										   0xd0, 0x5a},
										   
					};
#else
U1 g_ecies_recv_public_key[10][33] = {
										{ 0x03, 0xf4, 0x70, 0xc6, 0x08, 0x0a, 0x83, 0x09, 0x80, 0x93, 
										   0xce, 0xdc, 0x76, 0x8d, 0x27, 0x71, 0xfe, 0x48, 0xa0, 0x2f, 
										   0x50, 0xa6, 0x15, 0x2d, 0xf2, 0x9a, 0xe8, 0x62, 0x41, 0xa3, 
										   0x39, 0x40, 0x16},
										   
					};

U1 g_ecies_recv_private_key[10][32] = {
										{ 0x25, 0xa4, 0x00, 0x00, 0x90, 0x46, 0xe0, 0x1c, 0x25, 0xa4, 
										   0x00, 0x00, 0x10, 0x66, 0x80, 0x38, 0x25, 0x25, 0x00, 0x00, 
										   0x10, 0x62, 0xc0, 0x38, 0xda, 0x5b, 0xbf, 0x7e, 0x6f, 0xb9, 
										   0x1f, 0xc3},
										   
					};
#endif


int Init_Soft_ECIES(void);


ecp_domain g_epdom;

int Init_Soft_ECIES(void)
{
	int j;
	
	OCTET_INIT(&g_epdom.Q,32);
    	OCTET_INIT(&g_epdom.A,32);
    	OCTET_INIT(&g_epdom.B,32);
    	OCTET_INIT(&g_epdom.R,32);
    	OCTET_INIT(&g_epdom.Gx,32);
    	OCTET_INIT(&g_epdom.Gy,32);
    	OCTET_INIT(&g_epdom.K,32);
    	OCTET_INIT(&g_epdom.IK,32);

	g_epdom.words = 8;
	g_epdom.fsize = 32;
	g_epdom.rbits = 256;

	g_epdom.Q.len = 32;
	j=0;
	g_epdom.Q.val[j++] = 0xFF;
	g_epdom.Q.val[j++] = 0xFF;
	g_epdom.Q.val[j++] = 0xFF;
	g_epdom.Q.val[j++] = 0xFF;
	g_epdom.Q.val[j++] = 0x00;
	g_epdom.Q.val[j++] = 0x00;
	g_epdom.Q.val[j++] = 0x00;
	g_epdom.Q.val[j++] = 0x01;
	g_epdom.Q.val[j++] = 0x00;
	g_epdom.Q.val[j++] = 0x00;
	g_epdom.Q.val[j++] = 0x00;
	g_epdom.Q.val[j++] = 0x00;
	g_epdom.Q.val[j++] = 0x00;
	g_epdom.Q.val[j++] = 0x00;
	g_epdom.Q.val[j++] = 0x00;
	g_epdom.Q.val[j++] = 0x00;
	g_epdom.Q.val[j++] = 0x00;
	g_epdom.Q.val[j++] = 0x00;
	g_epdom.Q.val[j++] = 0x00;
	g_epdom.Q.val[j++] = 0x00;
	g_epdom.Q.val[j++] = 0xFF;
	g_epdom.Q.val[j++] = 0xFF;
	g_epdom.Q.val[j++] = 0xFF;
	g_epdom.Q.val[j++] = 0xFF;
	g_epdom.Q.val[j++] = 0xFF;
	g_epdom.Q.val[j++] = 0xFF;
	g_epdom.Q.val[j++] = 0xFF;
	g_epdom.Q.val[j++] = 0xFF;
	g_epdom.Q.val[j++] = 0xFF;
	g_epdom.Q.val[j++] = 0xFF;
	g_epdom.Q.val[j++] = 0xFF;
	g_epdom.Q.val[j++] = 0xFF;

	g_epdom.A.len = 32;
	j=0;
	g_epdom.A.val[j++] = 0xFF;
	g_epdom.A.val[j++] = 0xFF;
	g_epdom.A.val[j++] = 0xFF;
	g_epdom.A.val[j++] = 0xFF;
	g_epdom.A.val[j++] = 0x00;
	g_epdom.A.val[j++] = 0x00;
	g_epdom.A.val[j++] = 0x00;
	g_epdom.A.val[j++] = 0x01;
	g_epdom.A.val[j++] = 0x00;
	g_epdom.A.val[j++] = 0x00;
	g_epdom.A.val[j++] = 0x00;
	g_epdom.A.val[j++] = 0x00;
	g_epdom.A.val[j++] = 0x00;
	g_epdom.A.val[j++] = 0x00;
	g_epdom.A.val[j++] = 0x00;
	g_epdom.A.val[j++] = 0x00;
	g_epdom.A.val[j++] = 0x00;
	g_epdom.A.val[j++] = 0x00;
	g_epdom.A.val[j++] = 0x00;
	g_epdom.A.val[j++] = 0x00;
	g_epdom.A.val[j++] = 0xFF;
	g_epdom.A.val[j++] = 0xFF;
	g_epdom.A.val[j++] = 0xFF;
	g_epdom.A.val[j++] = 0xFF;
	g_epdom.A.val[j++] = 0xFF;
	g_epdom.A.val[j++] = 0xFF;
	g_epdom.A.val[j++] = 0xFF;
	g_epdom.A.val[j++] = 0xFF;
	g_epdom.A.val[j++] = 0xFF;
	g_epdom.A.val[j++] = 0xFF;
	g_epdom.A.val[j++] = 0xFF;
	g_epdom.A.val[j++] = 0xFC;

	g_epdom.B.len = 32;
	j=0;
	g_epdom.B.val[j++] = 0x5a;
	g_epdom.B.val[j++] = 0xc6;
	g_epdom.B.val[j++] = 0x35;
	g_epdom.B.val[j++] = 0xd8;
	g_epdom.B.val[j++] = 0xaa;
	g_epdom.B.val[j++] = 0x3a;
	g_epdom.B.val[j++] = 0x93;
	g_epdom.B.val[j++] = 0xe7;
	g_epdom.B.val[j++] = 0xb3;
	g_epdom.B.val[j++] = 0xeb;
	g_epdom.B.val[j++] = 0xbd;
	g_epdom.B.val[j++] = 0x55;
	g_epdom.B.val[j++] = 0x76;
	g_epdom.B.val[j++] = 0x98;
	g_epdom.B.val[j++] = 0x86;
	g_epdom.B.val[j++] = 0xbc;
	g_epdom.B.val[j++] = 0x65;
	g_epdom.B.val[j++] = 0x1d;
	g_epdom.B.val[j++] = 0x06;
	g_epdom.B.val[j++] = 0xb0;
	g_epdom.B.val[j++] = 0xcc;
	g_epdom.B.val[j++] = 0x53;
	g_epdom.B.val[j++] = 0xb0;
	g_epdom.B.val[j++] = 0xf6;
	g_epdom.B.val[j++] = 0x3b;
	g_epdom.B.val[j++] = 0xce;
	g_epdom.B.val[j++] = 0x3c;
	g_epdom.B.val[j++] = 0x3e;
	g_epdom.B.val[j++] = 0x27;
	g_epdom.B.val[j++] = 0xd2;
	g_epdom.B.val[j++] = 0x60;
	g_epdom.B.val[j++] = 0x4b;

	g_epdom.R.len = 32;
	j=0;
	g_epdom.R.val[j++] = 0xFF;
	g_epdom.R.val[j++] = 0xFF;
	g_epdom.R.val[j++] = 0xFF;
	g_epdom.R.val[j++] = 0xFF;
	g_epdom.R.val[j++] = 0x00;
	g_epdom.R.val[j++] = 0x00;
	g_epdom.R.val[j++] = 0x00;
	g_epdom.R.val[j++] = 0x00;
	g_epdom.R.val[j++] = 0xFF;
	g_epdom.R.val[j++] = 0xFF;
	g_epdom.R.val[j++] = 0xFF;
	g_epdom.R.val[j++] = 0xFF;
	g_epdom.R.val[j++] = 0xFF;
	g_epdom.R.val[j++] = 0xFF;
	g_epdom.R.val[j++] = 0xFF;
	g_epdom.R.val[j++] = 0xFF;
	g_epdom.R.val[j++] = 0xbc;
	g_epdom.R.val[j++] = 0xe6;
	g_epdom.R.val[j++] = 0xfa;
	g_epdom.R.val[j++] = 0xad;
	g_epdom.R.val[j++] = 0xa7;
	g_epdom.R.val[j++] = 0x17;
	g_epdom.R.val[j++] = 0x9e;
	g_epdom.R.val[j++] = 0x84;
	g_epdom.R.val[j++] = 0xf3;
	g_epdom.R.val[j++] = 0xb9;
	g_epdom.R.val[j++] = 0xca;
	g_epdom.R.val[j++] = 0xc2;
	g_epdom.R.val[j++] = 0xfc;
	g_epdom.R.val[j++] = 0x63;
	g_epdom.R.val[j++] = 0x25;
	g_epdom.R.val[j++] = 0x51;

	g_epdom.Gx.len = 32;
	j=0;
	g_epdom.Gx.val[j++] = 0x6b;
	g_epdom.Gx.val[j++] = 0x17;
	g_epdom.Gx.val[j++] = 0xd1;
	g_epdom.Gx.val[j++] = 0xf2;
	g_epdom.Gx.val[j++] = 0xe1;
	g_epdom.Gx.val[j++] = 0x2c;
	g_epdom.Gx.val[j++] = 0x42;
	g_epdom.Gx.val[j++] = 0x47;
	g_epdom.Gx.val[j++] = 0xf8;
	g_epdom.Gx.val[j++] = 0xbc;
	g_epdom.Gx.val[j++] = 0xe6;
	g_epdom.Gx.val[j++] = 0xe5;
	g_epdom.Gx.val[j++] = 0x63;
	g_epdom.Gx.val[j++] = 0xa4;
	g_epdom.Gx.val[j++] = 0x40;
	g_epdom.Gx.val[j++] = 0xf2;
	g_epdom.Gx.val[j++] = 0x77;
	g_epdom.Gx.val[j++] = 0x03;
	g_epdom.Gx.val[j++] = 0x7d;
	g_epdom.Gx.val[j++] = 0x81;
	g_epdom.Gx.val[j++] = 0x2d;
	g_epdom.Gx.val[j++] = 0xeb;
	g_epdom.Gx.val[j++] = 0x33;
	g_epdom.Gx.val[j++] = 0xa0;
	g_epdom.Gx.val[j++] = 0xf4;
	g_epdom.Gx.val[j++] = 0xa1;
	g_epdom.Gx.val[j++] = 0x39;
	g_epdom.Gx.val[j++] = 0x45;
	g_epdom.Gx.val[j++] = 0xd8;
	g_epdom.Gx.val[j++] = 0x98;
	g_epdom.Gx.val[j++] = 0xc2;
	g_epdom.Gx.val[j++] = 0x96;

	g_epdom.Gy.len = 32;
	j=0;
	g_epdom.Gy.val[j++] = 0x4f;
	g_epdom.Gy.val[j++] = 0xe3;
	g_epdom.Gy.val[j++] = 0x42;
	g_epdom.Gy.val[j++] = 0xe2;
	g_epdom.Gy.val[j++] = 0xfe;
	g_epdom.Gy.val[j++] = 0x1a;
	g_epdom.Gy.val[j++] = 0x7f;
	g_epdom.Gy.val[j++] = 0x9b;
	g_epdom.Gy.val[j++] = 0x8e;
	g_epdom.Gy.val[j++] = 0xe7;
	g_epdom.Gy.val[j++] = 0xeb;
	g_epdom.Gy.val[j++] = 0x4a;
	g_epdom.Gy.val[j++] = 0x7c;
	g_epdom.Gy.val[j++] = 0x0f;
	g_epdom.Gy.val[j++] = 0x9e;
	g_epdom.Gy.val[j++] = 0x16;
	g_epdom.Gy.val[j++] = 0x2b;
	g_epdom.Gy.val[j++] = 0xce;
	g_epdom.Gy.val[j++] = 0x33;
	g_epdom.Gy.val[j++] = 0x57;
	g_epdom.Gy.val[j++] = 0x6b;
	g_epdom.Gy.val[j++] = 0x31;
	g_epdom.Gy.val[j++] = 0x5e;
	g_epdom.Gy.val[j++] = 0xce;
	g_epdom.Gy.val[j++] = 0xcb;
	g_epdom.Gy.val[j++] = 0xb6;
	g_epdom.Gy.val[j++] = 0x40;
	g_epdom.Gy.val[j++] = 0x68;
	g_epdom.Gy.val[j++] = 0x37;
	g_epdom.Gy.val[j++] = 0xbf;
	g_epdom.Gy.val[j++] = 0x51;
	g_epdom.Gy.val[j++] = 0xf5;

	g_epdom.K.len = 1;
	g_epdom.K.val[0] = 0x01;

	g_epdom.IK.len = 1;
	g_epdom.IK.val[0] = 0x01;
	
	g_epdom.H = 128;

	g_epdom.PC.window = 0;

}






BOOL FPGA_KDF2(U1 *z, octet *p, int olen, U1 *k)
{
	/* NOTE: the parameter olen is the length of the output k in bytes */
	int counter,cthreshold;
	int hlen;
	octet h;
	U1		message[256];
	int i;
	int j, m;
	int c[4];
	int		msg_len;
	U1 sha_out[32];
	int k_index = 0;
    
	hlen=32;	/* SHA256이므로 */
	cthreshold=MR_ROUNDUP(olen,hlen);


	// OCTET_EMPTY(k);
	//OCTET_INIT(&h,hlen);
	for (counter=1;counter<=cthreshold;counter++)
	{
		i = 0;
		j = 0;

		for ( j = 0; j < 32; j++)
			message[i++] = z[j];

		c[0]=(counter>>24)&0xff;
		c[1]=(counter>>16)&0xff;
		c[2]=(counter>>8)&0xff;
		c[3]=(counter)&0xff;

		for ( j = 0; j < 4; j++)
			message[i++] = c[j];

		for ( j = 0; j < p->len; j++)
			message[i++] = p->val[j];

		msg_len = i;
		fsha256_test1(message, msg_len, 1, sha_out);
		if (k_index + hlen > olen)
		{
			for ( m = 0; m < (olen%hlen); m++)
			{
				k[k_index++] = sha_out[m];
			}
		}
		else
		{
			for ( m = 0; m < hlen; m++)
			{
				k[k_index++] = sha_out[m];
			}
		}
   
	}
    	return TRUE;
}

BOOL FPGA_KDF2_Interrupt(U1 *z, octet *p, int olen, U1 *k)
{
	/* NOTE: the parameter olen is the length of the output k in bytes */
	int counter,cthreshold;
	int hlen;
	octet h;
	U1	message[256];
	int i;
	int j, m;
	int c[4];
	int		msg_len;
	U1 sha_out[32];
	int k_index = 0;
    
	hlen=32;	/* SHA256이므로 */
	cthreshold=MR_ROUNDUP(olen,hlen);


	// OCTET_EMPTY(k);
	//OCTET_INIT(&h,hlen);
	for (counter=1;counter<=cthreshold;counter++)
	{
		i = 0;
		j = 0;

		for ( j = 0; j < 32; j++)
			message[i++] = z[j];

		c[0]=(counter>>24)&0xff;
		c[1]=(counter>>16)&0xff;
		c[2]=(counter>>8)&0xff;
		c[3]=(counter)&0xff;

		for ( j = 0; j < 4; j++)
			message[i++] = c[j];

		for ( j = 0; j < p->len; j++)
			message[i++] = p->val[j];

		msg_len = i;
		fsha256_interrupt_test1(message, msg_len, 1, sha_out);
		if (k_index + hlen > olen)
		{
			for ( m = 0; m < (olen%hlen); m++)
			{
				k[k_index++] = sha_out[m];
			}
		}
		else
		{
			for ( m = 0; m < hlen; m++)
			{
				k[k_index++] = sha_out[m];
			}
		}
   
	}
    	return TRUE;
}

BOOL FPGA_MAC1(U1 *m, int m_len, U1 *k, int k_len, int olen, U1 *tag)
{
	/* Input is either from an octet m, or a file fp.          *
 	* olen is requested output length in bytes. k is the key  *
 	* The output is the calculated tag */
	int hlen,b;
	U1 h[256];
	U1 k0[256];
	U1 sha_out[32];
	int i, j;
	int k0_index = 0;
	U1	message[256];
	int		msg_len;

	hlen = 32;
	b = 64;	/* block size */
    
	if (hlen==0 || k_len<hlen/2) return FALSE;
    
	if (m==NULL) return FALSE;
    
	if (olen<4 || olen>hlen) return FALSE;
 
	if (k_len > b)
	{
		fsha256_test1(k, k_len, 1, k0);
		k0_index = 32;
	}
	else
	{
		for( i = 0; i < k_len; i++)
			k0[i] = k[i];

		k0_index = k_len;
	}
	
	for( i = 0; i < (b-k_len); i++)
		k0[k0_index+i] = 0;

	k0_index += (b-k_len);
		
	for (i=0;i<k0_index;i++) 
		k0[i]^=0x36;

	i = 0;
	for ( j = 0; j < k0_index; j++)
    		message[i++] = k0[j];

    	for ( j = 0; j < m_len; j++)
    		message[i++] = m[j];

    	msg_len = i;
	fsha256_test1(message, msg_len, 1, h);

	/* SHKO : 이미 위에서 k0에 0x36으로 Exclusive-OR를 했기 때문에 원래 k0에서 0x5C로 Exclusive-OR */
	/* 하기 위해서는 k0에 0x36으로 Exclusive-OR 한 것에서 0x6a로 Exclusive-OR 하면 된다. */
	for (i=0;i<k0_index;i++) 
		k0[i]^=0x6a;	/* 0x6a = 0x36 ^ 0x5c */
	
	i = 0;
	for ( j = 0; j < k0_index; j++)
    		message[i++] = k0[j];

    	for ( j = 0; j < hlen; j++)
    		message[i++] = h[j];

    	msg_len = i;
	fsha256_test1(message, msg_len, 1, h);    
	
	for( i = 0; i < olen; i++)
		tag[i] = h[i];
    
	return TRUE;
}

BOOL FPGA_MAC1_Interrupt(U1 *m, int m_len, U1 *k, int k_len, int olen, U1 *tag)
{
	/* Input is either from an octet m, or a file fp.          *
 	* olen is requested output length in bytes. k is the key  *
 	* The output is the calculated tag */
	int hlen,b;
	U1 h[256];
	U1 k0[256];
	U1 sha_out[32];
	int i, j;
	int k0_index = 0;
	U1	message[256];
	int		msg_len;

	hlen = 32;
	b = 64;	/* block size */
    
	if (hlen==0 || k_len<hlen/2) return FALSE;
    
	if (m==NULL) return FALSE;
    
	if (olen<4 || olen>hlen) return FALSE;
 
	if (k_len > b)
	{
		fsha256_interrupt_test1(k, k_len, 1, k0);
		k0_index = 32;
	}
	else
	{
		for( i = 0; i < k_len; i++)
			k0[i] = k[i];

		k0_index = k_len;
	}
	
	for( i = 0; i < (b-k_len); i++)
		k0[k0_index+i] = 0;

	k0_index += (b-k_len);
		
	for (i=0;i<k0_index;i++) 
		k0[i]^=0x36;

	i = 0;
	for ( j = 0; j < k0_index; j++)
    		message[i++] = k0[j];

    	for ( j = 0; j < m_len; j++)
    		message[i++] = m[j];

    	msg_len = i;
	fsha256_interrupt_test1(message, msg_len, 1, h);

	/* SHKO : 이미 위에서 k0에 0x36으로 Exclusive-OR를 했기 때문에 원래 k0에서 0x5C로 Exclusive-OR */
	/* 하기 위해서는 k0에 0x36으로 Exclusive-OR 한 것에서 0x6a로 Exclusive-OR 하면 된다. */
	for (i=0;i<k0_index;i++) 
		k0[i]^=0x6a;	/* 0x6a = 0x36 ^ 0x5c */
	
	i = 0;
	for ( j = 0; j < k0_index; j++)
    		message[i++] = k0[j];

    	for ( j = 0; j < hlen; j++)
    		message[i++] = h[j];

    	msg_len = i;
	fsha256_interrupt_test1(message, msg_len, 1, h);    
	
	for( i = 0; i < olen; i++)
		tag[i] = h[i];
    
	return TRUE;
}

void fpga_ecies_test(void)
{
	U1		message[256];
	volatile unsigned int status;
	int 		i, j;
	int		msg_len;
	int		time_out;
	unsigned int initial_value;
	int mlen;
	BOOL compress, dhaes,result;
	octet h,s,p,f,g,d,u,v,w;
	octet s0,s1,w0,w1,u0,u1,v0,v1,z,vz;
	octet z1,z2,f1,f2,f3;
	octet p1,p2,L2;
	int res,bytes,bits;
	U1 send_z[32];
   	U1 rcv_z[32];
	U1 sha_out[32];
	U1 k[32];
	U1 k1[16];
	U1 k2[16];
	U1 m[16];
	U1 c[16];
	U1 C[256];
	U1 tag[16];
	U1 m1[16];
	U1 tag1[16];
	U1 sender_y_key_lsb = 0;
	U4 reg_data[8];
	U4 v_data[8];
	struct timeval start_point, end_point;
	volatile double operating_time;

	gettimeofday(&start_point, NULL);

	if (ecies_print_flag)
	{
		printf("=================================\n");
		printf("[fpga_ecies_test] Transmit Part!!\n");
		printf("=================================\n");
	}


	compress=TRUE;

	OCTET_INIT(&p1,30);
	OCTET_INIT(&p2,30);
 	OCTET_JOIN_STRING("Key Derivation Parameters",&p1);
 	OCTET_JOIN_STRING("Encoding Parameters",&p2);

	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base+ ECDSA_ECC_ENABLE_H_REG_OFFSET), 0x0);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ECC_ENABLE_H_REG_OFFSET, 0x0);
#endif

	/* Prime Number Setting */
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
	
	/* Order Setting */
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
	
	/* Gx Setting */
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
#if 0	/* ECIES인 경우 Private Key 세팅을 안해도 됨. */
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
#endif
	
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
	
	/* SIGVERIFY Setting */
#if 0	/* ECDSA 할 때만 필요 */
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R0_H_REG_OFFSET), 0xD73CD372);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R1_H_REG_OFFSET), 0x2BAE6CC0);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R2_H_REG_OFFSET), 0xB39065BB);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R3_H_REG_OFFSET), 0x4003D8EC);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R4_H_REG_OFFSET), 0xE1EF2F7A);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R5_H_REG_OFFSET), 0x8A55BFD6);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R6_H_REG_OFFSET), 0x77234B0B);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R7_H_REG_OFFSET), 0x3B902650);
	
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S0_H_REG_OFFSET), 0xD9C88297);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S1_H_REG_OFFSET), 0xFEFED844);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S2_H_REG_OFFSET), 0x1E08DDA6);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S3_H_REG_OFFSET), 0x9554A645);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S4_H_REG_OFFSET), 0x2B8A0BD4);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S5_H_REG_OFFSET), 0xA0EA1DDB);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S6_H_REG_OFFSET), 0x750499F0);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S7_H_REG_OFFSET), 0xC2298C2F);
#endif
	
#if 0	/* random 하게 생성할 것이니 필요없음. */
	/* 송신측 공개키 X좌표값  */
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), 0x3BD87E39);
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), 0x6DA09C7E);
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), 0x5C13B38F);
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), 0x69448A94);
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), 0x13499463);
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), 0xA5BA8D06);
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), 0xA92B10CE);
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), 0x3AE91E3B);
	
	/* 송신측 공개키 Y좌표값  */
	//reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_TO_REC_S0_REG_OFFSET), 0x1D140E58);
	//reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_TO_REC_S1_REG_OFFSET), 0x061AE303);
	//reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_TO_REC_S2_REG_OFFSET), 0xECD6F7B3);
	//reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_TO_REC_S3_REG_OFFSET), 0x99381FD7);
	//reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_TO_REC_S4_REG_OFFSET), 0x72985DFB);
	//reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_TO_REC_S5_REG_OFFSET), 0x4BF7DAAD);
	//reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_TO_REC_S6_REG_OFFSET), 0x4778D368);
	//reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_TO_REC_S7_REG_OFFSET), 0x953D7872);
	
	/* 수신측 공개키 X좌표값  */
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R0_REG_OFFSET), 0xD8CE32C0);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R1_REG_OFFSET), 0x96C0EAD1);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R2_REG_OFFSET), 0xA9B4AB0F);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R3_REG_OFFSET), 0xD6312459);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R4_REG_OFFSET), 0x55FEC361);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R5_REG_OFFSET), 0x33B97633);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R6_REG_OFFSET), 0x4A2B5AA2);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R7_REG_OFFSET), 0x10592977);
	
	/* 수신측 공개키 Y좌표값  */
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S0_REG_OFFSET), 0x349714AE);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S1_REG_OFFSET), 0x5FE2DAAE);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S2_REG_OFFSET), 0x514769E6);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S3_REG_OFFSET), 0x0D2E8343);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S4_REG_OFFSET), 0x37F9569F);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S5_REG_OFFSET), 0xA1D55DD3);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S6_REG_OFFSET), 0x7B28A9CF);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S7_REG_OFFSET), 0x3CB175BA);
    #endif

  #if 0	/* 테스트용 고정 모드 */
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x00000001);
	/* 2를 Write하면 Test 모드 : 즉, 송수신측 private key를 고정 시킴.  */
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00020000);
  #else
	/* 1를 Write하면 Random 모드 */
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA256_RANDOM_ENABLE);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA256_RANDOM_ENABLE);
#endif
  #endif
	
	
	
	/* Start ECIES */
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), SIGNATURE_GEN_RANDOM_SEL_BIT);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, SIGNATURE_GEN_RANDOM_SEL_BIT);
#endif

#if 0	//SHKO
	if (ecies_print_flag)
	{
		printf("Display ECDSA Random Number\n");
		
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECDSA_RANDOM_NUMBER0_H_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}
#endif
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), TRANSFER_PRIVATE_RANDOM_SEL_BIT);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, TRANSFER_PRIVATE_RANDOM_SEL_BIT);
#endif

#if 1	//SHKO
	if (ecies_print_flag)
	{
		printf("\nDisplay Sender Random Number\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_RANDOM_NUMBER0_REG_OFFSET)+(i*4))));
		}
		
		printf("\n");
	}
#endif

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), RECEIVER_PRIVATE_RANDOM_SEL_BIT);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, RECEIVER_PRIVATE_RANDOM_SEL_BIT);
#endif

#if 1	//SHKO
	if (ecies_print_flag)
	{
		printf("\nDisplay Receiver Random Number\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_RECEIVE_RANDOM_NUMBER0_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}
#endif

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00000000); /* RANDOM Number 동작을 멈춘다.*/
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, 0x00000000); /* RANDOM Number 동작을 멈춘다.*/
#endif


	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, TRANSFER_PUBLIC_ENABLE_BIT);
	time_out = 20000;
	
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & TRANS_PUBLIC_GEN_DONE_BIT)
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, TRANS_PUBLIC_GEN_DONE_BIT);/* Clear */
	if (time_out < 0)
		printf("[fpga_ecies_test] Sender Public Key Generation Time Out!!\n");
		
	if (ecies_print_flag)
	{
		//printf("TRANS_PUBLIC_GEN status = 0x%08x, time_out = %d\n", status, time_out);
		printf("\nDisplay Sender Public Key X\n");
	}
	
	for ( i = 0; i < 8; i++)
	{
		if (ecies_print_flag)
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_PUBLIC_KEY_PX0_REG_OFFSET)+(i*4))));

		v_data[i] = reg_readl(((wave_dsrc_base+ECIES_TRANS_PUBLIC_KEY_PX0_REG_OFFSET)+(i*4)));
		/* 송신측 공개키 X좌표값  */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel(((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET)+(i*4)), v_data[i]);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(((ECIES_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET)+(i*4)), v_data[i]);
	#endif
	}
	if (ecies_print_flag)
		printf("\n");

	if (ecies_print_flag)
	{
		printf("Display Sender Public Key Y\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_PUBLIC_KEY_PY0_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}

	sender_y_key_lsb = (reg_readl((wave_dsrc_base+ECIES_TRANS_PUBLIC_KEY_PY7_REG_OFFSET))) & 0xFF;

	if (sender_y_key_lsb & 0x01)
	{
		if (ecies_print_flag)
			printf("Setting Odd bit\n");

	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x00000001);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET, 0x00000001);
	#endif
	}
	else
	{
		if (ecies_print_flag)
			printf("Setting Even bit\n");
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x00000000);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET, 0x00000000);
	#endif
	}

	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, RECEIVER_PUBLIC_ENABLE_BIT);

	time_out = 20000;
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & REC_PUBLIC_GEN_DONE_BIT)
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, REC_PUBLIC_GEN_DONE_BIT);/* Clear */
	if (time_out < 0)
		printf("[fpga_ecies_test] Receiver Public Key Generation Time Out!!\n");
	
	if (ecies_print_flag)
	{
		printf("RECEIVER_PUBLIC_GEN status = 0x%08x, time_out = %d\n", status, time_out);
		printf("Display Receiver Public Key X\n");
	}
	
   	j = 0;
	for ( i = 0; i < 8; i++)
	{
		if (ecies_print_flag)
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PUBLIC_KEY_PX0_REG_OFFSET)+(i*4))));
		reg_data[i] = reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PUBLIC_KEY_PX0_REG_OFFSET)+(i*4)));

		/* 수신측 공개키 X좌표값  */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel(((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R0_REG_OFFSET)+(i*4)), reg_data[i]);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(((ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R0_REG_OFFSET)+(i*4)), reg_data[i]);
	#endif
	}
	if (ecies_print_flag)
		printf("\n");

	if (ecies_print_flag)
		printf("Display Receiver Public Key Y\n");
	for ( i = 0; i < 8; i++)
	{
		if (ecies_print_flag)
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PUBLIC_KEY_PY0_REG_OFFSET)+(i*4))));
		reg_data[i] = reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PUBLIC_KEY_PY0_REG_OFFSET)+(i*4)));
		
		/* 수신측 공개키 X좌표값  */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel(((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S0_REG_OFFSET)+(i*4)), reg_data[i]);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(((ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S0_REG_OFFSET)+(i*4)), reg_data[i]);
	#endif
	}
	if (ecies_print_flag)
		printf("\n");
	
	
	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, TRANSFER_PRIMITIVE_ENABLE_BIT);
	time_out = 20000;
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & TRANS_PRIMITIVE_DONE_BIT)
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, TRANS_PRIMITIVE_DONE_BIT);/* Clear */
	if (time_out < 0)
		printf("[fpga_ecies_test] Sender Primitive Done Time Out!!\n");
	
	if (ecies_print_flag)
	{
		printf("TRANS_PRIMITIVE_GEN status = 0x%08x, time_out = %d\n", status, time_out);
		//printf("Display Sender Private Key * Receiver Public Key X\n");
	}
	
   	j = 0;
	for ( i = 0; i < 8; i++)
	{
		//if (ecies_print_flag)
		//	printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))));
		send_z[j++] = (reg_readl(((wave_dsrc_base+ECIES_TRANS_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) >> 8) & 0xFF;
		send_z[j++] = reg_readl(((wave_dsrc_base+ECIES_TRANS_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) & 0xFF;
		send_z[j++] = (reg_readl(((wave_dsrc_base+ECIES_TRANS_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) >> 24) & 0xFF;
		send_z[j++] = (reg_readl(((wave_dsrc_base+ECIES_TRANS_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) >> 16) & 0xFF;
	}
	if (ecies_print_flag)
		printf("\n");
#if 1	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Sender Private Key * Receiver Public Key Y\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_PRIMITIVE_KEY_RY0_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}
#endif

#if 1	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Sender Z\n");
		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", send_z[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");

		//printf("p1 is \n");
	    	//OCTET_OUTPUT(&p1);
		//printf("\n");
	}
#endif

	/* 아래 #if 0을 열면 FPGA_KDF2 함수를 호출한후 다음과 같은 k값이 나와야 한다. */
	/* ffbbe0a54935bf931025612e5b8f81a52fb0f3669918f5ff10a4c8d98e00c1ae */
  #if 0
	i = 0;
	send_z[i++] = 0xeb;
	send_z[i++] = 0x74;
	send_z[i++] = 0x60;
	send_z[i++] = 0x89;
	send_z[i++] = 0xdb;
	send_z[i++] = 0x69;
	send_z[i++] = 0x55;
	send_z[i++] = 0x9a;
	send_z[i++] = 0x96;
	send_z[i++] = 0xbb;
	send_z[i++] = 0xe4;
	send_z[i++] = 0x71;
	send_z[i++] = 0xd3;
	send_z[i++] = 0xd6;
	send_z[i++] = 0x58;
	send_z[i++] = 0x9a;
	send_z[i++] = 0x0f;
	send_z[i++] = 0x32;
	send_z[i++] = 0x05;
	send_z[i++] = 0x18;
	send_z[i++] = 0x7f;
	send_z[i++] = 0x41;
	send_z[i++] = 0x5d;
	send_z[i++] = 0x6c;
	send_z[i++] = 0x19;
	send_z[i++] = 0xa2;
	send_z[i++] = 0x17;
	send_z[i++] = 0x58;
	send_z[i++] = 0x4e;
	send_z[i++] = 0xd3;
	send_z[i++] = 0x00;
	send_z[i++] = 0x9d;
  #endif
	
	/* SHKO : vz + counter 1(4바이트) + p1 을 합친 메세지를 SHA256로 Digest를 만들어서 k에 update한다. */
	res=FPGA_KDF2(send_z, &p1, 32, k);

#if 0	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Sender Key is\n");
		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", k[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}
#endif

	for (i=0;i<16;i++)	
	{
		k1[i]=k[i];
 		k2[i]=k[16+i];
	}

 
	for (i=0;i<16;i++)
 		m[i]=i+1;    /* fake a message */

 	if (ecies_print_flag)
	{
		printf("Plain Data M is\n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", m[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}
 
	/* SHKO : IEEE 1363A 규격의 11.3.2의 9) 참조 */
	for (i=0;i<16;i++) 
	{
		c[i]=m[i] ^ k1[i];
	}
	
	for ( i = 0; i < 16; i++)
	{
		C[i] = c[i];
	}


	for ( j = 0; j < p2.len; j++)
	{
		C[i+j] = p2.val[j];
	}

	
	/* 아래 #if 0을 열면 FPGA_MAC1 함수를 호출한후 다음과 같은 tag값이 나와야 한다. */
	/* 0d9810b379ae290c5ec3b6af9e6aa893 */
  #if 0
	i = 0;
	C[i++] = 0xd4;
	C[i++] = 0xf1;
	C[i++] = 0xb6;
	C[i++] = 0x20;
	C[i++] = 0x2b;
	C[i++] = 0x15;
	C[i++] = 0xe2;
	C[i++] = 0x32;
	C[i++] = 0x73;
	C[i++] = 0xe0;
	
	C[i++] = 0x47;
	C[i++] = 0x69;
	C[i++] = 0x72;
	C[i++] = 0x2f;
	C[i++] = 0x74;
	C[i++] = 0xae;
	C[i++] = 0x45;
	C[i++] = 0x6e;
	C[i++] = 0x63;
	C[i++] = 0x6f;
	
	C[i++] = 0x64;
	C[i++] = 0x69;
	C[i++] = 0x6e;
	C[i++] = 0x67;
	C[i++] = 0x20;
	C[i++] = 0x50;
	C[i++] = 0x61;
	C[i++] = 0x72;
	C[i++] = 0x61;
	C[i++] = 0x6d;
	
	C[i++] = 0x65;
	C[i++] = 0x74;
	C[i++] = 0x65;
	C[i++] = 0x72;
	C[i++] = 0x73;

	i = 0;
	k2[i++] = 0x52;
	k2[i++] = 0x92;
	k2[i++] = 0x12;
	k2[i++] = 0xe0;
	k2[i++] = 0xec;
	k2[i++] = 0x09;
	k2[i++] = 0xb4;
	k2[i++] = 0x61;
	k2[i++] = 0xb2;
	k2[i++] = 0x4e;

	k2[i++] = 0xdb;
	k2[i++] = 0x56;
	k2[i++] = 0x8a;
	k2[i++] = 0xde;
	k2[i++] = 0xe9;
	k2[i++] = 0x3a;
  #endif

	/* SHKO : IEEE 1363A 규격의 Figure 11에서 MAC에 해당 --> k2와 C를 입력으로 해서 16바이트 크기를 갖는 tag를 만든다. */
	res=FPGA_MAC1(C,(16+p2.len),k2,16,16,tag);

	if (ecies_print_flag)
	{
		printf("\n=================================\n");
		printf("Encryption Output\n");
		printf("\nDisplay V\n");
		if (sender_y_key_lsb & 0x01)
		{
			printf("[03]");
		}
		else
		{
			printf("[02]");
		}
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", v_data[i]);
		}
		printf("\n");

		printf("\nDisplay Ciphertext is\n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", c[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");

		printf("\nHMAC TAG is\n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", tag[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
		printf("=================================\n");
	}

	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("Encryption Operation Time : %f\n",operating_time);

	gettimeofday(&start_point, NULL);



	if (ecies_print_flag)
	{
		printf("\n\n=================================\n");
		printf("[fpga_ecies_test] Receive Part!!\n");
		printf("=================================\n");
	}

	if (ecies_print_flag)
	{
		printf("Decryption Start!!\n\n");
	}

	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, ECIES_KEY_RECOVERY_ENABLE_BIT);
	time_out = 20000;
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & ECIES_RECOVERY_DONE_BIT)
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, ECIES_RECOVERY_DONE_BIT);/* Clear */
	if (time_out < 0)
		printf("[fpga_ecies_test] Key Recovery Done Time Out!!\n");
	
	if (ecies_print_flag)
		printf("TRANS_PUBLIC_KEY_Y_RECOVERY status = 0x%08x, time_out = %d\n", status, time_out);

	if (ecies_print_flag)
	{
		printf("Display Recovery Sender Public Key Y\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_RECEIVE_RECOVERY_Y0_H_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}

	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, RECEIVER_PRIMITIVE_ENABLE_BIT);
	time_out = 20000;
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & REC_PRIMITIVE_DONE_BIT)
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, REC_PRIMITIVE_DONE_BIT);/* Clear */
	if (time_out < 0)
		printf("[fpga_ecies_test] Receiver Primitive Done Time Out!!\n");
	
	if (ecies_print_flag)
	{
	//	printf("REC_PRIMITIVE_DONE status = 0x%08x, time_out = %d\n", status, time_out);
		printf("Display Receiver Private Key * Sender Public Key X\n");
	}
    	j = 0;
	for ( i = 0; i < 8; i++)
	{
		//if (ecies_print_flag)
			//printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))));
		rcv_z[j++] = (reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) >> 8) & 0xFF;
		rcv_z[j++] = reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) & 0xFF;
		rcv_z[j++] = (reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) >> 24) & 0xFF;
		rcv_z[j++] = (reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) >> 16) & 0xFF;
	}
	if (ecies_print_flag)
		printf("\n");

#if 1	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Receiver Private Key * Sender Public Key Y\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PRIMITIVE_KEY_RY0_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}
#endif

#if 1	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Receiver Z\n");
		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", rcv_z[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}
#endif

	/* SHKO : vz + counter 1(4바이트) + p1 을 합친 메세지를 SHA256로 Digest를 만들어서 k에 update한다. */
	res=FPGA_KDF2(rcv_z, &p1, 32, k);

#if 0	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Receiver Key is\n");
		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", k[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}
#endif

	for (i=0;i<16;i++)	
	{
		k1[i]=k[i];
 		k2[i]=k[16+i];
	}

	/* SHKO : IEEE 1363A 규격의 11.3.3의 8) 참조 */
	for (i=0;i<16;i++) 
	{
		m1[i]=c[i] ^ k1[i];
	}

	if (ecies_print_flag)
	{
		printf("Plain Data is\n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", m1[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}

	for ( i = 0; i < 16; i++)
	{
		C[i] = c[i];
	}


	for ( j = 0; j < p2.len; j++)
	{
		C[i+j] = p2.val[j];
	}

	/* SHKO : IEEE 1363A 규격의 Figure 11에서 MAC에 해당 --> k2와 C를 입력으로 해서 16바이트 크기를 갖는 tag를 만든다. */
	res=FPGA_MAC1(C,(16+p2.len),k2,16,16,tag1);

	if (ecies_print_flag)
	{
		printf("HMAC TAG is\n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", tag1[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}

	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("Decrption Operation Time : %f\n",operating_time);

	if ((memcmp(m,m1,16) == 0) && (memcmp(tag,tag1,16) == 0))
		printf("ECIES Encryption/Decryption - OK\n");
    	else
	{
		printf("ECIES Encryption/Decryption Failed\n");
	} 


	//printf("ECDSA_RANDOM_SEL_H_REG = [%08x]", reg_readl(wave_dsrc_base+ECDSA_RANDOM_SEL_H_REG_OFFSET));
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */
	
}

void fpga_ecies_interrupt_test(void)
{
	U1		message[256];
	volatile unsigned int status;
	int 		i, j;
	int		msg_len;
	int		time_out;
	unsigned int initial_value;
	int mlen;
	BOOL compress, dhaes,result;
	octet h,s,p,f,g,d,u,v,w;
	octet s0,s1,w0,w1,u0,u1,v0,v1,z,vz;
	octet z1,z2,f1,f2,f3;
	octet p1,p2,L2;
	int res,bytes,bits;
	U1 send_z[32];
   	U1 rcv_z[32];
	U1 sha_out[32];
	U1 k[32];
	U1 k1[16];
	U1 k2[16];
	U1 m[16];
	U1 c[16];
	U1 C[256];
	U1 tag[16];
	U1 m1[16];
	U1 tag1[16];
	U1 sender_y_key_lsb = 0;
	U4 reg_data[8];
	U4 v_data[8];
	struct timeval start_point, end_point;
	volatile double operating_time;
	U4 wave_ecc_interrupt_status;
	int ret = 0;

	gettimeofday(&start_point, NULL);

	if (ecies_print_flag)
	{
		printf("=================================\n");
		printf("[fpga_ecies_test] Transmit Part!!\n");
		printf("=================================\n");
	}


	compress=TRUE;

	OCTET_INIT(&p1,30);
	OCTET_INIT(&p2,30);
 	OCTET_JOIN_STRING("Key Derivation Parameters",&p1);
 	OCTET_JOIN_STRING("Encoding Parameters",&p2);

	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */

	reg_writel((wave_dsrc_base+ ECDSA_ECC_ENABLE_H_REG_OFFSET), 0x0);

	/* Prime Number Setting */
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
	
	/* Order Setting */
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
	
	/* Gx Setting */
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
	
	/* SIGVERIFY Setting */
#if 0	/* ECDSA 할 때만 필요 */
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R0_H_REG_OFFSET), 0xD73CD372);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R1_H_REG_OFFSET), 0x2BAE6CC0);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R2_H_REG_OFFSET), 0xB39065BB);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R3_H_REG_OFFSET), 0x4003D8EC);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R4_H_REG_OFFSET), 0xE1EF2F7A);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R5_H_REG_OFFSET), 0x8A55BFD6);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R6_H_REG_OFFSET), 0x77234B0B);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_R7_H_REG_OFFSET), 0x3B902650);
	
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S0_H_REG_OFFSET), 0xD9C88297);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S1_H_REG_OFFSET), 0xFEFED844);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S2_H_REG_OFFSET), 0x1E08DDA6);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S3_H_REG_OFFSET), 0x9554A645);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S4_H_REG_OFFSET), 0x2B8A0BD4);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S5_H_REG_OFFSET), 0xA0EA1DDB);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S6_H_REG_OFFSET), 0x750499F0);
	reg_writel((wave_dsrc_base + ECDSA_SIGVERIFY_KEYPAIR_S7_H_REG_OFFSET), 0xC2298C2F);
#endif
	
#if 0	/* random 하게 생성할 것이니 필요없음. */
	/* 송신측 공개키 X좌표값  */
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET), 0x3BD87E39);
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R1_REG_OFFSET), 0x6DA09C7E);
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R2_REG_OFFSET), 0x5C13B38F);
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R3_REG_OFFSET), 0x69448A94);
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R4_REG_OFFSET), 0x13499463);
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R5_REG_OFFSET), 0xA5BA8D06);
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R6_REG_OFFSET), 0xA92B10CE);
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R7_REG_OFFSET), 0x3AE91E3B);
	
	/* 송신측 공개키 Y좌표값  */
	//reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_TO_REC_S0_REG_OFFSET), 0x1D140E58);
	//reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_TO_REC_S1_REG_OFFSET), 0x061AE303);
	//reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_TO_REC_S2_REG_OFFSET), 0xECD6F7B3);
	//reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_TO_REC_S3_REG_OFFSET), 0x99381FD7);
	//reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_TO_REC_S4_REG_OFFSET), 0x72985DFB);
	//reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_TO_REC_S5_REG_OFFSET), 0x4BF7DAAD);
	//reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_TO_REC_S6_REG_OFFSET), 0x4778D368);
	//reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_TO_REC_S7_REG_OFFSET), 0x953D7872);
	
	/* 수신측 공개키 X좌표값  */
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R0_REG_OFFSET), 0xD8CE32C0);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R1_REG_OFFSET), 0x96C0EAD1);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R2_REG_OFFSET), 0xA9B4AB0F);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R3_REG_OFFSET), 0xD6312459);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R4_REG_OFFSET), 0x55FEC361);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R5_REG_OFFSET), 0x33B97633);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R6_REG_OFFSET), 0x4A2B5AA2);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R7_REG_OFFSET), 0x10592977);
	
	/* 수신측 공개키 Y좌표값  */
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S0_REG_OFFSET), 0x349714AE);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S1_REG_OFFSET), 0x5FE2DAAE);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S2_REG_OFFSET), 0x514769E6);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S3_REG_OFFSET), 0x0D2E8343);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S4_REG_OFFSET), 0x37F9569F);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S5_REG_OFFSET), 0xA1D55DD3);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S6_REG_OFFSET), 0x7B28A9CF);
	reg_writel((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S7_REG_OFFSET), 0x3CB175BA);
    #endif

  #if 0	/* 테스트용 고정 모드 */
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x00000001);
	/* 2를 Write하면 Test 모드 : 즉, 송수신측 private key를 고정 시킴.  */
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00020000);
  #else
	/* 1를 Write하면 Random 모드 */
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA256_RANDOM_ENABLE);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA256_RANDOM_ENABLE);
#endif
  #endif
	
	
	
	/* Start ECIES */
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), SIGNATURE_GEN_RANDOM_SEL_BIT);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, SIGNATURE_GEN_RANDOM_SEL_BIT);
#endif

#if 0	//SHKO
	if (ecies_print_flag)
	{
		printf("Display ECDSA Random Number\n");
		
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECDSA_RANDOM_NUMBER0_H_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}
#endif

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), TRANSFER_PRIVATE_RANDOM_SEL_BIT);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, TRANSFER_PRIVATE_RANDOM_SEL_BIT);
#endif

#if 1	//SHKO
	if (ecies_print_flag)
	{
		printf("\nDisplay Sender Random Number\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_RANDOM_NUMBER0_REG_OFFSET)+(i*4))));
		}
		
		printf("\n");
	}
#endif

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), RECEIVER_PRIVATE_RANDOM_SEL_BIT);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, RECEIVER_PRIVATE_RANDOM_SEL_BIT);
#endif

#if 1	//SHKO
	if (ecies_print_flag)
	{
		printf("\nDisplay Receiver Random Number\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_RECEIVE_RANDOM_NUMBER0_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}
#endif

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00000000); /* RANDOM Number 동작을 멈춘다.*/
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, 0x00000000);/* RANDOM Number 동작을 멈춘다.*/
#endif


	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, TRANSFER_PUBLIC_ENABLE_BIT);
#if 0
	time_out = 20000;
	
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & TRANS_PUBLIC_GEN_DONE_BIT)
			break;
	}

	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, TRANS_PUBLIC_GEN_DONE_BIT);/* Clear */
	if (time_out < 0)
		printf("[fpga_ecies_test] Sender Public Key Generation Time Out!!\n");
		
	if (ecies_print_flag)
	{
		printf("TRANS_PUBLIC_GEN status = 0x%08x, time_out = %d\n", status, time_out);
		printf("Display Sender Public Key X\n");
	}
	
	for ( i = 0; i < 8; i++)
	{
		if (ecies_print_flag)
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_PUBLIC_KEY_PX0_REG_OFFSET)+(i*4))));

		v_data[i] = reg_readl(((wave_dsrc_base+ECIES_TRANS_PUBLIC_KEY_PX0_REG_OFFSET)+(i*4)));
		/* 송신측 공개키 X좌표값  */
		reg_writel(((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET)+(i*4)), v_data[i]);
	}
	if (ecies_print_flag)
		printf("\n");

	if (ecies_print_flag)
	{
		printf("Display Sender Public Key Y\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_PUBLIC_KEY_PY0_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}

	sender_y_key_lsb = (reg_readl((wave_dsrc_base+ECIES_TRANS_PUBLIC_KEY_PY7_REG_OFFSET))) & 0xFF;

	if (sender_y_key_lsb & 0x01)
	{
		if (ecies_print_flag)
			printf("Setting Odd bit\n");
		reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x00000001);
	}
	else
	{
		if (ecies_print_flag)
			printf("Setting Even bit\n");
		reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x00000000);
	}

	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, RECEIVER_PUBLIC_ENABLE_BIT);
#endif

#if 0
	time_out = 20000;
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & REC_PUBLIC_GEN_DONE_BIT)
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, REC_PUBLIC_GEN_DONE_BIT);/* Clear */
	if (time_out < 0)
		printf("[fpga_ecies_test] Receiver Public Key Generation Time Out!!\n");
	
	if (ecies_print_flag)
	{
		printf("RECEIVER_PUBLIC_GEN status = 0x%08x, time_out = %d\n", status, time_out);
		printf("Display Receiver Public Key X\n");
	}
	
   	j = 0;
	for ( i = 0; i < 8; i++)
	{
		if (ecies_print_flag)
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PUBLIC_KEY_PX0_REG_OFFSET)+(i*4))));
		reg_data[i] = reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PUBLIC_KEY_PX0_REG_OFFSET)+(i*4)));
		/* 수신측 공개키 X좌표값  */
		reg_writel(((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R0_REG_OFFSET)+(i*4)), reg_data[i]);
	}
	if (ecies_print_flag)
		printf("\n");

	if (ecies_print_flag)
		printf("Display Receiver Public Key Y\n");
	for ( i = 0; i < 8; i++)
	{
		if (ecies_print_flag)
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PUBLIC_KEY_PY0_REG_OFFSET)+(i*4))));
		reg_data[i] = reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PUBLIC_KEY_PY0_REG_OFFSET)+(i*4)));
		/* 수신측 공개키 X좌표값  */
		reg_writel(((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S0_REG_OFFSET)+(i*4)), reg_data[i]);
	}
	if (ecies_print_flag)
		printf("\n");
	
	
	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, TRANSFER_PRIMITIVE_ENABLE_BIT);
#endif

	time_out = 20000;
	while(time_out--)
	{	
		ret  = ioctl(dev, IOCTLWAVE_ECC_INT_READ, &wave_ecc_interrupt_status);
		if (ret != 0)
		{
			perror("[fpga_ecies_interrupt_test] ioctl:");
			break;
		}
		else
		{
			if (wave_ecc_interrupt_status == ECIES_TRANS_PRIMITIVE_DONE)
			{
				break;
			}
		}
	}
#if 0
	time_out = 20000;
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & TRANS_PRIMITIVE_DONE_BIT)
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, TRANS_PRIMITIVE_DONE_BIT);/* Clear */
#endif
	if (time_out < 0)
		printf("[fpga_ecies_test] Sender Primitive Done Time Out!!\n");
	
	if (ecies_print_flag)
	{
		printf("TRANS_PRIMITIVE_GEN status = 0x%08x, time_out = %d\n", status, time_out);
		//printf("Display Sender Private Key * Receiver Public Key X\n");
	}
	
   	j = 0;
	for ( i = 0; i < 8; i++)
	{
		//if (ecies_print_flag)
		//	printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))));
		send_z[j++] = (reg_readl(((wave_dsrc_base+ECIES_TRANS_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) >> 8) & 0xFF;
		send_z[j++] = reg_readl(((wave_dsrc_base+ECIES_TRANS_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) & 0xFF;
		send_z[j++] = (reg_readl(((wave_dsrc_base+ECIES_TRANS_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) >> 24) & 0xFF;
		send_z[j++] = (reg_readl(((wave_dsrc_base+ECIES_TRANS_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) >> 16) & 0xFF;
	}
	if (ecies_print_flag)
		printf("\n");


#if 0	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Sender Private Key * Receiver Public Key Y\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_PRIMITIVE_KEY_RY0_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}
#endif

#if 0	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Sender Z\n");
		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", send_z[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");

		//printf("p1 is \n");
	    	//OCTET_OUTPUT(&p1);
		//printf("\n");
	}
#endif

	/* 아래 #if 0을 열면 FPGA_KDF2 함수를 호출한후 다음과 같은 k값이 나와야 한다. */
	/* ffbbe0a54935bf931025612e5b8f81a52fb0f3669918f5ff10a4c8d98e00c1ae */
  #if 0
	i = 0;
	send_z[i++] = 0xeb;
	send_z[i++] = 0x74;
	send_z[i++] = 0x60;
	send_z[i++] = 0x89;
	send_z[i++] = 0xdb;
	send_z[i++] = 0x69;
	send_z[i++] = 0x55;
	send_z[i++] = 0x9a;
	send_z[i++] = 0x96;
	send_z[i++] = 0xbb;
	send_z[i++] = 0xe4;
	send_z[i++] = 0x71;
	send_z[i++] = 0xd3;
	send_z[i++] = 0xd6;
	send_z[i++] = 0x58;
	send_z[i++] = 0x9a;
	send_z[i++] = 0x0f;
	send_z[i++] = 0x32;
	send_z[i++] = 0x05;
	send_z[i++] = 0x18;
	send_z[i++] = 0x7f;
	send_z[i++] = 0x41;
	send_z[i++] = 0x5d;
	send_z[i++] = 0x6c;
	send_z[i++] = 0x19;
	send_z[i++] = 0xa2;
	send_z[i++] = 0x17;
	send_z[i++] = 0x58;
	send_z[i++] = 0x4e;
	send_z[i++] = 0xd3;
	send_z[i++] = 0x00;
	send_z[i++] = 0x9d;
  #endif
	
	/* SHKO : vz + counter 1(4바이트) + p1 을 합친 메세지를 SHA256로 Digest를 만들어서 k에 update한다. */
	res=FPGA_KDF2_Interrupt(send_z, &p1, 32, k);

#if 0	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Sender Key is\n");
		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", k[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}
#endif

	for (i=0;i<16;i++)	
	{
		k1[i]=k[i];
 		k2[i]=k[16+i];
	}

 
	for (i=0;i<16;i++)
 		m[i]=i+1;    /* fake a message */

 	if (ecies_print_flag)
	{
		printf("Plain Data M is\n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", m[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}
 
	/* SHKO : IEEE 1363A 규격의 11.3.2의 9) 참조 */
	for (i=0;i<16;i++) 
	{
		c[i]=m[i] ^ k1[i];
	}
	
	for ( i = 0; i < 16; i++)
	{
		C[i] = c[i];
	}


	for ( j = 0; j < p2.len; j++)
	{
		C[i+j] = p2.val[j];
	}

	
	/* 아래 #if 0을 열면 FPGA_MAC1 함수를 호출한후 다음과 같은 tag값이 나와야 한다. */
	/* 0d9810b379ae290c5ec3b6af9e6aa893 */
  #if 0
	i = 0;
	C[i++] = 0xd4;
	C[i++] = 0xf1;
	C[i++] = 0xb6;
	C[i++] = 0x20;
	C[i++] = 0x2b;
	C[i++] = 0x15;
	C[i++] = 0xe2;
	C[i++] = 0x32;
	C[i++] = 0x73;
	C[i++] = 0xe0;
	
	C[i++] = 0x47;
	C[i++] = 0x69;
	C[i++] = 0x72;
	C[i++] = 0x2f;
	C[i++] = 0x74;
	C[i++] = 0xae;
	C[i++] = 0x45;
	C[i++] = 0x6e;
	C[i++] = 0x63;
	C[i++] = 0x6f;
	
	C[i++] = 0x64;
	C[i++] = 0x69;
	C[i++] = 0x6e;
	C[i++] = 0x67;
	C[i++] = 0x20;
	C[i++] = 0x50;
	C[i++] = 0x61;
	C[i++] = 0x72;
	C[i++] = 0x61;
	C[i++] = 0x6d;
	
	C[i++] = 0x65;
	C[i++] = 0x74;
	C[i++] = 0x65;
	C[i++] = 0x72;
	C[i++] = 0x73;

	i = 0;
	k2[i++] = 0x52;
	k2[i++] = 0x92;
	k2[i++] = 0x12;
	k2[i++] = 0xe0;
	k2[i++] = 0xec;
	k2[i++] = 0x09;
	k2[i++] = 0xb4;
	k2[i++] = 0x61;
	k2[i++] = 0xb2;
	k2[i++] = 0x4e;

	k2[i++] = 0xdb;
	k2[i++] = 0x56;
	k2[i++] = 0x8a;
	k2[i++] = 0xde;
	k2[i++] = 0xe9;
	k2[i++] = 0x3a;
  #endif

	/* SHKO : IEEE 1363A 규격의 Figure 11에서 MAC에 해당 --> k2와 C를 입력으로 해서 16바이트 크기를 갖는 tag를 만든다. */
	res=FPGA_MAC1_Interrupt(C,(16+p2.len),k2,16,16,tag);

	if (ecies_print_flag)
	{
		printf("\n=================================\n");
		printf("Encryption Output\n");
		printf("\nDisplay V\n");
		if (sender_y_key_lsb & 0x01)
		{
			printf("[03]");
		}
		else
		{
			printf("[02]");
		}
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", v_data[i]);
		}
		printf("\n");

		printf("\nDisplay Ciphertext is\n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", c[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");

		printf("\nHMAC TAG is\n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", tag[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
		printf("=================================\n");
	}

	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("Encryption Operation Time : %f\n",operating_time);

	gettimeofday(&start_point, NULL);



	if (ecies_print_flag)
	{
		printf("\n\n=================================\n");
		printf("[fpga_ecies_test] Receive Part!!\n");
		printf("=================================\n");
	}

	if (ecies_print_flag)
	{
		printf("Decryption Start!!\n\n");
	}

	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, ECIES_KEY_RECOVERY_ENABLE_BIT);

#if 0
	time_out = 20000;
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & ECIES_RECOVERY_DONE_BIT)
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, ECIES_RECOVERY_DONE_BIT);/* Clear */
	if (time_out < 0)
		printf("[fpga_ecies_test] Key Recovery Done Time Out!!\n");
	
	if (ecies_print_flag)
		printf("TRANS_PUBLIC_KEY_Y_RECOVERY status = 0x%08x, time_out = %d\n", status, time_out);

	if (ecies_print_flag)
	{
		printf("Display Recovery Sender Public Key Y\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_RECEIVE_RECOVERY_Y0_H_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}
#endif

#if 0
	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, RECEIVER_PRIMITIVE_ENABLE_BIT);
	time_out = 20000;
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & REC_PRIMITIVE_DONE_BIT)
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, REC_PRIMITIVE_DONE_BIT);/* Clear */
#endif

	time_out = 20000;
	while(time_out--)
	{	
		ret  = ioctl(dev, IOCTLWAVE_ECC_INT_READ, &wave_ecc_interrupt_status);
		if (ret != 0)
		{
			perror("[fpga_ecies_interrupt_test] ioctl:");
			break;
		}
		else
		{
			if (wave_ecc_interrupt_status == ECIES_RECEIVE_PRIMITIVE_DONE)
			{
				break;
			}
		}
	}
	if (time_out < 0)
		printf("[fpga_ecies_test] Receiver Primitive Done Time Out!!\n");
	
	if (ecies_print_flag)
	{
		printf("REC_PRIMITIVE_DONE status = 0x%08x, time_out = %d\n", status, time_out);
		//printf("Display Receiver Private Key * Sender Public Key X\n");
	}
    	j = 0;
	for ( i = 0; i < 8; i++)
	{
		//if (ecies_print_flag)
			//printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))));
		rcv_z[j++] = (reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) >> 8) & 0xFF;
		rcv_z[j++] = reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) & 0xFF;
		rcv_z[j++] = (reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) >> 24) & 0xFF;
		rcv_z[j++] = (reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) >> 16) & 0xFF;
	}
	if (ecies_print_flag)
		printf("\n");

#if 0	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Receiver Private Key * Sender Public Key Y\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PRIMITIVE_KEY_RY0_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}
#endif

#if 0	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Receiver Z\n");
		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", rcv_z[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}
#endif

	/* SHKO : vz + counter 1(4바이트) + p1 을 합친 메세지를 SHA256로 Digest를 만들어서 k에 update한다. */
	res=FPGA_KDF2_Interrupt(rcv_z, &p1, 32, k);

#if 0	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Receiver Key is\n");
		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", k[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}
#endif

	for (i=0;i<16;i++)	
	{
		k1[i]=k[i];
 		k2[i]=k[16+i];
	}

	/* SHKO : IEEE 1363A 규격의 11.3.3의 8) 참조 */
	for (i=0;i<16;i++) 
	{
		m1[i]=c[i] ^ k1[i];
	}

	if (ecies_print_flag)
	{
		printf("Plain Data is\n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", m1[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}

	for ( i = 0; i < 16; i++)
	{
		C[i] = c[i];
	}


	for ( j = 0; j < p2.len; j++)
	{
		C[i+j] = p2.val[j];
	}

	/* SHKO : IEEE 1363A 규격의 Figure 11에서 MAC에 해당 --> k2와 C를 입력으로 해서 16바이트 크기를 갖는 tag를 만든다. */
	res=FPGA_MAC1_Interrupt(C,(16+p2.len),k2,16,16,tag1);

	if (ecies_print_flag)
	{
		printf("HMAC TAG is\n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", tag1[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}

	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("Decrption Operation Time : %f\n",operating_time);

	if ((memcmp(m,m1,16) == 0) && (memcmp(tag,tag1,16) == 0))
		printf("ECIES Encryption/Decryption - OK\n");
    	else
	{
		printf("ECIES Encryption/Decryption Failed\n");
	} 


	//printf("ECDSA_RANDOM_SEL_H_REG = [%08x]", reg_readl(wave_dsrc_base+ECDSA_RANDOM_SEL_H_REG_OFFSET));
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */
	
}


int Make_VCT(U1 *pub_key, U1 *cipher, U1 *atag)
{
	U1		message[256];
	volatile unsigned int status;
	int precompute;
	int 		i, j, r;
	int		msg_len;
	int		time_out;
	unsigned int initial_value;
	int mlen;
	BOOL compress, dhaes,result;
	octet h,s,p,f,g,d,u,v,w;
	octet s0,s1,w0,w1,u0,u1,v0,v1,z,vz;
	octet z1,z2,f1,f2,f3;
	octet p1,p2,L2;
	int res,bytes,bits;
	U1 send_z[32];
   	U1 rcv_z[32];
	U1 sha_out[32];
	U1 k[32];
	U1 k1[16];
	U1 k2[16];
	U1 m[16];
	U1 c[16];
	U1 C[256];
	U1 tag[16];
	U1 m1[16];
	U1 tag1[16];
	U1 sender_y_key_lsb = 0;
	U4 reg_data[8];
	U4 v_data[8];
	struct timeval start_point, end_point;
	volatile double operating_time;
	U1 s_private_key[32];
	U1 r_private_key[32];
	U1 s_public_key[32];
	U1 r_public_key[32];
	U4 random_key[8];

	gettimeofday(&start_point, NULL);

	if (ecies_print_flag)
	{
		printf("=================================\n");
		printf("[fpga_ecies_test] Transmit Part!!\n");
		printf("=================================\n");
	}


	compress=TRUE;
	precompute=0;
	dhaes=FALSE;
	bytes = 32;

	OCTET_INIT(&p1,30);
	OCTET_INIT(&p2,30);
 	OCTET_JOIN_STRING("Key Derivation Parameters",&p1);
 	OCTET_JOIN_STRING("Encoding Parameters",&p2);

 	OCTET_INIT(&m,20); OCTET_INIT(&c,32); /* round up to block size */
    	OCTET_INIT(&s,bytes);
    	OCTET_INIT(&u,bytes); OCTET_INIT(&v,2*bytes+1);
    	OCTET_INIT(&w,2*bytes+1);
    	OCTET_INIT(&m1,20);
    	OCTET_INIT(&k1,16); OCTET_INIT(&k2,16);
    	OCTET_INIT(&tag,16); OCTET_INIT(&tag1,16);
    	OCTET_INIT(&z,bytes);  OCTET_INIT(&vz,3*bytes+2);
    	OCTET_INIT(&L2,8); OCTET_INIT(&C,300);

	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base+ ECDSA_ECC_ENABLE_H_REG_OFFSET), 0x0);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ECC_ENABLE_H_REG_OFFSET, 0x0);
#endif

	/* Prime Number Setting */
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
	
	/* Order Setting */
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
	
	/* Gx Setting */
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
	
#if 1	/* 테스트용 고정 모드 */
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x00000001);
	/* 2를 Write하면 Test 모드 : 즉, 송수신측 private key를 고정 시킴.  */
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00020000);
  #else

	/* 1를 Write하면 Random 모드 */
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA256_RANDOM_ENABLE);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA256_RANDOM_ENABLE);
#endif
#endif
	

	/* Start ECIES */
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), SIGNATURE_GEN_RANDOM_SEL_BIT);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, SIGNATURE_GEN_RANDOM_SEL_BIT);
#endif


#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), TRANSFER_PRIVATE_RANDOM_SEL_BIT);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, TRANSFER_PRIVATE_RANDOM_SEL_BIT);
#endif

	for ( i = 0; i < 8; i++)
	{
		random_key[i] = reg_readl(((wave_dsrc_base+ECIES_TRANS_RANDOM_NUMBER0_REG_OFFSET)+(i*4)));
	}

	j = 0;
	u.len = 32;
	/* 개인키는 아래와 같이 뒤집어야 한다. */
	for ( i = 0; i < 8; i++)
	{
		u.val[j++] = (random_key[7-i] >> 24) & 0xFF;
		u.val[j++] = (random_key[7-i] >> 16) & 0xFF;
		u.val[j++] = (random_key[7-i] >> 8) & 0xFF;
		u.val[j++] = random_key[7-i] & 0xFF;
	}

#if 1	//SHKO
	if (ecies_print_flag)
	{
		printf("\nDisplay Sender Private Random Num\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", random_key[i]);
		}
		
		printf("\n");

		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", (U1)u.val[i]);
			if ( (( i + 1) %10 ) == 10 )
				printf("\n");
		}
	}
#endif

	/* 수신측 공개키 */
	w.len = 33;

    	for ( j = 0; j < w.len; j++ )
    	{
    		w.val[j] = g_ecies_recv_public_key[0][j];
    	}



#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00000000); /* RANDOM Number 동작을 멈춘다.*/
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, 0x00000000); /* RANDOM Number 동작을 멈춘다.*/
#endif


	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, TRANSFER_PUBLIC_ENABLE_BIT);
	time_out = 20000;
	
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & TRANS_PUBLIC_GEN_DONE_BIT)
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, TRANS_PUBLIC_GEN_DONE_BIT);/* Clear */
	if (time_out < 0)
	{
		printf("[fpga_ecies_test] Sender Public Key Generation Time Out!!\n");
		return(-1);
	}
		
	if (ecies_print_flag)
	{
		//printf("TRANS_PUBLIC_GEN status = 0x%08x, time_out = %d\n", status, time_out);
		printf("\nDisplay Sender Public Key X\n");
	}
	
	for ( i = 0; i < 8; i++)
	{
		if (ecies_print_flag)
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_PUBLIC_KEY_PX0_REG_OFFSET)+(i*4))));

		v_data[i] = reg_readl(((wave_dsrc_base+ECIES_TRANS_PUBLIC_KEY_PX0_REG_OFFSET)+(i*4)));
		/* 송신측 공개키 X좌표값  */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel(((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET)+(i*4)), v_data[i]);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(((ECIES_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET)+(i*4)), v_data[i]);
	#endif
	}
	if (ecies_print_flag)
		printf("\n");

	if (ecies_print_flag)
	{
		printf("Display Sender Public Key Y\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_PUBLIC_KEY_PY0_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}

	sender_y_key_lsb = (reg_readl((wave_dsrc_base+ECIES_TRANS_PUBLIC_KEY_PY7_REG_OFFSET))) & 0xFF;

	if (sender_y_key_lsb & 0x01)
	{
		if (ecies_print_flag)
			printf("Setting Odd bit\n");

		pub_key[0] = 0x03;	
	}
	else
	{
		if (ecies_print_flag)
			printf("Setting Even bit\n");

		pub_key[0] = 0x02;	
	
	}

	j = 1;
	for ( i = 0 ; i < 8 ; i++ )
	{
		pub_key[j++] = (v_data[i] >> 24) & 0xFF;
		pub_key[j++] = (v_data[i] >> 16) & 0xFF;
		pub_key[j++] = (v_data[i] >> 8) & 0xFF;
		pub_key[j++] = v_data[i] & 0xFF;
	}

	if (ecies_print_flag)
		printf("Display Sender Public Key - Byte\n");
	
	if (ecies_print_flag)
	{
		for ( i = 0; i < 33; i++)
		{
			printf("[%02x]", pub_key[i]);
			if ( (( i + 1) %10 ) == 10 )
				printf("\n");
		}
		printf("\n");
	}


#if 0	//SHKO, Origin
    	res=ECPSVDP_DH(NULL,&g_epdom,&u,&w,&z);
#else
	/* 아래 함수를 통해 z가 세팅된다. */
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 SVD Primitive에 해당 --> 송신측 개인키와 수신측 공개키를 입력으로 해서 z를 만든다. */
	res=ECPSVDP_DHC(NULL,&g_epdom,&u,&w,TRUE,&z);
#endif

	/* SHKO : IEEE 1363A 규격의 Figure 11에서 FE2OSP에 해당 --> z를 입력으로 해서 vz를 만든다. */
   	 if (dhaes)
    	{
        	OCTET_COPY(&v,&vz);
        	OCTET_JOIN_OCTET(&z,&vz);
   	}
    	else OCTET_COPY(&z,&vz);	/* SHKO, z를 vz로 copy한다. */

	if (ecies_print_flag)
	{
		printf("z Key is \n");
    		OCTET_OUTPUT(&vz);
		printf("\n");
	}
	
	
#if 0	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Sender Private Key * Receiver Public Key Y\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_PRIMITIVE_KEY_RY0_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}
#endif

#if 0	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Sender Z\n");
		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", send_z[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");

		//printf("p1 is \n");
	    	//OCTET_OUTPUT(&p1);
		//printf("\n");
	}
#endif

	/* 아래 #if 0을 열면 FPGA_KDF2 함수를 호출한후 다음과 같은 k값이 나와야 한다. */
	/* ffbbe0a54935bf931025612e5b8f81a52fb0f3669918f5ff10a4c8d98e00c1ae */
  #if 0
	i = 0;
	send_z[i++] = 0xeb;
	send_z[i++] = 0x74;
	send_z[i++] = 0x60;
	send_z[i++] = 0x89;
	send_z[i++] = 0xdb;
	send_z[i++] = 0x69;
	send_z[i++] = 0x55;
	send_z[i++] = 0x9a;
	send_z[i++] = 0x96;
	send_z[i++] = 0xbb;
	send_z[i++] = 0xe4;
	send_z[i++] = 0x71;
	send_z[i++] = 0xd3;
	send_z[i++] = 0xd6;
	send_z[i++] = 0x58;
	send_z[i++] = 0x9a;
	send_z[i++] = 0x0f;
	send_z[i++] = 0x32;
	send_z[i++] = 0x05;
	send_z[i++] = 0x18;
	send_z[i++] = 0x7f;
	send_z[i++] = 0x41;
	send_z[i++] = 0x5d;
	send_z[i++] = 0x6c;
	send_z[i++] = 0x19;
	send_z[i++] = 0xa2;
	send_z[i++] = 0x17;
	send_z[i++] = 0x58;
	send_z[i++] = 0x4e;
	send_z[i++] = 0xd3;
	send_z[i++] = 0x00;
	send_z[i++] = 0x9d;
  #endif
	
	/* SHKO : vz + counter 1(4바이트) + p1 을 합친 메세지를 SHA256로 Digest를 만들어서 k에 update한다. */
	res=FPGA_KDF2((U1 *)vz.val, &p1, 32, k);

#if 0	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Sender Key is\n");
		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", k[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}
#endif

	for (i=0;i<16;i++)	
	{
		k1[i]=k[i];
 		k2[i]=k[16+i];
	}

 
	for (i=0;i<16;i++)
 		m[i]=i+1;    /* fake a message */

 	if (ecies_print_flag)
	{
		printf("Plain Data M is\n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", m[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}
 
	/* SHKO : IEEE 1363A 규격의 11.3.2의 9) 참조 */
	for (i=0;i<16;i++) 
	{
		c[i]=m[i] ^ k1[i];
	}
	
	for ( i = 0; i < 16; i++)
	{
		C[i] = c[i];
	}


	for ( j = 0; j < p2.len; j++)
	{
		C[i+j] = p2.val[j];
	}

	
	/* 아래 #if 0을 열면 FPGA_MAC1 함수를 호출한후 다음과 같은 tag값이 나와야 한다. */
	/* 0d9810b379ae290c5ec3b6af9e6aa893 */
  #if 0
	i = 0;
	C[i++] = 0xd4;
	C[i++] = 0xf1;
	C[i++] = 0xb6;
	C[i++] = 0x20;
	C[i++] = 0x2b;
	C[i++] = 0x15;
	C[i++] = 0xe2;
	C[i++] = 0x32;
	C[i++] = 0x73;
	C[i++] = 0xe0;
	
	C[i++] = 0x47;
	C[i++] = 0x69;
	C[i++] = 0x72;
	C[i++] = 0x2f;
	C[i++] = 0x74;
	C[i++] = 0xae;
	C[i++] = 0x45;
	C[i++] = 0x6e;
	C[i++] = 0x63;
	C[i++] = 0x6f;
	
	C[i++] = 0x64;
	C[i++] = 0x69;
	C[i++] = 0x6e;
	C[i++] = 0x67;
	C[i++] = 0x20;
	C[i++] = 0x50;
	C[i++] = 0x61;
	C[i++] = 0x72;
	C[i++] = 0x61;
	C[i++] = 0x6d;
	
	C[i++] = 0x65;
	C[i++] = 0x74;
	C[i++] = 0x65;
	C[i++] = 0x72;
	C[i++] = 0x73;

	i = 0;
	k2[i++] = 0x52;
	k2[i++] = 0x92;
	k2[i++] = 0x12;
	k2[i++] = 0xe0;
	k2[i++] = 0xec;
	k2[i++] = 0x09;
	k2[i++] = 0xb4;
	k2[i++] = 0x61;
	k2[i++] = 0xb2;
	k2[i++] = 0x4e;

	k2[i++] = 0xdb;
	k2[i++] = 0x56;
	k2[i++] = 0x8a;
	k2[i++] = 0xde;
	k2[i++] = 0xe9;
	k2[i++] = 0x3a;
  #endif

	/* SHKO : IEEE 1363A 규격의 Figure 11에서 MAC에 해당 --> k2와 C를 입력으로 해서 16바이트 크기를 갖는 tag를 만든다. */
	res=FPGA_MAC1(C,(16+p2.len),k2,16,16,tag);

	if (ecies_print_flag)
	{
		printf("\n=================================\n");
		printf("Encryption Output\n");
		printf("\nDisplay V\n");
		if (sender_y_key_lsb & 0x01)
		{
			printf("[03]");
		}
		else
		{
			printf("[02]");
		}
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", v_data[i]);
		}
		printf("\n");

		printf("\nDisplay Ciphertext is\n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", c[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");

		printf("\nHMAC TAG is\n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", tag[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
		printf("=================================\n");
	}

	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("Encryption Operation Time : %f\n",operating_time);

	gettimeofday(&start_point, NULL);



	if (ecies_print_flag)
	{
		printf("\n\n=================================\n");
		printf("[fpga_ecies_test] Receive Part!!\n");
		printf("=================================\n");
	}

	if (ecies_print_flag)
	{
		printf("Decryption Start!!\n\n");
	}

	for ( i = 0; i < 8; i++)
	{
		/* 송신측 공개키 X좌표값  */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel(((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET)+(i*4)), v_data[i]);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(((ECIES_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET)+(i*4)), v_data[i]);
	#endif
	}

	if (pub_key[0] & 0x01)
	{
		if (ecies_print_flag)
			printf("Setting Odd bit\n");

	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x00000001);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET, 0x00000001);
	#endif
	}
	else
	{
		if (ecies_print_flag)
			printf("Setting Even bit\n");
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x00000000);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET, 0x00000000);
	#endif
	}

	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, ECIES_KEY_RECOVERY_ENABLE_BIT);
	time_out = 20000;
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & ECIES_RECOVERY_DONE_BIT)
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, ECIES_RECOVERY_DONE_BIT);/* Clear */
	if (time_out < 0)
		printf("[fpga_ecies_test] Key Recovery Done Time Out!!\n");
	
	if (ecies_print_flag)
		printf("TRANS_PUBLIC_KEY_Y_RECOVERY status = 0x%08x, time_out = %d\n", status, time_out);

	if (ecies_print_flag)
	{
		printf("Display Recovery Sender Public Key Y\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_RECEIVE_RECOVERY_Y0_H_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}

	/* 송신측 공개키 */
	v.len = 33;
	for ( j = 0; j < 33; j++)
		v.val[j] = pub_key[j];

	/* 수신측 개인키 */
	s.len = 32;

	r = 28;

	/* 개인키는 아래와 같이 뒤집어야 한다. */
	for ( j = 0; j < 32; j++ )
	{
		r = 28 - ((j/4) * 4);
		
		s.val[j] = g_ecies_recv_private_key[0][(j%4)+r];
	}

	if (ecies_print_flag)
	{
		printf("Receiver Private Key\n");
    		OCTET_OUTPUT(&s);
		printf("\n");
	}

	if (ecies_print_flag)
	{
		printf("Sender Public Key\n");
    		OCTET_OUTPUT(&s);
		printf("\n");
	}

#if 0	//SHKO, Origin
    	res=ECPSVDP_DH(NULL,&g_epdom,&s,&v,&z);
#else
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 오른편에 있는 SVD Primitive에 해당 --> 수신측 개인키와 송신측 공개키를 입력으로 해서 z를 만든다. */
	res=ECPSVDP_DHC(NULL,&g_epdom,&s,&v,TRUE,&z);
#endif

	/* SHKO : IEEE 1363A 규격의 Figure 11에서 오른편에 있는 FE2OSP에 해당 --> z를 입력으로 해서 vz를 만든다. */
	if (dhaes)
	{
		OCTET_COPY(&v,&vz);
		OCTET_JOIN_OCTET(&z,&vz);
	}
	else OCTET_COPY(&z,&vz);

	if (ecies_print_flag)
	{
		printf("z Key is \n");
    		OCTET_OUTPUT(&vz);
		printf("\n");
	}


	/* SHKO : IEEE 1363A 규격의 Figure 11에서 오른편에 있는 KDF에 해당 --> vz와 p1를 입력으로 해서 32바이트 크기를 갖는 k를 만든다. */
#if 0	//SHKO, Origin
	res=KDF2(&vz,&p1,32,SHA1,&k);
#else
	//res=KDF2(&vz,&p1,32,SHA256,&k);
	res=FPGA_KDF2((U1*)vz.val, &p1, 32, k);
#endif

 	for (i=0;i<16;i++)	
	{
		k1[i]=k[i];
 		k2[i]=k[16+i];
	}

	
#if 0	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Receiver Private Key * Sender Public Key Y\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PRIMITIVE_KEY_RY0_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}
#endif

#if 0	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Receiver Z\n");
		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", rcv_z[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}
#endif

	

#if 0	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Receiver Key is\n");
		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", k[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}
#endif

	

	/* SHKO : IEEE 1363A 규격의 11.3.3의 8) 참조 */
	for (i=0;i<16;i++) 
	{
		m1[i]=c[i] ^ k1[i];
	}

	if (ecies_print_flag)
	{
		printf("Plain Data is\n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", m1[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}

	for ( i = 0; i < 16; i++)
	{
		C[i] = c[i];
	}


	for ( j = 0; j < p2.len; j++)
	{
		C[i+j] = p2.val[j];
	}

	/* SHKO : IEEE 1363A 규격의 Figure 11에서 MAC에 해당 --> k2와 C를 입력으로 해서 16바이트 크기를 갖는 tag를 만든다. */
	res=FPGA_MAC1(C,(16+p2.len),k2,16,16,tag1);

	if (ecies_print_flag)
	{
		printf("HMAC TAG is\n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", tag1[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}

	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("Decrption Operation Time : %f\n",operating_time);

	if ((memcmp(m,m1,16) == 0) && (memcmp(tag,tag1,16) == 0))
		printf("ECIES Encryption/Decryption - OK\n");
    	else
	{
		printf("ECIES Encryption/Decryption Failed\n");
	} 


	//printf("ECDSA_RANDOM_SEL_H_REG = [%08x]", reg_readl(wave_dsrc_base+ECDSA_RANDOM_SEL_H_REG_OFFSET));
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */		
}


void rx_fpga_ecies_test(void)
{
	U1		message[256];
	volatile unsigned int status;
	int 		i, j;
	int		msg_len;
	int		time_out;
	unsigned int initial_value;
	int mlen;
	BOOL compress, dhaes,result;
	octet h,s,p,f,g,d,u,v,w;
	octet s0,s1,w0,w1,u0,u1,v0,v1,z,vz;
	octet z1,z2,f1,f2,f3;
	octet p1,p2,L2;
	int res,bytes,bits;
	U1 send_z[32];
   	U1 rcv_z[32];
	U1 sha_out[32];
	U1 k[32];
	U1 k1[16];
	U1 k2[16];
	U1 m[16];
	U1 c[16];
	U1 C[256];
	U1 tag[16];
	U1 m1[16];
	U1 tag1[16];
	U1 sender_y_key_lsb = 0;
	U4 reg_data[8];
	U4 v_data[8];
	struct timeval start_point, end_point;
	volatile double operating_time;

	gettimeofday(&start_point, NULL);


	compress=TRUE;

	OCTET_INIT(&p1,30);
	OCTET_INIT(&p2,30);
 	OCTET_JOIN_STRING("Key Derivation Parameters",&p1);
 	OCTET_JOIN_STRING("Encoding Parameters",&p2);

	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base+ ECDSA_ECC_ENABLE_H_REG_OFFSET), 0x0);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ECC_ENABLE_H_REG_OFFSET, 0x0);
#endif

	/* Prime Number Setting */
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
	
	/* Order Setting */
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
	
	/* Gx Setting */
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
	
	


  #if 0	/* 테스트용 고정 모드 */
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x00000001);
	/* 2를 Write하면 Test 모드 : 즉, 송수신측 private key를 고정 시킴.  */
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00020000);
  #else
	/* 1를 Write하면 Random 모드 */
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA256_RANDOM_ENABLE);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA256_RANDOM_ENABLE);
#endif
  #endif
	
	
	
	/* Start ECIES */
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), SIGNATURE_GEN_RANDOM_SEL_BIT);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, SIGNATURE_GEN_RANDOM_SEL_BIT);
#endif


#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), TRANSFER_PRIVATE_RANDOM_SEL_BIT);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, TRANSFER_PRIVATE_RANDOM_SEL_BIT);
#endif

#if 1	//SHKO
	if (ecies_print_flag)
	{
		printf("\nDisplay Sender Random Number\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_RANDOM_NUMBER0_REG_OFFSET)+(i*4))));
		}
		
		printf("\n");
	}
#endif

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), RECEIVER_PRIVATE_RANDOM_SEL_BIT);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, RECEIVER_PRIVATE_RANDOM_SEL_BIT);
#endif

#if 1	//SHKO
	if (ecies_print_flag)
	{
		printf("\nDisplay Receiver Random Number\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_RECEIVE_RANDOM_NUMBER0_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}
#endif

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00000000); /* RANDOM Number 동작을 멈춘다.*/
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, 0x00000000); /* RANDOM Number 동작을 멈춘다.*/
#endif

	v_data[0] = 0x2b15edd7;
	v_data[1] = 0xf787e479;
	v_data[2] = 0x1be3ac12;
	v_data[3] = 0x13dad36b;
	v_data[4] = 0x41912514;
	v_data[5] = 0xcedb7d87;
	v_data[6] = 0x4ea5ca7d;
	v_data[7] = 0xc7bd7270;
	
	for ( i = 0; i < 8; i++)
	{
		/* 송신측 공개키 X좌표값  */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel(((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET)+(i*4)), v_data[i]);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(((ECIES_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET)+(i*4)), v_data[i]);
	#endif
	}
	

	sender_y_key_lsb = 1;

	if (sender_y_key_lsb & 0x01)
	{
		if (ecies_print_flag)
			printf("Setting Odd bit\n");

	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x00000001);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET, 0x00000001);
	#endif
	}
	else
	{
		if (ecies_print_flag)
			printf("Setting Even bit\n");
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x00000000);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET, 0x00000000);
	#endif
	}

	if (ecies_print_flag)
	{
		printf("\n\n=================================\n");
		printf("[fpga_ecies_test] Receive Part!!\n");
		printf("=================================\n");
	}

	if (ecies_print_flag)
	{
		printf("Decryption Start!!\n\n");
	}

	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, ECIES_KEY_RECOVERY_ENABLE_BIT);
	time_out = 20000;
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & ECIES_RECOVERY_DONE_BIT)
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, ECIES_RECOVERY_DONE_BIT);/* Clear */
	if (time_out < 0)
		printf("[fpga_ecies_test] Key Recovery Done Time Out!!\n");
	
	if (ecies_print_flag)
		printf("TRANS_PUBLIC_KEY_Y_RECOVERY status = 0x%08x, time_out = %d\n", status, time_out);

	if (ecies_print_flag)
	{
		printf("Display Recovery Sender Public Key Y\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_RECEIVE_RECOVERY_Y0_H_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}

	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, RECEIVER_PRIMITIVE_ENABLE_BIT);
	time_out = 20000;
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & REC_PRIMITIVE_DONE_BIT)
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, REC_PRIMITIVE_DONE_BIT);/* Clear */
	if (time_out < 0)
		printf("[fpga_ecies_test] Receiver Primitive Done Time Out!!\n");
	
	if (ecies_print_flag)
	{
		printf("REC_PRIMITIVE_DONE status = 0x%08x, time_out = %d\n", status, time_out);
		//printf("Display Receiver Private Key * Sender Public Key X\n");
	}
    	j = 0;
	for ( i = 0; i < 8; i++)
	{
		//if (ecies_print_flag)
			//printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))));
		rcv_z[j++] = (reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) >> 8) & 0xFF;
		rcv_z[j++] = reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) & 0xFF;
		rcv_z[j++] = (reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) >> 24) & 0xFF;
		rcv_z[j++] = (reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) >> 16) & 0xFF;
	}
	if (ecies_print_flag)
		printf("\n");

#if 0	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Receiver Private Key * Sender Public Key Y\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_RECEIVER_PRIMITIVE_KEY_RY0_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}
#endif

#if 0	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Receiver Z\n");
		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", rcv_z[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}
#endif

	/* SHKO : vz + counter 1(4바이트) + p1 을 합친 메세지를 SHA256로 Digest를 만들어서 k에 update한다. */
	res=FPGA_KDF2(rcv_z, &p1, 32, k);

#if 0	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Receiver Key is\n");
		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", k[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}
#endif

	for (i=0;i<16;i++)	
	{
		k1[i]=k[i];
 		k2[i]=k[16+i];
	}

	c[0] = 0x3f;
	c[1] = 0x72;
	c[2] = 0x54;
	c[3] = 0x19;
	c[4] = 0x16;
	c[5] = 0x35;
	c[6] = 0xda;
	c[7] = 0x99;
	c[8] = 0xd3;
	c[9] = 0x05;
	c[10] = 0x6c;
	c[11] = 0x07;
	c[12] = 0xe8;
	c[13] = 0x86;
	c[14] = 0xf1;
	c[15] = 0x7c;
	

	/* SHKO : IEEE 1363A 규격의 11.3.3의 8) 참조 */
	for (i=0;i<16;i++) 
	{
		m1[i]=c[i] ^ k1[i];
	}

	if (ecies_print_flag)
	{
		printf("Plain Data is\n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", m1[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}

	for ( i = 0; i < 16; i++)
	{
		C[i] = c[i];
	}


	for ( j = 0; j < p2.len; j++)
	{
		C[i+j] = p2.val[j];
	}

	/* SHKO : IEEE 1363A 규격의 Figure 11에서 MAC에 해당 --> k2와 C를 입력으로 해서 16바이트 크기를 갖는 tag를 만든다. */
	res=FPGA_MAC1(C,(16+p2.len),k2,16,16,tag1);

	if (ecies_print_flag)
	{
		printf("HMAC TAG is\n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", tag1[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}

	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("Decrption Operation Time : %f\n",operating_time);

	if ((memcmp(m,m1,16) == 0) && (memcmp(tag,tag1,16) == 0))
		printf("ECIES Encryption/Decryption - OK\n");
    	else
	{
		printf("ECIES Encryption/Decryption Failed\n");
	} 


	//printf("ECDSA_RANDOM_SEL_H_REG = [%08x]", reg_readl(wave_dsrc_base+ECDSA_RANDOM_SEL_H_REG_OFFSET));
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */
	
}


void ecies_test(void)
{
	int i,mlen,precompute;
    BOOL compress,dhaes,result;
    octet h,s,p,f,g,c,d,u,v,w,m,m1,tag,tag1;
    octet s0,s1,w0,w1,u0,u1,v0,v1,k1,k2,z,vz;
    octet z1,z2,f1,f2,f3,k;
    octet p1,p2,L2,C;
    octet raw;
    time_t ran;
    dl_domain dom;
    //ecp_domain epdom;
    ec2_domain e2dom;
    if_public_key pub;
    if_private_key priv;
    csprng RNG;                  /* Crypto Strong RNG */
    int j;
 
    int res,bytes,bits;

    struct timeval start_point, end_point;
	volatile double operating_time;

	gettimeofday(&start_point, NULL);

    compress=TRUE;
    precompute=0;

    time((time_t *)&ran);
    //printf("ran=0x%08x\n", ran);
                               /* fake random seed source */
    OCTET_INIT(&raw,100);
    raw.len=100;
    raw.val[0]=ran;
    raw.val[1]=ran>>8;
    raw.val[2]=ran>>16;
    raw.val[3]=ran>>24;
    for (i=4;i<100;i++) raw.val[i]=i+1;

    CREATE_CSPRNG(&RNG,&raw);   /* initialise strong RNG */

    OCTET_KILL(&raw);


    //printf("\nP1363 ECIES Encryption/Decryption - DHAES mode\n");

#if 0	//SHKO, Origin
    dhaes=TRUE;   /* Use DHAES mode */
#else
	dhaes=FALSE;   /* Use DHAES mode */
#endif


    //bytes=ECP_DOMAIN_INIT(&g_epdom,"/usr/sbin/common.ecs",NULL,precompute);
    bytes = 32;
    //printf("bytes=%d\n", bytes);

    
    OCTET_INIT(&m,20); OCTET_INIT(&c,32); /* round up to block size */
    OCTET_INIT(&k,32); OCTET_INIT(&s,bytes);
    OCTET_INIT(&u,bytes); OCTET_INIT(&v,2*bytes+1);
    OCTET_INIT(&w,2*bytes+1);
    OCTET_INIT(&m1,20);
    OCTET_INIT(&k1,16); OCTET_INIT(&k2,16);

#if 0	/* SHKO, Origin */
    OCTET_INIT(&tag,12); OCTET_INIT(&tag1,12);
#else
	OCTET_INIT(&tag,16); OCTET_INIT(&tag1,16);
#endif
    OCTET_INIT(&z,bytes);  OCTET_INIT(&vz,3*bytes+2);
    OCTET_INIT(&p1,30); OCTET_INIT(&p2,30);
    OCTET_INIT(&L2,8); OCTET_INIT(&C,300);

    
    OCTET_JOIN_STRING("Key Derivation Parameters",&p1);
    OCTET_JOIN_STRING("Encoding Parameters",&p2);

    
	/* 아래 함수를 통해 u와 v가 세팅된다. */
	/* u : secret key, v : public key */
    res = ECP_KEY_PAIR_GENERATE(NULL,&g_epdom,&RNG,&u,compress,&v);  /* one time key pair */
    printf("u private Key is [%d]\n", res);
    OCTET_OUTPUT(&u);
	printf("\n");

	printf("v public Key is [%d]\n", v.len);
    OCTET_OUTPUT(&v);
	printf("\n");

	/* 아래 함수를 통해 s와 w가 세팅된다. */
	/* s : secret key, w : public key */
    res = ECP_KEY_PAIR_GENERATE(NULL,&g_epdom,&RNG,&s,compress,&w);  /* recipients key pair */
    printf("s private Key is [%d] \n", res);
    OCTET_OUTPUT(&s);
	printf("\n");

	printf("w public Key is \n");
    OCTET_OUTPUT(&w);
	printf("\n");


#if 0	//SHKO, Origin
    res=ECPSVDP_DH(NULL,&g_epdom,&u,&w,&z);
#else
	/* 아래 함수를 통해 z가 세팅된다. */
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 SVD Primitive에 해당 --> 송신측 개인키와 수신측 공개키를 입력으로 해서 z를 만든다. */
	res=ECPSVDP_DHC(NULL,&g_epdom,&u,&w,TRUE,&z);
#endif

	
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 FE2OSP에 해당 --> z를 입력으로 해서 vz를 만든다. */
    if (dhaes)
    {
        OCTET_COPY(&v,&vz);
        OCTET_JOIN_OCTET(&z,&vz);
    }
    else OCTET_COPY(&z,&vz);	/* SHKO, z를 vz로 copy한다. */

	if (ecies_print_flag)
	{
		printf("z Key is \n");
    		OCTET_OUTPUT(&vz);
		printf("\n");
	}

	/* SHKO : 아래 함수를 통해 k가 세팅된다. */
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 KDF에 해당 --> vz와 p1를 입력으로 해서 32바이트 크기를 갖는 k를 만든다. */
#if 0	//SHKO, Origin
    res=KDF2(&vz,&p1,32,SHA1,&k);
#else
	/* SHKO : vz + counter 1(4바이트) + p1 을 합친 메세지를 SHA256로 Digest를 만들어서 k에 update한다. */
	//res=KDF2(&vz,&p1,32,SHA256,&k);
	k.len = 32;
	res=FPGA_KDF2((U1*)vz.val, &p1, 32, (U1 *)k.val);
#endif

	if (ecies_print_flag)
	{
    		printf("Key is \n");
    		OCTET_OUTPUT(&k);
    	}

    k1.len=k2.len=16;
    for (i=0;i<16;i++) {k1.val[i]=k.val[i]; k2.val[i]=k.val[16+i];} 

	if (ecies_print_flag)
    		printf("Encryption\n");

#if 0	//SHKO, Origin
    m.len=20;
    for (i=0;i<20;i++) m.val[i]=i+1;    /* fake a message */
#else
	m.len=16;
	for (i=0;i<16;i++) m.val[i]=i+1;    /* fake a message */
#endif

	if (ecies_print_flag)
	{
		printf("Message is \n");
		OCTET_OUTPUT(&m);
    	}

	/* SHKO : k1과 m을 입력으로 해서 c를 만든다. */
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 Symm.Encrypt에 해당 --> k1와 m를 입력으로 해서 c를 만든다. */
#if 0	//SHKO, Origin
    res=AES_CBC_IV0_ENCRYPT(&k1,&m,NULL,&c,NULL);
#else
	/* SHKO : IEEE 1363A 규격의 11.3.2의 9) 참조 */
	for (i=0;i<16;i++) 
	{
		c.val[i]=m.val[i] ^ k1.val[i];
	}
	c.len = 16;
#endif

	if (ecies_print_flag)
	{
		printf("Ciphertext is \n");
		OCTET_OUTPUT(&c);
	}

    if (dhaes) OCTET_JOIN_LONG((long)p2.len,8,&L2);

    OCTET_COPY(&c,&C);
    OCTET_JOIN_OCTET(&p2,&C);
    OCTET_JOIN_OCTET(&L2,&C);

	if (ecies_print_flag)
	{
		printf("Before\n");
		OCTET_OUTPUT(&tag);
	}
	/* SHKO : C와 k2을 입력으로 해서 tag를 만든다. */
#if 0	/* SHKO, Origin */
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 MAC에 해당 --> k2와 C를 입력으로 해서 12바이트 크기를 갖는 tag를 만든다. */
    res=MAC1(&C,NULL,&k2,12,SHA256,&tag);
#else
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 MAC에 해당 --> k2와 C를 입력으로 해서 16바이트 크기를 갖는 tag를 만든다. */
	res=MAC1(&C,NULL,&k2,16,SHA256,&tag);
#endif
	if (ecies_print_flag)
	{
		printf("After\n");
		OCTET_OUTPUT(&tag);

    		printf("\nHMAC tag is \n");
    		OCTET_OUTPUT(&tag);
    	}

/* Note that "two passes" are required, one to encrypt, one
   to calculate the MAC. By integrating MAC1 with AES_CBC_IV0_ENCRYPT, only
   one pass would be needed */

/* Overall ciphertext is (u,c,tag) */

    OCTET_CLEAR(&z); OCTET_CLEAR(&k); 
    OCTET_CLEAR(&k1); OCTET_CLEAR(&k2); 
    OCTET_CLEAR(&vz); OCTET_CLEAR(&C);
    OCTET_CLEAR(&L2);

    	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("ECIES Encryption Operation Time : %f\n",operating_time);

	gettimeofday(&start_point, NULL);

	if (ecies_print_flag)
		printf("Decryption\n");

#if 0	//SHKO, Origin
    res=ECPSVDP_DH(NULL,&g_epdom,&s,&v,&z);
#else
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 오른편에 있는 SVD Primitive에 해당 --> 수신측 개인키와 송신측 공개키를 입력으로 해서 z를 만든다. */
	res=ECPSVDP_DHC(NULL,&g_epdom,&s,&v,TRUE,&z);
#endif

	/* SHKO : IEEE 1363A 규격의 Figure 11에서 오른편에 있는 FE2OSP에 해당 --> z를 입력으로 해서 vz를 만든다. */
    if (dhaes)
    {
        OCTET_COPY(&v,&vz);
        OCTET_JOIN_OCTET(&z,&vz);
    }
    else OCTET_COPY(&z,&vz);

	if (ecies_print_flag)
	{
		printf("z Key is \n");
    		OCTET_OUTPUT(&vz);
		printf("\n");
	}

	/* SHKO : IEEE 1363A 규격의 Figure 11에서 오른편에 있는 KDF에 해당 --> vz와 p1를 입력으로 해서 32바이트 크기를 갖는 k를 만든다. */
#if 0	//SHKO, Origin
	res=KDF2(&vz,&p1,32,SHA1,&k);
#else
	//res=KDF2(&vz,&p1,32,SHA256,&k);
	k.len = 32;
	res=FPGA_KDF2((U1*)vz.val, &p1, 32, (U1 *)k.val);
#endif

 	k1.len=k2.len=16;
	for (i=0;i<16;i++) {k1.val[i]=k.val[i]; k2.val[i]=k.val[16+i];} 

	if (ecies_print_flag)
	{
		printf("Key is \n");
		OCTET_OUTPUT(&k);
		printf("\n");
	}

	/* SHKO : IEEE 1363A 규격의 Figure 11에서 Symm.Decrypt에 해당 --> k1와 c를 입력으로 해서 m1를 만든다. */
#if 0	//SHKO, Origin
    res=AES_CBC_IV0_DECRYPT(&k1,&c,NULL,&m1,NULL);
#else
	/* SHKO : IEEE 1363A 규격의 11.3.3의 8) 참조 */
	for (i=0;i<16;i++) 
	{
		m1.val[i]=c.val[i] ^ k1.val[i];
	}
	m1.len = 16;
#endif

	if (ecies_print_flag)
	{
		printf("Message is \n");
		OCTET_OUTPUT(&m1);
	}

    if (dhaes) OCTET_JOIN_LONG((long)p2.len,8,&L2);

    OCTET_COPY(&c,&C);
    OCTET_JOIN_OCTET(&p2,&C);
    OCTET_JOIN_OCTET(&L2,&C);
	
#if 0	/* SHKO, Origin */
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 오른편에 있는 MAC에 해당 --> k2와 C를 입력으로 해서 12바이트 크기를 갖는 tag1를 만든다. */
    res=MAC1(&C,NULL,&k2,12,SHA256,&tag1);
#else
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 오른편에 있는 MAC에 해당 --> k2와 C를 입력으로 해서 16바이트 크기를 갖는 tag1를 만든다. */
    res=MAC1(&C,NULL,&k2,16,SHA256,&tag1);
#endif

	if (ecies_print_flag)
	{
		printf("\nHMAC tag is \n");
		OCTET_OUTPUT(&tag1);
	}

    if (OCTET_COMPARE(&m,&m1) && OCTET_COMPARE(&tag,&tag1))
    {
    	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("ECIES Decryption Operation Time : %f\n",operating_time);
        printf("ECIES Encryption/Decryption - OK\n");
	}
    else
    {
        printf("ECIES Encryption/Decryption Failed\n");
    } 

    OCTET_KILL(&tag); OCTET_KILL(&tag1);
    OCTET_KILL(&k1); OCTET_KILL(&k2);
    OCTET_KILL(&m);  OCTET_KILL(&c);
    OCTET_KILL(&k); OCTET_KILL(&s);
    OCTET_KILL(&u); OCTET_KILL(&v); 
    OCTET_KILL(&m1); OCTET_KILL(&w);  
    OCTET_KILL(&p1); OCTET_KILL(&p2);
    OCTET_KILL(&L2); OCTET_KILL(&C);

    //ECP_DOMAIN_KILL(&epdom);
    OCTET_KILL(&z); OCTET_KILL(&vz);

    KILL_CSPRNG(&RNG);
    return;
}

#if 0	//SHKO, Origin
int Soft_Make_VCT(U1 *pub_key, U1 *cipher, U1 *atag)
{
	int i,mlen,precompute;
	BOOL compress,dhaes,result;
	octet h,s,p,f,g,c,d,u,v,w,m,m1,tag,tag1;
	octet s0,s1,w0,w1,u0,u1,v0,v1,k1,k2,z,vz;
	octet z1,z2,f1,f2,f3,k;
	octet p1,p2,L2,C;
	octet raw;
	time_t ran;
	dl_domain dom;
	//ecp_domain epdom;
	ec2_domain e2dom;
	if_public_key pub;
	if_private_key priv;
	csprng RNG;                  /* Crypto Strong RNG */
	int j;
	 
	int res,bytes,bits;

	struct timeval start_point, end_point;
	volatile double operating_time;

	gettimeofday(&start_point, NULL);

	if (ecies_print_flag)
	{
		printf("=================================\n");
		printf("[fpga_ecies_test] Transmit Part!!\n");
		printf("=================================\n");
	}


	compress=TRUE;
    	precompute=0;

    	time((time_t *)&ran);
    	//printf("ran=0x%08x\n", ran);
                               /* fake random seed source */
    	OCTET_INIT(&raw,100);
    	raw.len=100;
   	 raw.val[0]=ran;
    	raw.val[1]=ran>>8;
   	 raw.val[2]=ran>>16;
    	raw.val[3]=ran>>24;
    	for (i=4;i<100;i++) raw.val[i]=i+1;

    	CREATE_CSPRNG(&RNG,&raw);   /* initialise strong RNG */

    	OCTET_KILL(&raw);

    	//printf("\nP1363 ECIES Encryption/Decryption - DHAES mode\n");

#if 0	//SHKO, Origin
    	dhaes=TRUE;   /* Use DHAES mode */
#else
	dhaes=FALSE;   /* Use DHAES mode */
#endif

	bytes = 32;

	OCTET_INIT(&m,20); OCTET_INIT(&c,32); /* round up to block size */
    	OCTET_INIT(&k,32); OCTET_INIT(&s,bytes);
    	OCTET_INIT(&u,bytes); OCTET_INIT(&v,2*bytes+1);
    	OCTET_INIT(&w,2*bytes+1);
    	OCTET_INIT(&m1,20);
    	OCTET_INIT(&k1,16); OCTET_INIT(&k2,16);

#if 0	/* SHKO, Origin */
    	OCTET_INIT(&tag,12); OCTET_INIT(&tag1,12);
#else
	OCTET_INIT(&tag,16); OCTET_INIT(&tag1,16);
#endif
    	OCTET_INIT(&z,bytes);  OCTET_INIT(&vz,3*bytes+2);
    	OCTET_INIT(&p1,30); OCTET_INIT(&p2,30);
    	OCTET_INIT(&L2,8); OCTET_INIT(&C,300);

 	OCTET_JOIN_STRING("Key Derivation Parameters",&p1);
 	OCTET_JOIN_STRING("Encoding Parameters",&p2);

 	/* 아래 함수를 통해 u와 v가 세팅된다. */
	/* u : secret key, v : public key */
	res = ECP_KEY_PAIR_GENERATE(NULL,&g_epdom,&RNG,&u,compress,&v);  /* one time key pair */
	if (ecies_print_flag)
	{
		printf("Sender u private Key is [%d]\n", res);
		OCTET_OUTPUT(&u);
		printf("\n");
	}

	if (ecies_print_flag)
	{
		printf("Sender v public Key is [%d]\n", v.len);
    		OCTET_OUTPUT(&v);
		printf("\n");
	}

	for ( j = 0; j < v.len; j++ )
		pub_key[j] = v.val[j];

	/* 아래 함수를 통해 s와 w가 세팅된다. */
	/* s : secret key, w : public key */
    //res = ECP_KEY_PAIR_GENERATE(NULL,&g_epdom,&RNG,&s,compress,&w);  /* recipients key pair */
    
    	w.len = 33;

    	for ( j = 0; j < w.len; j++ )
    	{
    		w.val[j] = g_ecies_recv_public_key[0][j];
    	}
    	
    //printf("s private Key is [%d] \n", res);
    //OCTET_OUTPUT(&s);
	//printf("\n");

	if (ecies_print_flag)
	{
		printf("w Receiver public Key is \n");
    		OCTET_OUTPUT(&w);
		printf("\n");
	}


#if 0	//SHKO, Origin
    res=ECPSVDP_DH(NULL,&g_epdom,&u,&w,&z);
#else
	/* 아래 함수를 통해 z가 세팅된다. */
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 SVD Primitive에 해당 --> 송신측 개인키와 수신측 공개키를 입력으로 해서 z를 만든다. */
	res=ECPSVDP_DHC(NULL,&g_epdom,&u,&w,TRUE,&z);
#endif

	
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 FE2OSP에 해당 --> z를 입력으로 해서 vz를 만든다. */
    if (dhaes)
    {
        OCTET_COPY(&v,&vz);
        OCTET_JOIN_OCTET(&z,&vz);
    }
    else OCTET_COPY(&z,&vz);	/* SHKO, z를 vz로 copy한다. */

	if (ecies_print_flag)
	{
		printf("z Key is \n");
    		OCTET_OUTPUT(&vz);
		printf("\n");
	}

	/* SHKO : 아래 함수를 통해 k가 세팅된다. */
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 KDF에 해당 --> vz와 p1를 입력으로 해서 32바이트 크기를 갖는 k를 만든다. */
#if 0	//SHKO, Origin
    res=KDF2(&vz,&p1,32,SHA1,&k);
#else
	/* SHKO : vz + counter 1(4바이트) + p1 을 합친 메세지를 SHA256로 Digest를 만들어서 k에 update한다. */
	//res=KDF2(&vz,&p1,32,SHA256,&k);
	k.len = 32;
	res=FPGA_KDF2((U1*)vz.val, &p1, 32, (U1 *)k.val);
#endif

#if 0
	if (ecies_print_flag)
	{
    		printf("Key is \n");
    		OCTET_OUTPUT(&k);
    	}
#endif

    	k1.len=k2.len=16;
    	for (i=0;i<16;i++) {k1.val[i]=k.val[i]; k2.val[i]=k.val[16+i];} 

	if (ecies_print_flag)
    		printf("Encryption\n");

#if 0	//SHKO, Origin
    	m.len=20;
    	for (i=0;i<20;i++) m.val[i]=i+1;    /* fake a message */
#else
	m.len=16;
	for (i=0;i<16;i++) 
		m.val[i]=g_aes_key[g_aes_key_index][i];    /* fake a message */
#endif

	if (ecies_print_flag || g_security_printf_flag)
	{
		printf("AES Plain Key is \n");
		OCTET_OUTPUT(&m);
    	}

	/* SHKO : k1과 m을 입력으로 해서 c를 만든다. */
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 Symm.Encrypt에 해당 --> k1와 m를 입력으로 해서 c를 만든다. */
#if 0	//SHKO, Origin
    res=AES_CBC_IV0_ENCRYPT(&k1,&m,NULL,&c,NULL);
#else
	/* SHKO : IEEE 1363A 규격의 11.3.2의 9) 참조 */
	for (i=0;i<16;i++) 
	{
		c.val[i]=m.val[i] ^ k1.val[i];
		cipher[i] = c.val[i];
	}
	c.len = 16;
#endif

	if (ecies_print_flag || g_security_printf_flag)
	{
		printf("\nAES Cipher Key is \n");
		OCTET_OUTPUT(&c);
	}

	if (dhaes) OCTET_JOIN_LONG((long)p2.len,8,&L2);

	OCTET_COPY(&c,&C);
	OCTET_JOIN_OCTET(&p2,&C);
	OCTET_JOIN_OCTET(&L2,&C);

	//if (ecies_print_flag)
	//{
	//	printf("Before\n");
	//	OCTET_OUTPUT(&tag);
	//}
	/* SHKO : C와 k2을 입력으로 해서 tag를 만든다. */
#if 0	/* SHKO, Origin */
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 MAC에 해당 --> k2와 C를 입력으로 해서 12바이트 크기를 갖는 tag를 만든다. */
    res=MAC1(&C,NULL,&k2,12,SHA256,&tag);
#else
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 MAC에 해당 --> k2와 C를 입력으로 해서 16바이트 크기를 갖는 tag를 만든다. */
	res=MAC1(&C,NULL,&k2,16,SHA256,&tag);
#endif
	if (ecies_print_flag)
	{
		//printf("After\n");
		//OCTET_OUTPUT(&tag);

    		printf("\nHMAC tag is \n");
    		OCTET_OUTPUT(&tag);
    	}

    	for ( j = 0; j < 16; j++ )
    		atag[j] = tag.val[j];

	/* Note that "two passes" are required, one to encrypt, one
		to calculate the MAC. By integrating MAC1 with AES_CBC_IV0_ENCRYPT, only
		one pass would be needed */

	/* Overall ciphertext is (u,c,tag) */

	OCTET_CLEAR(&z); OCTET_CLEAR(&k); 
	OCTET_CLEAR(&k1); OCTET_CLEAR(&k2); 
	OCTET_CLEAR(&vz); OCTET_CLEAR(&C);
	OCTET_CLEAR(&L2);

    	

	OCTET_KILL(&tag); OCTET_KILL(&tag1);
	OCTET_KILL(&k1); OCTET_KILL(&k2);
	OCTET_KILL(&m);  OCTET_KILL(&c);
	OCTET_KILL(&k); OCTET_KILL(&s);
	OCTET_KILL(&u); OCTET_KILL(&v); 
	OCTET_KILL(&m1); OCTET_KILL(&w);  
	OCTET_KILL(&p1); OCTET_KILL(&p2);
	OCTET_KILL(&L2); OCTET_KILL(&C);

	//ECP_DOMAIN_KILL(&epdom);
	OCTET_KILL(&z); OCTET_KILL(&vz);

	KILL_CSPRNG(&RNG);

	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("Encryption Operation Time : %f\n",operating_time);

	return;
}
#else
#if 0	//SHKO, Origin
int Soft_Make_VCT(U1 *pub_key, U1 *cipher, U1 *atag)
{
	int i,precompute;
	BOOL compress,dhaes,result;
	octet s,u,v,w;
	//octet w1,u0,u1,v0,v1,z,vz;
	octet z,vz;
	//octet z1,z2,f1,f2,f3;
	octet p1,p2,L2;
	//ecp_domain epdom;
	int j;
	U4 random_key[8];
	 
	int res,bytes;

	struct timeval start_point, end_point;
	volatile double operating_time;
	int time_out;
	U4 status;
	U4 v_data[8];
	U1 sender_y_key_lsb = 0;
	U1 k[32];
	U1 k1[16];
	U1 k2[16];
	U1 m[16];
	U1 c[16];
	U1 tag[16];
	U1 C[256];
	U4_T receiver_public_key[8];

	gettimeofday(&start_point, NULL);

	if (ecies_print_flag)
	{
		printf("=================================\n");
		printf("[fpga_ecies_test] Transmit Part!!\n");
		printf("=================================\n");
	}


	compress=TRUE;
    	precompute=0;
	bytes = 32;

    	//printf("\nP1363 ECIES Encryption/Decryption - DHAES mode\n");

#if 0	//SHKO, Origin
    	dhaes=TRUE;   /* Use DHAES mode */
#else
	dhaes=FALSE;   /* Use DHAES mode */
#endif


	/* round up to block size */
    	OCTET_INIT(&k,32); OCTET_INIT(&s,bytes);
    	OCTET_INIT(&u,bytes); OCTET_INIT(&v,2*bytes+1);
    	OCTET_INIT(&w,2*bytes+1);
    	OCTET_INIT(&k2,16);


    	OCTET_INIT(&z,bytes);  OCTET_INIT(&vz,3*bytes+2);
    	OCTET_INIT(&p1,30); OCTET_INIT(&p2,30);
    	OCTET_INIT(&L2,8);

 	OCTET_JOIN_STRING("Key Derivation Parameters",&p1);
 	OCTET_JOIN_STRING("Encoding Parameters",&p2);

 	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base+ ECDSA_ECC_ENABLE_H_REG_OFFSET), 0x0);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ECC_ENABLE_H_REG_OFFSET, 0x0);
#endif

	/* Prime Number Setting */
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

	/* Order Setting */
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

	/* Gx Setting */
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

#if 0	/* 테스트용 고정 모드 */
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x00000001);
	/* 2를 Write하면 Test 모드 : 즉, 송수신측 private key를 고정 시킴.  */
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00020000);
  #else

	/* 1를 Write하면 Random 모드 */
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA256_RANDOM_ENABLE);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA256_RANDOM_ENABLE);
#endif
#endif

	/* Start ECIES */
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), SIGNATURE_GEN_RANDOM_SEL_BIT);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, SIGNATURE_GEN_RANDOM_SEL_BIT);
#endif

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), TRANSFER_PRIVATE_RANDOM_SEL_BIT);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, TRANSFER_PRIVATE_RANDOM_SEL_BIT);
#endif

	for ( i = 0; i < 8; i++)
	{
		random_key[i] = reg_readl(((wave_dsrc_base+ECIES_TRANS_RANDOM_NUMBER0_REG_OFFSET)+(i*4)));
	}

	j = 0;
	u.len = 32;
	/* 개인키는 아래와 같이 뒤집어야 한다. */
	for ( i = 0; i < 8; i++)
	{
		u.val[j++] = (random_key[7-i] >> 24) & 0xFF;
		u.val[j++] = (random_key[7-i] >> 16) & 0xFF;
		u.val[j++] = (random_key[7-i] >> 8) & 0xFF;
		u.val[j++] = random_key[7-i] & 0xFF;
	}

#if 1	//SHKO
	if (ecies_print_flag)
	{
		printf("\nDisplay Sender Private Random Num\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", random_key[i]);
		}
		
		printf("\n");

		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", (U1)u.val[i]);
			if ( (( i + 1) %10 ) == 10 )
				printf("\n");
		}
		printf("\n");
	}
#endif

	/* 수신측 공개키 */
	w.len = 33;

    	for ( j = 0; j < w.len; j++ )
    	{
    		w.val[j] = g_ecies_recv_public_key[0][j];
    	}

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00000000); /* RANDOM Number 동작을 멈춘다.*/
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, 0x00000000); /* RANDOM Number 동작을 멈춘다.*/
#endif

	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, TRANSFER_PUBLIC_ENABLE_BIT);
	time_out = 20000;
	
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & TRANS_PUBLIC_GEN_DONE_BIT)
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, TRANS_PUBLIC_GEN_DONE_BIT);/* Clear */
	if (time_out < 0)
	{
		printf("[fpga_ecies_test] Sender Public Key Generation Time Out!!\n");
		return(-1);
	}

	if (ecies_print_flag)
	{
		//printf("TRANS_PUBLIC_GEN status = 0x%08x, time_out = %d\n", status, time_out);
		printf("\nDisplay Sender Public Key X\n");
	}

	for ( i = 0; i < 8; i++)
	{
		if (ecies_print_flag)
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_PUBLIC_KEY_PX0_REG_OFFSET)+(i*4))));

		v_data[i] = reg_readl(((wave_dsrc_base+ECIES_TRANS_PUBLIC_KEY_PX0_REG_OFFSET)+(i*4)));
		/* 송신측 공개키 X좌표값  */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel(((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET)+(i*4)), v_data[i]);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(((ECIES_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET)+(i*4)), v_data[i]);
	#endif
	}
	if (ecies_print_flag)
		printf("\n");

	if (ecies_print_flag)
	{
		printf("Display Sender Public Key Y\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_PUBLIC_KEY_PY0_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}

	sender_y_key_lsb = (reg_readl((wave_dsrc_base+ECIES_TRANS_PUBLIC_KEY_PY7_REG_OFFSET))) & 0xFF;

	if (sender_y_key_lsb & 0x01)
	{
		if (ecies_print_flag)
			printf("Setting Odd bit\n");

		pub_key[0] = 0x03;	
	}
	else
	{
		if (ecies_print_flag)
			printf("Setting Even bit\n");

		pub_key[0] = 0x02;	
	
	}

	j = 1;
	for ( i = 0 ; i < 8 ; i++ )
	{
		pub_key[j++] = (v_data[i] >> 24) & 0xFF;
		pub_key[j++] = (v_data[i] >> 16) & 0xFF;
		pub_key[j++] = (v_data[i] >> 8) & 0xFF;
		pub_key[j++] = v_data[i] & 0xFF;
	}

	if (ecies_print_flag)
		printf("Display Sender Public Key - Byte\n");

	if (ecies_print_flag)
	{
		for ( i = 0; i < 33; i++)
		{
			printf("[%02x]", pub_key[i]);
			if ( (( i + 1) %10 ) == 10 )
				printf("\n");
		}
		printf("\n");
	}


	/* 아래 함수를 통해 s와 w가 세팅된다. */
	/* s : secret key, w : public key */
    //res = ECP_KEY_PAIR_GENERATE(NULL,&g_epdom,&RNG,&s,compress,&w);  /* recipients key pair */
    
    	w.len = 33;

    	for ( j = 0; j < w.len; j++ )
    	{
    		w.val[j] = g_ecies_recv_public_key[0][j];
    	}
    	
    //printf("s private Key is [%d] \n", res);
    //OCTET_OUTPUT(&s);
	//printf("\n");

	if (ecies_print_flag)
	{
		printf("w Receiver public Key is \n");
    		OCTET_OUTPUT(&w);
		printf("\n");
	}


#if 0	//SHKO, Origin
    	res=ECPSVDP_DH(NULL,&g_epdom,&u,&w,&z);
#else
	/* 아래 함수를 통해 z가 세팅된다. */
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 SVD Primitive에 해당 --> 송신측 개인키와 수신측 공개키를 입력으로 해서 z를 만든다. */
	res=ECPSVDP_DHC(NULL,&g_epdom,&u,&w,TRUE,&z);
#endif

	
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 FE2OSP에 해당 --> z를 입력으로 해서 vz를 만든다. */
    if (dhaes)
    {
        OCTET_COPY(&v,&vz);
        OCTET_JOIN_OCTET(&z,&vz);
    }
    else OCTET_COPY(&z,&vz);	/* SHKO, z를 vz로 copy한다. */

	if (ecies_print_flag)
	{
		printf("z Key is \n");
    		OCTET_OUTPUT(&vz);
		printf("\n");
	}

	/* SHKO : 아래 함수를 통해 k가 세팅된다. */
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 KDF에 해당 --> vz와 p1를 입력으로 해서 32바이트 크기를 갖는 k를 만든다. */
#if 0	//SHKO, Origin
    res=KDF2(&vz,&p1,32,SHA1,&k);
#else
	/* SHKO : vz + counter 1(4바이트) + p1 을 합친 메세지를 SHA256로 Digest를 만들어서 k에 update한다. */
	//res=KDF2(&vz,&p1,32,SHA256,&k);
	res=FPGA_KDF2((U1*)vz.val, &p1, 32, k);
#endif

#if 0	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Sender Key is\n");
		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", k[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}
#endif
	for (i=0;i<16;i++)	
	{
		k1[i]=k[i];
 		k2[i]=k[16+i];
	}

	if (ecies_print_flag)
    		printf("Encryption\n");

#if 0	//SHKO, Origin
    	m.len=20;
    	for (i=0;i<20;i++) m.val[i]=i+1;    /* fake a message */
#else
	for (i=0;i<16;i++) 
		m[i]=g_aes_key[g_aes_key_index][i];    /* fake a message */
#endif

	if (ecies_print_flag || g_security_printf_flag)
	{
		printf("AES Plain Key is \n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", m[i]);
			if ( ((i+1)%10) == 0)
				printf("\n");
		}
		printf("\n");
		
    	}

	/* SHKO : k1과 m을 입력으로 해서 c를 만든다. */
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 Symm.Encrypt에 해당 --> k1와 m를 입력으로 해서 c를 만든다. */
#if 0	//SHKO, Origin
    res=AES_CBC_IV0_ENCRYPT(&k1,&m,NULL,&c,NULL);
#else
	/* SHKO : IEEE 1363A 규격의 11.3.2의 9) 참조 */
	for (i=0;i<16;i++) 
	{
		c[i]=m[i] ^ k1[i];
		cipher[i] = c[i];
	}
#endif

	if (ecies_print_flag || g_security_printf_flag)
	{
		printf("\nAES Cipher Key is \n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", c[i]);
			if ( ((i+1)%10) == 0)
				printf("\n");
		}
		printf("\n");
	}

	for ( i = 0; i < 16; i++)
	{
		C[i] = c[i];
	}


	for ( j = 0; j < p2.len; j++)
	{
		C[i+j] = p2.val[j];
	}

	//if (dhaes) OCTET_JOIN_LONG((long)p2.len,8,&L2);

	//OCTET_COPY(&c,&C);
	//OCTET_JOIN_OCTET(&p2,&C);
	//OCTET_JOIN_OCTET(&L2,&C);

	//if (ecies_print_flag)
	//{
	//	printf("Before\n");
	//	OCTET_OUTPUT(&tag);
	//}
	/* SHKO : C와 k2을 입력으로 해서 tag를 만든다. */
#if 0	/* SHKO, Origin */
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 MAC에 해당 --> k2와 C를 입력으로 해서 12바이트 크기를 갖는 tag를 만든다. */
    res=MAC1(&C,NULL,&k2,12,SHA256,&tag);
#else
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 MAC에 해당 --> k2와 C를 입력으로 해서 16바이트 크기를 갖는 tag를 만든다. */
	res=FPGA_MAC1(C,(16+p2.len),k2,16,16,tag);
#endif
	if (ecies_print_flag)
	{
		printf("\n=================================\n");
		printf("Encryption Output\n");
		printf("\nDisplay V\n");
		if (sender_y_key_lsb & 0x01)
		{
			printf("[03]");
		}
		else
		{
			printf("[02]");
		}
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", v_data[i]);
		}
		printf("\n");

		printf("\nDisplay Ciphertext is\n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", c[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");

		printf("\nHMAC TAG is\n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", tag[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
		printf("=================================\n");
	}
	

    	for ( j = 0; j < 16; j++ )
    		atag[j] = tag[j];

	/* Note that "two passes" are required, one to encrypt, one
		to calculate the MAC. By integrating MAC1 with AES_CBC_IV0_ENCRYPT, only
		one pass would be needed */

	/* Overall ciphertext is (u,c,tag) */

	OCTET_CLEAR(&z);
	OCTET_CLEAR(&vz);
	OCTET_CLEAR(&L2);

  
	OCTET_KILL(&s);
	OCTET_KILL(&u); OCTET_KILL(&v); 
	OCTET_KILL(&w);  
	OCTET_KILL(&p1); OCTET_KILL(&p2);
	OCTET_KILL(&L2);

	//ECP_DOMAIN_KILL(&epdom);
	OCTET_KILL(&z); OCTET_KILL(&vz);

	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("Encryption Operation Time : %f\n",operating_time);

	return;
}
#else
int Soft_Make_VCT(U1 *pub_key, U1 *cipher, U1 *atag)
{
	int i,precompute;
	BOOL compress,dhaes,result;
	octet s,u,v,w;
	//octet w1,u0,u1,v0,v1,z,vz;
	octet z,vz;
	//octet z1,z2,f1,f2,f3;
	octet p1,p2,L2;
	//ecp_domain epdom;
	int j;
	U4 random_key[8];
	 
	int res,bytes;

	struct timeval start_point, end_point;
	volatile double operating_time;
	int time_out;
	U4 status;
	U4 v_data[8];
	U1 sender_y_key_lsb = 0;
	U1 k[32];
	U1 k1[16];
	U1 k2[16];
	U1 m[16];
	U1 c[16];
	U1 tag[16];
	U1 C[256];
	U4_T receiver_public_key[8];
	U4	receiver_public_key_y[8];
	U1 send_z[32];
	volatile U4 primitive_z;
	

	gettimeofday(&start_point, NULL);

	if (ecies_print_flag)
	{
		printf("=================================\n");
		printf("[fpga_ecies_test] Transmit Part!!\n");
		printf("=================================\n");
	}


	compress=TRUE;
    	precompute=0;
	bytes = 32;

    	//printf("\nP1363 ECIES Encryption/Decryption - DHAES mode\n");

#if 0	//SHKO, Origin
    	dhaes=TRUE;   /* Use DHAES mode */
#else
	dhaes=FALSE;   /* Use DHAES mode */
#endif


	/* round up to block size */
    	OCTET_INIT(&k,32); OCTET_INIT(&s,bytes);
    	OCTET_INIT(&u,bytes); OCTET_INIT(&v,2*bytes+1);
    	OCTET_INIT(&w,2*bytes+1);
    	OCTET_INIT(&k2,16);


    	OCTET_INIT(&z,bytes);  OCTET_INIT(&vz,3*bytes+2);
    	OCTET_INIT(&p1,30); OCTET_INIT(&p2,30);
    	OCTET_INIT(&L2,8);

 	OCTET_JOIN_STRING("Key Derivation Parameters",&p1);
 	OCTET_JOIN_STRING("Encoding Parameters",&p2);

 	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */

	

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base+ ECDSA_ECC_ENABLE_H_REG_OFFSET), 0x0);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ECC_ENABLE_H_REG_OFFSET, 0x0);
#endif

	/* Prime Number Setting */
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

	/* Order Setting */
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

	/* Gx Setting */
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

#if 0	/* 테스트용 고정 모드 */
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x00000001);
	/* 2를 Write하면 Test 모드 : 즉, 송수신측 private key를 고정 시킴.  */
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00020000);
  #else

	/* 1를 Write하면 Random 모드 */
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA256_RANDOM_ENABLE);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA256_RANDOM_ENABLE);
#endif
#endif

	/* Start ECIES */
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), SIGNATURE_GEN_RANDOM_SEL_BIT);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, SIGNATURE_GEN_RANDOM_SEL_BIT);
#endif

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), TRANSFER_PRIVATE_RANDOM_SEL_BIT);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, TRANSFER_PRIVATE_RANDOM_SEL_BIT);
#endif




	for ( i = 0; i < 8; i++)
	{
		random_key[i] = reg_readl(((wave_dsrc_base+ECIES_TRANS_RANDOM_NUMBER0_REG_OFFSET)+(i*4)));
	}

	j = 0;
	u.len = 32;
	/* 개인키는 아래와 같이 뒤집어야 한다. */
	for ( i = 0; i < 8; i++)
	{
		u.val[j++] = (random_key[7-i] >> 24) & 0xFF;
		u.val[j++] = (random_key[7-i] >> 16) & 0xFF;
		u.val[j++] = (random_key[7-i] >> 8) & 0xFF;
		u.val[j++] = random_key[7-i] & 0xFF;
	}

#if 1	//SHKO
	if (ecies_print_flag)
	{
		printf("\nDisplay Sender Private Random Num\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", random_key[i]);
		}
		
		printf("\n");

		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", (U1)u.val[i]);
			if ( (( i + 1) %10 ) == 10 )
				printf("\n");
		}
		printf("\n");
	}
#endif

	

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00000000); /* RANDOM Number 동작을 멈춘다.*/
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, 0x00000000); /* RANDOM Number 동작을 멈춘다.*/
#endif

	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, TRANSFER_PUBLIC_ENABLE_BIT);
	time_out = 20000;
	
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & TRANS_PUBLIC_GEN_DONE_BIT)
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, TRANS_PUBLIC_GEN_DONE_BIT);/* Clear */
	if (time_out < 0)
	{
		printf("[fpga_ecies_test] Sender Public Key Generation Time Out!!\n");
		//printf("ECDSA_RANDOM_SEL_H_REG = [%08x]", reg_readl(wave_dsrc_base+ECDSA_RANDOM_SEL_H_REG_OFFSET));
		write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
		write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
		write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */
		return(-1);
	}

	if (ecies_print_flag)
	{
		//printf("TRANS_PUBLIC_GEN status = 0x%08x, time_out = %d\n", status, time_out);
		printf("\nDisplay Sender Public Key X\n");
	}

	for ( i = 0; i < 8; i++)
	{
		v_data[i] = reg_readl(((wave_dsrc_base+ECIES_TRANS_PUBLIC_KEY_PX0_REG_OFFSET)+(i*4)));
		if (ecies_print_flag)
			printf("[%08x]", v_data[i]);

		

#if 0	/* 이 부분은 수신측에서 해야할 일임. */
		/* 송신측 공개키 X좌표값  */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel(((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET)+(i*4)), v_data[i]);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(((ECIES_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET)+(i*4)), v_data[i]);
	#endif
#endif
	}
	if (ecies_print_flag)
		printf("\n");

	if (ecies_print_flag)
	{
		printf("Display Sender Public Key Y\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_PUBLIC_KEY_PY0_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}

	sender_y_key_lsb = (reg_readl((wave_dsrc_base+ECIES_TRANS_PUBLIC_KEY_PY7_REG_OFFSET))) & 0xFF;

	if (sender_y_key_lsb & 0x01)
	{
		if (ecies_print_flag)
			printf("Setting Odd bit\n");

		pub_key[0] = 0x03;	
	}
	else
	{
		if (ecies_print_flag)
			printf("Setting Even bit\n");

		pub_key[0] = 0x02;	
	
	}

	j = 1;
	for ( i = 0 ; i < 8 ; i++ )
	{
		pub_key[j++] = (v_data[i] >> 24) & 0xFF;
		pub_key[j++] = (v_data[i] >> 16) & 0xFF;
		pub_key[j++] = (v_data[i] >> 8) & 0xFF;
		pub_key[j++] = v_data[i] & 0xFF;
	}

#if 0
	if (ecies_print_flag)
		printf("Display Sender Public Key - Byte\n");


	if (ecies_print_flag)
	{
		for ( i = 0; i < 33; i++)
		{
			printf("[%02x]", pub_key[i]);
			if ( (( i + 1) %10 ) == 0 )
				printf("\n");
		}
		printf("\n");
	}
#endif

	
	/* 수신측 공개키 */    
    	w.len = 33;

    	for ( j = 0; j < w.len; j++ )
    	{
    		w.val[j] = g_ecies_recv_public_key[0][j];
    	}

	j = 1;
	for (i = 0; i < 8; i++)
	{
    		receiver_public_key[i].b1[3] = g_ecies_recv_public_key[0][j++];
    		receiver_public_key[i].b1[2] = g_ecies_recv_public_key[0][j++];
    		receiver_public_key[i].b1[1] = g_ecies_recv_public_key[0][j++];
    		receiver_public_key[i].b1[0] = g_ecies_recv_public_key[0][j++];
    	}

#if 0
	if (ecies_print_flag)
		printf("Display Receiver Public Key X\n");
#endif
		
    	for ( i = 0; i < 8; i++)
	{
	#if 0
		if (ecies_print_flag)
			printf("[%08x]", receiver_public_key[i].b4);
	#endif

		/* 송신측 공개키 X좌표값  */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel(((wave_dsrc_base + ECIES_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET)+(i*4)), receiver_public_key[i].b4);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(((ECIES_TRANS_PUBLIC_PX_TO_REC_R0_REG_OFFSET)+(i*4)), receiver_public_key[i].b4);
	#endif
	}
#if 0
	if (ecies_print_flag)
		printf("\n");
#endif

	if (g_ecies_recv_public_key[0][0] & 0x01)
	{
		if (ecies_print_flag)
			printf("Setting Odd bit\n");

	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x00000001);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET, 0x00000001);
	#endif
	}
	else
	{
		if (ecies_print_flag)
			printf("Setting Even bit\n");
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x00000000);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET, 0x00000000);
	#endif
	}


	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, ECIES_KEY_RECOVERY_ENABLE_BIT);
	time_out = 20000;
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & ECIES_RECOVERY_DONE_BIT)
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, ECIES_RECOVERY_DONE_BIT);/* Clear */
	if (time_out < 0)
		printf("[fpga_ecies_test] Key Recovery Done Time Out!!\n");

#if 0
	if (ecies_print_flag)
		printf("TRANS_PUBLIC_KEY_Y_RECOVERY status = 0x%08x, time_out = %d\n", status, time_out);
#endif

	for ( i = 0; i < 8; i++)
	{
		receiver_public_key_y[i] = reg_readl(((wave_dsrc_base+ECIES_TRANS_RECEIVE_RECOVERY_Y0_H_REG_OFFSET)+(i*4)));
	}

	if (ecies_print_flag)
	{
		printf("Display Recovery Receiver Public Key Y\n");

		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", receiver_public_key_y[i]);
		}
		
		printf("\n");
	}
    	
    //printf("s private Key is [%d] \n", res);
    //OCTET_OUTPUT(&s);
	//printf("\n");

	if (ecies_print_flag)
	{
		printf("w Receiver public Key is \n");
    		OCTET_OUTPUT(&w);
		printf("\n");
	}

	j = 0;
	for ( i = 0; i < 8; i++)
	{
		/* 수신측 공개키 X좌표값  */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel(((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R0_REG_OFFSET)+(i*4)), receiver_public_key[i].b4);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(((ECIES_RECEIVER_PUBLIC_PX_TO_TRANS_R0_REG_OFFSET)+(i*4)), receiver_public_key[i].b4);
	#endif
	}
	

	for ( i = 0; i < 8; i++)
	{
		/* 수신측 공개키 Y좌표값  */
	#if WAVE_SECURITY_16BIT_ENABLE == 0
		reg_writel(((wave_dsrc_base + ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S0_REG_OFFSET)+(i*4)), receiver_public_key_y[i]);
	#else
		write_wave_ecc_reg32_by_16bit_or_32bit(((ECIES_RECEIVER_PUBLIC_PY_TO_TRANS_S0_REG_OFFSET)+(i*4)), receiver_public_key_y[i]);
	#endif
	}
	

	write_wave_ecc_reg32(ECDSA_ECC_ENABLE_H_REG_OFFSET, TRANSFER_PRIMITIVE_ENABLE_BIT);
	time_out = 20000;
	while(time_out--)
	{
		status = read_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET);
		if (status & TRANS_PRIMITIVE_DONE_BIT)
			break;
	}
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, TRANS_PRIMITIVE_DONE_BIT);/* Clear */
	if (time_out < 0)
		printf("[fpga_ecies_test] Sender Primitive Done Time Out!!\n");
	
	if (ecies_print_flag)
	{
		printf("TRANS_PRIMITIVE_GEN status = 0x%08x, time_out = %d\n", status, time_out);
		//printf("Display Sender Private Key * Receiver Public Key X\n");
	}

	j = 0;
	for ( i = 0; i < 8; i++)
	{
		//if (ecies_print_flag)
		//	printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))));
	#if 0	/* SHKO, Origin */
		send_z[j++] = (reg_readl(((wave_dsrc_base+ECIES_TRANS_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) >> 8) & 0xFF;
		send_z[j++] = reg_readl(((wave_dsrc_base+ECIES_TRANS_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) & 0xFF;
		send_z[j++] = (reg_readl(((wave_dsrc_base+ECIES_TRANS_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) >> 24) & 0xFF;
		send_z[j++] = (reg_readl(((wave_dsrc_base+ECIES_TRANS_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4))) >> 16) & 0xFF;
	#else
		primitive_z = reg_readl(((wave_dsrc_base+ECIES_TRANS_PRIMITIVE_KEY_RX0_REG_OFFSET)+(i*4)));
		send_z[j++] = (primitive_z >> 24) & 0xFF;
		send_z[j++] = (primitive_z >> 16) & 0xFF;
		send_z[j++] = (primitive_z >> 8) & 0xFF;
		send_z[j++] = primitive_z & 0xFF;

		
	#endif
	}
	if (ecies_print_flag)
		printf("\n");

	#if 1	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Sender Private Key * Receiver Public Key Y\n");
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", reg_readl(((wave_dsrc_base+ECIES_TRANS_PRIMITIVE_KEY_RY0_REG_OFFSET)+(i*4))));
		}
		printf("\n");
	}
	#endif

#if 1	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Sender Z\n");
		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", send_z[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");

		//printf("p1 is \n");
	    	//OCTET_OUTPUT(&p1);
		//printf("\n");
	}
#endif

	/* SHKO : vz + counter 1(4바이트) + p1 을 합친 메세지를 SHA256로 Digest를 만들어서 k에 update한다. */
	res=FPGA_KDF2(send_z, &p1, 32, k);

#if 0	//SHKO
	if (ecies_print_flag)
	{
		printf("Display Sender Key is\n");
		for ( i = 0; i < 32; i++)
		{
			printf("[%02x]", k[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}
#endif

	for (i=0;i<16;i++)	
	{
		k1[i]=k[i];
 		k2[i]=k[16+i];
	}

 

	if (ecies_print_flag)
    		printf("Encryption\n");

#if 0	//SHKO, Origin
    	m.len=20;
    	for (i=0;i<20;i++) m.val[i]=i+1;    /* fake a message */
#else
	for (i=0;i<16;i++) 
		m[i]=g_aes_key[g_aes_key_index][i];    /* fake a message */
#endif

	if (ecies_print_flag || g_security_printf_flag)
	{
		printf("AES Plain Key is \n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", m[i]);
			if ( ((i+1)%10) == 0)
				printf("\n");
		}
		printf("\n");
		
    	}

	/* SHKO : k1과 m을 입력으로 해서 c를 만든다. */
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 Symm.Encrypt에 해당 --> k1와 m를 입력으로 해서 c를 만든다. */
#if 0	//SHKO, Origin
    res=AES_CBC_IV0_ENCRYPT(&k1,&m,NULL,&c,NULL);
#else
	/* SHKO : IEEE 1363A 규격의 11.3.2의 9) 참조 */
	for (i=0;i<16;i++) 
	{
		c[i]=m[i] ^ k1[i];
		cipher[i] = c[i];
	}
#endif

	if (ecies_print_flag || g_security_printf_flag)
	{
		printf("\nAES Cipher Key is \n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", c[i]);
			if ( ((i+1)%10) == 0)
				printf("\n");
		}
		printf("\n");
	}

	for ( i = 0; i < 16; i++)
	{
		C[i] = c[i];
	}


	for ( j = 0; j < p2.len; j++)
	{
		C[i+j] = p2.val[j];
	}

	//if (dhaes) OCTET_JOIN_LONG((long)p2.len,8,&L2);

	//OCTET_COPY(&c,&C);
	//OCTET_JOIN_OCTET(&p2,&C);
	//OCTET_JOIN_OCTET(&L2,&C);

	//if (ecies_print_flag)
	//{
	//	printf("Before\n");
	//	OCTET_OUTPUT(&tag);
	//}
	/* SHKO : C와 k2을 입력으로 해서 tag를 만든다. */
#if 0	/* SHKO, Origin */
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 MAC에 해당 --> k2와 C를 입력으로 해서 12바이트 크기를 갖는 tag를 만든다. */
    res=MAC1(&C,NULL,&k2,12,SHA256,&tag);
#else
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 MAC에 해당 --> k2와 C를 입력으로 해서 16바이트 크기를 갖는 tag를 만든다. */
	res=FPGA_MAC1(C,(16+p2.len),k2,16,16,tag);
#endif
	if (ecies_print_flag)
	{
		printf("\n=================================\n");
		printf("Encryption Output\n");
		printf("\nDisplay V\n");
		if (sender_y_key_lsb & 0x01)
		{
			printf("[03]");
		}
		else
		{
			printf("[02]");
		}
		for ( i = 0; i < 8; i++)
		{
			printf("[%08x]", v_data[i]);
		}
		printf("\n");

		printf("\nDisplay Ciphertext is\n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", c[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");

		printf("\nHMAC TAG is\n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", tag[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
		printf("=================================\n");
	}
	

    	for ( j = 0; j < 16; j++ )
    		atag[j] = tag[j];

	/* Note that "two passes" are required, one to encrypt, one
		to calculate the MAC. By integrating MAC1 with AES_CBC_IV0_ENCRYPT, only
		one pass would be needed */

	/* Overall ciphertext is (u,c,tag) */

	OCTET_CLEAR(&z);
	OCTET_CLEAR(&vz);
	OCTET_CLEAR(&L2);

  
	OCTET_KILL(&s);
	OCTET_KILL(&u); OCTET_KILL(&v); 
	OCTET_KILL(&w);  
	OCTET_KILL(&p1); OCTET_KILL(&p2);
	OCTET_KILL(&L2);

	//ECP_DOMAIN_KILL(&epdom);
	OCTET_KILL(&z); OCTET_KILL(&vz);

	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("ECIES Encryption Operation Time : %f\n",operating_time);

	//printf("ECDSA_RANDOM_SEL_H_REG = [%08x]", reg_readl(wave_dsrc_base+ECDSA_RANDOM_SEL_H_REG_OFFSET));
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */

	return;
}

#endif

#endif


#if 0	/* SHKO, Origin */
int Soft_Decrypt_Ecies(U1 *pub_key, U1 *cipher, U1 *atag, U1 *plain_key)
{
	int i,mlen,precompute;
	BOOL compress,dhaes,result;
	octet h,s,p,f,g,c,d,u,v,w,m,m1,tag,tag1;
	octet s0,s1,w0,w1,u0,u1,v0,v1,k1,k2,z,vz;
	octet z1,z2,f1,f2,f3,k;
	octet p1,p2,L2,C;
	octet raw;
	time_t ran;
	//ecp_domain epdom;
	ec2_domain e2dom;
	int j;
 
	int res,bytes,bits;

	struct timeval start_point, end_point;
	volatile double operating_time;

	//gettimeofday(&start_point, NULL);

	compress=TRUE;
	precompute=0;

    //printf("\nP1363 ECIES Encryption/Decryption - DHAES mode\n");

#if 0	//SHKO, Origin
    dhaes=TRUE;   /* Use DHAES mode */
#else
	dhaes=FALSE;   /* Use DHAES mode */
#endif


	//bytes=ECP_DOMAIN_INIT(&g_epdom,"/usr/sbin/common.ecs",NULL,precompute);
	bytes = 32;
	//printf("bytes=%d\n", bytes);

    
	OCTET_INIT(&m,20); OCTET_INIT(&c,32); /* round up to block size */
	OCTET_INIT(&k,32); OCTET_INIT(&s,bytes);
    OCTET_INIT(&u,bytes); OCTET_INIT(&v,2*bytes+1);
    OCTET_INIT(&w,2*bytes+1);
    OCTET_INIT(&m1,20);
    OCTET_INIT(&k1,16); OCTET_INIT(&k2,16);

#if 0	/* SHKO, Origin */
    OCTET_INIT(&tag,12); OCTET_INIT(&tag1,12);
#else
	OCTET_INIT(&tag,16); OCTET_INIT(&tag1,16);
#endif
	OCTET_INIT(&z,bytes);  OCTET_INIT(&vz,3*bytes+2);
	OCTET_INIT(&p1,30); OCTET_INIT(&p2,30);
	OCTET_INIT(&L2,8); OCTET_INIT(&C,300);

    
	OCTET_JOIN_STRING("Key Derivation Parameters",&p1);
	OCTET_JOIN_STRING("Encoding Parameters",&p2);

	v.len = 33;
	for ( j = 0; j < 33; j++ )
	{
		v.val[j] = pub_key[j];
	}

	s.len = 32;

	for ( j = 0; j < 32; j++ )
	{
		s.val[j] = g_ecies_recv_private_key[0][j];
	}

	if (ecies_print_flag)
	{
		printf("Display Sender Public Key\n");
		printf("v public Key is [%d]\n", v.len);
    		OCTET_OUTPUT(&v);
		printf("\n");

		printf("Display Receiver Private Key\n");
		printf("s private Key is [%d]\n", s.len);
    		OCTET_OUTPUT(&s);
		printf("\n");
	}

    	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("ECIES Encryption Operation Time : %f\n",operating_time);

	//gettimeofday(&start_point, NULL);

	if (ecies_print_flag)
		printf("Decryption\n");

#if 0	//SHKO, Origin
    	res=ECPSVDP_DH(NULL,&g_epdom,&s,&v,&z);
#else
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 오른편에 있는 SVD Primitive에 해당 --> 수신측 개인키와 송신측 공개키를 입력으로 해서 z를 만든다. */
	res=ECPSVDP_DHC(NULL,&g_epdom,&s,&v,TRUE,&z);
#endif

	/* SHKO : IEEE 1363A 규격의 Figure 11에서 오른편에 있는 FE2OSP에 해당 --> z를 입력으로 해서 vz를 만든다. */
	if (dhaes)
	{
		OCTET_COPY(&v,&vz);
		OCTET_JOIN_OCTET(&z,&vz);
	}
	else OCTET_COPY(&z,&vz);

	if (ecies_print_flag)
	{
		printf("z Key is \n");
    		OCTET_OUTPUT(&vz);
		printf("\n");
	}


	/* SHKO : IEEE 1363A 규격의 Figure 11에서 오른편에 있는 KDF에 해당 --> vz와 p1를 입력으로 해서 32바이트 크기를 갖는 k를 만든다. */
#if 0	//SHKO, Origin
	res=KDF2(&vz,&p1,32,SHA1,&k);
#else
	//res=KDF2(&vz,&p1,32,SHA256,&k);
	k.len = 32;
	res=FPGA_KDF2((U1*)vz.val, &p1, 32, (U1 *)k.val);
#endif

 	k1.len=k2.len=16;
	for (i=0;i<16;i++) {k1.val[i]=k.val[i]; k2.val[i]=k.val[16+i];} 

#if 0
	if (ecies_print_flag)
	{
		printf("Key is \n");
		OCTET_OUTPUT(&k);
		printf("\n");
	}
#endif

	/* SHKO : IEEE 1363A 규격의 Figure 11에서 Symm.Decrypt에 해당 --> k1와 c를 입력으로 해서 m1를 만든다. */
#if 0	//SHKO, Origin
    res=AES_CBC_IV0_DECRYPT(&k1,&c,NULL,&m1,NULL);
#else
	if ( ecies_print_flag )
	{
		printf("Display Cipher\n");
		for ( j = 0; j < 16; j++ )
		{

			printf("[%02x]", cipher[j]);

			if ( ((j+1)%10) == 0 )
			{
				printf("\n");
			}
		}
		printf("\n");
	}

	/* SHKO : IEEE 1363A 규격의 11.3.3의 8) 참조 */
	for (i=0;i<16;i++) 
	{
		m1.val[i]=cipher[i] ^ k1.val[i];
	}
	m1.len = 16;
#endif

	if (ecies_print_flag)
	{
		printf("\nDisplay Plain Key \n");
		OCTET_OUTPUT(&m1);
	}

	c.len = 16;
	for (i=0;i<16;i++) 
	{
		c.val[i]=cipher[i];
	}

	if (dhaes) OCTET_JOIN_LONG((long)p2.len,8,&L2);

	OCTET_COPY(&c,&C);
	OCTET_JOIN_OCTET(&p2,&C);
	OCTET_JOIN_OCTET(&L2,&C);
	
#if 0	/* SHKO, Origin */
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 오른편에 있는 MAC에 해당 --> k2와 C를 입력으로 해서 12바이트 크기를 갖는 tag1를 만든다. */
    res=MAC1(&C,NULL,&k2,12,SHA256,&tag1);
#else
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 오른편에 있는 MAC에 해당 --> k2와 C를 입력으로 해서 16바이트 크기를 갖는 tag1를 만든다. */
	res=MAC1(&C,NULL,&k2,16,SHA256,&tag1);
#endif

	if (ecies_print_flag)
	{
		printf("\nHMAC tag is \n");
		OCTET_OUTPUT(&tag1);
	}

	if ( memcmp(atag, tag1.val, 16) == 0 )
	{
		printf("ECIES Encryption/Decryption - OK\n");
		for ( j = 0; j < m1.len; j++)
		{
			plain_key[j] = m1.val[j];
		}
	}
	else
	{
		printf("ECIES Encryption/Decryption Failed\n");
	}

   

	OCTET_KILL(&tag); OCTET_KILL(&tag1);
	OCTET_KILL(&k1); OCTET_KILL(&k2);
	OCTET_KILL(&m);  OCTET_KILL(&c);
	OCTET_KILL(&k); OCTET_KILL(&s);
	OCTET_KILL(&u); OCTET_KILL(&v); 
	OCTET_KILL(&m1); OCTET_KILL(&w);  
	OCTET_KILL(&p1); OCTET_KILL(&p2);
	OCTET_KILL(&L2); OCTET_KILL(&C);

	//ECP_DOMAIN_KILL(&epdom);
	OCTET_KILL(&z); OCTET_KILL(&vz);

	return;
}
#else
int Soft_Decrypt_Ecies(U1 *pub_key, U1 *cipher, U1 *atag, U1 *plain_key)
{
	int i,precompute;
	BOOL compress,dhaes;
	octet s,u,v,w;
	octet z,vz;
	octet p1,p2,L2;
	//ecp_domain epdom;
	int j, r;
	U1 k[32];
	U1 k1[16];
	U1 k2[16];
	U1 m1[16];
	U1 C[256];
	U1 tag1[16];
 
	int res,bytes;

	struct timeval start_point, end_point;
	volatile double operating_time;

	gettimeofday(&start_point, NULL);

	compress=TRUE;
	precompute=0;

    //printf("\nP1363 ECIES Encryption/Decryption - DHAES mode\n");

#if 0	//SHKO, Origin
    dhaes=TRUE;   /* Use DHAES mode */
#else
	dhaes=FALSE;   /* Use DHAES mode */
#endif


	//bytes=ECP_DOMAIN_INIT(&g_epdom,"/usr/sbin/common.ecs",NULL,precompute);
	bytes = 32;
	//printf("bytes=%d\n", bytes);

	OCTET_INIT(&s,bytes);
    OCTET_INIT(&u,bytes); OCTET_INIT(&v,2*bytes+1);
    OCTET_INIT(&w,2*bytes+1);


	OCTET_INIT(&z,bytes);  OCTET_INIT(&vz,3*bytes+2);
	OCTET_INIT(&p1,30); OCTET_INIT(&p2,30);
	OCTET_INIT(&L2,8);

    
	OCTET_JOIN_STRING("Key Derivation Parameters",&p1);
	OCTET_JOIN_STRING("Encoding Parameters",&p2);

#if 0	//SHKO, ECIES
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base+ ECDSA_ECC_ENABLE_H_REG_OFFSET), 0x0);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_ECC_ENABLE_H_REG_OFFSET, 0x0);
#endif

	/* Prime Number Setting */
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

/* Order Setting */
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

/* Gx Setting */
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

#if 0	/* 테스트용 고정 모드 */
	reg_writel((wave_dsrc_base + ECIES_TRANS_PUBLIC_PY_0_BIT_TO_RECEIVE_REG_OFFSET), 0x00000001);
	/* 2를 Write하면 Test 모드 : 즉, 송수신측 private key를 고정 시킴.  */
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00020000);
  #else

	/* 1를 Write하면 Random 모드 */
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), ECDSA256_RANDOM_ENABLE);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, ECDSA256_RANDOM_ENABLE);
#endif
#endif

/* Start ECIES */
#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_SEL_H_REG_OFFSET), SIGNATURE_GEN_RANDOM_SEL_BIT);
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_SEL_H_REG_OFFSET, SIGNATURE_GEN_RANDOM_SEL_BIT);
#endif

#if WAVE_SECURITY_16BIT_ENABLE == 0
	reg_writel((wave_dsrc_base + ECDSA_RANDOM_ON_OFF_H_REG_OFFSET), 0x00000000); /* RANDOM Number 동작을 멈춘다.*/
#else
	write_wave_ecc_reg32_by_16bit_or_32bit(ECDSA_RANDOM_ON_OFF_H_REG_OFFSET, 0x00000000); /* RANDOM Number 동작을 멈춘다.*/
#endif
#endif //SHKO, ECIES

	v.len = 33;
	for ( j = 0; j < 33; j++ )
	{
		v.val[j] = pub_key[j];
	}

	/* 수신측 개인키 */
	s.len = 32;

	r = 28;

	/* 개인키는 아래와 같이 뒤집어야 한다. */
	for ( j = 0; j < 32; j++ )
	{
		r = 28 - ((j/4) * 4);
		
		s.val[j] = g_ecies_recv_private_key[0][(j%4)+r];
	}

	if (ecies_print_flag)
	{
		printf("Receiver Private Key\n");
    		OCTET_OUTPUT(&s);
		printf("\n");
	}

	if (ecies_print_flag)
	{
		printf("Display Sender Public Key\n");
		printf("v public Key is [%d]\n", v.len);
    		OCTET_OUTPUT(&v);
		printf("\n");
	}

    	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("ECIES Encryption Operation Time : %f\n",operating_time);

	//gettimeofday(&start_point, NULL);

	if (ecies_print_flag)
		printf("Decryption\n");

#if 0	//SHKO, Origin
    	res=ECPSVDP_DH(NULL,&g_epdom,&s,&v,&z);
#else
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 오른편에 있는 SVD Primitive에 해당 --> 수신측 개인키와 송신측 공개키를 입력으로 해서 z를 만든다. */
	res=ECPSVDP_DHC(NULL,&g_epdom,&s,&v,TRUE,&z);
#endif

	/* SHKO : IEEE 1363A 규격의 Figure 11에서 오른편에 있는 FE2OSP에 해당 --> z를 입력으로 해서 vz를 만든다. */
	if (dhaes)
	{
		OCTET_COPY(&v,&vz);
		OCTET_JOIN_OCTET(&z,&vz);
	}
	else OCTET_COPY(&z,&vz);

	if (ecies_print_flag)
	{
		printf("z Key is \n");
    		OCTET_OUTPUT(&vz);
		printf("\n");
	}


	/* SHKO : IEEE 1363A 규격의 Figure 11에서 오른편에 있는 KDF에 해당 --> vz와 p1를 입력으로 해서 32바이트 크기를 갖는 k를 만든다. */
#if 0	//SHKO, Origin
	res=KDF2(&vz,&p1,32,SHA1,&k);
#else
	//res=KDF2(&vz,&p1,32,SHA256,&k);
	res=FPGA_KDF2((U1*)vz.val, &p1, 32, k);
#endif

	for (i=0;i<16;i++)	
	{
		k1[i]=k[i];
 		k2[i]=k[16+i];
	}

 	
#if 0
	if (ecies_print_flag)
	{
		printf("Key is \n");
		OCTET_OUTPUT(&k);
		printf("\n");
	}
#endif

	/* SHKO : IEEE 1363A 규격의 Figure 11에서 Symm.Decrypt에 해당 --> k1와 c를 입력으로 해서 m1를 만든다. */
#if 0	//SHKO, Origin
    res=AES_CBC_IV0_DECRYPT(&k1,&c,NULL,&m1,NULL);
#else
	if ( ecies_print_flag || g_security_printf_flag)
	{
		printf("WAVE Data Received\n");
		printf("Display Cipher Key\n");
		for ( j = 0; j < 16; j++ )
		{

			printf("[%02x]", cipher[j]);

			if ( ((j+1)%10) == 0 )
			{
				printf("\n");
			}
		}
		printf("\n");
	}

	/* SHKO : IEEE 1363A 규격의 11.3.3의 8) 참조 */
	for (i=0;i<16;i++) 
	{
		m1[i]=cipher[i] ^ k1[i];
	}
#endif

	if (ecies_print_flag)
	{
		printf("\nDisplay Plain Key \n");
		
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", m1[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	
	}

	for (i=0;i<16;i++) 
	{
		C[i]=cipher[i];
	}

	for ( j = 0; j < p2.len; j++)
	{
		C[i+j] = p2.val[j];
	}

	//if (dhaes) OCTET_JOIN_LONG((long)p2.len,8,&L2);

	//OCTET_COPY(&c,&C);
	//OCTET_JOIN_OCTET(&p2,&C);
	//OCTET_JOIN_OCTET(&L2,&C);
	
#if 0	/* SHKO, Origin */
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 오른편에 있는 MAC에 해당 --> k2와 C를 입력으로 해서 12바이트 크기를 갖는 tag1를 만든다. */
    res=MAC1(&C,NULL,&k2,12,SHA256,&tag1);
#else
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 오른편에 있는 MAC에 해당 --> k2와 C를 입력으로 해서 16바이트 크기를 갖는 tag1를 만든다. */
	//res=MAC1(&C,NULL,&k2,16,SHA256,&tag1);
	res=FPGA_MAC1(C,(16+p2.len),k2,16,16,tag1);
#endif

	if (ecies_print_flag)
	{
		printf("HMAC TAG is\n");
		for ( i = 0; i < 16; i++)
		{
			printf("[%02x]", tag1[i]);
			if (((i+1) % 10) == 0)
				printf("\n");
		}
		printf("\n");
	}

	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	operating_time = operating_time / 100;
	printf("ECIES Decryption Operation Time : %f\n",operating_time);

	if ( memcmp(atag, tag1, 16) == 0 )
	{
		printf("ECIES Encryption/Decryption - OK\n");
		for ( j = 0; j < 16; j++)
		{
			plain_key[j] = m1[j];
		}
	}
	else
	{
		printf("ECIES Encryption/Decryption Fail\n");
	}

   

	OCTET_KILL(&s);
	OCTET_KILL(&u); OCTET_KILL(&v); 
	OCTET_KILL(&w);  
	OCTET_KILL(&p1); OCTET_KILL(&p2);
	OCTET_KILL(&L2);

	//ECP_DOMAIN_KILL(&epdom);
	OCTET_KILL(&z); OCTET_KILL(&vz);

	//printf("ECDSA_RANDOM_SEL_H_REG = [%08x]", reg_readl(wave_dsrc_base+ECDSA_RANDOM_SEL_H_REG_OFFSET));
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_VALID_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGVERIFY_DONE_STATUS_BIT);	/* Clear */
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, SIGGEN_DONE_STATUS_BIT);	/* Clear */		

	return;
}
#endif


