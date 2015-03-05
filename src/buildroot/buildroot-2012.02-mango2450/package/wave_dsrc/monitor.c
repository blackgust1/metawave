/* vi: set sw=4 ts=4: */
/*
 * Poweroff reboot and halt, oh my.
 *
 * Copyright 2006 by Rob Landley <rob@landley.net>
 *
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */
#include <pthread.h>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/sockios.h>

#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/stat.h>
#include <signal.h>
#include <sys/time.h>

#include "type_def.h"
#include "task.h"
#include "cpu_reg.h"
#include "wave_reg.h"
#include "wave_mac.h"
#include "wave_int.h"
#include "ecdsa_ecc.h"
#include "fpga_aes.h"
#include "linked_list.h"
#include "util.h"
#include "gmp.h"
#include "aes.h"
#include "mode_hdr.h"		/* Added By SHKO */
#include "ccm.h"
#include "sha2.h"
#include "p1363.h"
#include "serial.h"
#include "wsmp.h"
#include "smsc_lan9220.h"

char    hist_buf[10][256];
extern void memory_dump(const char *title, const void *address, int num_of_items, int flags);
extern int mac_rx_count;
extern char address4_omit_flag;
extern unsigned int tx_add_len;

extern U1 *system_control_base;
extern int system_control_fd;
extern U1 *gpio_base;
extern U1 *static_memory_controller_base;
extern U1 *interrupt_controller_base;
extern U1 *wave_dsrc_base;
extern U1 *ethernet_base;
extern U1 *hs_spi0_base;
extern U1 *hs_spi1_base;
extern int shell_process_pid;

extern int dev;

extern int fpga_aes_encrypt(const unsigned char *in, unsigned char *out, int flag);
extern int fpga_ccm_test(int test_mode, int flag);
extern int fpga_ecdsa_test(int flag);
extern int fpga_ecdsa_interrupt_test(int flag);
extern void fpga_ecdsa_random_test(int flag);
extern void fpga_ecies_test(void);
extern int fsha256_test1(U1 *msg, volatile unsigned int len, int flag, U1 *sha_out);
extern BOOL FPGA_KDF2(U1 *z, octet *p, int olen, U1 *k);
extern BOOL FPGA_MAC1(U1 *m, int m_len, U1 *k, int k_len, int olen, U1 *tag);
extern int MakeSignedMsg(int flag, U1 *signed_msg, U1 *unsigned_msg, int unsigned_msg_len);
extern void ecdsa_random_generator_test(void);

int aes_print_flag;
int sha_print_flag;
int ecdsa_print_flag;
int ecies_print_flag;
int g_security_printf_flag = 1;
int ecdsa_sw_test_fix_flag;	/* 이 변수를 1로 하면 ANSI X9.62 규격에 있는 테스트 벡터를 그래로 사용한다. */
int ecdsa_test_flag;

int sr5500_rx_test_flag;

U4_T	psid;
U1		psid_len = 1;

extern int eth_rx_broadcast_discard_flag;
extern int etri_flag;

extern int default_wave_tx_delay;
extern int wsa_received_flag;
extern int psid_flag;		/* 0이면 psid 길이가 0으로 고정, 1이면 규격대로 psid 길이가 가변 */

extern int wave_mac_addr_auto_flag;
extern int auto_dest_mac_flag;

extern int send_ethernet_pause_frame(void);

extern unsigned char device_mac_addr[ETH_MAC_ADDR_LEN];

extern U1 WSA_SRC_MAC_ADDR[ETH_MAC_ADDR_LEN];	/* WSA를 송신한 기지국의 WAVE MAC 주소 */
extern U1 WSA_DEST_MAC_ADDR[ETH_MAC_ADDR_LEN];	/* WSA를 송신한 기지국과 연결된 PC MAC 주소 */

extern timer_t SR5500_TEST_RX_TIMER_ID;
extern U1 sr5500_rx_test_end_flag;
extern U2 sr5500_prev_ap_len;
extern U1 sr5500_prev_modulation;
extern U2 sr5500_prev_total_cnt;
extern U1 sr5500_prev_start_flag;
extern U4 g_rts_rate;

U4 g_tx_reset_reg_test;
U1 g_display_mac_rx_seq_num_flag;
extern U1 g_aes_key[10][16];

extern int g_ecdsa_msg_falut_flag;
extern int g_aes_cmsg_falut_flag;
extern int g_aes_key_index;
extern int g_ecdsa_public_key_falut_flag;
U1 g_ecdsa_sw_proc_flag;


int parser( char *p, char *argv[], int maxargc )
{
    int argc = 0;

    while ( *p )
    {
        /*while ( *p && isspace( *p ) ) p++;*/
        while ( *p && (*p==0x20) ) p++;
        if ( ! *p ) return( argc );
        argv[argc++] = p++;

        /*while ( *p && !isspace( *p ) ) p++;*/
        while ( *p && (*p!=0x20) ) p++;
        if( *p ) *p++ = 0;

        if ( argc >= maxargc ) return( argc );
    }
    return( argc );
}

void user_gets(char *buf)
{
        char ch;
        unsigned int i;
        int default_len=256;
        char buffer[256];
  	int offset=0;

        for(i=0;i<default_len;i++)
        {
        	ch=getchar();

                if ((ch == '\b') && (offset > 0))
    		{
                	// Rub out the old character & update the console output
      			offset--;
			buffer[offset] = '\0';
      			buf[offset] = '\0';

      			printf("\r%s%s \b","WAVE]",buffer);
                }
                else if(ch==0)
                {
                        continue;
                }
    		else
    		{
                	putchar(ch);
        		if (ch == '\r')/*'\r'==0x0d*/
                        {
                                ch = '\n';    /*'\n'==0x0A*/   // treat \r as \n
                        }

      			buffer[offset++] = ch;
      			if (ch == '\n')
      			{
        			buf[(offset-1)]='\0';
        			break;
      			}
      			else
      			{
        			/*buf[i]=ch;*/
        			buf[(offset-1)]=ch;
                        }
                }
        }
}

int toint(char c)
{
    if((c>0x2F)&&(c<0x3A)) return(c-'0');/*equal to isdigit(c)*/
    if ( c >= 'a' && c <= 'f' ) return(c-'a'+10);
    if ( c >= 'A' && c <= 'F' ) return(c-'A'+10);
    else return(0);
}

int htoi(char *s)
{
    int sum = 0;

    while (*s)
    {
        sum = sum * 16 + toint(*s++);
    }
    return(sum);
}


/* if del is 1, 45usec delay */
void time_delay(int del)
{
	int i, j;
	for(i=0; i<del; i++){
		for(j=0; j<0x80; j++){
		}
	}
}


void MON_HelpCmd()
{
	char input;

	printf("help               : print this message\n");
	printf("Built on %s %s\n", str_date(built_date), str_time(built_time));
#if 1
	printf("double size = %d\n",sizeof(double));
	printf("unsigned long long size = %d\n",sizeof(unsigned long long));
    
	printf("print [flag] : set print on/off\n");
	printf("cntmac :  Diplay Tx, Rx, Err Counter\n");
	printf("clrcnt :  Clear Tx, Rx, Err Counter\n");
	printf("omita4 [flag] :  if flag is 1, omit address4 field in mac header\n");
	printf("talen [value] :  when tx, txlen register is added by value\n");
	
	printf("ethdbf [value] : set eth_rx_broadcast_discard_flag\n");
	printf("txdelay [value] : wave tx interval setting\n");
	printf("wsar [value] : print WSA Received Flag\n");
	printf("psidlen [value] : 0 : PSID Len is Fixed, 1: PSID Len is Variable\n");
	printf("rfpower [value] : 0 : Power Level is Etri Set, 1: Power Level is Ranix Set\n");
	printf("automac [value] : 0 : wave mac addr fixed, 1: wave mac addr auto set\n");
	printf("autodmac [value] : 0 : wave dest PC mac addr fixed, 1: wave dest PC mac addr auto set\n");
	printf("txpower [value] :  Set Default WAVE Modem Tx Power\n");
	printf("datarate [value] :  Set Default WAVE Modem Data Rate\n");
	printf("wmacaddr [hval] : WAVE Source Adderess Setting\n");
	printf("dmacaddr [hval] : WAVE Dest PC MAC Source Adderss Setting\n");
	printf("fchange [freq] : if freq is 50, RF is 5.85GHz, if freq is 60, RF is 5.86GHz, if freq is 70, RF is 5.87GHz\n");
	printf("-------------------------------------\n");
	printf("Continue?Y|N  ");
	input=(char)getchar();

	if((input=='N') || (input=='n'))
	{
		return;
	}
	printf("estmode [mode] : RF Channel A, if mod is 0, burst mode, if mod is 1, re-estimation mode\n");	
	printf("estmode1 [mode] : RF Channel B, if mod is 0, burst mode, if mod is 1, re-estimation mode\n");
	printf("diver [val] : if val is 0, Diversity Off, if val is 1, Diversity On\n");
	printf("chfilter [val] : RF Channel A, if val is 0, Channel Filter Disable, if val is 1, Channel Filter Enable\n");
	printf("chfilter1 [val] : RF Channel B, if val is 0, Channel Filter Disable, if val is 1, Channel Filter Enable\n");
	printf("midamble [val] : RF Channel A, if val is 0, Midamble Disable, if val is 1, Midamble Enable\n");
	printf("midamble1 [val] : RF Channel B, if val is 0, Midamble Disable, if val is 1, Midamble Enable\n");
	printf("loopback [val] : if val is 0, Normal Mode, if val is 1, Loopback Mode\n");
	printf("dmrsn [val] : Display MAC Rx Sequence Number, if val is 0, Not Display, if val is 1, Enable Display\n");
	printf("ecdsa_msg_fault [val] : if val is 1, last byte data of msg is changed to 0xff\n");
	printf("aes_cmsg_fault [val] : if val is 1, last byte data of cipher msg is changed to 0xff or 0x00\n");
	printf("ecdsa_key_fault [val] : if val is 1, last byte data of sender public key is changed to 0xff or 0x00\n");
	printf("aes_key [index] : change AES KEY Value, indes is 0 or 1\n");
	printf("-------------------------------------\n");
    printf("Continue?Y|N  ");
    input=(char)getchar();
    if(input == 0x0a)
	{
		input=(char)getchar();
	}
    if((input=='N') || (input=='n'))
    {
    	return;
    }
	
	printf("-------------------------------------\n");
#endif
}



int edian_test(int argc, char *argv[])
{
	U4 data[2] = {0x12345678, 0xabcdef12};
	U1 *buf;
	U1 onebuf[8];
	U4 a;
	U2 b=0x1234;
	U2 c=0x5678;
	int i;
	U1 one_data[4] = {0x01, 0x02, 0x03, 0x04};
	U4 *four_ptr;

	four_ptr = (U4 *)one_data;
	printf("four_ptr = 0x%08x, one_data[0]=0x%02x\n",*four_ptr, one_data[0]);
	

	/* data = strtoul(argv[1], NULL, 16); */
	buf = (U1 *)data;
	printf("buf[0] addr = 0x%08x, data = 0x%02x\n",buf, *buf);
	buf++;
	printf("buf[1] addr = 0x%08x, data = 0x%02x\n",buf, *buf);
	buf++;
	printf("buf[2] addr = 0x%08x, data = 0x%02x\n",buf, *buf);
	buf++;
	printf("buf[3] addr = 0x%08x, data = 0x%02x\n",buf, *buf);
	
	memcpy(onebuf, (U1 *)data, 8);
	for (i=0;i<8;i++)
		printf("data = 0x%02x\n",onebuf[i]);
	printf("\n");
	
	memcpy2(onebuf, data, 8);
	for (i=0;i<8;i++)
		printf("data = 0x%02x\n",onebuf[i]);
	printf("\n");
		
	memcpy4(onebuf, data, 8);
	for (i=0;i<8;i++)
		printf("data = 0x%02x\n",onebuf[i]);
	printf("\n");
	
	
	a = get_u4_from_u2 (b, c);
	printf("a=0x%08x\n",a);
	
	printf("b=0x%08x\n",get_u2_high_from_u4(a));
	printf("c=0x%08x\n",get_u2_low_from_u4(a));
	
	
	put_cap_data_u4(onebuf, data[0]);
	printf("onebuf[0] = 0x%02x\n",onebuf[0]);
	printf("onebuf[1] = 0x%02x\n",onebuf[1]);
	printf("onebuf[2] = 0x%02x\n",onebuf[2]);
	printf("onebuf[3] = 0x%02x\n",onebuf[3]);
	
	put_cap_data_u2(onebuf, data[0]);
	printf("onebuf[0] = 0x%02x\n",onebuf[0]);
	printf("onebuf[1] = 0x%02x\n",onebuf[1]);
	return 0;
	
}

int float_test(int argc, char *argv[])
{
	UFLOAT_T u_float;
	
	
	u_float.f = 40.0;
	
	printf("u_float.f = %f\n",u_float.f);
	printf("u_float.b4 = 0x%08x\n",u_float.b4);
	printf("u_float.b1 = [0x%02x] [0x%02x] [0x%02x] [0x%02x]\n",u_float.b1[0],u_float.b1[1],u_float.b1[2],u_float.b1[3]);

	return 0;
	
}



#if 1
int Socket_SendCmd(int argc, char *argv[])
{
	unsigned char send_buf[1024];
	int i,j;
	unsigned char data;
	int len, count;
	int nReturn;
	U1 *send_msg;

	if(argc == 4)
	{
		data = (unsigned char)atoi(argv[1]);
		printf("send data = %d\n",data);

		len = atoi(argv[2]);
		printf("send len = %d\n",len);

		count = atoi(argv[3]);
		printf("send count = %d\n",count);

		for (j=0 ; j < count; j++)
		{
			for(i=0; i<len; i++)
			{
				send_buf[i] = data;
			}
		 	nReturn = send(clnt_sock, (char *)send_buf, len, 0);
    		printf("nReturn=%d\n", nReturn);
		}
	}
	else
	{
		printf("[usage] ss [data] [len] [count]: Send Frame to UART1\n");
	}
	return 0;
	
}
#endif

int software_ccm_test(int test_mode)
{
	int    i, j;
    	ccm_ctx	ctx[1];
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
	gettimeofday(&start_point, NULL);

	switch(test_mode)
	{
		case 1:	/* SHKO : NIST SP 800-38C 규격 Appendix C.1 참조 */
			key_len = 16;
			iv_len = 7;
			hdr_len = 8;
			mac_len = 4;
			payload_len = 4;
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


	ccm_init_and_key(kp, key_len, ctx);
		
		

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
	aes_encrypt(&block[AES_BLOCK_SIZE*0], &y[AES_BLOCK_SIZE*0], ctx->aes);	/* Y0 = CIPHk(B0) */
		

	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("2.%f\n",operating_time);

	if (aes_print_flag)
	{
		printf("Display y\n");
		for(i = 0; i < AES_BLOCK_SIZE; i++)
		{
			printf("[%02x]", y[(AES_BLOCK_SIZE*0)+i]);
		}
		printf("\n");
	}

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

		aes_encrypt(z, &y[index0], ctx->aes);
			

		if (aes_print_flag)
		{
			printf("Display y%d\n",index0);
			for(j = 0; j < AES_BLOCK_SIZE; j++)
			{
				printf("[%02x]", y[index0+j]);
			}
			printf("\n");
		}

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
		aes_encrypt(&ctr[(AES_BLOCK_SIZE*i)], &s[(AES_BLOCK_SIZE*i)], ctx->aes);
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

	if (aes_print_flag)
	{
		printf("Display a\n");
	}
	for(i = 0; i < payload_len; i++)
	{
		a[i] = plain_text[i] ^ s[(AES_BLOCK_SIZE*1)+i];
		if (aes_print_flag)
			printf("[%02x]", a[i]);
	}
	if (aes_print_flag)
		printf("\n");
	
	if (aes_print_flag)
		printf("Display b\n");
	
	for(i = 0; i < mac_len; i++)
	{
		//b[i] = y2[i] ^ s0[i];
		b[i] = y[(AES_BLOCK_SIZE*(block_cnt-1)) + i] ^ s[(AES_BLOCK_SIZE*0)+i];
		if (aes_print_flag)
			printf("[%02x]", b[i]);
	}
	if (aes_print_flag)
		printf("\n");

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
		printf("AEC CCM Decryption Start\n");

	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("7.%f\n",operating_time);

	//gettimeofday(&start_point, NULL);
	for ( i = 0; i < count_block_cnt; i++)
	{
		aes_encrypt(&ctr[(AES_BLOCK_SIZE*i)], &s[(AES_BLOCK_SIZE*i)], ctx->aes);
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

	aes_encrypt(&block[AES_BLOCK_SIZE*0], &y[AES_BLOCK_SIZE*0], ctx->aes);
		
		
	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("9.%f\n",operating_time);

	//gettimeofday(&start_point, NULL);

	for ( i = 1; i < block_cnt; i++ )
	{
		for ( k = 0; k < AES_BLOCK_SIZE; k++)
		{
			z[k] = block[(AES_BLOCK_SIZE*i) + k] ^ y[(AES_BLOCK_SIZE*(i-1)) + k];
		}
	
		aes_encrypt(z, &y[AES_BLOCK_SIZE*i], ctx->aes);
			
			
	}

	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("10.%f\n",operating_time);

	//gettimeofday(&start_point, NULL);

	if (aes_print_flag)
	{
		printf("Display T\n");
		for(i = 0; i < mac_len; i++)
		{
			printf("[%02x]", y[(AES_BLOCK_SIZE*(block_cnt-1))+i]);
		}
		printf("\n");
	}
	
	ccm_end(ctx);
    		

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


int fpga_ccm_test1(int flag)
{
	int    i, j;
    	ccm_ctx	ctx[1];
	int k;
	unsigned char *kp;
	unsigned char *ip;
	unsigned char *hp;
	unsigned char *tp;
	int mac_len;
	unsigned char plain_text[65536];
	unsigned char ctr[AES_BLOCK_SIZE*5120];
	unsigned char z[AES_BLOCK_SIZE];
	unsigned char s[AES_BLOCK_SIZE*5120];
	int payload_len;
	/* 아래 a, b, c, p, t 배열의 크기는 최소한 payload_len 만큼의 크기는 가져야 한다. */
	unsigned char a[AES_BLOCK_SIZE*5120], b[AES_BLOCK_SIZE*5120], c[AES_BLOCK_SIZE*5120];
	unsigned char p[AES_BLOCK_SIZE*5120], t[AES_BLOCK_SIZE*5120];
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

	//reg_value = reg_readl((gpio_base + 0x14));
	//reg_value |= 0x200;
	//reg_writel((gpio_base + 0x14), reg_value);	/* GPB9 OutputData Setting, CON1의 48번 핀 */
	gettimeofday(&start_point, NULL);

	key_len = 16;
	iv_len = 12;
	hdr_len = 0;
	mac_len = 16;
	payload_len = 65536;
	cipher_text_len = payload_len + mac_len;
	c_len = payload_len + mac_len;

	kp = malloc(key_len);
	ip = malloc(iv_len);

	for (i = 0; i < key_len; i++)
		kp[i] = 0x40 + i;
	
	for (i = 0; i < iv_len; i++)
		ip[i] = 0x10 + i;

	for (i = 0; i < payload_len; i++)
		plain_text[i] = i & 0xFF;


	if (flag == 1)
		fpga_aes_key_setting(kp);
	else
		ccm_init_and_key(kp, key_len, ctx);
		

	
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
	if (flag == 1)
		fpga_aes_encrypt(&block[AES_BLOCK_SIZE*0], &y[AES_BLOCK_SIZE*0], 0);	/* Y0 = CIPHk(B0) */
	else
		aes_encrypt(&block[AES_BLOCK_SIZE*0], &y[AES_BLOCK_SIZE*0], ctx->aes);	/* Y0 = CIPHk(B0) */

	if (aes_print_flag)
	{
		printf("Display y\n");
		for(i = 0; i < AES_BLOCK_SIZE; i++)
		{
			printf("[%02x]", y[(AES_BLOCK_SIZE*0)+i]);
		}
		printf("\n");
	}

	operating_time = 0;
	
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

		if (flag == 1)
			fpga_aes_encrypt(z, &y[index0], 0);
		else
			aes_encrypt(z, &y[index0], ctx->aes);

		if (aes_print_flag)
		{
			printf("Display y%d\n",index0);
			for(j = 0; j < AES_BLOCK_SIZE; j++)
			{
				printf("[%02x]", y[index0+j]);
			}
			printf("\n");
		}

		
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

	

	count_block_total_len = formatting_counter_blocks(iv_len, ip, count_block_cnt, ctr);

	

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
		if (flag == 1)
			fpga_aes_encrypt(&ctr[(AES_BLOCK_SIZE*i)], &s[(AES_BLOCK_SIZE*i)], 0);
		else
			aes_encrypt(&ctr[(AES_BLOCK_SIZE*i)], &s[(AES_BLOCK_SIZE*i)], ctx->aes);
			
	}

	

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

	if (aes_print_flag)
	{
		printf("Display a\n");
	}
	for(i = 0; i < payload_len; i++)
	{
		a[i] = plain_text[i] ^ s[(AES_BLOCK_SIZE*1)+i];
		if (aes_print_flag)
			printf("[%02x]", a[i]);
	}
	if (aes_print_flag)
		printf("\n");
	
	if (aes_print_flag)
		printf("Display b\n");
	
	for(i = 0; i < mac_len; i++)
	{
		//b[i] = y2[i] ^ s0[i];
		b[i] = y[(AES_BLOCK_SIZE*(block_cnt-1)) + i] ^ s[(AES_BLOCK_SIZE*0)+i];
		if (aes_print_flag)
			printf("[%02x]", b[i]);
	}
	if (aes_print_flag)
		printf("\n");


	k = 0;
	for(i = 0; i < (payload_len); i++)
	{
		c[k++] = a[i];
		
	}

	for(i = 0; i < (mac_len); i++)
	{
		c[k++] = b[i];
	}

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
		printf("AEC CCM Decryption Start\n");

	
	for ( i = 0; i < count_block_cnt; i++)
	{
	
		if (flag == 1)
			fpga_aes_encrypt(&ctr[(AES_BLOCK_SIZE*i)], &s[(AES_BLOCK_SIZE*i)], 0);
		else
			aes_encrypt(&ctr[(AES_BLOCK_SIZE*i)], &s[(AES_BLOCK_SIZE*i)], ctx->aes);
			
	}

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

	if (flag == 1)
		fpga_aes_encrypt(&block[AES_BLOCK_SIZE*0], &y[AES_BLOCK_SIZE*0], 0);
	else
		aes_encrypt(&block[AES_BLOCK_SIZE*0], &y[AES_BLOCK_SIZE*0], ctx->aes);


	for ( i = 1; i < block_cnt; i++ )
	{
		for ( k = 0; k < AES_BLOCK_SIZE; k++)
		{
			z[k] = block[(AES_BLOCK_SIZE*i) + k] ^ y[(AES_BLOCK_SIZE*(i-1)) + k];
		}
	
		if (flag == 1)
			fpga_aes_encrypt(z, &y[AES_BLOCK_SIZE*i], 0);
		else
			aes_encrypt(z, &y[AES_BLOCK_SIZE*i], ctx->aes);
			
	}
	

	if (aes_print_flag)
	{
		printf("Display T\n");
		for(i = 0; i < mac_len; i++)
		{
			printf("[%02x]", y[(AES_BLOCK_SIZE*(block_cnt-1))+i]);
		}
		printf("\n");
	}
	
	if (flag == 0)
    		ccm_end(ctx);

    	free(kp); 
	free(ip);

	gettimeofday(&end_point, NULL);

	operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	printf("Operation Time : %f\n",operating_time);
	//reg_value = reg_readl((gpio_base + 0x14));
	//reg_value &= ~((unsigned int)0x200);
	//reg_writel((gpio_base + 0x14), reg_value);	/* GPB9 OutputData Setting, CON1의 48번 핀 */

	if( memcmp( &y[(AES_BLOCK_SIZE*(block_cnt-1))], t, mac_len ) == 0) 
	{
		printf("AES Encryption/Decryption MAC Success!!\n");
	}
	else
	{
		printf("AES Encryption/Decryption MAC Fail!!\n");
	}

	if( memcmp( p, plain_text, payload_len ) == 0)
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
			printf("[%02x]", plain_text[i]);
		}
		printf("\n");
	}

    	return (0);
}


/* SHKO : fips180-2.pdf 파일의 Appendix B.1 참조 */
int sha256_test1(void)
{
	int i;
    unsigned char sha2sum[32];
    sha2_context ctx;
	unsigned char plain_buf[3];

	plain_buf[0] = 0x61;	/* 'a' */
	plain_buf[1] = 0x62;	/* 'b' */
	plain_buf[2] = 0x63;	/* 'c' */

	/* SHKO : 두번째 인자 k가 0이면 SHA256이고 k가 1이면 SHA224이다. */
    sha2_starts( &ctx, 0 );

	sha2_update( &ctx, plain_buf, 3 );

	sha2_finish( &ctx, sha2sum ); /* 출력은 sha2sum에 저장됨. */

	/* SHA256 이므로 결과는 32바이트가 나온다. */
	for ( i = 0; i < 32; i++ )
	{
		printf("[%02x]", sha2sum[i]);
		if ( ( (i+1) % 10 ) == 0 )
			printf("\n");
	}

	printf("\n");

    return( 0 );
}

/* SHKO : fips180-2.pdf 파일의 Appendix B.2 참조 */
int sha256_test2(void)
{
	int i;
    unsigned char sha2sum[32];
    sha2_context ctx;
	unsigned char plain_buf[56];
	int buf_len;

	i = 0;
	plain_buf[i++] = 'a';	/* 'a' */
	plain_buf[i++] = 'b';	/* 'b' */
	plain_buf[i++] = 'c';	/* 'c' */
	plain_buf[i++] = 'd';
	plain_buf[i++] = 'b';
	plain_buf[i++] = 'c';
	plain_buf[i++] = 'd';
	plain_buf[i++] = 'e';
	plain_buf[i++] = 'c';
	plain_buf[i++] = 'd';

	plain_buf[i++] = 'e';
	plain_buf[i++] = 'f';
	plain_buf[i++] = 'd';
	plain_buf[i++] = 'e';
	plain_buf[i++] = 'f';
	plain_buf[i++] = 'g';
	plain_buf[i++] = 'e';
	plain_buf[i++] = 'f';
	plain_buf[i++] = 'g';
	plain_buf[i++] = 'h';

	plain_buf[i++] = 'f';
	plain_buf[i++] = 'g';
	plain_buf[i++] = 'h';
	plain_buf[i++] = 'i';
	plain_buf[i++] = 'g';
	plain_buf[i++] = 'h';
	plain_buf[i++] = 'i';
	plain_buf[i++] = 'j';
	plain_buf[i++] = 'h';
	plain_buf[i++] = 'i';

	plain_buf[i++] = 'j';
	plain_buf[i++] = 'k';
	plain_buf[i++] = 'i';
	plain_buf[i++] = 'j';
	plain_buf[i++] = 'k';
	plain_buf[i++] = 'l';
	plain_buf[i++] = 'j';
	plain_buf[i++] = 'k';
	plain_buf[i++] = 'l';
	plain_buf[i++] = 'm';

	plain_buf[i++] = 'k';
	plain_buf[i++] = 'l';
	plain_buf[i++] = 'm';
	plain_buf[i++] = 'n';
	plain_buf[i++] = 'l';
	plain_buf[i++] = 'm';
	plain_buf[i++] = 'n';
	plain_buf[i++] = 'o';
	plain_buf[i++] = 'm';
	plain_buf[i++] = 'n';

	plain_buf[i++] = 'o';
	plain_buf[i++] = 'p';
	plain_buf[i++] = 'n';
	plain_buf[i++] = 'o';
	plain_buf[i++] = 'p';
	plain_buf[i++] = 'q';
	
	buf_len = i;

	/* SHKO : 두번째 인자 k가 0이면 SHA256이고 k가 1이면 SHA224이다. */
    sha2_starts( &ctx, 0 );

	sha2_update( &ctx, plain_buf, buf_len );

	sha2_finish( &ctx, sha2sum ); /* 출력은 sha2sum에 저장됨. */

	/* SHA256 이므로 결과는 32바이트가 나온다. */
	for ( i = 0; i < 32; i++ )
	{
		printf("[%02x]", sha2sum[i]);
		if ( ( (i+1) % 10 ) == 0 )
			printf("\n");
	}

	printf("\n");

    return( 0 );
}


/* SHKO : fips180-2.pdf 파일의 Appendix B.2 참조 */
int fsha256_test2(void)
{
	int i;
    unsigned char sha2sum[32];
    sha2_context ctx;
	unsigned char plain_buf[56];
	int buf_len;

	i = 0;
	plain_buf[i++] = 'a';	/* 'a' */
	plain_buf[i++] = 'b';	/* 'b' */
	plain_buf[i++] = 'c';	/* 'c' */
	plain_buf[i++] = 'd';
	plain_buf[i++] = 'b';
	plain_buf[i++] = 'c';
	plain_buf[i++] = 'd';
	plain_buf[i++] = 'e';
	plain_buf[i++] = 'c';
	plain_buf[i++] = 'd';

	plain_buf[i++] = 'e';
	plain_buf[i++] = 'f';
	plain_buf[i++] = 'd';
	plain_buf[i++] = 'e';
	plain_buf[i++] = 'f';
	plain_buf[i++] = 'g';
	plain_buf[i++] = 'e';
	plain_buf[i++] = 'f';
	plain_buf[i++] = 'g';
	plain_buf[i++] = 'h';

	plain_buf[i++] = 'f';
	plain_buf[i++] = 'g';
	plain_buf[i++] = 'h';
	plain_buf[i++] = 'i';
	plain_buf[i++] = 'g';
	plain_buf[i++] = 'h';
	plain_buf[i++] = 'i';
	plain_buf[i++] = 'j';
	plain_buf[i++] = 'h';
	plain_buf[i++] = 'i';

	plain_buf[i++] = 'j';
	plain_buf[i++] = 'k';
	plain_buf[i++] = 'i';
	plain_buf[i++] = 'j';
	plain_buf[i++] = 'k';
	plain_buf[i++] = 'l';
	plain_buf[i++] = 'j';
	plain_buf[i++] = 'k';
	plain_buf[i++] = 'l';
	plain_buf[i++] = 'm';

	plain_buf[i++] = 'k';
	plain_buf[i++] = 'l';
	plain_buf[i++] = 'm';
	plain_buf[i++] = 'n';
	plain_buf[i++] = 'l';
	plain_buf[i++] = 'm';
	plain_buf[i++] = 'n';
	plain_buf[i++] = 'o';
	plain_buf[i++] = 'm';
	plain_buf[i++] = 'n';

	plain_buf[i++] = 'o';
	plain_buf[i++] = 'p';
	plain_buf[i++] = 'n';
	plain_buf[i++] = 'o';
	plain_buf[i++] = 'p';
	plain_buf[i++] = 'q';
	
	buf_len = i;

	/* SHKO : 두번째 인자 k가 0이면 SHA256이고 k가 1이면 SHA224이다. */
    sha2_starts( &ctx, 0 );

	sha2_update( &ctx, plain_buf, buf_len );

	sha2_finish( &ctx, sha2sum ); /* 출력은 sha2sum에 저장됨. */

	/* SHA256 이므로 결과는 32바이트가 나온다. */
	for ( i = 0; i < 32; i++ )
	{
		printf("[%02x]", sha2sum[i]);
		if ( ( (i+1) % 10 ) == 0 )
			printf("\n");
	}

	printf("\n");

    return( 0 );
}


#if 0
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
    ecp_domain epdom;
    ec2_domain e2dom;
    if_public_key pub;
    if_private_key priv;
    csprng RNG;                  /* Crypto Strong RNG */
 
    int res,bytes,bits;

    struct timeval start_point, end_point;
	volatile double operating_time;

	//gettimeofday(&start_point, NULL);

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


    bytes=ECP_DOMAIN_INIT(&epdom,"/usr/sbin/common.ecs",NULL,precompute);
    printf("bytes=%d\n", bytes);

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
    res = ECP_KEY_PAIR_GENERATE(NULL,&epdom,&RNG,&u,compress,&v);  /* one time key pair */
    printf("u private Key is [%d]\n", res);
    OCTET_OUTPUT(&u);
	printf("\n");

	printf("v public Key is [%d]\n", v.len);
    OCTET_OUTPUT(&v);
	printf("\n");

	/* 아래 함수를 통해 s와 w가 세팅된다. */
	/* s : secret key, w : public key */
    res = ECP_KEY_PAIR_GENERATE(NULL,&epdom,&RNG,&s,compress,&w);  /* recipients key pair */
    printf("s private Key is [%d] \n", res);
    OCTET_OUTPUT(&s);
	printf("\n");

	printf("w public Key is \n");
    OCTET_OUTPUT(&w);
	printf("\n");


#if 0	//SHKO, Origin
    res=ECPSVDP_DH(NULL,&epdom,&u,&w,&z);
#else
	/* 아래 함수를 통해 z가 세팅된다. */
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 SVD Primitive에 해당 --> 송신측 개인키와 수신측 공개키를 입력으로 해서 z를 만든다. */
	res=ECPSVDP_DHC(NULL,&epdom,&u,&w,TRUE,&z);
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
	res=KDF2(&vz,&p1,32,SHA256,&k);
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

    	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("ECIES Encryption Operation Time : %f\n",operating_time);

	//gettimeofday(&start_point, NULL);

	if (ecies_print_flag)
		printf("Decryption\n");

#if 0	//SHKO, Origin
    res=ECPSVDP_DH(NULL,&epdom,&s,&v,&z);
#else
	/* SHKO : IEEE 1363A 규격의 Figure 11에서 오른편에 있는 SVD Primitive에 해당 --> 수신측 개인키와 송신측 공개키를 입력으로 해서 z를 만든다. */
	res=ECPSVDP_DHC(NULL,&epdom,&s,&v,TRUE,&z);
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
	res=KDF2(&vz,&p1,32,SHA256,&k);
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
    	//gettimeofday(&end_point, NULL);

	//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
	//printf("ECIES Decryption Operation Time : %f\n",operating_time);
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

    ECP_DOMAIN_KILL(&epdom);
    OCTET_KILL(&z); OCTET_KILL(&vz);

    KILL_CSPRNG(&RNG);
    return;
}
#endif

static U4 __smsc911x_reg_read(U4 reg)
{
	return ((reg_readw(ethernet_base + reg) & 0xFFFF) |
			((reg_readw(ethernet_base + reg + 2) & 0xFFFF) << 16));

	return 0;
}

static void __smsc911x_reg_write(U4 reg, U4 val)
{
	reg_writew((ethernet_base + reg), val & 0xFFFF);
	reg_writew((ethernet_base + reg + 2), (val >> 16) & 0xFFFF);
	return;
}


/* waits for MAC not busy, with timeout.  Only called by smsc911x_mac_read
 * and smsc911x_mac_write, so assumes mac_lock is held */
static int smsc911x_mac_complete(void)
{
	int i;
	U4 val;

	//SMSC_ASSERT_MAC_LOCK(pdata);

	for (i = 0; i < 100; i++) {
		val = __smsc911x_reg_read(MAC_CSR_CMD);
		if (!(val & MAC_CSR_CMD_CSR_BUSY_))
			return 0;
	}
	printf("[smsc911x_mac_complete] Timed out waiting for MAC not BUSY. MAC_CSR_CMD: 0x%08X\n", val);
	return(-1);
}


/* Fetches a MAC register value. Assumes mac_lock is acquired */
static U4 smsc911x_mac_read(unsigned int offset)
{
	unsigned int temp;

	//SMSC_ASSERT_MAC_LOCK(pdata);

	/*SHKO : SMSC_LAN9220db.pdf 파일의 5.3.20 참조. 이 레지스터는 MAC Control and Status Register 를 가지고 */
	/* read와 write 동작을 제어하기 위해 사용된다. */
	temp = __smsc911x_reg_read(MAC_CSR_CMD);
	if (temp & MAC_CSR_CMD_CSR_BUSY_) 
	{
		printf("[smsc911x_mac_read] MAC busy at entry\n");
		return 0xFFFFFFFF;
	}

	/* Send the MAC cmd */
	__smsc911x_reg_write(MAC_CSR_CMD, ((offset & 0xFF) |
		MAC_CSR_CMD_CSR_BUSY_ | MAC_CSR_CMD_R_NOT_W_));

	/* Workaround for hardware read-after-write restriction */
	temp = __smsc911x_reg_read(BYTE_TEST);

	/* Wait for the read to complete */
	if (smsc911x_mac_complete() == 0)
		return __smsc911x_reg_read(MAC_CSR_DATA);

	printf("[smsc911x_mac_read]MAC busy after read\n");
	return 0xFFFFFFFF;
}

/* Set a mac register, mac_lock must be acquired before calling */
static void smsc911x_mac_write(unsigned int offset, U4 val)
{
	unsigned int temp;

	//SMSC_ASSERT_MAC_LOCK(pdata);

	/*SHKO : SMSC_LAN9220db.pdf 파일의 5.3.20 참조. 이 레지스터는 MAC Control and Status Register 를 가지고 */
	/* read와 write 동작을 제어하기 위해 사용된다. */
	temp = __smsc911x_reg_read(MAC_CSR_CMD);
	if (temp & MAC_CSR_CMD_CSR_BUSY_) 
	{
		printf("[smsc911x_mac_write] smsc911x_mac_write failed, MAC busy at entry\n");
		return;
	}

	/* Send data to write */
	/*SHKO : SMSC_LAN9220db.pdf 파일의 5.3.21 참조. */
	__smsc911x_reg_write(MAC_CSR_DATA, val);

	/* Write the actual data */
	__smsc911x_reg_write(MAC_CSR_CMD, ((offset & 0xFF) |
		MAC_CSR_CMD_CSR_BUSY_));

	/* Workaround for hardware read-after-write restriction */
	temp = __smsc911x_reg_read(BYTE_TEST);

	/* Wait for the write to complete */
	if (smsc911x_mac_complete() == 0)
		return;

	printf("[smsc911x_mac_write]smsc911x_mac_write failed, MAC busy after write");
}


/* Get a phy register */
int smsc911x_mii_read(int regidx)
{
	unsigned long flags;
	unsigned int addr;
	int i, reg;
	int phyaddr = 1;

	/* Confirm MII not busy */
	for ( i = 0; i < 1000; i++)
	{
		if (smsc911x_mac_read(MII_ACC) & MII_ACC_MII_BUSY_) 
		{
			printf("[smsc911x_mii_read] MII is busy in smsc911x_mii_read???\n");
			//reg = -1;
			//return(reg);
		}
		else
		{
			break;
		}
	}
	if ( i == 1000 )
	{
		printf("[smsc911x_mii_read] MII is busy Fail!!\n");
	}

	/* Set the address, index & direction (read from PHY) */
	addr = ((phyaddr & 0x1F) << 11) | ((regidx & 0x1F) << 6);
	smsc911x_mac_write(MII_ACC, addr);

	/* Wait for read to complete w/ timeout */
	for (i = 0; i < 1000; i++)
		if (!(smsc911x_mac_read(MII_ACC) & MII_ACC_MII_BUSY_)) {
			reg = smsc911x_mac_read(MII_DATA);
			return(reg);
		}

	printf("[smsc911x_mii_read]Timed out waiting for MII read to finish\n");
	reg = -1;
	return(reg);
}

/* Set a phy register */
int smsc911x_mii_write(int regidx, U2 val)
{
	unsigned long flags;
	unsigned int addr;
	int i, reg;
	int phyaddr = 1;

	//spin_lock_irqsave(&pdata->mac_lock, flags);

	/* Confirm MII not busy */
	for ( i = 0; i < 1000; i++)
	{
		if (smsc911x_mac_read(MII_ACC) & MII_ACC_MII_BUSY_) 
		{
			printf("[smsc911x_mii_write] MII is busy in smsc911x_mii_write???\n");
		}
		else
		{
			break;
		}
	}
	if ( i == 1000 )
	{
		printf("[smsc911x_mii_write] MII is busy Fail!!\n");
	}

	/* Put the data to write in the MAC */
	smsc911x_mac_write(MII_DATA, val);

	/* Set the address, index & direction (write to PHY) */
	addr = ((phyaddr & 0x1F) << 11) | ((regidx & 0x1F) << 6) | MII_ACC_MII_WRITE_;
	smsc911x_mac_write(MII_ACC, addr);

	/* Wait for write to complete w/ timeout */
	for (i = 0; i < 1000; i++)
		if (!(smsc911x_mac_read(MII_ACC) & MII_ACC_MII_BUSY_)) {
			reg = 0;
			return reg;
		}

	printf("[smsc911x_mii_write]Timed out waiting for MII write to finish\n");
	reg = -1;
	return reg;
}


/* SHKO : 참고사이트 - http://ftp.gwdg.de/linux/misc/ftp.scyld.com/diag/mii-diag.c */
U4 mdio_read(int phy_id, int location)
{
	struct ifreq ifr;
	U2 *data;
	U4 read_data;
	U1 memory_array[32];

	strcpy(ifr.ifr_name, "eth0");

	ifr.ifr_data = memory_array;

	data = (U2 *)(ifr.ifr_data);
	printf("data=0x%08x\n", data);

	data[0] = phy_id;
	data[1] = location;

	if (ioctl(serv_sock, SIOCGMIIREG, &ifr) < 0) {
		fprintf(stderr, "SIOCGMIIREG on %s failed: %s\n", ifr.ifr_name,
				strerror(errno));
		return -1;
	}
#if 0
	return data[3];
#else
	read_data = ((U4)data[2] & 0xFFFF) | (((U4)data[3]  & 0xFFFF) << 16);
	return(read_data);
#endif
}

#if 0
void mdio_write(int phy_id, int location, int value)
{
	struct ifreq ifr;
	U2 *data;

	strcpy(ifr.ifr_name, "eth0");
	data = (U2 *)(&ifr.ifr_data);

	data[0] = phy_id;
	data[1] = location;
	data[2] = value;

	if (ioctl(serv_sock, SIOCSMIIREG, &ifr) < 0) {
		fprintf(stderr, "SIOCSMIIREG on %s failed: %s\n", ifr.ifr_name,
				strerror(errno));
	}
}
#else
void mdio_write(int phy_id, int location, U4 value)
{
	struct ifreq ifr;
	U2 *data;

	strcpy(ifr.ifr_name, "eth0");
	data = (U2 *)(&ifr.ifr_data);

	data[0] = phy_id;
	data[1] = location;
	data[2] = value & 0xFFFF;
	data[3] = (value >> 16) & 0xFFFF;

	if (ioctl(serv_sock, SIOCSMIIREG, &ifr) < 0) {
		fprintf(stderr, "SIOCSMIIREG on %s failed: %s\n", ifr.ifr_name,
				strerror(errno));
	}
}
#endif


int Wave_Register_Read_Write_Test (U4 offset, int size, U4 pattern, U4 mask)
{
	U4 reg_value = 0;
	U2 reg_data = 0;

	if (size == 2 )
	{
		reg_writew((wave_dsrc_base + offset), (pattern & mask));

		reg_data = reg_readw((wave_dsrc_base + offset));

		if (reg_data  != (pattern & mask))
		{
			printf("Fail Address=0x%08x, Expected=0x%08x, Result=0x%08x\n", offset, (pattern & mask), reg_data);
			return(-1);
		}
	}
	else if (size == 4)
	{
		write_wave_dsrc_reg32(offset, (pattern & mask));

		reg_value = read_wave_dsrc_reg32(offset);

		if (reg_value  != (pattern & mask))
		{
			printf("Fail Address=0x%08x, Expected=0x%08x, Result=0x%08x\n", offset, (pattern & mask), reg_value);
			return(-1);
		}
	}
	return(0);
}


int ExecCommand(int argc,char* argv[])
{
	int i,k, m;
	U4 u4, address;
	U2 u2;
	U1	u1;
	int length = 0;
	int start_len = 0;
	int end_len = 0;
	int count;
	int tx_power;
	int modulation;
	int rf_num;
	U1 data_rate;
	int interval;
	__attribute__((aligned(4))) U1 send_buf[2048];
	U1 sdata;
	int start_data;
	int end_data;
	int j;
	unsigned int val;
	int test_mode;
	//Default return value, means internal inconsistency
	int return_value = 4;
	struct bigtype w;
	mr_small a;
	mr_small b;
	mpz_t x;
	mpz_t t1;
	mpz_t t2;
	mpz_t p;
	gmp_randstate_t rstate;
	U1	message[256];
	U1 aes_key[16];
	U1 aes_plain[16];
	U1 aes_encrypt[16];
	char  str_buf[256];
	volatile unsigned int reg_value;
	U1 sha_out[32];
	U1 expected_sha_out[32];
	U1 prime_number_out[28];
	U1 prime_number_str[64];
	U2 wsmp_header_len = 0;
	U2 wsmp_data_len = 0;
	U2_T	version_id0;
	U2_T	version_id1;
	U2_T	version_id2;
	struct timeval start_point, end_point;
	volatile double operating_time;
	U4 data;
	U2_T high_mac_addr;
	U4_T low_mac_addr;
	int ret;
	IOCTLWAVE_INFO ctrl_info;
	IOCTLWAVE_RX_INFO ctrl_rx_info;
	U4_T reg_data;
	int ch_kind = 0;
	U1 ToBeSignedMsg[1024];
	int signed_msg_len;
	int wsmp_len_index;
	
#if 0	//SHKO, Origin
	U1 rx_ecdsa_test_256[183] = {	0x88, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
									0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
									0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0x03, 0x00,
									0x00, 0x00, 0x88, 0xdc, 0x01, 0x01, 0x80, 0x00, 0x90, 0x21,
									0x03, 0x59, 0x63, 0x75, 0xe6, 0xce, 0x57, 0xe0, 0xf2, 0x02,
									0x94, 0xfc, 0x46, 0xbd, 0xfc, 0xfd, 0x19, 0xa3, 0x9f, 0x81,
									0x61, 0xb5, 0x86, 0x95, 0xb3, 0xec, 0x5b, 0x3d, 0x16, 0x42,
									0x7c, 0x27, 0x4d, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
									0x20, 0x6f, 0x66, 0x20, 0x45, 0x43, 0x44, 0x53, 0x41, 0x20,
									0x77, 0x69, 0x74, 0x68, 0x20, 0x61, 0x6e, 0x73, 0x69, 0x70,
									0x32, 0x35, 0x36, 0x72, 0x31, 0x20, 0x61, 0x6e, 0x64, 0x20,
									0x53, 0x48, 0x41, 0x2d, 0x32, 0x35, 0x36, 0x01, 0x20, 0xec,
									0x76, 0x22, 0x10, 0x36, 0x29, 0x1d, 0x0c, 0x1c, 0x26, 0x22,
									0x3a, 0xb5, 0x4f, 0x81, 0x29, 0x89, 0xc4, 0x0a, 0xf3, 0xb2,
									0xa4, 0x42, 0x13, 0x8a, 0xcb, 0x30, 0xd9, 0x25, 0xf1, 0xc4,
									0x53, 0x40, 0x0c, 0xed, 0x60, 0x74, 0x6f, 0xd9, 0x03, 0x26,
									0x2a, 0xfc, 0xf8, 0x6d, 0x91, 0xb7, 0x24, 0x2d, 0x54, 0xe5,
									0x92, 0xda, 0x04, 0x94, 0xf4, 0x3a, 0x16, 0xc9, 0x47, 0xf9,
									0xfa, 0x26, 0x5f
							     };

	U1 rx_ecdsa_test_224[171] = {	0x88, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
									0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
									0xff, 0xff, 0x10, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0x03, 0x00,
									0x00, 0x00, 0x88, 0xdc, 0x01, 0x01, 0x80, 0x00, 0x84, 0x1d,
									0x03, 0xfd, 0x44, 0xec, 0x11, 0xf9, 0xd4, 0x3d, 0x9d, 0x23,
									0xb1, 0xe1, 0xd1, 0xc9, 0xed, 0x65, 0x19, 0xb4, 0x0e, 0xcf,
									0x0c, 0x79, 0xf4, 0x8c, 0xf4, 0x76, 0xcc, 0x43, 0xf1, 0x45,
									0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x6f, 0x66, 0x20,
									0x45, 0x43, 0x44, 0x53, 0x41, 0x20, 0x77, 0x69, 0x74, 0x68,
									0x20, 0x61, 0x6e, 0x73, 0x69, 0x70, 0x32, 0x32, 0x34, 0x72,
									0x31, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x53, 0x48, 0x41, 0x2d,
									0x32, 0x32, 0x34, 0x00, 0x1c, 0xa0, 0xde, 0x0e, 0x86, 0xcb,
									0x20, 0x80, 0xf6, 0x0f, 0xed, 0xf4, 0xed, 0x12, 0x32, 0x1a,
									0xff, 0x71, 0x10, 0xdb, 0xe5, 0x08, 0xd2, 0x49, 0xe0, 0x3e,
									0x3c, 0x83, 0x13, 0xda, 0xec, 0x01, 0x01, 0x5c, 0x06, 0x0b,
									0x62, 0x75, 0xcd, 0xe0, 0xbb, 0x7d, 0x9b, 0x84, 0xd4, 0xb7,
									0xd1, 0xdd, 0x6a, 0x18, 0x00, 0x3b, 0xae, 0x6c, 0xa1, 0xc9,
									0x0e
								};
#else
	U1 rx_ecdsa_test_256[239] = {	0x88, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
									0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
									0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0x03, 0x00,
									0x00, 0x00, 0x88, 0xdc, 0x01, 0x01, 0x80, 0x00, 0xc8, 0x21,
									0x03, 0x59, 0x63, 0x75, 0xe6, 0xce, 0x57, 0xe0, 0xf2, 0x02,
									0x94, 0xfc, 0x46, 0xbd, 0xfc, 0xfd, 0x19, 0xa3, 0x9f, 0x81,
									0x61, 0xb5, 0x86, 0x95, 0xb3, 0xec, 0x5b, 0x3d, 0x16, 0x42,
									0x7c, 0x27, 0x4d, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
									0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
									0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
									0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
									0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
									0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
									0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42,
									0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c,
									0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56,
									0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
									0x61, 0x62, 0x63, 0x01, 0x20, 0x1e, 0x8e, 0xf0, 0x37, 0x74,
									0x10, 0xbe, 0x13, 0x75, 0xc5, 0x5b, 0xd0, 0x1d, 0x06, 0xc1,
									0xa5, 0x32, 0xc9, 0x4e, 0x1f, 0xa9, 0xe5, 0x87, 0xc6, 0x56,
									0x10, 0xdf, 0x1d, 0x16, 0xfc, 0xe3, 0xf6, 0x66, 0x5f, 0x56,
									0xd4, 0x6e, 0x33, 0x37, 0x30, 0x3b, 0x1c, 0x52, 0xb3, 0xae,
									0x63, 0xb1, 0x16, 0x83, 0x5d, 0xf5, 0xac, 0x9c, 0x04, 0x01,
									0x87, 0x87, 0x65, 0x69, 0x92, 0x81, 0xb4, 0xa3, 0x0d
							     };

	U1 rx_ecdsa_test_224[227] = {	0x88, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
									0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
									0xff, 0xff, 0x10, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0x03, 0x00,
									0x00, 0x00, 0x88, 0xdc, 0x01, 0x01, 0x80, 0x00, 0xbc, 0x1d,
									0x03, 0xfd, 0x44, 0xec, 0x11, 0xf9, 0xd4, 0x3d, 0x9d, 0x23,
									0xb1, 0xe1, 0xd1, 0xc9, 0xed, 0x65, 0x19, 0xb4, 0x0e, 0xcf,
									0x0c, 0x79, 0xf4, 0x8c, 0xf4, 0x76, 0xcc, 0x43, 0xf1, 0x00,
									0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
									0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
									0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
									0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
									0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
									0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
									0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
									0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
									0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
									0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x00,
									0x1c, 0xa6, 0xe0, 0x18, 0xd7, 0x99, 0xe2, 0xd8, 0x6b, 0x27,
									0x7f, 0x25, 0x78, 0x77, 0x19, 0xaf, 0x7d, 0xc1, 0x94, 0x81,
									0x6e, 0xdd, 0xeb, 0x36, 0x4c, 0x27, 0x19, 0x80, 0x8f, 0x98,
									0x98, 0x15, 0x0b, 0xe4, 0x93, 0xee, 0x6d, 0x78, 0x12, 0x31,
									0xe9, 0x80, 0x73, 0xe6, 0x63, 0xde, 0x23, 0x42, 0x91, 0x86,
									0x50, 0x12, 0xcb, 0x71, 0x3f, 0x5a, 0x1d
								};
#endif

	U1 rx_ecies_test[239] = {			0x88, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
									0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
									0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0x03, 0x00,
									0x00, 0x00, 0x88, 0xdc, 0x01, 0x02, 0x80, 0x00, 0xc8, 0x00,
									0x00, 0x00, 0xc4, 0x02, 0x02, 0x8d, 0x00, 0xc3, 0x17, 0xbb,
									0x97, 0x72, 0x82, 0x0c, 0xbf, 0x39, 0xb8, 0x6e, 0x01, 0xd4,
									0x74, 0x69, 0x06, 0x37, 0x74, 0xf2, 0xac, 0x6d, 0x2a, 0x49,
									0xcd, 0x54, 0xef, 0x6f, 0xe4, 0x05, 0x8a, 0x8e, 0xb7, 0xa3,
									0x48, 0x70, 0xc7, 0x33, 0xcf, 0x38, 0x3b, 0x55, 0x90, 0x87,
									0x82, 0xdc, 0x70, 0xb6, 0x1c, 0xe6, 0xb3, 0x91, 0x33, 0x62,
									0xc5, 0x83, 0x46, 0x1f, 0x08, 0x41, 0x35, 0x72, 0x2e, 0x00,
									0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x00, 0x00,
									0x25, 0x00, 0x74, 0x21, 0x62, 0xb4, 0x27, 0x30, 0xc3, 0x74,
									0x02, 0x20, 0xc0, 0x0d, 0xdb, 0x8d, 0x01, 0x23, 0x4a, 0xe7,
									0xd5, 0x92, 0x4b, 0x0f, 0x30, 0x7d, 0xb8, 0x2c, 0x40, 0x2a,
									0xbb, 0x25, 0x3a, 0xf6, 0x9b, 0xc2, 0x8a, 0x83, 0x3e, 0xad,
									0xa2, 0xd7, 0x78, 0xbd, 0xbd, 0x61, 0xde, 0x6a, 0xd7, 0x0c,
									0x45, 0xbc, 0xbc, 0x46, 0x91, 0xcd, 0xa7, 0x49, 0x02, 0xd6,
									0x9e, 0x40, 0xd4, 0x6e, 0x5b, 0x68, 0x04, 0x7b, 0xce, 0x3d,
									0xc0, 0xb6, 0x8a, 0x97, 0xe1, 0x42, 0xa6, 0xad, 0xb9, 0xe9,
									0x28, 0x02, 0xcb, 0x59, 0xf0, 0xfc, 0xcd, 0xbb, 0x99, 0xc4,
									0xf2, 0xf2, 0x91, 0xfb, 0xb0, 0xd5, 0x83, 0x6d, 0xeb, 0xd4,
									0x08, 0x19, 0x81, 0x6c, 0x44, 0x38, 0xdc, 0x52, 0x35, 0x5d,
									0x46, 0x43, 0x1f, 0xfb, 0x08, 0x94, 0x85, 0xf5, 0x19
								};
	
	

	if (!strcmp( argv[0], "help" ) ) MON_HelpCmd();
	//else if (!strcmp( argv[0], "sc" ) ) close(clnt_sock);
	else if (!strcmp( argv[0], "ss" ) ) Socket_SendCmd(argc, argv);
	//else if (!strcmp( argv[0], "net" ) ) net_main();
	else if (!strcmp( argv[0], "et" ) ) edian_test(argc, argv);
	else if (!strcmp( argv[0], "ft" ) ) float_test(argc, argv);
	else if(!strcmp( argv[0], "r4" ))
	{
		if (argc != 4)
		{
			printf("USAGE: r4 base offset len\n");
			printf("base = 0 : system_control_base\n");
			printf("base = 1 : gpio_base\n");
			printf("base = 2 : static_memory_controller_base\n");
			printf("base = 3 : interrupt_controller_base\n");
			printf("base = 4 : wave_dsrc_base\n");
			printf("base = 5 : ethernet_base\n");
			printf("base = 6 : hs_spi0_base\n");
			printf("base = 7 : hs_spi1_base\n");
		}
		else
		{
			if (atoi(argv[1]) == 0)
			{
				address = (U4)system_control_base;
			}
			else if (atoi(argv[1]) == 1)
			{
				address = (U4)gpio_base;
			}
			else if (atoi(argv[1]) == 2)
			{
				address = (U4)static_memory_controller_base;
			}
			else if (atoi(argv[1]) == 3)
			{
				address = (U4)interrupt_controller_base;
			}
			else if (atoi(argv[1]) == 4)
			{
				address = (U4)wave_dsrc_base;
			}
			else if (atoi(argv[1]) == 5)
			{
				address = (U4)ethernet_base;
			}
			else if (atoi(argv[1]) == 6)
			{
				address = (U4)hs_spi0_base;
			}
			else if (atoi(argv[1]) == 7)
			{
				address = (U4)hs_spi1_base;
			}
			address += (U4)strtoul(argv[2], NULL, 16);
			//my_printf("address=0x%08x\n", address);
			length = atoi(argv[3]);
			if (length == 0)	length = 1;
			//my_printf("len=%d\n", length);
		}
		memory_dump(NULL, (void *)address, length, DUMP_A4C);

	}	
	// r2: memory read by short
	else if(!strcmp( argv[0], "r2" ))
	{
		if (argc != 4)
		{
			printf("USAGE: r2 base offset len\n");
			printf("base = 0 : system_control_base\n");
			printf("base = 1 : gpio_base\n");
			printf("base = 2 : static_memory_controller_base\n");
			printf("base = 3 : interrupt_controller_base\n");
			printf("base = 4 : wave_dsrc_base\n");
			printf("base = 5 : ethernet_base\n");
			printf("base = 6 : hs_spi0_base\n");
			printf("base = 7 : hs_spi1_base\n");
		}
		else
		{
			if (atoi(argv[1]) == 0)
			{
				address = (U4)system_control_base;
			}
			else if (atoi(argv[1]) == 1)
			{
				address = (U4)gpio_base;
			}
			else if (atoi(argv[1]) == 2)
			{
				address = (U4)static_memory_controller_base;
			}
			else if (atoi(argv[1]) == 3)
			{
				address = (U4)interrupt_controller_base;
			}
			else if (atoi(argv[1]) == 4)
			{
				address = (U4)wave_dsrc_base;
			}
			else if (atoi(argv[1]) == 5)
			{
				address = (U4)ethernet_base;
			}
			else if (atoi(argv[1]) == 6)
			{
				address = (U4)hs_spi0_base;
			}
			else if (atoi(argv[1]) == 7)
			{
				address = (U4)hs_spi1_base;
			}
			address += (U4)strtoul(argv[2], NULL, 16);
			length = atoi(argv[3]);
			if (length == 0)	length = 1;
			memory_dump(NULL, (void *)address, length, DUMP_A2C);
		}
	}

	// r1: memory read by char
	else if(!strcmp( argv[0], "r1" ))
	{
		if (argc != 4)
		{
			printf("USAGE: r1 base offset len\n");
			printf("base = 0 : system_control_base\n");
			printf("base = 1 : gpio_base\n");
			printf("base = 2 : static_memory_controller_base\n");
			printf("base = 3 : interrupt_controller_base\n");
			printf("base = 4 : wave_dsrc_base\n");
			printf("base = 5 : ethernet_base\n");
			printf("base = 6 : hs_spi0_base\n");
			printf("base = 7 : hs_spi1_base\n");
		}
		else
		{
			if (atoi(argv[1]) == 0)
			{
				address = (U4)system_control_base;
			}
			else if (atoi(argv[1]) == 1)
			{
				address = (U4)gpio_base;
			}
			else if (atoi(argv[1]) == 2)
			{
				address = (U4)static_memory_controller_base;
			}
			else if (atoi(argv[1]) == 3)
			{
				address = (U4)interrupt_controller_base;
			}
			else if (atoi(argv[1]) == 4)
			{
				address = (U4)wave_dsrc_base;
			}
			else if (atoi(argv[1]) == 5)
			{
				address = (U4)ethernet_base;
			}
			else if (atoi(argv[1]) == 6)
			{
				address = (U4)hs_spi0_base;
			}
			else if (atoi(argv[1]) == 7)
			{
				address = (U4)hs_spi1_base;
			}
			address += (U4)strtoul(argv[2], NULL, 16);
			length = atoi(argv[3]);
			if (length == 0)	length = 1;
			
			memory_dump(NULL, (void *)address, length, DUMP_A1C);
		}
	}

	// w4: memory write by int
	else if(!strcmp( argv[0], "w4" ))
	{
		if (argc < 4)
		{
			printf("USAGE: w4 base offset data\n");
			printf("base = 0 : system_control_base\n");
			printf("base = 1 : gpio_base\n");
			printf("base = 2 : static_memory_controller_base\n");
			printf("base = 3 : interrupt_controller_base\n");
			printf("base = 4 : wave_dsrc_base\n");
			printf("base = 5 : ethernet_base\n");
			printf("base = 6 : hs_spi0_base\n");
			printf("base = 7 : hs_spi1_base\n");
		}
		else
		{
			if (atoi(argv[1]) == 0)
			{
				address = (U4)system_control_base;
			}
			else if (atoi(argv[1]) == 1)
			{
				address = (U4)gpio_base;
			}
			else if (atoi(argv[1]) == 2)
			{
				address = (U4)static_memory_controller_base;
			}
			else if (atoi(argv[1]) == 3)
			{
				address = (U4)interrupt_controller_base;
			}
			else if (atoi(argv[1]) == 4)
			{
				address = (U4)wave_dsrc_base;
			}
			else if (atoi(argv[1]) == 5)
			{
				address = (U4)ethernet_base;
			}
			else if (atoi(argv[1]) == 6)
			{
				address = (U4)hs_spi0_base;
			}
			else if (atoi(argv[1]) == 7)
			{
				address = (U4)hs_spi1_base;
			}
			
			address += (U4)strtoul(argv[2], NULL, 16);
			for (i = 3; i < argc; i++)
			{
				u4 = (U4)strtoul(argv[i], NULL, 16);
				reg_readl(address) = u4;
				printf(" write4 0x%08x to 0x%08x\n\r", address, u4);
				address += 4;
			}
		}
	}

	// w2: memory write by short
	else if (!strcmp( argv[0], "w2" ))
	{
		if (argc < 4)
		{
			printf("USAGE: w2 base offset data\n");
			printf("base = 0 : system_control_base\n");
			printf("base = 1 : gpio_base\n");
			printf("base = 2 : static_memory_controller_base\n");
			printf("base = 3 : interrupt_controller_base\n");
			printf("base = 4 : wave_dsrc_base\n");
			printf("base = 5 : ethernet_base\n");
			printf("base = 6 : hs_spi0_base\n");
			printf("base = 7 : hs_spi1_base\n");
		}
		else
		{
			if (atoi(argv[1]) == 0)
			{
				address = (U4)system_control_base;
			}
			else if (atoi(argv[1]) == 1)
			{
				address = (U4)gpio_base;
			}
			else if (atoi(argv[1]) == 2)
			{
				address = (U4)static_memory_controller_base;
			}
			else if (atoi(argv[1]) == 3)
			{
				address = (U4)interrupt_controller_base;
			}
			else if (atoi(argv[1]) == 4)
			{
				address = (U4)wave_dsrc_base;
			}
			else if (atoi(argv[1]) == 5)
			{
				address = (U4)ethernet_base;
			}
			else if (atoi(argv[1]) == 6)
			{
				address = (U4)hs_spi0_base;
			}
			else if (atoi(argv[1]) == 7)
			{
				address = (U4)hs_spi1_base;
			}

			address += (U4)strtoul(argv[2], NULL, 16);
			for (i = 3; i < argc; i++)
			{
				u2 = (U2)strtoul(argv[i], NULL, 16);
				reg_readw(address) = u2;
				printf(" write2 0x%08x to 0x%04x\n\r", address, u2);
				address += 2;
			}
		}
	}

	// w1: memory write by char
	else if (!strcmp( argv[0], "w1" ))
	{
		if (argc < 4)
		{
			printf("USAGE: w1 base offset data\n");
			printf("base = 0 : system_control_base\n");
			printf("base = 1 : gpio_base\n");
			printf("base = 2 : static_memory_controller_base\n");
			printf("base = 3 : interrupt_controller_base\n");
			printf("base = 4 : wave_dsrc_base\n");
			printf("base = 5 : ethernet_base\n");
			printf("base = 6 : hs_spi0_base\n");
			printf("base = 7 : hs_spi1_base\n");
		}
		else
		{
			if (atoi(argv[1]) == 0)
			{
				address = (U4)system_control_base;
			}
			else if (atoi(argv[1]) == 1)
			{
				address = (U4)gpio_base;
			}
			else if (atoi(argv[1]) == 2)
			{
				address = (U4)static_memory_controller_base;
			}
			else if (atoi(argv[1]) == 3)
			{
				address = (U4)interrupt_controller_base;
			}
			else if (atoi(argv[1]) == 4)
			{
				address = (U4)wave_dsrc_base;
			}
			else if (atoi(argv[1]) == 5)
			{
				address = (U4)ethernet_base;
			}
			else if (atoi(argv[1]) == 6)
			{
				address = (U4)hs_spi0_base;
			}
			else if (atoi(argv[1]) == 7)
			{
				address = (U4)hs_spi1_base;
			}
			
			address += (U4)strtoul(argv[2], NULL, 16);
			for (i = 3; i < argc; i++)
			{
				u1 = (U1)strtoul(argv[i], NULL, 16);
				reg_readb(address) = u1;
				printf(" write1 0x%08x to 0x%02x\n\r", address, u1);
				address ++;
			}
		}
	}
	else if (!strcmp( argv[0], "lsmod" ))
	{
		system("lsmod");
	}
	else if (!strcmp( argv[0], "kill" ))
	{
		sprintf(str_buf, "kill %s %s", argv[1], argv[2]);
		system(str_buf);
	}
	else if (!strcmp( argv[0], "ps" ))
	{
		system("ps -ef");
	}
	else if (!strcmp( argv[0], "ioctl" ))
	{
		if (argc == 1)
		{
			ret  = ioctl(dev, IOCTLWAVE_READ, &ctrl_info);
			if (ret != 0)
			{
				perror("ioctl read:");
			}
			else
			{
				printf("wave_tx_queue_write_index=%d, wave_tx_queue_read_index=%d, wave_tx_write_success_index=%d\n", ctrl_info.wave_tx_queue_write_index, ctrl_info.wave_tx_queue_read_index, ctrl_info.wave_tx_write_success_index);
			}
		}
		else if (argc == 4)
		{
			ctrl_info.wave_tx_queue_write_index = atoi(argv[1]);
			ctrl_info.wave_tx_queue_read_index = atoi(argv[2]);
			ctrl_info.wave_tx_write_success_index = atoi(argv[3]);
			printf("wave_tx_queue_write_index=%d, wave_tx_queue_read_index=%d, wave_tx_write_success_index=%d\n", ctrl_info.wave_tx_queue_write_index, ctrl_info.wave_tx_queue_read_index, ctrl_info.wave_tx_write_success_index);
			ret  = ioctl(dev, IOCTLWAVE_WRITE, &ctrl_info);
			if (ret != 0)
			{
				perror("ioctl write:");
			}
		}
		else
		{
			printf("[USAGE] ioctl [tx_write_index] [tx_read_index] [tx_succ_index]\n");
		}
	}
	else if (!strcmp( argv[0], "ioctlrx" ))
	{
		if (argc == 1)
		{
			ret  = ioctl(dev, IOCTLWAVE_READ_RX, &ctrl_rx_info);
			if (ret != 0)
			{
				perror("ioctl read:");
			}
			else
			{
				printf("wave_rx_queue_write_index=%d, wave_rx_queue_read_index=%d\n", ctrl_rx_info.wave_rx_queue_write_index, ctrl_rx_info.wave_rx_queue_read_index);
			}
		}
		else if (argc == 3)
		{
			ctrl_rx_info.wave_rx_queue_write_index = atoi(argv[1]);
			ctrl_rx_info.wave_rx_queue_read_index = atoi(argv[2]);
			printf("wave_tx_queue_write_index=%d, wave_tx_queue_read_index=%d\n", ctrl_rx_info.wave_rx_queue_write_index, ctrl_rx_info.wave_rx_queue_read_index);
			ret  = ioctl(dev, IOCTLWAVE_WRITE_RX, &ctrl_rx_info);
			if (ret != 0)
			{
				perror("ioctl write:");
			}
		}
		else
		{
			printf("[USAGE] ioctlrx [tx_write_index] [tx_read_index]\n");
		}
	}
	else if (!strcmp( argv[0], "ver" ))
	{
		u4 = read_wave_dsrc_reg32(WAVE_MAC_HW_VERSION_H_REG_OFFSET);
		printf("MAC Version=0x%08x\n", u4);

		reg_data.b2[1] = reg_readw((wave_dsrc_base + WAVE_MODEM_A_VERSION_H_REG_OFFSET));
		reg_data.b2[0] = reg_readw((wave_dsrc_base + WAVE_MODEM_A_VERSION_L_REG_OFFSET));
		printf("Modem A Version=0x%08x\n", reg_data.b4);

		version_id0.b2 = reg_readw((wave_dsrc_base + WAVE_MODEM_A_VERSION_ID0_REG_OFFSET));
		version_id1.b2 = reg_readw((wave_dsrc_base + WAVE_MODEM_A_VERSION_ID1_REG_OFFSET));
		version_id2.b2 = reg_readw((wave_dsrc_base + WAVE_MODEM_A_VERSION_ID2_REG_OFFSET));

		printf("Modem Version ID=%c%c%c%c%c%c\n", version_id0.b1[1], version_id0.b1[0], version_id1.b1[1], version_id1.b1[0], version_id2.b1[1], version_id2.b1[0]);

	#if WAVE_MERGE

		reg_data.b2[1] = reg_readw((wave_dsrc_base + WAVE_MODEM_B_VERSION_H_REG_OFFSET));
		reg_data.b2[0] = reg_readw((wave_dsrc_base + WAVE_MODEM_B_VERSION_L_REG_OFFSET));
		printf("Modem B Version=0x%08x\n", reg_data.b4);

		version_id0.b2 = reg_readw((wave_dsrc_base + WAVE_MODEM_B_VERSION_ID0_REG_OFFSET));
		version_id1.b2 = reg_readw((wave_dsrc_base + WAVE_MODEM_B_VERSION_ID1_REG_OFFSET));
		version_id2.b2 = reg_readw((wave_dsrc_base + WAVE_MODEM_B_VERSION_ID2_REG_OFFSET));

		printf("Modem B Version ID=%c%c%c%c%c%c\n", version_id0.b1[1], version_id0.b1[0], version_id1.b1[1], version_id1.b1[0], version_id2.b1[1], version_id2.b1[0]);
	#endif

		
	}
	else if (!strcmp( argv[0], "loopback" ))
	{
		if (argc == 2)
		{
			if (atoi(argv[1]) == 0)	/* Normal Mode */
			{
				u2 = reg_readw((wave_dsrc_base + WAVE_MODE_SET_L_REG_OFFSET));
				u2 &= ~LOOP_BACK_MODE_BIT;	/* loopback bit is 0*/
				reg_writew((wave_dsrc_base + WAVE_MODE_SET_L_REG_OFFSET), u2);

				reg_writew((wave_dsrc_base + WAVE_MODEM_A_FTO_THRESHOLD_REG_OFFSET), 0);
				reg_writew((wave_dsrc_base + WAVE_MODEM_B_FTO_THRESHOLD_REG_OFFSET), 0);
			}
			else		/* Loopback mode */
			{
				u2 = reg_readw((wave_dsrc_base + WAVE_MODE_SET_L_REG_OFFSET));
				u2 |= LOOP_BACK_MODE_BIT;	/* loopback bit is 1*/
				reg_writew((wave_dsrc_base + WAVE_MODE_SET_L_REG_OFFSET), u2);

				reg_writew((wave_dsrc_base + WAVE_MODEM_A_FTO_THRESHOLD_REG_OFFSET), 1);
				reg_writew((wave_dsrc_base + WAVE_MODEM_B_FTO_THRESHOLD_REG_OFFSET), 1);
			}
		}
		else
		{
			printf("[USAGE] loopback [mode] : if mod is 0, Normal mode, if mod is 1, Loopback mode\n");	
			u2 = reg_readw((wave_dsrc_base + WAVE_MODE_SET_L_REG_OFFSET));
			if ( u2 & LOOP_BACK_MODE_BIT )
			{
				printf("Current Mode is Loopback Mode\n");
			}
			else
			{
				printf("Current Mode is Normal Mode\n");
			}
			
		}
	}
	else if (!strcmp( argv[0], "estmode" ))
	{
		if (argc == 2)
		{
			if (atoi(argv[1]) == 0)	/* burst mode */
			{
				u2 = reg_readw((wave_dsrc_base + WAVE_MODEM_A_MODE_SELECT_REG_OFFSET));
				u2 &= 0xFFF7;	/* 3rd bit is 0*/
				reg_writew((wave_dsrc_base + WAVE_MODEM_A_MODE_SELECT_REG_OFFSET), u2);
			}
			else		/* Re-estimation mode */
			{
				u2 = reg_readw((wave_dsrc_base + WAVE_MODEM_A_MODE_SELECT_REG_OFFSET));
				u2 |= 0x0008;	/* 3rd bit is 1*/
				reg_writew((wave_dsrc_base + WAVE_MODEM_A_MODE_SELECT_REG_OFFSET), u2);
			}
		}
		else
		{
			printf("[USAGE] estmode [mode] : if mod is 0, burst mode, if mod is 1, re-estimation mode\n");	
			u2 = reg_readw((wave_dsrc_base + WAVE_MODEM_A_MODE_SELECT_REG_OFFSET));
			if ( u2 & 0x0008 )
			{
				printf("Current Mode is Re-estimation Mode\n");
			}
			else
			{
				printf("Current Mode is Burst Mode\n");
			}
			
		}
	}
	else if (!strcmp( argv[0], "estmode1" ))
	{
		if (argc == 2)
		{
			if (atoi(argv[1]) == 0)	/* burst mode */
			{
				u2 = reg_readw((wave_dsrc_base + WAVE_MODEM_B_MODE_SELECT_REG_OFFSET));
				u2 &= 0xFFF7;	/* 3rd bit is 0*/
				reg_writew((wave_dsrc_base + WAVE_MODEM_B_MODE_SELECT_REG_OFFSET), u2);
			}
			else		/* Re-estimation mode */
			{
				u2 = reg_readw((wave_dsrc_base + WAVE_MODEM_B_MODE_SELECT_REG_OFFSET));
				u2 |= 0x0008;	/* 3rd bit is 1*/
				reg_writew((wave_dsrc_base + WAVE_MODEM_B_MODE_SELECT_REG_OFFSET), u2);
			}
		}
		else
		{
			printf("[USAGE] estmode1 [mode] : if mod is 0, burst mode, if mod is 1, re-estimation mode\n");	
			u2 = reg_readw((wave_dsrc_base + WAVE_MODEM_B_MODE_SELECT_REG_OFFSET));
			if ( u2 & 0x0008 )
			{
				printf("Current Mode is Re-estimation Mode\n");
			}
			else
			{
				printf("Current Mode is Burst Mode\n");
			}
			
		}
	}
	else if (!strcmp( argv[0], "diver" ))	/* 이 명령은 Channel A 만 세팅하면 된다. */
	{
		if (argc == 2)
		{
			if (atoi(argv[1]) == 0)	/* Diversity Off */
			{
				u2 = reg_readw((wave_dsrc_base + WAVE_MODEM_A_PK_OFF_THRESHOLD_REG_OFFSET));
				u2 &= 0xDFFF;	/* 13rd bit is 0*/
				reg_writew((wave_dsrc_base + WAVE_MODEM_A_PK_OFF_THRESHOLD_REG_OFFSET), u2);
			}
			else		/* Diversity On */
			{
				u2 = reg_readw((wave_dsrc_base + WAVE_MODEM_A_PK_OFF_THRESHOLD_REG_OFFSET));
				u2 |= 0x2000;	/* 13rd bit is 1*/
				reg_writew((wave_dsrc_base + WAVE_MODEM_A_PK_OFF_THRESHOLD_REG_OFFSET), u2);
			}
		}
		else
		{
			printf("[USAGE] diver [val] : if val is 0, Diversity Off, if val is 1, Diversity On\n");	
			u2 = reg_readw((wave_dsrc_base + WAVE_MODEM_A_PK_OFF_THRESHOLD_REG_OFFSET));
			if ( u2 & 0x2000 )
			{
				printf("Current Mode is Diversity On\n");
			}
			else
			{
				printf("Current Mode is Diversity Off\n");
			}
			
		}
	}
	else if (!strcmp( argv[0], "chfilter" ))	
	{
		if (argc == 2)
		{
			if (atoi(argv[1]) == 0)	/* Channel Filter Off */
			{
				u2 = reg_readw((wave_dsrc_base + WAVE_MODEM_A_PK_OFF_THRESHOLD_REG_OFFSET));
				u2 &= 0xEFFF;	/* 12rd bit is 0*/
				reg_writew((wave_dsrc_base + WAVE_MODEM_A_PK_OFF_THRESHOLD_REG_OFFSET), u2);
			}
			else		/* Channel Filter On */
			{
				u2 = reg_readw((wave_dsrc_base + WAVE_MODEM_A_PK_OFF_THRESHOLD_REG_OFFSET));
				u2 |= 0x1000;	/* 12rd bit is 1*/
				reg_writew((wave_dsrc_base + WAVE_MODEM_A_PK_OFF_THRESHOLD_REG_OFFSET), u2);
			}
		}
		else
		{
			printf("[USAGE] chfilter [val] : if val is 0, Channel Filter Disable, if val is 1, Channel Filter Enable\n");	
			u2 = reg_readw((wave_dsrc_base + WAVE_MODEM_A_PK_OFF_THRESHOLD_REG_OFFSET));
			if ( u2 & 0x1000 )
			{
				printf("Current Mode is Channel Filter Enable\n");
			}
			else
			{
				printf("Current Mode is Channel Filter Disable\n");
			}
			
		}
	}
	else if (!strcmp( argv[0], "chfilter1" ))	
	{
		if (argc == 2)
		{
			if (atoi(argv[1]) == 0)	/* Channel Filter Off */
			{
				u2 = reg_readw((wave_dsrc_base + WAVE_MODEM_B_PK_OFF_THRESHOLD_REG_OFFSET));
				u2 &= 0xEFFF;	/* 12rd bit is 0*/
				reg_writew((wave_dsrc_base + WAVE_MODEM_B_PK_OFF_THRESHOLD_REG_OFFSET), u2);
			}
			else		/* Channel Filter On */
			{
				u2 = reg_readw((wave_dsrc_base + WAVE_MODEM_B_PK_OFF_THRESHOLD_REG_OFFSET));
				u2 |= 0x1000;	/* 12rd bit is 1*/
				reg_writew((wave_dsrc_base + WAVE_MODEM_B_PK_OFF_THRESHOLD_REG_OFFSET), u2);
			}
		}
		else
		{
			printf("[USAGE] chfilter1 [val] : if val is 0, Channel Filter Disable, if val is 1, Channel Filter Enable\n");	
			u2 = reg_readw((wave_dsrc_base + WAVE_MODEM_B_PK_OFF_THRESHOLD_REG_OFFSET));
			if ( u2 & 0x1000 )
			{
				printf("Current Mode is Channel Filter Enable\n");
			}
			else
			{
				printf("Current Mode is Channel Filter Disable\n");
			}
			
		}
	}
	else if (strcmp(argv[0], "ecdsa_fix_flag") == 0)
	{
		if (argc == 2)
		{
			ecdsa_sw_test_fix_flag = atoi(argv[1]);
			printf("ecdsa_sw_test_fix_flag = %d\n", ecdsa_sw_test_fix_flag);
		}
		else
		{
			printf("Current ecdsa_sw_test_fix_flag = %d\n", ecdsa_sw_test_fix_flag);
		}
	}
	else if (strcmp(argv[0], "ecdsa_test_flag") == 0)
	{
		if (argc == 2)
		{
			ecdsa_test_flag = atoi(argv[1]);
			printf("ecdsa_test_flag = %d\n", ecdsa_test_flag);
		}
		else
		{
			printf("Current ecdsa_test_flag = %d\n", ecdsa_test_flag);
		}
	}
	else if (strcmp(argv[0], "ecdsa_sw_flag") == 0)
	{
		if (argc == 2)
		{
			g_ecdsa_sw_proc_flag = atoi(argv[1]);

			if (g_ecdsa_sw_proc_flag == 1)
			{
				ecdsa_sw_test_fix_flag = 1;
			}
			else
			{
				ecdsa_sw_test_fix_flag = 0;
			}
			
			printf("g_ecdsa_sw_proc_flag = %d\n", g_ecdsa_sw_proc_flag);
		}
		else
		{
			printf("Current g_ecdsa_sw_proc_flag = %d\n", g_ecdsa_sw_proc_flag);
		}
	}
	else if (strcmp(argv[0], "ecdsa_msg_fault") == 0)
	{
		if (argc == 2)
		{
			g_ecdsa_msg_falut_flag = atoi(argv[1]);
			printf("g_ecdsa_msg_falut_flag = %d\n", g_ecdsa_msg_falut_flag);
		}
		else
		{
			printf("Current g_ecdsa_msg_falut_flag = %d\n", g_ecdsa_msg_falut_flag);
		}
	}
	else if (strcmp(argv[0], "aes_cmsg_fault") == 0)
	{
		if (argc == 2)
		{
			g_aes_cmsg_falut_flag = atoi(argv[1]);
			printf("g_aes_cmsg_falut_flag = %d\n", g_aes_cmsg_falut_flag);
		}
		else
		{
			printf("Current g_aes_cmsg_falut_flag = %d\n", g_aes_cmsg_falut_flag);
		}
	}
	else if (strcmp(argv[0], "ecdsa_key_fault") == 0)
	{
		if (argc == 2)
		{
			g_ecdsa_public_key_falut_flag = atoi(argv[1]);
			printf("g_ecdsa_public_key_falut_flag = %d\n", g_ecdsa_public_key_falut_flag);
		}
		else
		{
			printf("Current g_ecdsa_public_key_falut_flag = %d\n", g_ecdsa_public_key_falut_flag);
		}
	}
	else if (strcmp(argv[0], "aes_key") == 0)
	{
		if (argc == 2)
		{
			g_aes_key_index = atoi(argv[1]);
			printf("g_aes_key_index = %d\n", g_aes_key_index);
		}
		else
		{
			printf("Current g_aes_key_index = %d\n", g_aes_key_index);
		}
	}
	else if (strcmp(argv[0], "aes_key_value") == 0)
	{
		if (argc == 17)
		{
			for ( i = 0; i < 16; i++)
				g_aes_key[0][i] = (U1)strtoul(argv[(i+1)], NULL, 16);
		}
		else
		{
			for ( i = 0; i < 16; i++)
			{
				printf("[%02x]", g_aes_key[0][i]);
				if ( ((i+1)%10) == 0 )
					printf("\n");
			}
			printf("\n");
		}
	}
	
	else if (strcmp(argv[0], "dmrsn") == 0)		/* Display MAC Rx Sequence Number */
	{
		if (argc == 2)
		{
			g_display_mac_rx_seq_num_flag = (U1)atoi(argv[1]);
			printf("g_display_mac_rx_seq_num_flag = %d\n", g_display_mac_rx_seq_num_flag);
		}
		else
		{
			printf("Current g_display_mac_rx_seq_num_flag = %d\n", g_display_mac_rx_seq_num_flag);
		}
	}
	else if (strcmp(argv[0], "print") == 0)
	{
		if (argc == 2)
		{
			val = atoi(argv[1]);
			
			if (val == 0)	//debug
			{
				if( print_flag & WAVE_MAC_RX_DEBUG_MODE )	/* deg 명령에 해당 */
				{ 
					printf("\nPrint for WAVE_MAC_RX_DATA debug Disable\n");
					print_flag &= ~WAVE_MAC_RX_DEBUG_MODE;
				}
				else 
				{
					printf("\nPrint for WAVE_MAC_RX debug Enable\n");
					print_flag |= WAVE_MAC_RX_DEBUG_MODE;
				}
			}
			else if (val == 1)	//debug
			{
				if( print_flag & WAVE_MAC_TX_DEBUG_MODE )	/* deg 명령에 해당 */
				{ 
					printf("\nPrint for WAVE_MAC_TX debug Disable\n");
					print_flag &= ~WAVE_MAC_TX_DEBUG_MODE;
				}
				else 
				{
					printf("\nPrint for WAVE_MAC_TX debug Enable\n");
					print_flag |= WAVE_MAC_TX_DEBUG_MODE;
				}
			}
			else if (val == 2)	//debug
			{
				if( print_flag & ETHERNET_RX_DEBUG_MODE )	/* deg 명령에 해당 */
				{ 
					printf("\nPrint for ETHERNET_RX debug Disable\n");
					print_flag &= ~ETHERNET_RX_DEBUG_MODE;
				}
				else 
				{
					printf("\nPrint for ETHERNET_RX debug Enable\n");
					print_flag |= ETHERNET_RX_DEBUG_MODE;
				}
			}
			else if (val == 3)	//debug
			{
				if( print_flag & ETHERNET_TX_DEBUG_MODE )	/* deg 명령에 해당 */
				{ 
					printf("\nPrint for ETHERNET_TX debug Disable\n");
					print_flag &= ~ETHERNET_TX_DEBUG_MODE;
				}
				else 
				{
					printf("\nPrint for ETHERNET_TX debug Enable\n");
					print_flag |= ETHERNET_TX_DEBUG_MODE;
				}
			}
			else if(val == 4)	//AES Debug
			{
				if(aes_print_flag== FALSE)
				{
					aes_print_flag=TRUE;
					printf("\n>> AES Test Start...\n\r");
				}
				else
				{
					aes_print_flag=FALSE;
					printf("\n>> AES Test End...\n\r");
				}
			}
			else if(val == 5)	//SHA Debug
			{
				if(sha_print_flag== FALSE)
				{
					sha_print_flag=TRUE;
					printf("\n>> SHA Test Start...\n\r");
				}
				else
				{
					sha_print_flag=FALSE;
					printf("\n>> SHA Test End...\n\r");
				}
			}
			else if(val == 6)	//ECDSA Debug
			{
				if(ecdsa_print_flag== FALSE)
				{
					ecdsa_print_flag=TRUE;
					printf("\n>> ECDSA Test Start...\n\r");
				}
				else
				{
					ecdsa_print_flag=FALSE;
					printf("\n>> ECDSA Test End...\n\r");
				}
			}
			else if(val == 7)	//ECIES Debug
			{
				if(ecies_print_flag== FALSE)
				{
					ecies_print_flag=TRUE;
					printf("\n>> ECIES Test Start...\n\r");
				}
				else
				{
					ecies_print_flag=FALSE;
					printf("\n>> ECIES Test End...\n\r");
				}
			}
			else if (val == 8)	//debug
			{
				if( print_flag & WAVE_MAC_RX_MANAGE_DEBUG_MODE )	/* deg 명령에 해당 */
				{ 
					printf("\nPrint for WAVE MAC RX Manage Data debug Disable\n");
					print_flag &= ~WAVE_MAC_RX_MANAGE_DEBUG_MODE;
				}
				else 
				{
					printf("\nPrint for WAVE MAC RX Manage Data debug Enable\n");
					print_flag |= WAVE_MAC_RX_MANAGE_DEBUG_MODE;
				}
			}
			else if(val == 9)	//ECIES Debug
			{
				if(g_security_printf_flag== FALSE)
				{
					g_security_printf_flag=TRUE;
					printf("\n>> Security Print Test Start...\n\r");
				}
				else
				{
					g_security_printf_flag=FALSE;
					printf("\n>> Security Print Test End...\n\r");
				}
			}
			else if (val == 10)
			{
				print_sr5500_test_result();
				
				//start_timer(&SR5500_TEST_RX_TIMER_ID, sr5500_rx_test_timer_handler, 3, 0);
			}
			printf("current print_flag=%d\n", print_flag);
		}
		else
		{
			printf("[usage] print [value] : print for debugging enable or disable by toggle method\n");
			printf("	value 0: WAVE_RX_DATA, 1: WAVE_TX, 2: ETH_RX, 3: ETH_TX, 4:AES, 5:SHA, 6:ECDSA, 7:ECIES, 8:WAVE_RX_MNG, 9: Security Print\n");
			printf("Current print for debugging\n");
			if( print_flag & WAVE_MAC_RX_DEBUG_MODE)
			{ 
				printf("Print for WAVE RX DATA Enable\n");
			}
			else 
			{
				printf("Print for WAVE RX DATA Disable\n");
			}
			if( print_flag & WAVE_MAC_TX_DEBUG_MODE)
			{ 
				printf("Print for WAVE TX Enable\n");
			}
			else 
			{
				printf("Print for WAVE TX Disable\n");
			}
			if( print_flag & ETHERNET_RX_DEBUG_MODE)
			{ 
				printf("Print for ETHERNET RX Enable\n");
			}
			else 
			{
				printf("Print for ETHERNET RX Disable\n");
			}
			if( print_flag & ETHERNET_TX_DEBUG_MODE)
			{ 
				printf("Print for ETHERNET TX Enable\n");
			}
			else 
			{
				printf("Print for ETHERNET TX Disable\n");
			}
			if(aes_print_flag == TRUE)
			{
				printf("Print for AES Enable\n");
			}
			else
			{
				printf("Print for AES Disable\n");
			}
			if(sha_print_flag == TRUE)
			{
				printf("Print for SHA Enable\n");
			}
			else
			{
				printf("Print for SHA Disable\n");
			}
			if(ecdsa_print_flag == TRUE)
			{
				printf("Print for ECDSA Enable\n");
			}
			else
			{
				printf("Print for ECDSA Disable\n");
			}
			if(ecies_print_flag == TRUE)
			{
				printf("Print for ECIES Enable\n");
			}
			else
			{
				printf("Print for ECIES Disable\n");
			}
			if( print_flag & WAVE_MAC_RX_MANAGE_DEBUG_MODE)
			{ 
				printf("Print for WAVE RX MNG Enable\n");
			}
			else 
			{
				printf("Print for WAVE RX MNG Disable\n");
			}
		}
	}
	else if (!strcmp( argv[0], "open" ))
	{
		dev = open(DEVICE_FILENAME, O_RDWR|O_NDELAY);
	
		if(dev >= 0)
			printf("[wave_externel_interrupt_init]%s open Success, [%d]!!\n", DEVICE_FILENAME, dev);
		else
		{
			//printf("[wave_externel_interrupt_init]%s open Fail!!\n", DEVICE_FILENAME);
			perror("[wave_externel_interrupt_init]\n");
			return(-1);
		}
	}
	else if (!strcmp( argv[0], "cntmac" ))
	{
		printf("**** MAC DATA counters *************************\n");
		printf("*** Tx DATA : %d\n", read_wave_dsrc_reg32(WAVE_MAC_A_TX_DATA_COUNTER_H_REG_OFFSET));
		printf("*** Rx DATA : %d\n", read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_COUNTER_H_REG_OFFSET));
		printf("*** CRC Err : %d\n", read_wave_dsrc_reg32(WAVE_MAC_A_CRC_ERR_COUNTER_H_REG_OFFSET));
		printf("*** PHY Err : %d\n", read_wave_dsrc_reg32(WAVE_MAC_A_PHY_ERR_COUNTER_H_REG_OFFSET));
		printf("*** Tx DATA including Retry : 0\n");
		printf("*** Tx ACK : %d\n",read_wave_dsrc_reg32(WAVE_MAC_A_TX_ACK_COUNTER_H_REG_OFFSET));							/* 내가 상대방으로 보낸 ACK 갯수 */
		printf("*** Rx MyACK : %d\n",read_wave_dsrc_reg32(WAVE_MAC_A_RX_MY_ACK_COUNTER_H_REG_OFFSET));					/* 상대방이 나에게 보낸 ACK 갯수 */
		printf("*** Rx Other ACK : %d\n",read_wave_dsrc_reg32(WAVE_MAC_A_RX_OTHER_ACK_COUNTER_H_REG_OFFSET));				/* 상대방이 내가 아닌 다른곳으로 ACK 갯수 */
		printf("*** Rx Total frame : %d\n", read_wave_dsrc_reg32(WAVE_MAC_A_RX_FRAME_COUNTER_H_REG_OFFSET));
		printf("********************************************\n");
		printf("**** MODEM DATA counters *************************\n");
		reg_data.b2[1] = reg_readw((wave_dsrc_base + WAVE_MODEM_A_PHY_ERR0_CNT_H_REG_OFFSET));
		reg_data.b2[0] = reg_readw((wave_dsrc_base + WAVE_MODEM_A_PHY_ERR0_CNT_L_REG_OFFSET));
		printf("*** NO Error : %d\n", reg_data.b4);
		reg_data.b2[1] = reg_readw((wave_dsrc_base + WAVE_MODEM_A_PHY_ERR1_CNT_H_REG_OFFSET));
		reg_data.b2[0] = reg_readw((wave_dsrc_base + WAVE_MODEM_A_PHY_ERR1_CNT_L_REG_OFFSET));
		printf("*** Parity Error : %d\n", reg_data.b4);
		reg_data.b2[1] = reg_readw((wave_dsrc_base + WAVE_MODEM_A_PHY_ERR2_CNT_H_REG_OFFSET));
		reg_data.b2[0] = reg_readw((wave_dsrc_base + WAVE_MODEM_A_PHY_ERR2_CNT_L_REG_OFFSET));
		printf("*** Carrier Lost : %d\n", reg_data.b4);
		reg_data.b2[1] = reg_readw((wave_dsrc_base + WAVE_MODEM_A_PHY_ERR3_CNT_H_REG_OFFSET));
		reg_data.b2[0] = reg_readw((wave_dsrc_base + WAVE_MODEM_A_PHY_ERR3_CNT_L_REG_OFFSET));
		printf("*** Unsupport Rate : %d\n", reg_data.b4);

		reg_data.b2[1] = reg_readw((wave_dsrc_base + WAVE_MODEM_A_CCA_BUSY_COUNT_H_REG_OFFSET));
		reg_data.b2[0] = reg_readw((wave_dsrc_base + WAVE_MODEM_A_CCA_BUSY_COUNT_L_REG_OFFSET));
		printf("*** CCA Busy Counter : %d\n", reg_data.b4);

		reg_data.b2[1] = reg_readw((wave_dsrc_base + WAVE_MODEM_A_PACKET_DET_COUNT_H_REG_OFFSET));
		reg_data.b2[0] = reg_readw((wave_dsrc_base + WAVE_MODEM_A_PACKET_DET_COUNT_L_REG_OFFSET));
		printf("*** Packet Detect: %d\n", reg_data.b4);
		reg_data.b2[1] = reg_readw((wave_dsrc_base + WAVE_MODEM_A_AGC_COMP_COUNT_H_REG_OFFSET));
		reg_data.b2[0] = reg_readw((wave_dsrc_base + WAVE_MODEM_A_AGC_COMP_COUNT_L_REG_OFFSET));
		printf("*** AGC Complete: %d\n", reg_data.b4);
		reg_data.b2[1] = reg_readw((wave_dsrc_base + WAVE_MODEM_A_DECIMATION_COMP_COUNT_H_REG_OFFSET));
		reg_data.b2[0] = reg_readw((wave_dsrc_base + WAVE_MODEM_A_DECIMATION_COMP_COUNT_L_REG_OFFSET));
		printf("*** Decimation Complete: %d\n", reg_data.b4);
		reg_data.b2[1] = reg_readw((wave_dsrc_base + WAVE_MODEM_A_SYMBOL_DET_COUNT_H_REG_OFFSET));
		reg_data.b2[0] = reg_readw((wave_dsrc_base + WAVE_MODEM_A_SYMBOL_DET_COUNT_L_REG_OFFSET));
		printf("*** Symbol Detect: %d\n", reg_data.b4);
		printf("********************************************\n");
	#if 0	//SHKO
		printf("****Control counters*********************\n");
		printf("*** Tx ACK : %d\n", read_wave_dsrc_reg32(WAVE_MAC_A_TX_ACK_COUNTER_H_REG_OFFSET));
		printf("*** Rx ACK : %d\n", read_wave_dsrc_reg32(WAVE_MAC_A_RX_MY_ACK_COUNTER_H_REG_OFFSET));
	#endif	//SHKO

		printf("mac_rx_count=%d\n", mac_rx_count);
		printf("wave_mac_rx_retry_count=%d\n", wave_mac_rx_retry_count);
		printf("wave_mac_rx_duplication_count=%d\n", wave_mac_rx_duplication_count);
		printf("wave_mac_rx_no_retry_duplication_count=%d\n", wave_mac_rx_no_retry_duplication_count);
		
	}
#if WAVE_MERGE
	else if (!strcmp( argv[0], "cntmac1" ))
	{
		printf("**** MAC DATA counters *************************\n");
		printf("*** Tx DATA : %d\n", read_wave_dsrc_reg32(WAVE_MAC_B_TX_DATA_COUNTER_H_REG_OFFSET));
		printf("*** Rx DATA : %d\n", read_wave_dsrc_reg32(WAVE_MAC_B_RX_DATA_COUNTER_H_REG_OFFSET));
		printf("*** CRC Err : %d\n", read_wave_dsrc_reg32(WAVE_MAC_B_CRC_ERR_COUNTER_H_REG_OFFSET));
		printf("*** PHY Err : %d\n", read_wave_dsrc_reg32(WAVE_MAC_B_PHY_ERR_COUNTER_H_REG_OFFSET));
		printf("*** Tx DATA including Retry : 0\n");
		printf("*** Tx ACK : %d\n",read_wave_dsrc_reg32(WAVE_MAC_B_TX_ACK_COUNTER_H_REG_OFFSET));							/* 내가 상대방으로 보낸 ACK 갯수 */
		printf("*** Rx MyACK : %d\n",read_wave_dsrc_reg32(WAVE_MAC_B_RX_MY_ACK_COUNTER_H_REG_OFFSET));					/* 상대방이 나에게 보낸 ACK 갯수 */
		printf("*** Rx Other ACK : %d\n",read_wave_dsrc_reg32(WAVE_MAC_B_RX_OTHER_ACK_COUNTER_H_REG_OFFSET));				/* 상대방이 내가 아닌 다른곳으로 ACK 갯수 */
		printf("*** Rx Total frame : %d\n", read_wave_dsrc_reg32(WAVE_MAC_B_RX_FRAME_COUNTER_H_REG_OFFSET));
		printf("********************************************\n");
		printf("**** MODEM DATA counters *************************\n");
		reg_data.b2[1] = reg_readw((wave_dsrc_base + WAVE_MODEM_B_PHY_ERR0_CNT_H_REG_OFFSET));
		reg_data.b2[0] = reg_readw((wave_dsrc_base + WAVE_MODEM_B_PHY_ERR0_CNT_L_REG_OFFSET));
		printf("*** NO Error : %d\n", reg_data.b4);
		reg_data.b2[1] = reg_readw((wave_dsrc_base + WAVE_MODEM_B_PHY_ERR1_CNT_H_REG_OFFSET));
		reg_data.b2[0] = reg_readw((wave_dsrc_base + WAVE_MODEM_B_PHY_ERR1_CNT_L_REG_OFFSET));
		printf("*** Parity Error : %d\n", reg_data.b4);
		reg_data.b2[1] = reg_readw((wave_dsrc_base + WAVE_MODEM_B_PHY_ERR2_CNT_H_REG_OFFSET));
		reg_data.b2[0] = reg_readw((wave_dsrc_base + WAVE_MODEM_B_PHY_ERR2_CNT_L_REG_OFFSET));
		printf("*** Carrier Lost : %d\n", reg_data.b4);
		reg_data.b2[1] = reg_readw((wave_dsrc_base + WAVE_MODEM_B_PHY_ERR3_CNT_H_REG_OFFSET));
		reg_data.b2[0] = reg_readw((wave_dsrc_base + WAVE_MODEM_B_PHY_ERR3_CNT_L_REG_OFFSET));
		printf("*** Unsupport Rate : %d\n", reg_data.b4);

		reg_data.b2[1] = reg_readw((wave_dsrc_base + WAVE_MODEM_B_CCA_BUSY_COUNT_H_REG_OFFSET));
		reg_data.b2[0] = reg_readw((wave_dsrc_base + WAVE_MODEM_B_CCA_BUSY_COUNT_L_REG_OFFSET));
		printf("*** CCA Busy Counter : %d\n", reg_data.b4);

		reg_data.b2[1] = reg_readw((wave_dsrc_base + WAVE_MODEM_B_PACKET_DET_COUNT_H_REG_OFFSET));
		reg_data.b2[0] = reg_readw((wave_dsrc_base + WAVE_MODEM_B_PACKET_DET_COUNT_L_REG_OFFSET));
		printf("*** Packet Detect: %d\n", reg_data.b4);
		reg_data.b2[1] = reg_readw((wave_dsrc_base + WAVE_MODEM_B_AGC_COMP_COUNT_H_REG_OFFSET));
		reg_data.b2[0] = reg_readw((wave_dsrc_base + WAVE_MODEM_B_AGC_COMP_COUNT_L_REG_OFFSET));
		printf("*** AGC Complete: %d\n", reg_data.b4);
		reg_data.b2[1] = reg_readw((wave_dsrc_base + WAVE_MODEM_B_DECIMATION_COMP_COUNT_H_REG_OFFSET));
		reg_data.b2[0] = reg_readw((wave_dsrc_base + WAVE_MODEM_B_DECIMATION_COMP_COUNT_L_REG_OFFSET));
		printf("*** Decimation Complete: %d\n", reg_data.b4);
		reg_data.b2[1] = reg_readw((wave_dsrc_base + WAVE_MODEM_B_SYMBOL_DET_COUNT_H_REG_OFFSET));
		reg_data.b2[0] = reg_readw((wave_dsrc_base + WAVE_MODEM_B_SYMBOL_DET_COUNT_L_REG_OFFSET));
		printf("*** Symbol Detect: %d\n", reg_data.b4);
		printf("********************************************\n");
	#if 0	//SHKO
		printf("****Control counters*********************\n");
		printf("*** Tx ACK : %d\n", read_wave_dsrc_reg32(WAVE_MAC_A_TX_ACK_COUNTER_H_REG_OFFSET));
		printf("*** Rx ACK : %d\n", read_wave_dsrc_reg32(WAVE_MAC_A_RX_MY_ACK_COUNTER_H_REG_OFFSET));
	#endif	//SHKO

		printf("mac_rx_count=%d\n", mac_rx_count);
		printf("wave_mac_rx_retry_count=%d\n", wave_mac_rx_retry_count);
		printf("wave_mac_rx_duplication_count=%d\n", wave_mac_rx_duplication_count);
		printf("wave_mac_rx_no_retry_duplication_count=%d\n", wave_mac_rx_no_retry_duplication_count);
	}
#endif
	else if (!strcmp( argv[0], "clrcnt" ))
	{
		u2 = reg_readw((wave_dsrc_base + WAVE_CONTROL_L_REG_OFFSET));
		u2 |= MAC_A_COUNTER_CLEAR_BIT;
		reg_writew((wave_dsrc_base + WAVE_CONTROL_L_REG_OFFSET), u2);
		

		u2 = reg_readw((wave_dsrc_base + WAVE_MODEM_A_ETC_REG_OFFSET));
		//printf("read u4=0x%08x\n", u4);
		u2 |= PHY_COUNTER_CLEAR_BIT;
		//printf("write u4=0x%08x\n", u4);
		reg_writew((wave_dsrc_base + WAVE_MODEM_A_ETC_REG_OFFSET), u2);

		mac_rx_count = 0;
		wave_mac_rx_retry_count = 0;
		wave_mac_rx_duplication_count = 0;
		wave_mac_rx_no_retry_duplication_count = 0;
	}
#if WAVE_MERGE
	else if (!strcmp( argv[0], "clrcnt1" ))
	{
		u2 = reg_readw((wave_dsrc_base + WAVE_CONTROL_L_REG_OFFSET));
		u2 |= MAC_B_COUNTER_CLEAR_BIT;
		reg_writew((wave_dsrc_base + WAVE_CONTROL_L_REG_OFFSET), u2);

		u2 = reg_readw((wave_dsrc_base + WAVE_MODEM_B_ETC_REG_OFFSET));
		//printf("read u4=0x%08x\n", u4);
		u2 |= PHY_COUNTER_CLEAR_BIT;
		//printf("write u4=0x%08x\n", u4);
		reg_writew((wave_dsrc_base + WAVE_MODEM_B_ETC_REG_OFFSET), u2);

		mac_rx_count = 0;
		wave_mac_rx_retry_count = 0;
		wave_mac_rx_duplication_count = 0;
		wave_mac_rx_no_retry_duplication_count = 0;
	}
#endif
	else if (!strcmp( argv[0], "timer" ))
	{
		if (argc < 3)
		{
			printf("[USAGE] timer [id] [value]\n");
			printf("if value==1, Timer Start!!, if value==0, Timer Stop!!\n");
			return(0);
		}

		if (atoi(argv[2]) == 1 )
		{
			//start_timer(atoi(argv[1]) );
			start_timer(&wave_tx_timer_id, wave_tx_timer_handler, 1, 0);
		}
		else
		{
			//stop_timer(atoi(argv[1]) );
			stop_timer(&wave_tx_timer_id);
		}

		
	}
	else if (!strcmp( argv[0], "mactable" ))
	{
		for ( i = 0; i < WAVE_MAC_TABLE_MAX_NUM; i++)
		{
			if ( wave_rx_dest_mac_table[i].Ocupied == 1 )
			{
				printf("[%d][%02x:%02x:%02x:%02x:%02x:%02x]\n", i, wave_rx_dest_mac_table[i].wave_rx_dest_mac_addr[0], 
					wave_rx_dest_mac_table[i].wave_rx_dest_mac_addr[1], wave_rx_dest_mac_table[i].wave_rx_dest_mac_addr[2], 
					wave_rx_dest_mac_table[i].wave_rx_dest_mac_addr[3], wave_rx_dest_mac_table[i].wave_rx_dest_mac_addr[4], 
					wave_rx_dest_mac_table[i].wave_rx_dest_mac_addr[5]); 
				
			}
		}
	}
	else if (!strcmp( argv[0], "ethdbf" ))
	{
		if (argc < 2)
		{
			printf("[USAGE] ethdbf [value]\n");
			printf("Current eth_rx_broadcast_discard_flag = %d\n", eth_rx_broadcast_discard_flag);
			return(0);
		}

		eth_rx_broadcast_discard_flag = atoi(argv[1]);
		printf("eth_rx_broadcast_discard_flag = %d\n", eth_rx_broadcast_discard_flag);
	}
	else if (!strcmp( argv[0], "rts" ))
	{
		if (argc < 2)
		{
			printf("[USAGE] rts [value]\n");
			printf("Current g_rts_rate = %d\n", g_rts_rate);
			return(0);
		}

		g_rts_rate = (U4)atoi(argv[1]);
		printf("default_wave_tx_delay = %d\n", g_rts_rate);
	}
	else if (!strcmp( argv[0], "txdelay" ))
	{
		if (argc < 2)
		{
			printf("[USAGE] txdelay [value]\n");
			printf("Current default_wave_tx_delay = %d\n", default_wave_tx_delay);
			return(0);
		}

		default_wave_tx_delay = atoi(argv[1]);
		printf("default_wave_tx_delay = %d\n", default_wave_tx_delay);
	}
	else if (!strcmp( argv[0], "txpower" ))
	{
		if (argc < 2)
		{
			printf("[USAGE] txpower [value]\n");
			printf("Current Tx power = %d\n", wave_mac_default_tx_power);
			return(0);
		}

		val = atoi(argv[1]);

		if ( (val < 1) || (val > 8) )
		{
			printf("Invalid Tx power=%d\n", val);
			printf("Tx Power Value range must be from 1 to 8!!\n");
			return(0);
		}

		wave_mac_default_tx_power = val;
		printf("wave_mac_default_tx_power = %d\n", wave_mac_default_tx_power);
	}
	else if (!strcmp( argv[0], "rfpower" ))
	{
		if (argc < 2)
		{
			printf("[USAGE] rfpower [value]\n");
			printf("if value is 0, Power Level is Etri Set, if value is 1, Power Level is Ranix Set\n");
			return(0);
		}

		val = atoi(argv[1]);
		if (val)
		{
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET1_2_REG_OFFSET), 0x0600);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET3_4_REG_OFFSET), 0x120C);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET5_6_REG_OFFSET), 0x1E18);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET7_8_REG_OFFSET), 0x2A3F);
		}
		else
		{
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET1_2_REG_OFFSET), 0x0180);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET3_4_REG_OFFSET), 0x028C);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET5_6_REG_OFFSET), 0x0798);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_TX_PWR_SET7_8_REG_OFFSET), 0x0AA4);
		}
		
	}
#if WAVE_MERGE
	else if (!strcmp( argv[0], "rfpower1" ))
	{
		if (argc < 2)
		{
			printf("[USAGE] rfpower1 [value]\n");
			printf("if value is 0, Power Level is Etri Set, if value is 1, Power Level is Ranix Set\n");
			return(0);
		}

		val = atoi(argv[1]);
		if (val)
		{
			reg_writew((wave_dsrc_base + WAVE_MODEM_B_TX_PWR_SET1_2_REG_OFFSET), 0x0600);
			reg_writew((wave_dsrc_base + WAVE_MODEM_B_TX_PWR_SET3_4_REG_OFFSET), 0x120C);
			reg_writew((wave_dsrc_base + WAVE_MODEM_B_TX_PWR_SET5_6_REG_OFFSET), 0x1E18);
			reg_writew((wave_dsrc_base + WAVE_MODEM_B_TX_PWR_SET7_8_REG_OFFSET), 0x2A3F);
		}
		else
		{
			reg_writew((wave_dsrc_base + WAVE_MODEM_B_TX_PWR_SET1_2_REG_OFFSET), 0x0180);
			reg_writew((wave_dsrc_base + WAVE_MODEM_B_TX_PWR_SET3_4_REG_OFFSET), 0x028C);
			reg_writew((wave_dsrc_base + WAVE_MODEM_B_TX_PWR_SET5_6_REG_OFFSET), 0x0798);
			reg_writew((wave_dsrc_base + WAVE_MODEM_B_TX_PWR_SET7_8_REG_OFFSET), 0x0AA4);
		}
		
	}
#endif
	else if (!strcmp( argv[0], "datarate" ))
	{
		if (argc < 2)
		{
			printf("[USAGE] datarate [value]\n");
			printf("Current Datarate = %d\n", wave_mac_default_data_rate);
			return(0);
		}

		val = atoi(argv[1]);

		if ( (val != 3) && (val != 4) && (val != 6) && (val != 9) && (val != 12) && (val != 18) && (val != 24) && (val != 27))
		{
			printf("Invalid Datarate=%d\n", val);
			printf("Datarate must be 3 or 4 or 6 or 9 or 12 or 18 or 24 or 27\n");
			return(0);
		}

		wave_mac_default_data_rate = val;
		printf("wave_mac_default_data_rate = %d\n", wave_mac_default_data_rate);
	}
	else if (!strcmp( argv[0], "multiac" ))
	{
		if (argc < 2)
		{
			printf("[USAGE] multiac [value]\n");
			printf("Current multi_ac_channel_alloc_flag = %d\n", multi_ac_channel_alloc_flag);
			return(0);
		}

		val = atoi(argv[1]);

		multi_ac_channel_alloc_flag = val;

		
		printf("multi_ac_channel_alloc_flag = %d\n", multi_ac_channel_alloc_flag);
	}
	else if (!strcmp( argv[0], "fchange" ))
	{
		if (argc != 2)
		{
			printf("[USAGE] fchange [freq] \n");
			printf(" if freq is 50, RF Frequency is 5.85GHz\n");
			printf(" if freq is 60, RF Frequency is 5.86GHz\n");
			printf(" if freq is 70, RF Frequency is 5.87GHz\n");
			return(0);
		}
		
		val = atoi(argv[1]);
		if (val == 50)
		{
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_MAX2829_DATA3_REG_OFFSET), 0x00EA);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_MAX2829_DATA4_REG_OFFSET), 0x0000);

			reg_writew((wave_dsrc_base + WAVE_MODEM_A_RF_SPI_CTRL_REG_OFFSET), 0x2000);	/* SPI 를 통해 RF 칩으로 세팅을 하게 한다. */
		}
		else if (val == 60) /* 5860*0.8/20M = 234.4, 234 = 0xEA */
		{
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_MAX2829_DATA3_REG_OFFSET), 0x20EA);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_MAX2829_DATA4_REG_OFFSET), 0x1999);

			reg_writew((wave_dsrc_base + WAVE_MODEM_A_RF_SPI_CTRL_REG_OFFSET), 0x2000);	/* SPI 를 통해 RF 칩으로 세팅을 하게 한다. */
		}
		else if (val == 70)
		{
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_MAX2829_DATA3_REG_OFFSET), 0x00EA);
			reg_writew((wave_dsrc_base + WAVE_MODEM_A_MAX2829_DATA4_REG_OFFSET), 0x3333);

			reg_writew((wave_dsrc_base + WAVE_MODEM_A_RF_SPI_CTRL_REG_OFFSET), 0x2000);	/* SPI 를 통해 RF 칩으로 세팅을 하게 한다. */
		}
		else
		{
			printf("Not Supported val = %d\n", val);
			printf("[USAGE] fchange [freq] \n");
			printf(" if freq is 50, RF Frequency is 5.85GHz\n");
			printf(" if freq is 60, RF Frequency is 5.86GHz\n");
			printf(" if freq is 70, RF Frequency is 5.87GHz\n");
		}
	}
#if WAVE_MERGE
	else if (!strcmp( argv[0], "fchange1" ))
	{
		if (argc != 2)
		{
			printf("[USAGE] fchange1 [freq] \n");
			printf(" if freq is 50, RF Frequency is 5.85GHz\n");
			printf(" if freq is 60, RF Frequency is 5.86GHz\n");
			printf(" if freq is 70, RF Frequency is 5.87GHz\n");
			return(0);
		}
		
		val = atoi(argv[1]);
		if (val == 50)
		{
			reg_writew((wave_dsrc_base + WAVE_MODEM_B_MAX2829_DATA3_REG_OFFSET), 0x00EA);
			reg_writew((wave_dsrc_base + WAVE_MODEM_B_MAX2829_DATA4_REG_OFFSET), 0x0000);

			reg_writew((wave_dsrc_base + WAVE_MODEM_B_RF_SPI_CTRL_REG_OFFSET), 0x2000);	/* SPI 를 통해 RF 칩으로 세팅을 하게 한다. */
		}
		else if (val == 60)
		{
			reg_writew((wave_dsrc_base + WAVE_MODEM_B_MAX2829_DATA3_REG_OFFSET), 0x20EA);
			reg_writew((wave_dsrc_base + WAVE_MODEM_B_MAX2829_DATA4_REG_OFFSET), 0x1999);

			reg_writew((wave_dsrc_base + WAVE_MODEM_B_RF_SPI_CTRL_REG_OFFSET), 0x2000);	/* SPI 를 통해 RF 칩으로 세팅을 하게 한다. */
		}
		else if (val == 70)
		{
			reg_writew((wave_dsrc_base + WAVE_MODEM_B_MAX2829_DATA3_REG_OFFSET), 0x00EA);
			reg_writew((wave_dsrc_base + WAVE_MODEM_B_MAX2829_DATA4_REG_OFFSET), 0x3333);

			reg_writew((wave_dsrc_base + WAVE_MODEM_B_RF_SPI_CTRL_REG_OFFSET), 0x2000);	/* SPI 를 통해 RF 칩으로 세팅을 하게 한다. */
		}
		else
		{
			printf("Not Supported val = %d\n", val);
			printf("[USAGE] fchange [freq] \n");
			printf(" if freq is 50, RF Frequency is 5.85GHz\n");
			printf(" if freq is 60, RF Frequency is 5.86GHz\n");
			printf(" if freq is 70, RF Frequency is 5.87GHz\n");
		}
	}
#endif
	else if (!strcmp( argv[0], "multichon"))
	{
		Multi_Ch_OnOff(1);
	}
	else if (!strcmp( argv[0], "multichoff"))
	{
		Multi_Ch_OnOff(0);
	}
	else if (!strcmp( argv[0], "fchange_cch" ))
	{
		if (argc != 2)
		{
			printf("[USAGE] fchange_cch [freq] \n");
			printf(" if freq is 50, RF Frequency is 5.85GHz\n");
			printf(" if freq is 60, RF Frequency is 5.86GHz\n");
			printf(" if freq is 70, RF Frequency is 5.87GHz\n");
			return(0);
		}
		
		val = atoi(argv[1]);

		set_multi_ch_cch((U4)val);
	}
	else if (!strcmp( argv[0], "fchange_sch" ))
	{
		if (argc != 2)
		{
			printf("[USAGE] fchange_sch [freq] \n");
			printf(" if freq is 50, RF Frequency is 5.85GHz\n");
			printf(" if freq is 60, RF Frequency is 5.86GHz\n");
			printf(" if freq is 70, RF Frequency is 5.87GHz\n");
			return(0);
		}
		
		val = atoi(argv[1]);
		
		set_multi_ch_sch((U4)val);
	}
	else if (!strcmp( argv[0], "psid" ))
	{
		if (argc < 3)
		{
			printf("[USAGE] psid [len] [value]\n");
			printf("Current PSID Len = %d\n", psid_len);
			printf("Current PSID = 0x%08x\n", psid.b4);
			return(0);
		}

		psid_len = atoi(argv[1]);
		printf("PSID Len = %d\n", psid_len);

		if (argc != (2+psid_len))
		{
			printf("[USAGE] psid [len] [value]\n");
			printf("Current PSID Len = %d\n", psid_len);
			printf("Current PSID = 0x%08x\n", psid.b4);
			return(0);
		}

		for ( i = 0; i < 4; i++)
		{
			psid.b1[i] = 0;
		}

		for ( i = 0; i < psid_len; i++)
		{
			psid.b1[(psid_len-1-i)] = (U1)strtoul(argv[(2+i)], NULL, 16);
		}
		printf("PSID = 0x%08x\n", psid.b4);
	}
	else if (!strcmp( argv[0], "psidlen" ))
	{
		if (argc < 2)
		{
			printf("[USAGE] psidlen [value]\n");
			printf("  if value is 0, PSID Len is fixed, if vaule is 1, PSID Len is Variable\n");
			printf("Current psid_flag = %d\n", psid_flag);
			return(0);
		}

		psid_flag = atoi(argv[1]);
		printf("psid_flag = %d\n", psid_flag);
	}
	
	else if (!strcmp( argv[0], "automac" ))
	{
		if (argc < 2)
		{
			printf("[USAGE] automac [value]\n");
			printf("  if value is 1, wave mac addr auto set, if vaule is 0, wave mac addr fixed\n");
			printf("Current wave_mac_addr_auto_flag = %d\n", wave_mac_addr_auto_flag);
			return(0);
		}

		wave_mac_addr_auto_flag = atoi(argv[1]);
		printf("wave_mac_addr_auto_flag = %d\n", wave_mac_addr_auto_flag);
	}
	else if (!strcmp( argv[0], "autodmac" ))
	{
		if (argc < 2)
		{
			printf("[USAGE] autodmac [value]\n");
			printf("  if value is 1, wave dest PC mac addr auto set, if vaule is 0, wave dest PC mac addr fixed\n");
			printf("Current auto_dest_mac_flag = %d\n", auto_dest_mac_flag);
			return(0);
		}

		auto_dest_mac_flag = atoi(argv[1]);
		printf("wave_mac_addr_auto_flag = %d\n", auto_dest_mac_flag);
	}
	else if (!strcmp( argv[0], "txqth" ))
	{
		if (argc < 2)
		{
			printf("[USAGE] txqth [value]\n");
			printf("Current tx_queue_pause_threshold = %d\n", tx_queue_pause_threshold);
			return(0);
		}

		tx_queue_pause_threshold = atoi(argv[1]);
		printf("tx_queue_pause_threshold = %d\n", tx_queue_pause_threshold);
	}

	else if (!strcmp( argv[0], "initwave" ))
	{
		if (argc < 2)
		{
			printf("[USAGE] initwave [value] : if value is 0, Channel A, if value is 1, Channel B\n");
			return(0);
		}

		if (atoi(argv[1]) == 0)
		{
			wave_mac_init();
			wave_modem_init();
		}
		else
		{
		#if WAVE_MERGE
			wave_mac_b_init();
			wave_modem_b_init();
		#endif
		}

		
	}
	
	else if (!strcmp( argv[0], "wmacaddr" ))
	{
		if (argc < 7)
		{
			printf("[USAGE] wmacaddr [hval][hval][hval][hval][hval][hval]\n");
			printf("  Set WAVE MAC Source Adderss\n");
			printf("Current WAVE MAC Source Address = [%02x:%02x:%02x:%02x:%02x:%02x]\n", device_mac_addr[0], device_mac_addr[1], device_mac_addr[2], device_mac_addr[3], device_mac_addr[4], device_mac_addr[5]);

			high_mac_addr.b2 = reg_readw((wave_dsrc_base + WAVE_MAC_A_ADDR16_REG_OFFSET));
			low_mac_addr.b4 = read_wave_dsrc_reg32(WAVE_MAC_A_ADDR32_H_REG_OFFSET);
			printf("Current Register WAVE MAC A Source Address = [%02x:%02x:%02x:%02x:%02x:%02x]\n", high_mac_addr.b1[1], high_mac_addr.b1[0], low_mac_addr.b1[3], low_mac_addr.b1[2], low_mac_addr.b1[1], low_mac_addr.b1[0]);
			return(0);
		}

		device_mac_addr[0] = (U1)strtoul(argv[1], NULL, 16);
		device_mac_addr[1] = (U1)strtoul(argv[2], NULL, 16);
		device_mac_addr[2] = (U1)strtoul(argv[3], NULL, 16);
		device_mac_addr[3] = (U1)strtoul(argv[4], NULL, 16);
		device_mac_addr[4] = (U1)strtoul(argv[5], NULL, 16);
		device_mac_addr[5] = (U1)strtoul(argv[6], NULL, 16);

		high_mac_addr.b1[1] = device_mac_addr[0];
		high_mac_addr.b1[0] = device_mac_addr[1];

		low_mac_addr.b1[3] = device_mac_addr[2];
		low_mac_addr.b1[2] = device_mac_addr[3];
		low_mac_addr.b1[1] = device_mac_addr[4];
		low_mac_addr.b1[0] = device_mac_addr[5];

		reg_writew((wave_dsrc_base + WAVE_MAC_A_ADDR16_REG_OFFSET), high_mac_addr.b2);
		write_wave_dsrc_reg32(WAVE_MAC_A_ADDR32_H_REG_OFFSET, low_mac_addr.b4);

		printf("Current WAVE MAC Source Address = [%02x:%02x:%02x:%02x:%02x:%02x]\n", device_mac_addr[0], device_mac_addr[1], device_mac_addr[2], device_mac_addr[3], device_mac_addr[4], device_mac_addr[5]);
	}
#if WAVE_MERGE
	else if (!strcmp( argv[0], "wmacaddr1" ))
	{
		if (argc < 7)
		{
			printf("[USAGE] wmacaddr1 [hval][hval][hval][hval][hval][hval]\n");
			printf("  Set WAVE MAC Source Adderss\n");
			printf("Current WAVE MAC Source Address = [%02x:%02x:%02x:%02x:%02x:%02x]\n", device_mac_addr[0], device_mac_addr[1], device_mac_addr[2], device_mac_addr[3], device_mac_addr[4], device_mac_addr[5]);

			high_mac_addr.b2 = reg_readw((wave_dsrc_base + WAVE_MAC_B_ADDR16_REG_OFFSET));
			low_mac_addr.b4 = read_wave_dsrc_reg32(WAVE_MAC_B_ADDR32_H_REG_OFFSET);
			printf("Current Register WAVE MAC B Source Address = [%02x:%02x:%02x:%02x:%02x:%02x]\n", high_mac_addr.b1[1], high_mac_addr.b1[0], low_mac_addr.b1[3], low_mac_addr.b1[2], low_mac_addr.b1[1], low_mac_addr.b1[0]);
			return(0);
		}

		device_mac_addr[0] = (U1)strtoul(argv[1], NULL, 16);
		device_mac_addr[1] = (U1)strtoul(argv[2], NULL, 16);
		device_mac_addr[2] = (U1)strtoul(argv[3], NULL, 16);
		device_mac_addr[3] = (U1)strtoul(argv[4], NULL, 16);
		device_mac_addr[4] = (U1)strtoul(argv[5], NULL, 16);
		device_mac_addr[5] = (U1)strtoul(argv[6], NULL, 16);

		high_mac_addr.b1[1] = device_mac_addr[0];
		high_mac_addr.b1[0] = device_mac_addr[1];

		low_mac_addr.b1[3] = device_mac_addr[2];
		low_mac_addr.b1[2] = device_mac_addr[3];
		low_mac_addr.b1[1] = device_mac_addr[4];
		low_mac_addr.b1[0] = device_mac_addr[5];

		reg_writew((wave_dsrc_base + WAVE_MAC_B_ADDR16_REG_OFFSET), high_mac_addr.b2);
		write_wave_dsrc_reg32(WAVE_MAC_B_ADDR32_H_REG_OFFSET, low_mac_addr.b4);

		printf("Current WAVE MAC Source Address = [%02x:%02x:%02x:%02x:%02x:%02x]\n", device_mac_addr[0], device_mac_addr[1], device_mac_addr[2], device_mac_addr[3], device_mac_addr[4], device_mac_addr[5]);
	}
#endif
	else if (!strcmp( argv[0], "dmacaddr" ))
	{
		if (argc < 7)
		{
			printf("[USAGE] dmacaddr [hval][hval][hval][hval][hval][hval]\n");
			printf("  Set WAVE Dest PC MAC Source Adderss\n");
			printf("Current WAVE Dest PC MAC Source Address = [%02x:%02x:%02x:%02x:%02x:%02x]\n", WSA_DEST_MAC_ADDR[0], WSA_DEST_MAC_ADDR[1], WSA_DEST_MAC_ADDR[2], WSA_DEST_MAC_ADDR[3], WSA_DEST_MAC_ADDR[4], WSA_DEST_MAC_ADDR[5]);
			return(0);
		}

		WSA_DEST_MAC_ADDR[0] = (U1)strtoul(argv[1], NULL, 16);
		WSA_DEST_MAC_ADDR[1] = (U1)strtoul(argv[2], NULL, 16);
		WSA_DEST_MAC_ADDR[2] = (U1)strtoul(argv[3], NULL, 16);
		WSA_DEST_MAC_ADDR[3] = (U1)strtoul(argv[4], NULL, 16);
		WSA_DEST_MAC_ADDR[4] = (U1)strtoul(argv[5], NULL, 16);
		WSA_DEST_MAC_ADDR[5] = (U1)strtoul(argv[6], NULL, 16);

		

		printf("Current WAVE Dest PC MAC Source Address = [%02x:%02x:%02x:%02x:%02x:%02x]\n", WSA_DEST_MAC_ADDR[0], WSA_DEST_MAC_ADDR[1], WSA_DEST_MAC_ADDR[2], WSA_DEST_MAC_ADDR[3], WSA_DEST_MAC_ADDR[4], WSA_DEST_MAC_ADDR[5]);
	}
	else if (!strcmp( argv[0], "txlen" ))
	{
		if (argc != 6)
		{
			printf("[USAGE] txpkt [start_len] [end_len] [tx_powr] [modulation] [interval(usec)]\n");
			return(0);
		}
		
		start_len = atoi(argv[1]);
		if (start_len > 1024)
		{
			printf("Length Error\n");
			return(0);
		}
		end_len = atoi(argv[2]);
		if (end_len > 1024)
		{
			printf("Length Error\n");
			return(0);
		}

		if ( start_len > end_len)
		{
			printf("Length Error: end_len must be bigger than start_len\n");
			return(0);
		}

		count = end_len - start_len + 1;
		tx_power = atoi(argv[3]);
		modulation = atoi(argv[4]);
		interval = atoi(argv[5]);
		

#if 0
		/* 현재 OS Time Tick이 5ms이기 때문에 5ms 이상이 되어야 한다. */
		if ( (interval < 5) || (interval > 999) )
		{
			printf("Invalid Interval = %d\n", interval);
			printf("Interval value range is from 5 to 999\n");
			return(0);
		}
		interval = interval * 1000000;		/* msec를 nano sec로 변환 */
#endif

		switch(modulation)
		{
			case 3:
				data_rate = 6;
				break;
			case 6:
				data_rate = 12;
				break;
			case 12:
				data_rate = 24;
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
		

		for ( i = 0; i < end_len; i++)
		{
			send_buf[i] = 0xAA;
		}

		length = start_len;

		for ( i = 0; i < count; i++)
		{
			Send_MPDU(DATA_FRAME, CONTROL_CHANNEL, AC4, length, tx_power, modulation, IBSS_TO_DS_FROM_DS, send_buf);
			//my_nanosleep(0, (long)interval);
			time_delay(interval);
			length++;
		}
	}
	else if (!strcmp( argv[0], "regtest" ))
	{
		if (argc != 2)
		{
			printf("[USAGE] regtest [count]\n");
			return(0);
		}

		count = atoi(argv[1]);

		for ( i = 0; i < count; i++)
		{
			ret = Wave_Register_Read_Write_Test (WAVE_MAC_A_INT_MASK_H_REG_OFFSET, 4, 0x12345678, 0x00FFFFFF);
			if (ret != 0)
				break;
			ret = Wave_Register_Read_Write_Test (WAVE_MAC_A_INT_MASK_H_REG_OFFSET, 4, 0xaaaaaaaa, 0x00FFFFFF);
			if (ret != 0)
				break;
			ret = Wave_Register_Read_Write_Test (WAVE_MAC_A_INT_MASK_H_REG_OFFSET, 4, 0x55555555, 0x00FFFFFF);
			if (ret != 0)
				break;

			/* 24번지는 0 ~ 13비트 까지 있는데, 13번째는 비트는 Read/Write이 안됨. */
			ret = Wave_Register_Read_Write_Test (WAVE_ECDSA_INT_MASK_H_REG_OFFSET, 4, 0x12345678, 0x1FFF);
			if (ret != 0)
				break;
			ret = Wave_Register_Read_Write_Test (WAVE_ECDSA_INT_MASK_H_REG_OFFSET, 4, 0xaaaaaaaa, 0x1FFF);
			if (ret != 0)
				break;
			ret = Wave_Register_Read_Write_Test (WAVE_ECDSA_INT_MASK_H_REG_OFFSET, 4, 0x55555555, 0x1FFF);
			if (ret != 0)
				break;

			ret = Wave_Register_Read_Write_Test (WAVE_MAC_A_TIMING_CHARACTER_H_REG_OFFSET, 4, 0x12345678, 0x0FFFFFFF);
			if (ret != 0)
				break;
			ret = Wave_Register_Read_Write_Test (WAVE_MAC_A_TIMING_CHARACTER_H_REG_OFFSET, 4, 0xaaaaaaaa, 0x0FFFFFFF);
			if (ret != 0)
				break;
			ret = Wave_Register_Read_Write_Test (WAVE_MAC_A_TIMING_CHARACTER_H_REG_OFFSET, 4, 0x55555555, 0x0FFFFFFF);
			if (ret != 0)
				break;

			ret = Wave_Register_Read_Write_Test (WAVE_MAC_A_ADDR16_REG_OFFSET, 2, 0x12345678, 0x0000FFFF);
			if (ret != 0)
				break;
			ret = Wave_Register_Read_Write_Test (WAVE_MAC_A_ADDR16_REG_OFFSET, 2, 0xaaaaaaaa, 0x0000FFFF);
			if (ret != 0)
				break;
			ret = Wave_Register_Read_Write_Test (WAVE_MAC_A_ADDR16_REG_OFFSET, 2, 0x55555555, 0x0000FFFF);
			if (ret != 0)
				break;
			
		}
		if (ret != 0)
		{
			printf("Register R/W Test Fail\n");
		}
		else
		{
			printf("Register R/W Test Success\n");
		}

		
		
	}
	else if (!strcmp( argv[0], "rregtest" ))
	{
		if (argc != 2)
		{
			printf("[USAGE] rregtest [count]\n");
			return(0);
		}

		count = atoi(argv[1]);

		for ( i = 0; i < count; i++)
		{
			reg_writew((wave_dsrc_base + WAVE_MAC_B_CCH_AC1_FREE_SPACE_L_REG_OFFSET), 0xFF);
			reg_writew((wave_dsrc_base + WAVE_CONTROL_L_REG_OFFSET), 0x8);
			u4 = reg_readw((wave_dsrc_base + WAVE_MODEM_A_MODE_SELECT_REG_OFFSET));

			if ( u4 != 0x8319 )
				printf("Reset Register Read/Write Test Fail!!\n");

			usleep(100);
			
		}
		printf("Reset Register Read/Write Test Success!!\n");

	}

	else if (!strcmp( argv[0], "txregtest" ))
	{
		if (argc < 2)
		{
			printf("[USAGE] txregtest [value]\n");
			printf("Current g_tx_reset_reg_test = %d\n", g_tx_reset_reg_test);
			return(0);
		}

		g_tx_reset_reg_test = atoi(argv[1]);
		printf("g_tx_reset_reg_test = %d\n", g_tx_reset_reg_test);
	}
	
	/* txpkt 1000 10000 1 3 3 */
	else if (!strcmp( argv[0], "txpkt" ))
	{
		if ((argc != 8) && (argc != 9))
		{
			printf("[USAGE] txpkt [len] [count] [tx_powr] [modulation] [interval(usec)][start_data][end_data][ch_kind]\n");
			return(0);
		}
		
		length = atoi(argv[1]);
		if (length > 2000)
		{
			printf("Length Error!!, Length is smaller than 2000\n");
			return(0);
		}
		count = atoi(argv[2]);
		tx_power = atoi(argv[3]);
		modulation = atoi(argv[4]);
		interval = atoi(argv[5]);
		start_data = atoi(argv[6]);
		if (start_data > 255)
		{
			printf("start_data is overflow, start_data range is 0 ~ 255\n");
			return(0);
		}
		end_data = atoi(argv[7]);
		if (end_data > 255)
		{
			printf("end_data is overflow, end_data range is 0 ~ 255\n");
			return(0);
		}

		if (argc == 8)
		{
			ch_kind = 0;	/* CONTROL_CHANNEL */
		}
		else
		{
			ch_kind = atoi(argv[8]);
		}

#if 0
		/* 현재 OS Time Tick이 5ms이기 때문에 5ms 이상이 되어야 한다. */
		if ( (interval < 5) || (interval > 999) )
		{
			printf("Invalid Interval = %d\n", interval);
			printf("Interval value range is from 5 to 999\n");
			return(0);
		}
		interval = interval * 1000000;		/* msec를 nano sec로 변환 */
#endif
		i = 26;						/* MAC Header를 위해 남겨 놓음. 26 = dataframe의 MAC 헤더의 길이 */
		
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

		j = 0;

		for ( ; i < length; i++)
		{
			send_buf[i] = start_data+j;
			j++;
			if ((start_data+j) > end_data)
			{
				j = 0;	
			}
		}
		

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

		for ( i = 0; i < count; i++)
		{
			if (ch_kind == 0)
			{
				/* 26 = MAC Header를 위해 남겨 놓음. */
				Send_MPDU(DATA_FRAME, CONTROL_CHANNEL, AC4, (length - 26), tx_power, modulation, IBSS_TO_DS_FROM_DS, &send_buf[26]);
			}
			else
			{
				/* 26 = MAC Header를 위해 남겨 놓음. */
				Send_MPDU(DATA_FRAME, SERVICE_CHANNEL, AC4, (length - 26), tx_power, modulation, IBSS_TO_DS_FROM_DS, &send_buf[26]);
			}
			//my_nanosleep(0, (long)interval);
			//gettimeofday(&start_point, NULL);
			time_delay(interval);

			if (g_tx_reset_reg_test)
			{
				reg_value = 0x08;	/* Channel A의 Modem에서 Register를 제외한 Logic Reset */
				write_wave_dsrc_reg32(WAVE_CONTROL_H_REG_OFFSET, reg_value);
				if (reg_readw((wave_dsrc_base + WAVE_MODEM_A_MODE_SELECT_REG_OFFSET)) == 0xC319)
				{
					printf("Invalid Status\n");
					break;
				}
			}

			//if (reg_readw((wave_dsrc_base + WAVE_MODEM_A_MODE_SELECT_REG_OFFSET)) == 0xC319)
			//{
			//	printf("Invalid Status\n");
			//	break;
			//}
			//gettimeofday(&end_point, NULL);

			//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
			//printf("\nSleep Operation Time : %f\n",operating_time);
		}
	}
#if WAVE_MERGE
	else if (!strcmp( argv[0], "txpkt1" ))
	{
		if ((argc != 8) && (argc != 9))
		{
			printf("[USAGE] txpkt1 [len] [count] [tx_powr] [modulation] [interval(usec)][start_data][end_data][ch_kind]\n");
			return(0);
		}
		
		length = atoi(argv[1]);
		if (length > 2000)
		{
			printf("Length Error!!, Length is smaller than 2000\n");
			return(0);
		}
		count = atoi(argv[2]);
		tx_power = atoi(argv[3]);
		modulation = atoi(argv[4]);
		interval = atoi(argv[5]);
		start_data = atoi(argv[6]);
		if (start_data > 255)
		{
			printf("start_data is overflow, start_data range is 0 ~ 255\n");
			return(0);
		}
		end_data = atoi(argv[7]);
		if (end_data > 255)
		{
			printf("end_data is overflow, end_data range is 0 ~ 255\n");
			return(0);
		}

		if (argc == 8)
		{
			ch_kind = 0;	/* CONTROL_CHANNEL */
		}
		else
		{
			ch_kind = atoi(argv[8]);
		}

#if 0
		/* 현재 OS Time Tick이 5ms이기 때문에 5ms 이상이 되어야 한다. */
		if ( (interval < 5) || (interval > 999) )
		{
			printf("Invalid Interval = %d\n", interval);
			printf("Interval value range is from 5 to 999\n");
			return(0);
		}
		interval = interval * 1000000;		/* msec를 nano sec로 변환 */
#endif
		i = 26;						/* MAC Header를 위해 남겨 놓음. 26 = dataframe의 MAC 헤더의 길이 */
		
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

		j = 0;

		for ( ; i < length; i++)
		{
			send_buf[i] = start_data+j;
			j++;
			if ((start_data+j) > end_data)
			{
				j = 0;	
			}
		}
		

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

		for ( i = 0; i < count; i++)
		{
			if (ch_kind == 0)
			{
				/* 26 = MAC Header를 위해 남겨 놓음. */
				Send_MPDU_B(DATA_FRAME, CONTROL_CHANNEL, AC4, (length - 26), tx_power, modulation, IBSS_TO_DS_FROM_DS, &send_buf[26]);
			}
			else
			{
				/* 26 = MAC Header를 위해 남겨 놓음. */
				Send_MPDU_B(DATA_FRAME, SERVICE_CHANNEL, AC4, (length - 26), tx_power, modulation, IBSS_TO_DS_FROM_DS, &send_buf[26]);
			}
			//my_nanosleep(0, (long)interval);
			//gettimeofday(&start_point, NULL);
			time_delay(interval);
			//gettimeofday(&end_point, NULL);

			//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
			//printf("\nSleep Operation Time : %f\n",operating_time);
		}
	}
#endif
	/* txpkt 1000 10000 1 3 3 */
	else if (!strcmp( argv[0], "txecdsa" ))
	{
		if ((argc != 9))
		{
			printf("[USAGE] txecdsa [len] [count] [tx_powr] [modulation] [interval(usec)][start_data][end_data][mode(256:1, 224:2)]\n");
			return(0);
		}
		val = reg_readl((gpio_base + GPGCON_OFFSET));
		val &= 0xFFF3FFFF;	/* 18, 19번째 비트를 0으로 만든다. */
		val |= 0x00040000;	/* GPG9을 Output Mode으로 세팅한다. */
		reg_writel((gpio_base + GPGCON_OFFSET), val);
		
		length = atoi(argv[1]);
		if (length > 2000)
		{
			printf("Length Error!!, Length is smaller than 2000\n");
			return(0);
		}
		count = atoi(argv[2]);
		tx_power = atoi(argv[3]);
		modulation = atoi(argv[4]);
		interval = atoi(argv[5]);
		start_data = atoi(argv[6]);
		if (start_data > 255)
		{
			printf("start_data is overflow, start_data range is 0 ~ 255\n");
			return(0);
		}
		end_data = atoi(argv[7]);
		if (end_data > 255)
		{
			printf("end_data is overflow, end_data range is 0 ~ 255\n");
			return(0);
		}

		
		val = atoi(argv[8]);		/* 1이면 256mode, 2이면 224 mode */

#if 0
		/* 현재 OS Time Tick이 5ms이기 때문에 5ms 이상이 되어야 한다. */
		if ( (interval < 5) || (interval > 999) )
		{
			printf("Invalid Interval = %d\n", interval);
			printf("Interval value range is from 5 to 999\n");
			return(0);
		}
		interval = interval * 1000000;		/* msec를 nano sec로 변환 */
#endif
		i = 26;						/* MAC Header를 위해 남겨 놓음. 26 = dataframe의 MAC 헤더의 길이 */
		
		send_buf[i++] = 0xAA;
		send_buf[i++] = 0xAA;
		send_buf[i++] = 0x03;
		send_buf[i++] = 0x00;
		send_buf[i++] = 0x00;
		send_buf[i++] = 0x00;
		send_buf[i++] = 0x88;
		send_buf[i++] = 0xdc;
		send_buf[i++] = WAVE_SECURITY_VERSION;	/* version : 1609.2의 5.2 참조. */
		send_buf[i++] = MSG_TYPE_SIGNED;			/* Message Type : 1609.2의 5.2 참조. */
		send_buf[i++] = WAVE_EID_WSM;				/* WSMP WAVE element ID */

		
		
		if (ecdsa_sw_test_fix_flag)	//SHKO, Origin
		{
			length = 44;
			wsmp_len_index = i;
			send_buf[i++] = (length >> 8) & 0xFF;
			send_buf[i++] = length & 0xFF;
		
			k = 0;
			if (val == 1)  /* 256 Mode */
			{
				ToBeSignedMsg[k++] = 0x45;
				ToBeSignedMsg[k++] = 0x78;
				ToBeSignedMsg[k++] = 0x61;
				ToBeSignedMsg[k++] = 0x6D;
				ToBeSignedMsg[k++] = 0x70;
				ToBeSignedMsg[k++] = 0x6C;
				ToBeSignedMsg[k++] = 0x65;
				ToBeSignedMsg[k++] = 0x20;

				ToBeSignedMsg[k++] = 0x6F;
				ToBeSignedMsg[k++] = 0x66;
				ToBeSignedMsg[k++] = 0x20;
				ToBeSignedMsg[k++] = 0x45;
				ToBeSignedMsg[k++] = 0x43;
				ToBeSignedMsg[k++] = 0x44;
				ToBeSignedMsg[k++] = 0x53;
				ToBeSignedMsg[k++] = 0x41;

				ToBeSignedMsg[k++] = 0x20;
				ToBeSignedMsg[k++] = 0x77;
				ToBeSignedMsg[k++] = 0x69;
				ToBeSignedMsg[k++] = 0x74;
				ToBeSignedMsg[k++] = 0x68;
				ToBeSignedMsg[k++] = 0x20;
				ToBeSignedMsg[k++] = 0x61;
				ToBeSignedMsg[k++] = 0x6E;

				ToBeSignedMsg[k++] = 0x73;
				ToBeSignedMsg[k++] = 0x69;
				ToBeSignedMsg[k++] = 0x70;
				ToBeSignedMsg[k++] = 0x32;
				ToBeSignedMsg[k++] = 0x35;
				ToBeSignedMsg[k++] = 0x36;
				ToBeSignedMsg[k++] = 0x72;
				ToBeSignedMsg[k++] = 0x31;

				ToBeSignedMsg[k++] = 0x20;
				ToBeSignedMsg[k++] = 0x61;
				ToBeSignedMsg[k++] = 0x6E;
				ToBeSignedMsg[k++] = 0x64;
				ToBeSignedMsg[k++] = 0x20;
				ToBeSignedMsg[k++] = 0x53;
				ToBeSignedMsg[k++] = 0x48;
				ToBeSignedMsg[k++] = 0x41;

				ToBeSignedMsg[k++] = 0x2D;
				ToBeSignedMsg[k++] = 0x32;
				ToBeSignedMsg[k++] = 0x35;
				ToBeSignedMsg[k++] = 0x36;
			}
			else
			{
				ToBeSignedMsg[k++] = 0x45;
				ToBeSignedMsg[k++] = 0x78;
				ToBeSignedMsg[k++] = 0x61;
				ToBeSignedMsg[k++]= 0x6D;
				ToBeSignedMsg[k++] = 0x70;
				ToBeSignedMsg[k++] = 0x6C;
				ToBeSignedMsg[k++] = 0x65;
				ToBeSignedMsg[k++] = 0x20;

				ToBeSignedMsg[k++] = 0x6F;
				ToBeSignedMsg[k++] = 0x66;
				ToBeSignedMsg[k++] = 0x20;
				ToBeSignedMsg[k++] = 0x45;
				ToBeSignedMsg[k++] = 0x43;
				ToBeSignedMsg[k++] = 0x44;
				ToBeSignedMsg[k++] = 0x53;
				ToBeSignedMsg[k++] = 0x41;

				ToBeSignedMsg[k++] = 0x20;
				ToBeSignedMsg[k++] = 0x77;
				ToBeSignedMsg[k++] = 0x69;
				ToBeSignedMsg[k++] = 0x74;
				ToBeSignedMsg[k++] = 0x68;
				ToBeSignedMsg[k++] = 0x20;
				ToBeSignedMsg[k++] = 0x61;
				ToBeSignedMsg[k++] = 0x6E;

				ToBeSignedMsg[k++] = 0x73;
				ToBeSignedMsg[k++] = 0x69;
				ToBeSignedMsg[k++] = 0x70;
				ToBeSignedMsg[k++] = 0x32;
				ToBeSignedMsg[k++] = 0x32;
				ToBeSignedMsg[k++] = 0x34;
				ToBeSignedMsg[k++] = 0x72;
				ToBeSignedMsg[k++] = 0x31;

				ToBeSignedMsg[k++] = 0x20;
				ToBeSignedMsg[k++] = 0x61;
				ToBeSignedMsg[k++] = 0x6E;
				ToBeSignedMsg[k++] = 0x64;
				ToBeSignedMsg[k++] = 0x20;
				ToBeSignedMsg[k++] = 0x53;
				ToBeSignedMsg[k++] = 0x48;
				ToBeSignedMsg[k++] = 0x41;

				ToBeSignedMsg[k++] = 0x2D;
				ToBeSignedMsg[k++] = 0x32;
				ToBeSignedMsg[k++] = 0x32;
				ToBeSignedMsg[k++] = 0x34;
			}
		}
		else
		{
			wsmp_len_index = i;
			send_buf[i++] = (length >> 8) & 0xFF;
			send_buf[i++] = length & 0xFF;
			
			j = 0;
			for ( k = 0; k < length; k++)
			{
				ToBeSignedMsg[k] = start_data + j;
				j++;

				if ((start_data + j) > end_data )
				{
					j = 0;
				}
			}
		}
		

		signed_msg_len = MakeSignedMsg(val, &send_buf[i], ToBeSignedMsg, length);
		

		if (signed_msg_len > 0)
		{
			length = signed_msg_len;
			send_buf[wsmp_len_index] = (length >> 8) & 0xFF;
			send_buf[wsmp_len_index+1] = length & 0xFF;

			length = wsmp_len_index + 2 + signed_msg_len;		/* 2 = Length field 길이 */
		}		
		

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

		if (signed_msg_len > 0 )
		{

			for ( i = 0; i < count; i++)
			{
				if (ch_kind == 0)
				{
					/* 26 = MAC Header를 위해 남겨 놓음. */
					Send_MPDU(DATA_FRAME, CONTROL_CHANNEL, AC4, (length - 26), tx_power, modulation, IBSS_TO_DS_FROM_DS, &send_buf[26]);
				}
				else
				{
					/* 26 = MAC Header를 위해 남겨 놓음. */
					Send_MPDU(DATA_FRAME, SERVICE_CHANNEL, AC4, (length - 26), tx_power, modulation, IBSS_TO_DS_FROM_DS, &send_buf[26]);
				}
				//my_nanosleep(0, (long)interval);
				//gettimeofday(&start_point, NULL);
				time_delay(interval);

			}
		}
	}
	else if (!strcmp( argv[0], "rxecdsa" ))
	{
		if ((argc != 2))
		{
			printf("[USAGE] rxecdsa [mode(256:1, 224:2)]\n");
			return(0);
		}
		val = reg_readl((gpio_base + GPGCON_OFFSET));
		val &= 0xFFF3FFFF;	/* 18, 19번째 비트를 0으로 만든다. */
		val |= 0x00040000;	/* GPG9을 Output Mode으로 세팅한다. */
		reg_writel((gpio_base + GPGCON_OFFSET), val);
		
		val = atoi(argv[1]);		/* 1이면 256mode, 2이면 224 mode */

		if (val == 1)
		{
			wave_mac_rx_proc(rx_ecdsa_test_256, 183);
		}
		else
		{
			wave_mac_rx_proc(rx_ecdsa_test_224, 171);
		}
	}
	else if (!strcmp( argv[0], "txecies" ))
	{
		if ((argc != 8))
		{
			printf("[USAGE] txecies [len] [count] [tx_powr] [modulation] [interval(usec)][start_data][end_data]\n");
			return(0);
		}
		val = reg_readl((gpio_base + GPGCON_OFFSET));
		val &= 0xFFF3FFFF;	/* 18, 19번째 비트를 0으로 만든다. */
		val |= 0x00040000;	/* GPG9을 Output Mode으로 세팅한다. */
		reg_writel((gpio_base + GPGCON_OFFSET), val);
		
		length = atoi(argv[1]);
		if (length > 2000)
		{
			printf("Length Error!!, Length is smaller than 2000\n");
			return(0);
		}
		count = atoi(argv[2]);
		tx_power = atoi(argv[3]);
		modulation = atoi(argv[4]);
		interval = atoi(argv[5]);
		start_data = atoi(argv[6]);
		if (start_data > 255)
		{
			printf("start_data is overflow, start_data range is 0 ~ 255\n");
			return(0);
		}
		end_data = atoi(argv[7]);
		if (end_data > 255)
		{
			printf("end_data is overflow, end_data range is 0 ~ 255\n");
			return(0);
		}

#if 0
		/* 현재 OS Time Tick이 5ms이기 때문에 5ms 이상이 되어야 한다. */
		if ( (interval < 5) || (interval > 999) )
		{
			printf("Invalid Interval = %d\n", interval);
			printf("Interval value range is from 5 to 999\n");
			return(0);
		}
		interval = interval * 1000000;		/* msec를 nano sec로 변환 */
#endif
		i = 26;						/* MAC Header를 위해 남겨 놓음. 26 = dataframe의 MAC 헤더의 길이 */
		
		send_buf[i++] = 0xAA;
		send_buf[i++] = 0xAA;
		send_buf[i++] = 0x03;
		send_buf[i++] = 0x00;
		send_buf[i++] = 0x00;
		send_buf[i++] = 0x00;
		send_buf[i++] = 0x88;
		send_buf[i++] = 0xdc;
		send_buf[i++] = WAVE_SECURITY_VERSION;	/* version : 1609.2의 5.2 참조. */
		send_buf[i++] = MSG_TYPE_ENCRYPTED;			/* Message Type : 1609.2의 5.2 참조. */
		send_buf[i++] = WAVE_EID_WSM;				/* WSMP WAVE element ID */

		//length = 44;
		wsmp_len_index = i;
		send_buf[i++] = (length >> 8) & 0xFF;
		send_buf[i++] = length & 0xFF;

		j = 0;
		for ( k = 0; k < length; k++)
		{
			ToBeSignedMsg[k] = start_data + j;
			j++;

			if ((start_data + j) > end_data )
			{
				j = 0;
			}
		}

		

		//Soft_Decrypt_Ecies(v, c, t);

		signed_msg_len = MakeEncryptedMsg(&send_buf[i], ToBeSignedMsg, length);

		send_buf[wsmp_len_index] = (signed_msg_len >> 8) & 0xFF;
		send_buf[(wsmp_len_index + 1)] = signed_msg_len & 0xFF;

		length = wsmp_len_index + 2 + signed_msg_len;		/* 2 = Length field 길이 */
		


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

		if (signed_msg_len > 0 )
		{

			for ( i = 0; i < count; i++)
			{
				if (ch_kind == 0)
				{
					/* 26 = MAC Header를 위해 남겨 놓음. */
					Send_MPDU(DATA_FRAME, CONTROL_CHANNEL, AC4, (length - 26), tx_power, modulation, IBSS_TO_DS_FROM_DS, &send_buf[26]);
				}
				else
				{
					/* 26 = MAC Header를 위해 남겨 놓음. */
					Send_MPDU(DATA_FRAME, SERVICE_CHANNEL, AC4, (length - 26), tx_power, modulation, IBSS_TO_DS_FROM_DS, &send_buf[26]);
				}
				//my_nanosleep(0, (long)interval);
				//gettimeofday(&start_point, NULL);
				time_delay(interval);

			}
		}
	}

	/* unicast 1000 10000 1 3 3 */
	else if (!strcmp( argv[0], "unicast" ))
	{
		if (argc != 6)
		{
			printf("[USAGE] unicast [len] [count] [interval(usec)][start_data][end_data]\n");
			return(0);
		}
		
		length = atoi(argv[1]);
		if (length > 2000)
		{
			printf("Length Error!!, Length is smaller than 2000\n");
			return(0);
		}
		count = atoi(argv[2]);
		interval = atoi(argv[3]);
		start_data = atoi(argv[4]);
		if (start_data > 255)
		{
			printf("start_data is overflow, start_data range is 0 ~ 255\n");
			return(0);
		}
		end_data = atoi(argv[5]);
		if (end_data > 255)
		{
			printf("end_data is overflow, end_data range is 0 ~ 255\n");
			return(0);
		}

#if 0
		/* 현재 OS Time Tick이 5ms이기 때문에 5ms 이상이 되어야 한다. */
		if ( (interval < 5) || (interval > 999) )
		{
			printf("Invalid Interval = %d\n", interval);
			printf("Interval value range is from 5 to 999\n");
			return(0);
		}
		interval = interval * 1000000;		/* msec를 nano sec로 변환 */
#endif
		i = 50;						/* MAC Header를 위해 남겨 놓음. 26 = dataframe의 MAC 헤더의 길이 */

		/* LLC 헤더 */
		send_buf[i++] = 0xAA;
		send_buf[i++] = 0xAA;
		send_buf[i++] = 0x03;

		/* 프로토콜 ID */
		send_buf[i++] = 0x00;
		send_buf[i++] = 0x00;
		send_buf[i++] = 0x00;

		send_buf[i++] = 0x08;
		send_buf[i++] = 0x00;

		

		/* SHKO : IEEE 802.11 규격의 10.4.4.2를 참조하면 된다. */
		data_rate = wave_mac_default_data_rate;
		
		send_buf[i++] = data_rate;

		send_buf[i++] = EXT_WAVE_CHANNEL_NUM_EID;
		send_buf[i++] = 1;		/* Channel Number Length */
		send_buf[i++] = 0xac;
		
		send_buf[i++] = WAVE_EID_WSM;/* WSMP WAVE element ID */

		wsmp_header_len = i + 2;		/* 2 = Length Field 길이 */

		send_buf[i++] = (length >> 8) & 0xFF;
		send_buf[i++] = length & 0xFF;

		length += wsmp_header_len;

		j = 0;

		for ( ; i < length; i++)
		{
			send_buf[i] = start_data+j;
			j++;
			if ((start_data+j) > end_data)
			{
				j = 0;	
			}
		}

		length = i - 50;

		wave_mac_dest_addr[0] = WSA_DEST_MAC_ADDR[0];
		wave_mac_dest_addr[1] = WSA_DEST_MAC_ADDR[1];
		wave_mac_dest_addr[2] = WSA_DEST_MAC_ADDR[2];
		wave_mac_dest_addr[3] = WSA_DEST_MAC_ADDR[3];
		wave_mac_dest_addr[4] = WSA_DEST_MAC_ADDR[4];
		wave_mac_dest_addr[5] = WSA_DEST_MAC_ADDR[5];

		wave_mac_src_addr[0] = device_mac_addr[0];
		wave_mac_src_addr[1] = device_mac_addr[1];
		wave_mac_src_addr[2] = device_mac_addr[2];
		wave_mac_src_addr[3] = device_mac_addr[3];
		wave_mac_src_addr[4] = device_mac_addr[4];
		wave_mac_src_addr[5] = device_mac_addr[5];

		

		for ( i = 0; i < count; i++)
		{
			/* 26 = MAC Header를 위해 남겨 놓음. */
			ret = Store_Tx_Queue(0, DATA_FRAME, CONTROL_CHANNEL, AC1, length, wave_mac_default_tx_power, wave_mac_default_data_rate, IBSS_TO_DS_FROM_DS, &send_buf[50]);

			//my_nanosleep(0, (long)interval);
			//gettimeofday(&start_point, NULL);
			time_delay(interval);
			//gettimeofday(&end_point, NULL);

			//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
			//printf("\nSleep Operation Time : %f\n",operating_time);
		}
	}

#if WAVE_MERGE
	else if (!strcmp( argv[0], "unicast1" ))
	{
		if (argc != 6)
		{
			printf("[USAGE] unicast1 [len] [count] [interval(usec)][start_data][end_data]\n");
			return(0);
		}
		
		length = atoi(argv[1]);
		if (length > 2000)
		{
			printf("Length Error!!, Length is smaller than 2000\n");
			return(0);
		}
		count = atoi(argv[2]);
		interval = atoi(argv[3]);
		start_data = atoi(argv[4]);
		if (start_data > 255)
		{
			printf("start_data is overflow, start_data range is 0 ~ 255\n");
			return(0);
		}
		end_data = atoi(argv[5]);
		if (end_data > 255)
		{
			printf("end_data is overflow, end_data range is 0 ~ 255\n");
			return(0);
		}

#if 0
		/* 현재 OS Time Tick이 5ms이기 때문에 5ms 이상이 되어야 한다. */
		if ( (interval < 5) || (interval > 999) )
		{
			printf("Invalid Interval = %d\n", interval);
			printf("Interval value range is from 5 to 999\n");
			return(0);
		}
		interval = interval * 1000000;		/* msec를 nano sec로 변환 */
#endif
		i = 50;						/* MAC Header를 위해 남겨 놓음. 26 = dataframe의 MAC 헤더의 길이 */

		/* LLC 헤더 */
		send_buf[i++] = 0xAA;
		send_buf[i++] = 0xAA;
		send_buf[i++] = 0x03;

		/* 프로토콜 ID */
		send_buf[i++] = 0x00;
		send_buf[i++] = 0x00;
		send_buf[i++] = 0x00;

		send_buf[i++] = 0x08;
		send_buf[i++] = 0x00;

		

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

		j = 0;

		for ( ; i < length; i++)
		{
			send_buf[i] = start_data+j;
			j++;
			if ((start_data+j) > end_data)
			{
				j = 0;	
			}
		}

		length = i - 50;

		wave_mac_dest_addr[0] = WSA_DEST_MAC_ADDR[0];
		wave_mac_dest_addr[1] = WSA_DEST_MAC_ADDR[1];
		wave_mac_dest_addr[2] = WSA_DEST_MAC_ADDR[2];
		wave_mac_dest_addr[3] = WSA_DEST_MAC_ADDR[3];
		wave_mac_dest_addr[4] = WSA_DEST_MAC_ADDR[4];
		wave_mac_dest_addr[5] = WSA_DEST_MAC_ADDR[5];

		wave_mac_src_addr[0] = device_mac_addr[0];
		wave_mac_src_addr[1] = device_mac_addr[1];
		wave_mac_src_addr[2] = device_mac_addr[2];
		wave_mac_src_addr[3] = device_mac_addr[3];
		wave_mac_src_addr[4] = device_mac_addr[4];
		wave_mac_src_addr[5] = device_mac_addr[5];

#if 0
		for ( i = 0 ; i < length; i++)
		{
			printf("[%02x]", send_buf[50+i]);
		}
		printf("\n");
#endif
		

		for ( i = 0; i < count; i++)
		{
			/* 26 = MAC Header를 위해 남겨 놓음. */
			ret = Store_Tx_Queue(1, DATA_FRAME, CONTROL_CHANNEL, AC1, length, wave_mac_default_tx_power, wave_mac_default_data_rate, IBSS_TO_DS_FROM_DS, &send_buf[50]);

			//my_nanosleep(0, (long)interval);
			//gettimeofday(&start_point, NULL);
			time_delay(interval);
			//gettimeofday(&end_point, NULL);

			//operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
			//printf("\nSleep Operation Time : %f\n",operating_time);
		}
	}
#endif
	else if (!strcmp( argv[0], "freespace" ))
	{
		u4 = read_wave_dsrc_reg32(WAVE_MAC_A_CCH_AC1_FREE_SPACE_H_REG_OFFSET);
		printf("MAC_A CCH AC1 Free Space = 0x%08x\n", u4);

		u4 = read_wave_dsrc_reg32(WAVE_MAC_A_CCH_AC2_FREE_SPACE_H_REG_OFFSET);
		printf("MAC_A CCH AC2 Free Space = 0x%08x\n", u4);

		u4 = read_wave_dsrc_reg32(WAVE_MAC_A_CCH_AC3_FREE_SPACE_H_REG_OFFSET);
		printf("MAC_A CCH AC3 Free Space = 0x%08x\n", u4);

		u4 = read_wave_dsrc_reg32(WAVE_MAC_A_CCH_AC4_FREE_SPACE_H_REG_OFFSET);
		printf("MAC_A CCH AC4 Free Space = 0x%08x\n", u4);

		u4 = read_wave_dsrc_reg32(WAVE_MAC_A_SCH_AC1_FREE_SPACE_H_REG_OFFSET);
		printf("MAC_A SCH AC1 Free Space = 0x%08x\n", u4);

		u4 = read_wave_dsrc_reg32(WAVE_MAC_A_SCH_AC2_FREE_SPACE_H_REG_OFFSET);
		printf("MAC_A SCH AC2 Free Space = 0x%08x\n", u4);

		u4 = read_wave_dsrc_reg32(WAVE_MAC_A_SCH_AC3_FREE_SPACE_H_REG_OFFSET);
		printf("MAC_A SCH AC3 Free Space = 0x%08x\n", u4);

		u4 = read_wave_dsrc_reg32(WAVE_MAC_A_SCH_AC4_FREE_SPACE_H_REG_OFFSET);
		printf("MAC_A SCH AC4 Free Space = 0x%08x\n", u4);
	}
	else if (!strcmp( argv[0], "freespace1" ))
	{
		u4 = read_wave_dsrc_reg32(WAVE_MAC_B_CCH_AC1_FREE_SPACE_H_REG_OFFSET);
		printf("MAC_B CCH AC1 Free Space = 0x%08x\n", u4);

		u4 = read_wave_dsrc_reg32(WAVE_MAC_B_CCH_AC2_FREE_SPACE_H_REG_OFFSET);
		printf("MAC_B CCH AC2 Free Space = 0x%08x\n", u4);

		u4 = read_wave_dsrc_reg32(WAVE_MAC_B_CCH_AC3_FREE_SPACE_H_REG_OFFSET);
		printf("MAC_B CCH AC3 Free Space = 0x%08x\n", u4);

		u4 = read_wave_dsrc_reg32(WAVE_MAC_B_CCH_AC4_FREE_SPACE_H_REG_OFFSET);
		printf("MAC_B CCH AC4 Free Space = 0x%08x\n", u4);

		u4 = read_wave_dsrc_reg32(WAVE_MAC_B_SCH_AC1_FREE_SPACE_H_REG_OFFSET);
		printf("MAC_B SCH AC1 Free Space = 0x%08x\n", u4);

		u4 = read_wave_dsrc_reg32(WAVE_MAC_B_SCH_AC2_FREE_SPACE_H_REG_OFFSET);
		printf("MAC_B SCH AC2 Free Space = 0x%08x\n", u4);

		u4 = read_wave_dsrc_reg32(WAVE_MAC_B_SCH_AC3_FREE_SPACE_H_REG_OFFSET);
		printf("MAC_B SCH AC3 Free Space = 0x%08x\n", u4);

		u4 = read_wave_dsrc_reg32(WAVE_MAC_B_SCH_AC4_FREE_SPACE_H_REG_OFFSET);
		printf("MAC_B SCH AC4 Free Space = 0x%08x\n", u4);
	}
	else if (!strcmp( argv[0], "sleep" ))
	{
		if (argc == 2)
		{
			count = atoi(argv[1]);

			printf("sleep time = %d nanosec\n", count);
			
			gettimeofday(&start_point, NULL);
			my_nanosleep(0, count);

			gettimeofday(&end_point, NULL);

			operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
			printf("\nSleep Operation Time : %f\n",operating_time);
		}
		else
		{
			printf("[USAGE] sleep [value(nanosec)]\n");
		}
	}
	else if (!strcmp( argv[0], "usleep" ))
	{
		if (argc == 2)
		{
			count = atoi(argv[1]);

			printf("sleep time = %d usec\n", count);
			
			gettimeofday(&start_point, NULL);
			usleep(count);

			gettimeofday(&end_point, NULL);

			operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
			printf("\nSleep Operation Time : %f\n",operating_time);
		}
		else
		{
			printf("[USAGE] usleep [value(usec)]\n");
		}
	}
	else if (!strcmp( argv[0], "omita4" ))
	{
		if (argc == 2)
		{
			address4_omit_flag = atoi(argv[1]);
		}
		else
		{
			printf("Current address4_omit_flag=%d\n", address4_omit_flag);
		}
	}
	else if (!strcmp( argv[0], "talen" ))
	{
		if (argc == 2)
		{
			tx_add_len = atoi(argv[1]);
		}
		else
		{
			printf("Current tx_add_len=%d\n", tx_add_len);
		}
	}
	else if (!strcmp( argv[0], "wsar" ))
	{
		if (argc == 2)
		{
			wsa_received_flag = atoi(argv[1]);
		}
		else
		{
			printf("Current wsa_received_flag=%d\n", wsa_received_flag);
			printf("Current RSE MAC Source Address = [%02x:%02x:%02x:%02x:%02x:%02x]\n", WSA_SRC_MAC_ADDR[0], WSA_SRC_MAC_ADDR[1], WSA_SRC_MAC_ADDR[2], WSA_SRC_MAC_ADDR[3], WSA_SRC_MAC_ADDR[4], WSA_SRC_MAC_ADDR[5]);
			printf("Current RSE PC MAC Source Address = [%02x:%02x:%02x:%02x:%02x:%02x]\n", WSA_DEST_MAC_ADDR[0], WSA_DEST_MAC_ADDR[1], WSA_DEST_MAC_ADDR[2], WSA_DEST_MAC_ADDR[3], WSA_DEST_MAC_ADDR[4], WSA_DEST_MAC_ADDR[5]);
		}
	}
	else if(!strcmp( argv[0], "faes" ))
	{
		if (argc == 3)
		{
			val = reg_readl((gpio_base + GPGCON_OFFSET));
			val &= 0xFFF3FFFF;	/* 18, 19번째 비트를 0으로 만든다. */
			val |= 0x00040000;	/* GPG9을 Output Mode으로 세팅한다. */
			reg_writel((gpio_base + GPGCON_OFFSET), val);
			
			val = atoi(argv[1]);
			test_mode = atoi(argv[2]);

			if (val == 1)
			{
				software_ccm_test(test_mode);
			
				
			}
			else if (val == 2)
			{
				fpga_ccm_test(test_mode, 0);
				//fpga_ccm_test1(test_mode);
			}
			else if (val == 3)
			{
				fpga_ccm_test1(0);
			}
			else if (val == 4)
			{
				fpga_ccm_test1(1);
			}
			else
			{
				
				aes_key[0] = 0x00;
				aes_key[1] = 0x01;
				aes_key[2] = 0x02;
				aes_key[3] = 0x03;
				aes_key[4] = 0x04;
				aes_key[5] = 0x05;
				aes_key[6] = 0x06;
				aes_key[7] = 0x07;
				aes_key[8] = 0x08;
				aes_key[9] = 0x09;
				aes_key[10] = 0x0a;
				aes_key[11] = 0x0b;
				aes_key[12] = 0x0c;
				aes_key[13] = 0x0d;
				aes_key[14] = 0x0e;
				aes_key[15] = 0x0f;

				aes_plain[0] = 0x00;
				aes_plain[1] = 0x11;
				aes_plain[2] = 0x22;
				aes_plain[3] = 0x33;
				aes_plain[4] = 0x44;
				aes_plain[5] = 0x55;
				aes_plain[6] = 0x66;
				aes_plain[7] = 0x77;
				aes_plain[8] = 0x88;
				aes_plain[9] = 0x99;
				aes_plain[10] = 0xaa;
				aes_plain[11] = 0xbb;
				aes_plain[12] = 0xcc;
				aes_plain[13] = 0xdd;
				aes_plain[14] = 0xee;
				aes_plain[15] = 0xff;
				
				fpga_aes_encrypt(aes_plain, aes_encrypt, 0);
			}
		}
		else
		{
			printf("[USAGE] faes [test_value] [test_mode]\n");
		}
	}
	else if(!strcmp( argv[0], "faesint" ))
	{
		if (argc == 2)
		{
			val = reg_readl((gpio_base + GPGCON_OFFSET));
			val &= 0xFFF3FFFF;	/* 18, 19번째 비트를 0으로 만든다. */
			val |= 0x00080000;	/* GPG9을 EINT17으로 세팅한다. */
			reg_writel((gpio_base + GPGCON_OFFSET), val);
		
			test_mode = atoi(argv[1]);

			fpga_ccm_test(test_mode, 1);
		}
		else
		{
			printf("[USAGE] faesint [test_mode]\n");
		}
	}
	else if(!strcmp( argv[0], "ecies" ))
	{
		ecies_test();
	}
	else if(!strcmp( argv[0], "fecies" ))
	{
		val = reg_readl((gpio_base + GPGCON_OFFSET));
		val &= 0xFFF3FFFF;	/* 18, 19번째 비트를 0으로 만든다. */
		val |= 0x00040000;	/* GPG9을 Output Mode으로 세팅한다. */
		reg_writel((gpio_base + GPGCON_OFFSET), val);
			
		val = 1;
		val = atoi(argv[1]);

		printf("Count=%d\n", val);

		for ( i = 0; i < val; i++)
			fpga_ecies_test();
			//rx_fpga_ecies_test();
	}
	else if(!strcmp( argv[0], "feciesint" ))
	{
		val = reg_readl((gpio_base + GPGCON_OFFSET));
		val &= 0xFFF3FFFF;	/* 18, 19번째 비트를 0으로 만든다. */
		val |= 0x00080000;	/* GPG9을 EINT17으로 세팅한다. */
		reg_writel((gpio_base + GPGCON_OFFSET), val);
			
		val = 1;
		val = atoi(argv[1]);

		printf("Count=%d\n", val);

		for ( i = 0; i < val; i++)
			fpga_ecies_interrupt_test();
	}
	else if(!strcmp( argv[0], "sha" ))
	{
		if (argc == 2)
		{
			val = atoi(argv[1]);

			if (val == 1)
			{
				sha256_test1();
			}
			else if (val == 2)
			{
				sha256_test2();
			}
		}
		else
		{
			printf("[USAGE] sha [test_value]\n");
		}
	}
	/* fips180-2.pdf 파일의 Appendix B.1 참조 */
	else if(!strcmp( argv[0], "fsha256" ))
	{
		if (argc == 2)
		{
			val = reg_readl((gpio_base + GPGCON_OFFSET));
			val &= 0xFFF3FFFF;	/* 18, 19번째 비트를 0으로 만든다. */
			val |= 0x00040000;	/* GPG9을 Output Mode으로 세팅한다. */
			reg_writel((gpio_base + GPGCON_OFFSET), val);
			
			val = atoi(argv[1]);

			if (val == 1)
			{
				i = 0;
				
				expected_sha_out[i++] = 0xba;
				expected_sha_out[i++] = 0x78;
				expected_sha_out[i++] = 0x16;
				expected_sha_out[i++] = 0xbf;
				expected_sha_out[i++] = 0x8f;
				expected_sha_out[i++] = 0x01;
				expected_sha_out[i++] = 0xcf;
				expected_sha_out[i++] = 0xea;
				expected_sha_out[i++] = 0x41;
				expected_sha_out[i++] = 0x41;
				expected_sha_out[i++] = 0x40;
				expected_sha_out[i++] = 0xde;
				expected_sha_out[i++] = 0x5d;
				expected_sha_out[i++] = 0xae;
				expected_sha_out[i++] = 0x22;
				expected_sha_out[i++] = 0x23;
				expected_sha_out[i++] = 0xb0;
				expected_sha_out[i++] = 0x03;
				expected_sha_out[i++] = 0x61;
				expected_sha_out[i++] = 0xa3;
				expected_sha_out[i++] = 0x96;
				expected_sha_out[i++] = 0x17;
				expected_sha_out[i++] = 0x7a;
				expected_sha_out[i++] = 0x9c;
				expected_sha_out[i++] = 0xb4;
				expected_sha_out[i++] = 0x10;
				expected_sha_out[i++] = 0xff;
				expected_sha_out[i++] = 0x61;
				expected_sha_out[i++] = 0xf2;
				expected_sha_out[i++] = 0x00;
				expected_sha_out[i++] = 0x15;
				expected_sha_out[i++] = 0xad;

				
				message[0] = 0x61;	/* 'a' */
				message[1] = 0x62;	/* 'b' */
				message[2] = 0x63;	/* 'c' */
				fsha256_test1(message, 3, 1, sha_out);


				if( memcmp( (U1 *)sha_out, (U1 *)expected_sha_out, 32 ) == 0 )
				{
					printf("===============================================\n");
					printf("SHA256 Test Vector1 Success!!\n");
					printf("===============================================\n");
				}
				else
				{
					printf("===============================================\n");
					printf("SHA256 Test Vector1 Fail!!\n");
					printf("===============================================\n");
				}
			}
			else if (val == 2)
			{
				i = 0;

				expected_sha_out[i++] = 0x24;
				expected_sha_out[i++] = 0x8d;
				expected_sha_out[i++] = 0x6a;
				expected_sha_out[i++] = 0x61;
				expected_sha_out[i++] = 0xd2;
				expected_sha_out[i++] = 0x06;
				expected_sha_out[i++] = 0x38;
				expected_sha_out[i++] = 0xb8;
				expected_sha_out[i++] = 0xe5;
				expected_sha_out[i++] = 0xc0;
				expected_sha_out[i++] = 0x26;
				expected_sha_out[i++] = 0x93;
				expected_sha_out[i++] = 0x0c;
				expected_sha_out[i++] = 0x3e;
				expected_sha_out[i++] = 0x60;
				expected_sha_out[i++] = 0x39;
				expected_sha_out[i++] = 0xa3;
				expected_sha_out[i++] = 0x3c;
				expected_sha_out[i++] = 0xe4;
				expected_sha_out[i++] = 0x59;
				expected_sha_out[i++] = 0x64;
				expected_sha_out[i++] = 0xff;
				expected_sha_out[i++] = 0x21;
				expected_sha_out[i++] = 0x67;
				expected_sha_out[i++] = 0xf6;
				expected_sha_out[i++] = 0xec;
				expected_sha_out[i++] = 0xed;
				expected_sha_out[i++] = 0xd4;
				expected_sha_out[i++] = 0x19;
				expected_sha_out[i++] = 0xdb;
				expected_sha_out[i++] = 0x06;
				expected_sha_out[i++] = 0xc1;

				i = 0;
				message[i++] = 'a';	/* 'a' */
				message[i++] = 'b';	/* 'b' */
				message[i++] = 'c';	/* 'c' */
				message[i++] = 'd';
				
				message[i++] = 'b';
				message[i++] = 'c';
				message[i++] = 'd';
				message[i++] = 'e';
				
				message[i++] = 'c';
				message[i++] = 'd';
				message[i++] = 'e';
				message[i++] = 'f';
				
				message[i++] = 'd';
				message[i++] = 'e';
				message[i++] = 'f';
				message[i++] = 'g';
				
				message[i++] = 'e';
				message[i++] = 'f';
				message[i++] = 'g';
				message[i++] = 'h';

				message[i++] = 'f';
				message[i++] = 'g';
				message[i++] = 'h';
				message[i++] = 'i';
				
				message[i++] = 'g';
				message[i++] = 'h';
				message[i++] = 'i';
				message[i++] = 'j';
				
				message[i++] = 'h';
				message[i++] = 'i';
				message[i++] = 'j';
				message[i++] = 'k';
				
				message[i++] = 'i';
				message[i++] = 'j';
				message[i++] = 'k';
				message[i++] = 'l';
				
				message[i++] = 'j';
				message[i++] = 'k';
				message[i++] = 'l';
				message[i++] = 'm';

				message[i++] = 'k';
				message[i++] = 'l';
				message[i++] = 'm';
				message[i++] = 'n';
				
				message[i++] = 'l';
				message[i++] = 'm';
				message[i++] = 'n';
				message[i++] = 'o';
				
				message[i++] = 'm';
				message[i++] = 'n';
				message[i++] = 'o';
				message[i++] = 'p';
				
				message[i++] = 'n';
				message[i++] = 'o';
				message[i++] = 'p';
				message[i++] = 'q';

				fsha256_test1(message, i, 1, sha_out);

				if( memcmp( (U1 *)sha_out, (U1 *)expected_sha_out, 32 ) == 0 )
				{
					printf("===============================================\n");
					printf("SHA256 Test Vector2 Success!!\n");
					printf("===============================================\n");
				}
				else
				{
					printf("===============================================\n");
					printf("SHA256 Test Vector2 Fail!!\n");
					printf("===============================================\n");
				}
				//fsha256_test2();
			}
		}
		else
		{
			printf("[USAGE] fsha256 [test_value] : if test_value is 1, One block Test, if test_value is 2, Two block Test \n");
		}
	}
	/* SHA224_TestVector.pdf 파일 참조 */
	else if(!strcmp( argv[0], "fsha224" ))
	{
		if (argc == 2)
		{
			val = reg_readl((gpio_base + GPGCON_OFFSET));
			val &= 0xFFF3FFFF;	/* 18, 19번째 비트를 0으로 만든다. */
			val |= 0x00040000;	/* GPG9을 Output Mode으로 세팅한다. */
			reg_writel((gpio_base + GPGCON_OFFSET), val);
			
			val = atoi(argv[1]);

			if (val == 1)
			{
				i = 0;
				expected_sha_out[i++] = 0x23;
				expected_sha_out[i++] = 0x09;
				expected_sha_out[i++] = 0x7D;
				expected_sha_out[i++] = 0x22;
				expected_sha_out[i++] = 0x34;
				expected_sha_out[i++] = 0x05;
				expected_sha_out[i++] = 0xD8;
				expected_sha_out[i++] = 0x22;
				expected_sha_out[i++] = 0x86;
				expected_sha_out[i++] = 0x42;
				expected_sha_out[i++] = 0xA4;
				expected_sha_out[i++] = 0x77;
				expected_sha_out[i++] = 0xBD;
				expected_sha_out[i++] = 0xA2;
				expected_sha_out[i++] = 0x55;
				expected_sha_out[i++] = 0xB3;
				expected_sha_out[i++] = 0x2A;
				expected_sha_out[i++] = 0xAD;
				expected_sha_out[i++] = 0xBC;
				expected_sha_out[i++] = 0xE4;
				expected_sha_out[i++] = 0xBD;
				expected_sha_out[i++] = 0xA0;
				expected_sha_out[i++] = 0xB3;
				expected_sha_out[i++] = 0xF7;
				expected_sha_out[i++] = 0xE3;
				expected_sha_out[i++] = 0x6C;
				expected_sha_out[i++] = 0x9D;
				expected_sha_out[i++] = 0xA7;

				
				message[0] = 0x61;	/* 'a' */
				message[1] = 0x62;	/* 'b' */
				message[2] = 0x63;	/* 'c' */
				fsha256_test1(message, 3, 0, sha_out);

				if( memcmp( (U1 *)&sha_out[4], (U1 *)expected_sha_out, 28 ) == 0 )
				{
					printf("===============================================\n");
					printf("SHA224 Test Vector1 Success!!\n");
					printf("===============================================\n");
				}
				else
				{
					printf("===============================================\n");
					printf("SHA224 Test Vector1 Fail!!\n");
					printf("===============================================\n");
				}
			}
			else if (val == 2)
			{
				i = 0;
				expected_sha_out[i++] = 0x75;
				expected_sha_out[i++] = 0x38;
				expected_sha_out[i++] = 0x8B;
				expected_sha_out[i++] = 0x16;
				expected_sha_out[i++] = 0x51;
				expected_sha_out[i++] = 0x27;
				expected_sha_out[i++] = 0x76;
				expected_sha_out[i++] = 0xCC;
				expected_sha_out[i++] = 0x5D;
				expected_sha_out[i++] = 0xBA;
				expected_sha_out[i++] = 0x5D;
				expected_sha_out[i++] = 0xA1;
				expected_sha_out[i++] = 0xFD;
				expected_sha_out[i++] = 0x89;
				expected_sha_out[i++] = 0x01;
				expected_sha_out[i++] = 0x50;
				expected_sha_out[i++] = 0xB0;
				expected_sha_out[i++] = 0xC6;
				expected_sha_out[i++] = 0x45;
				expected_sha_out[i++] = 0x5C;
				expected_sha_out[i++] = 0xB4;
				expected_sha_out[i++] = 0xF5;
				expected_sha_out[i++] = 0x8B;
				expected_sha_out[i++] = 0x19;
				expected_sha_out[i++] = 0x52;
				expected_sha_out[i++] = 0x52;
				expected_sha_out[i++] = 0x25;
				expected_sha_out[i++] = 0x25;

				
				i = 0;
				message[i++] = 'a';	/* 'a' */
				message[i++] = 'b';	/* 'b' */
				message[i++] = 'c';	/* 'c' */
				message[i++] = 'd';
				
				message[i++] = 'b';
				message[i++] = 'c';
				message[i++] = 'd';
				message[i++] = 'e';
				
				message[i++] = 'c';
				message[i++] = 'd';
				message[i++] = 'e';
				message[i++] = 'f';
				
				message[i++] = 'd';
				message[i++] = 'e';
				message[i++] = 'f';
				message[i++] = 'g';
				
				message[i++] = 'e';
				message[i++] = 'f';
				message[i++] = 'g';
				message[i++] = 'h';

				message[i++] = 'f';
				message[i++] = 'g';
				message[i++] = 'h';
				message[i++] = 'i';
				
				message[i++] = 'g';
				message[i++] = 'h';
				message[i++] = 'i';
				message[i++] = 'j';
				
				message[i++] = 'h';
				message[i++] = 'i';
				message[i++] = 'j';
				message[i++] = 'k';
				
				message[i++] = 'i';
				message[i++] = 'j';
				message[i++] = 'k';
				message[i++] = 'l';
				
				message[i++] = 'j';
				message[i++] = 'k';
				message[i++] = 'l';
				message[i++] = 'm';

				message[i++] = 'k';
				message[i++] = 'l';
				message[i++] = 'm';
				message[i++] = 'n';
				
				message[i++] = 'l';
				message[i++] = 'm';
				message[i++] = 'n';
				message[i++] = 'o';
				
				message[i++] = 'm';
				message[i++] = 'n';
				message[i++] = 'o';
				message[i++] = 'p';
				
				message[i++] = 'n';
				message[i++] = 'o';
				message[i++] = 'p';
				message[i++] = 'q';

				fsha256_test1(message, i, 0, sha_out);

				if( memcmp( (U1 *)&sha_out[4], (U1 *)expected_sha_out, 28 ) == 0 )
				{
					printf("===============================================\n");
					printf("SHA224 Test Vector2 Success!!\n");
					printf("===============================================\n");
				}
				else
				{
					printf("===============================================\n");
					printf("SHA224 Test Vector2 Fail!!\n");
					printf("===============================================\n");
				}
				//fsha256_test2();
			}
		}
		else
		{
			printf("[USAGE] fsha224 [test_value] : if test_value is 1, One block Test, if test_value is 2, Two block Test \n");
		}
	}
	else if(!strcmp( argv[0], "fecdsaint" ))
	{
		if (argc == 2)
		{
			val = reg_readl((gpio_base + GPGCON_OFFSET));
			val &= 0xFFF3FFFF;	/* 18, 19번째 비트를 0으로 만든다. */
			val |= 0x00080000;	/* GPG9을 EINT17으로 세팅한다. */
			reg_writel((gpio_base + GPGCON_OFFSET), val);

			val = atoi(argv[1]);

			if (val == 1)
			{
				fpga_ecdsa_interrupt_test(1);
			}
			else if (val == 2)
			{
				fpga_ecdsa_interrupt_test(2);
			}
			else
			{
				count = atoi(argv[1]);
				printf("count = %d\n", count);

				for ( i = 0; i < count; i++)
				{
					fpga_ecdsa_interrupt_test(1);
					fpga_ecdsa_interrupt_test(2);
				}
			}
			
		}
		else
		{
			printf("[USAGE] fecdsa [test_value]\n");
			printf("test_value 1 : 256 mode, 2 : 224 mode\n");
		}
	}
	else if(!strcmp( argv[0], "fecdsa" ))
	{
		if (argc == 2)
		{
			val = reg_readl((gpio_base + GPGCON_OFFSET));
			val &= 0xFFF3FFFF;	/* 18, 19번째 비트를 0으로 만든다. */
			val |= 0x00040000;	/* GPG9을 Output Mode으로 세팅한다. */
			reg_writel((gpio_base + GPGCON_OFFSET), val);
		
			val = atoi(argv[1]);

			if (val == 1)
			{
				fpga_ecdsa_test(1);
			}
			else if (val == 2)
			{
				fpga_ecdsa_test(2);
			}
			else
			{
				count = atoi(argv[1]);
				printf("count = %d\n", count);

				for ( i = 0; i < count; i++)
				{
					fpga_ecdsa_test(1);
					fpga_ecdsa_test(2);
				}
			}
			
		}
		else
		{
			printf("[USAGE] fecdsa [test_value]\n");
			printf("test_value 1 : 256 mode, 2 : 224 mode\n");
		}
	}
	else if(!strcmp( argv[0], "fecdsar" ))
	{
		if (argc == 2)
		{
			val = reg_readl((gpio_base + GPGCON_OFFSET));
			val &= 0xFFF3FFFF;	/* 18, 19번째 비트를 0으로 만든다. */
			val |= 0x00040000;	/* GPG9을 Output Mode으로 세팅한다. */
			reg_writel((gpio_base + GPGCON_OFFSET), val);
			
			val = atoi(argv[1]);

			if (val == 1)
			{
				fpga_ecdsa_random_test(1);
			}
			else if (val == 2)
			{
				fpga_ecdsa_random_test(2);
			}
			else
			{
				count = atoi(argv[1]);
				printf("count = %d\n", count);

				for ( i = 0; i < count; i++)
				{
					fpga_ecdsa_random_test(1);
					fpga_ecdsa_random_test(2);
				}
			}
			
		}
		else
		{
			printf("[USAGE] fecdsa [test_value]\n");
			printf("test_value 1 : 256 mode, 2 : 224 mode\n");
		}
	}
	else if(!strcmp( argv[0], "frandom" ))
	{
		if (argc == 3)
		{
			val = reg_readl((gpio_base + GPGCON_OFFSET));
			val &= 0xFFF3FFFF;	/* 18, 19번째 비트를 0으로 만든다. */
			val |= 0x00040000;	/* GPG9을 Output Mode으로 세팅한다. */
			reg_writel((gpio_base + GPGCON_OFFSET), val);
			
			count = atoi(argv[1]);
			val = (unsigned int)atoi(argv[2]);	/* msec 단위 */
			val = val*1000;		/* usec 단위로 변환 */

			for ( i = 0; i < count; i++)
			{
				ecdsa_random_generator_test();
				gettimeofday(&start_point, NULL);
				usleep(val);

				gettimeofday(&end_point, NULL);

				operating_time = (double)(end_point.tv_sec)+(double)(end_point.tv_usec)/1000000.0-(double)(start_point.tv_sec)-(double)(start_point.tv_usec)/1000000.0;
				printf("\nSleep Operation Time : %f\n",operating_time);
			}
			
		}
		else
		{
			printf("[USAGE] frandom [count] [msec]\n");
		}
	}

	
	/* ecdsa --test */
	/* ecdsa -g d84a873b14b9c0e1680bbdc87647f3c382902d2f58d2754b39bca874 -c 8  :  개인키를 입력으로 준 다음 공개키를 얻는 명령어임. secp2241인 경우 */
	/* ecdsa -s d84a873b14b9c0e1680bbdc87647f3c382902d2f58d2754b39bca874 -c 8  : 개인키를 입력으로 준 다음, 서명자를 만든다. 평문은 224mode인 경우 */
	/* ecdsa --verify 03fd44ec11f9d43d9d23b1e1d1c9ed6519b40ecf0c79f48cf476cc43f1 -c 8 : 공개키를 입력으로 준 다음 서명자를 검증한다. 224mode인 경우 */
	/* ecdsa -s d84a873b14b9c0e1680bbdc87647f3c382902d2f58d2754b39bca874 -c 10 : 개인키를 입력으로 준 다음, 서명자를 만든다. 256 mode */
	/* ecdsa --verify 03596375e6ce57e0f20294fc46bdfcfd19a39f8161b58695b3ec5b3d16427c274d -c 10 : 공개키를 입력으로 준 다음 서명자를 검증한다. 256 mode 인 경우 */
	/* secp256r1 인 경우에는 위의 명령에서 -c 8 대신에 -c 10으로 하면 된다. */
	else if(!strcmp( argv[0], "ecdsa" ))
	{
		//Execute command depending on parameters
		if(argc == 1){
			return_value = command_undefined(argc, argv);
		}else if(!strcmp(argv[1],"--generate") || !strcmp(argv[1],"-g")){
			return_value = command_generate(argc, argv);
		}else if(!strcmp(argv[1],"--sign") || !strcmp(argv[1],"-s")){
			return_value = command_sign(argc, argv);
		}else if(!strcmp(argv[1],"--verify")){
			return_value = command_verify(argc, argv);
		}else if(!strcmp(argv[1],"--crack")){
			return_value = command_crack(argc, argv);
		}else if(!strcmp(argv[1],"--benchmark") || !strcmp(argv[1],"-b")){
			return_value = command_benchmark(argc, argv);
		}else if(!strcmp(argv[1],"--test") || !strcmp(argv[1],"-t")){
			return_value = command_test(argc, argv);
			printf("return_value = %d\n", return_value);
		}else if(!strcmp(argv[1],"--test-generate")){
			return_value = command_test_generate(argc, argv);
		}else if(!strcmp(argv[1],"--test-verify")){
			return_value = command_test_verify(argc, argv);
		}else if(!strcmp(argv[1],"--test-compression")){
			return_value = command_test_compression(argc, argv);
		}else if(!strcmp(argv[1],"--test-numbertheory")){
			return_value = command_test_number_theory(argc, argv);
		}else if(!strcmp(argv[1],"--test-self")){
			return_value = command_test_self(argc, argv);
		}else if(!strcmp(argv[1],"--help") || !strcmp(argv[1],"-h")){
			return_value = command_help(argc, argv);
		}else if(!strcmp(argv[1],"--version") || !strcmp(argv[1],"-v")){
			return_value = command_version(argc, argv);
		}else{
			return_value = command_undefined(argc, argv);
		}
	}
	else if(!strcmp( argv[0], "gpio" ))
	{
		if (argc == 2)
		{
			val = atoi(argv[1]);

			if (val)
			{
				reg_value = reg_readl((gpio_base + 0x14));
				reg_value |= 0x200;
			}
			else
			{
				reg_value = reg_readl((gpio_base + 0x14));
				reg_value &= ~((unsigned int)0x200);
			}
			printf("GPB Control Register : 0x%08x\n", reg_readl((gpio_base + 0x10)));

			reg_writel((gpio_base + 0x14), reg_value);	/* GPB9 OutputData Setting, CON1의 48번 핀 */
		}
		else
		{
			printf("[USAGE] gpio [value]\n");
		}
	}
	else if (!strcmp( argv[0], "q" ) ) return 1;
	else
	{
		printf("Invalid Command\n");
	}
	return 0;
}

void *monitor_thread(void *pd)
{
	char  buf[256];
    char* argv[128];
	int   argc, i, index, cnt;
  	char  tmp_buf[256];
	int ret;
	char system_cmd[256];

	printf("Task MONI start....\n");

	printf("\nWAVE]");

	for(cnt=0 ; cnt<10 ; cnt++) hist_buf[cnt][0] = '\0';
	cnt = 0;



	while(1)
  	{
		user_gets(buf);

		if(buf[0] == '.') strcpy(buf, "!!");
		if(buf[0] == '!')
    	{
       		if(buf[1] == '!' || (buf[1] >='0' && buf[1] <='9'))
			{
				if(buf[1] == '!')
       			{
           			index = (cnt+9) % 10;
       			}
       			else index = buf[1] - '0';
       			if(buf[2] == '\0' || buf[3] == '\0')
       			{
           			strcpy(buf, hist_buf[index]);
       			}
       			else
       			{
           			sprintf(tmp_buf, "%s %s", hist_buf[index], &buf[3]);
       				strcpy(buf, tmp_buf);
       			}
       			printf("\n%s\n", buf);
       		}
   			else {
       			for(i=0 ; i<10 ; i++) printf("%d %s\n", i, hist_buf[i]);
           			continue;
   			}
		}

  		strcpy(tmp_buf, buf);
   		argc = parser( buf, argv, 128 );
		if ( argc == 0 ) {
       		printf("\nWAVE]");
      		continue;
    	}
    	else if ( argc != 0 )
    	{
			strcpy(hist_buf[cnt], tmp_buf);
      		cnt++;
      		if(cnt == 10) cnt = 0;
    	}
    	ret = ExecCommand(argc,argv);
		if (ret)
		{
			if (shell_process_pid > 0)
			{
				sprintf(system_cmd, "kill -SIGCONT %d", shell_process_pid);
				system(system_cmd);
			}
			close(clnt_sock);
			munmap(system_control_base, FND_SIZE);
			munmap(gpio_base, FND_SIZE);
			munmap(static_memory_controller_base, FND_SIZE);
			munmap(interrupt_controller_base, FND_SIZE);
			munmap(wave_dsrc_base, WAVE_DSRC_REG_SIZE);
	 		
			close(system_control_fd);
			close(uart1_fd);
			//release(DEVICE_FILENAME, O_RDWR|O_NDELAY);

			if (dev)
				close(dev);

		  #if WAVE_MODEM  || WAVE_MERGE
			system("rmmod wave_drv");
		  #endif
		  	if (serv_sock)
				close(serv_sock);
			//close(uart1_fd);
			//CSFP_Serial_Close(uart1_fd);
			//close(memFd);
		  #if 0
			kill(1, SIGUSR1);	/* Init Process에게 signal을 보낸다. */
		  #else
		  	exit(0);
		  #endif
			break;
		}
    	printf("\nWAVE]");
	}
	exit(0);
}



