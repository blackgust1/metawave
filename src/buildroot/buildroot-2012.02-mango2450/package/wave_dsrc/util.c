/*
 * Various utility functions
 *
 * Copyright (C) 2005 CoreCross, Inc.
 *
 */
#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <string.h>
#include <math.h>		//pow
#include <stdlib.h>		//strtoul
#include "type_def.h"
#include "util.h"
#include "wave_reg.h"
#include "linked_list.h"
#include "task.h"

U4 debug_control;											// 해당 bit가 '1'인 경우 print
int dump_lines = DUMP_LINES_DEFAULT;						// brief 모드에서는 dump_lines 줄만큼만 인쇄한다.

void memory_dump(const char *title, const void *address, int num_of_items, int flags);
char *uintToBinary(unsigned int i) ;

int print_flag = 0;
const char *t_month[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

U1 Gain_table[200]= {	0x00,0x01,0x03,0x05,0x06,0x07,0x08,0x09,0x0A,0x0C, // 20
				  		0x0D,0x0E,0x10,0x12,0x13,0x14,0x15,0x16,0x17,0x19, // 19
				  		0x1A,0x1B,0x1D,0x1E,0x1F,0x20,0x21,0x22,0x23,0x25, // 18
				  		0x26,0x27,0x29,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,0x32, // 17
						0x33,0x34,0x36,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3F, // 16
						0x40,0x41,0x43,0x45,0x46,0x47,0x48,0x49,0x4A,0x4C, // 15
						0x4D,0x4E,0x50,0x52,0x53,0x54,0x55,0x56,0x57,0x59, // 14
						0x5A,0x5B,0x5D,0x5E,0x5F,0x60,0x61,0x62,0x63,0x65, // 13
						0x66,0x67,0x69,0x6B,0x6C,0x6D,0x6E,0x6F,0x70,0x72, // 12
						0x73,0x74,0x76,0x78,0x79,0x7A,0x7B,0x7C,0x7D,0x7F, // 11
						0x80,0x81,0x83,0x85,0x86,0x87,0x88,0x89,0x8A,0x8C, // 10
						0x8D,0x8E,0x90,0x92,0x93,0x94,0x95,0x96,0x97,0x99, // 9
						0x9A,0x9B,0x9D,0x9E,0x9F,0xA0,0xA1,0xA2,0xA3,0xA5, // 8
						0xA6,0xA7,0xA9,0xAB,0xAC,0xAD,0xAE,0xAF,0xB0,0xB2, // 7
						0xB3,0xB4,0xB6,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBF, // 6
						0xC0,0xC1,0xC3,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCC, // 5
						0xCD,0xCE,0xD0,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD9, // 4
						0xDA,0xDB,0xDD,0xDE,0xDF,0xE0,0xE1,0xE2,0xE3,0xE5, // 3
						0xE6,0xE7,0xE9,0xEB,0xEC,0xED,0xEE,0xEF,0xF0,0xF2, // 2
						0xF3,0xF4,0xF6,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFF}; // 1

void print_dump_data(U1 *data, int len, char *title)
{
    int i;
		
    printf("%s\n",title);
    for (i=0;i<len;i++)
    {
        if( (i!=0) && ((i%10)==0) )
        {
            printf("\n");
        }
        printf("%02x ",data[i]);
    }
	printf("\n");
}

void print_dump_char_data(char *data, int len, char *title)
{
    int i;
	
	if (print_flag == 0)
		return;
		
    printf("%s\n",title);
    for (i=0;i<len;i++)
    {
        if( (i!=0) && ((i%10)==0) )
        {
            printf("\n");
        }
        printf("%c",data[i]);
    }
	printf("\n");
}

void print_dump_data2(U2 *data, int len, char *title)
{
    int i;
	
	if (print_flag == 0)
		return;
		
    printf("%s\n",title);
    for (i=0;i<(len/2);i++)
    {
        if( (i!=0) && ((i%10)==0) )
        {
            printf("\n");
        }
        printf("[%04x]",data[i]);
    }
	printf("\n");
}

void print_dump_data4(U4 *data, int len, char *title)
{
    int i;
	
	if (print_flag == 0)
		return;
		
    printf("%s\n",title);
    for (i=0;i<(len/4);i++)
    {
        if( (i!=0) && ((i%8)==0) )
        {
            printf("\n");
        }
        printf("[%08x]",data[i]);
    }
	printf("\n");
}

int twos_complement(int data, int bit)		
{
	int	DATA	;
	int		def	;
	
	def = (int)(pow(2,bit)/2);/* bit 값이 8일 때, def == 128 */
	DATA = data;
	if(data > def)
		DATA = (int)(data - (def*2));
	return( DATA );
}

/* 0xFFFFFFFF -> -1*/
int twos_complement_from_u4_to_int(U4 data)		
{
	int	DATA = 0;
	
	if(data & 0x80000000)
	{
		DATA = -((~data) + 1);
	}
	else
	{
		DATA = data;
	}
	return( DATA );
}

/* -1 -> 0xFFFFFFFF */
U4 twos_complement_from_int_to_u4(int data)		
{
	int	DATA = 0;
	
	DATA = (U4)data;
	return( DATA );
}

U2 get_ps(U1 *dst, const U1 *src, U2 len)
{
	memcpy(dst, src, len);
	dst[len] = 0;
	return len;
}

/* exam: 0x12 0x34 => 0x1234 */
U2 get_p2(U2 *d2, const U1 *s1)
{
	((U1 *)d2)[1] = *s1++;
	((U1 *)d2)[0] = *s1;
	return 2;
}

/* exam: 0x12 0x34 => 0x1234 & mask */
U2 get_p2m(U2 *d2, const U1 *s1, U2 mask)
{
	((U1 *)d2)[1] = *s1++;
	((U1 *)d2)[0] = *s1;
	*d2 &= mask;
	return 2;
}

/* exam: 0x12 0x34 => 0x3412 */
U2 get_i2(U2 *d2, const U1 *s1)
{
	U1 *t = (U1 *)(s1 + 1);

	*d2 = *t--; *d2 <<= 8;
	*d2 |= *t;
	return 2;
}

/* exam: 0x12 0x34 0x56 => 0x00123456 */
U2 get_p3(U4 *d4, const U1 *s1)
{
	*d4  = *s1++; *d4 <<= 8;
	*d4 |= *s1++; *d4 <<= 8;
	*d4 |= *s1;
	return 3;
}

/* exam: 0x12 0x34 0x56 0x78 => 0x12345678 */
U2 get_p4(U4 *d4, const U1 *s1)
{
	*d4  = *s1++; *d4 <<= 8;
	*d4 |= *s1++; *d4 <<= 8;
	*d4 |= *s1++; *d4 <<= 8;
	*d4 |= *s1;
	return 4;
}

/* exam: 0x12 0x34 0x56 0x78 => 0x12345678 */
U2 get_p4m(U4 *d4, const U1 *s1, U4 mask)
{
	*d4  = *s1++; *d4 <<= 8;
	*d4 |= *s1++; *d4 <<= 8;
	*d4 |= *s1++; *d4 <<= 8;
	*d4 |= *s1;

	*d4 &= mask;

	return 4;
}

/* exam: 0x12 0x34 0x56 0x78 => 0x78563412 */
U2 get_i4(U4 *d4, const U1 *s1)
{
	U1 *t = (U1 *)(s1 + 3);

	*d4  = *t--; *d4 <<= 8;
	*d4 |= *t--; *d4 <<= 8;
	*d4 |= *t--; *d4 <<= 8;
	*d4 |= *t;
	return 4;
}

/* exam: 0x12 0x34 0x56 0x78 => 0x78563412 */
U2 get_i4m(U4 *d4, const U1 *s1, U4 mask)
{
	U1 *t = (U1 *)(s1 + 3);

	*d4  = *t--; *d4 <<= 8;
	*d4 |= *t--; *d4 <<= 8;
	*d4 |= *t--; *d4 <<= 8;
	*d4 |= *t;

	*d4 &= mask;

	return 4;
}

/* 0x12345678 --> 0x56781234 */
U4 get_u4_swap_u2(U4 data)		
{
	U4_T a;
	U4_T b;

	a.b4 = data;

	b.b2[0] = a.b2[1];
	b.b2[1] = a.b2[0];
	
	return( b.b4 );
}

/* exam: s2 = 0x1234 => 0x12 0x34 */
U2 put_u2(U1 *d1, const U2 s2)
{
	*d1++ = (U1)(s2 >> 8);
	*d1++ = (U1)s2;
	return 2;
}

/* exam: s2 = 0x1234 => 0x34 0x12 */
U2 net_put_u2(U1 *d1, const U2 s2)
{
	*d1++ = (U1)s2;
	*d1++ = (U1)(s2 >> 8);
	return 2;
}

/* exam: s3 = 0x123456 => 0x12 0x34 0x56 */
U2 put_u3(U1 *d1, const U4 s3)
{
	*d1++ = (U1)(s3 >> 16);
	*d1++ = (U1)(s3 >> 8);
	*d1++ = (U1)s3;
	return 3;
}

/* exam: s4 = 0x12345678 => 0x12 0x34 0x56 0x78 */
U2 put_u4(U1 *d1, const U4 s4)
{
	*d1++ = (U1)(s4 >> 24);
	*d1++ = (U1)(s4 >> 16);
	*d1++ = (U1)(s4 >> 8);
	*d1++ = (U1)s4;
	return 4;
}

/* exam: s4 = 0x12345678 => 0x78 0x56 0x34 0x12 */
U2 net_put_u4(U1 *d1, const U4 s4)
{
	*d1++ = (U1)s4;
	*d1++ = (U1)(s4 >> 8);
	*d1++ = (U1)(s4 >> 16);
	*d1++ = (U1)(s4 >> 24);
	return 4;
}

/* exam: s4 = 0236022f => 0x23 0x23 0x22 0x22 */
U2 put_cap_data_u4(U1 *d1, const U4 s4)
{
	*d1++ = (U1)(s4 >> 20);
	*d1++ = (U1)(s4 >> 20);
	*d1++ = (U1)(s4 >> 4);
	*d1++ = (U1)(s4 >> 4);;
	return 4;
}

/* exam: s4 = 0236022f => 0x23 0x22 */
U2 put_cap_data_u2(U1 *d1, const U4 s4)
{
	*d1++ = (U1)(s4 >> 20);
	*d1++ = (U1)(s4 >> 4);
	return 2;
}

/* exam: 0x12 0x34 => 0x1234 */
U2 str_to_2byte(const char *p1)
{
	U2 ret;

	ret  = *p1++; ret <<= 8;
	ret |= *p1++;

	return ret;
}

/* exam: 0x12 0x34 0x56 0x78 => 0x12345678 */
U4 str_to_4byte(const char *p1)
{
	U4 ret;

	ret  = *p1++; ret <<= 8;
	ret |= *p1++; ret <<= 8;
	ret |= *p1++; ret <<= 8;
	ret |= *p1;

	return ret;
}

/* exam: "ab" => 0x000000ab, "12 34 56 78" => 0x12345678 */
U4 hstrtoul(const char *s)
{
	U4 x=0;
	int i=0;

	while (*s && i < 8)
	{
		x <<= 4;

		if (*s >= '0' && *s <= '9')
		{
			x |= *s - '0';
			i++;
		}
		else if (*s >= 'a' && *s <= 'f')
		{
			x |= *s - 'a' + 10;
			i++;
		}
		else if (*s >= 'A' && *s <= 'F')
		{
			x |= *s - 'A' + 10;
			i++;
		}
		else
		{
			break;
		}

		s++;
	}

	return x;
}

/* exam: '7' => 0x7, 'b' => 0x0B, 'E' = 0x0E */
U1 atox(char a)
{
	U1 x = 0;

	if ('0' <= a && a <= '9')
		x = a - '0';
	else if ('a' <= a && a <= 'f')
		x = a - 'a' + 10;
	else if ('A' <= a && a <= 'F')
		x = a - 'A' + 10;

	return x;
}

/* exam: 3 => 0x33, 11 => 0x62 */
char xtoa(U1 x)
{
	char a = ' ';

	if (x <= 9)
		a = x + 0x30;
	else if (x <= 15)
		a = x + 0x57;

	return a;
}

/* exam: 0x12345678 => 12345678 */
U4 bcd2dec(U4 bcd)
{
	int i;
	U4 h, dec = 0;

	for (i = 0; i < 8; i++)
	{
		dec *= 10;
		h = bcd >> (7 - i) * 4;
		dec += h & 0xF;
	}

	return dec;
}

/* exam: 12345678 => 0x12345678 */
U4 dec2bcd(U4 dec)
{
	int i;
	U4 d, n, bcd = 0;

	n = 10000000;
	for (i = 0; i < 8; i++)
	{
		bcd <<= 4;
		d = dec / n % 10;
		n /= 10;
		bcd |= d;
	}

	return bcd;
}

/* exam: "789ABCDEF0" => 0x78 0x9A 0xBC 0xDE 0xF0 */
void str_to_hex(const char *str, U1 *hex, int len)
{
	const char *ptr;
	int i;

	ptr = str;
	for (i = 0; i < len; i++)
	{
		hex[i] = atox(*ptr++) << 4;
		hex[i] |= atox(*ptr++);
	}
}

const char *_make_binary(U4 n, int num_of_bits, char cZero)
{
	static char tb[40];
	int i, j, k;
	int leading_zero = 1;
	U4 b;

	b = 1 << (num_of_bits-1);

	k = num_of_bits % 4;
	for (i = j = 0; i < num_of_bits; i++, j++)
	{
		if (n & b)
		{
			tb[j] = '1';
			leading_zero = 0;
		}
		else if (leading_zero && i < num_of_bits-1)
		{
			tb[j] = cZero;
		}
		else
		{
			tb[j] = '0';
		}

		b >>= 1;
		if (i+1 < num_of_bits && ++k == 4)
		{
			k = 0;
			tb[++j] = ' ';
		}
	}

	tb[j] = 0;

	return tb;
}

void memory_swap(void *dst, void *src, int size)
{
	U1 *d, *s, t;
	int i;

	if (dst == src || size < 1)
		return;

	d = (U1 *)dst;
	s = (U1 *)src;
	for (i = 0; i < size; i++)
	{
		t = *d;
		*d++ = *s;
		*s++ = t;
	}
}

/* note: 단, s1, s2 문자열의 길이가 len 보다 길면 그만큼 더 검사함 */
/* exam: ("0125", "01234567", 3) => return TRUE */
/*       ("0125", "01234567", 4) => return FALSE */
/*       ("02",   "01234567", 1) => return FALSE */
/*       ("01",   "01234567", 3) => return FALSE */
int strncmd(const char *s1, const char *s2, int len)
{
	int n1, n2;	
	int check_len;
	int i;

	n1 = strlen(s1);
	n2 = strlen(s2);
	check_len = MIN(n1, n2);

	if (check_len < len)
		return FALSE;

	for (i = 0; i < check_len; i++)
	{
		if (s1[i] != s2[i])
			return FALSE;
	}

	return TRUE;
}

/* exam: 0x1234 => 0x3412 */
U2 endian_swap2(U2 r0)
{
	return (r0 >> 8) | (r0 << 8);
}

U2 *endian_swap2p(void *ptr)
{
	U1 b0;

	b0 = ((U1 *)ptr)[0];
	((U1 *)ptr)[0] = ((U1 *)ptr)[1];
	((U1 *)ptr)[1] = b0;
	return ptr;
}

U4 *endian_swap4p(void *ptr)
{
	U1 *p, b0, b1, b2, b3;

	p = (U1 *)ptr;
	b0 = *p++;
	b1 = *p++;
	b2 = *p++;
	b3 = *p;
	*p-- = b0;
	*p-- = b1;
	*p-- = b2;
	*p = b3;
	return ptr;
}

void *memcpy4(void *dst, const void *src, size_t size)
{
	U4 *d;
	const U4 *s;

	d = (U4 *)dst;
	s = (const U4 *)src;

	size = (size + 3) >> 2;	
	while (size--)
		*d++ = *s++;

	return dst;
}

void *memcpy2(void *dst, const void *src, size_t size)
{
	U2 *d;
	const U2 *s;

	d = (U2 *)dst;
	s = (const U2 *)src;

	size = (size + 1) >> 1;	
	while (size--)
		*d++ = *s++;

	return dst;
}

int count_bits(U4 data)
{
	int cnt = 0;

	while (data != 0)
	{
		data = data & (data - 1);
		cnt++;
	}

	return cnt;
}

U1 bit_reverse(U1 value)
{
	U1 tmp, reverse;
	int i;

	tmp = value;
	for (reverse = 0, i = 0; i < 8; i++)					// reverse
	{
		reverse <<= 1;
		reverse |= tmp & 1;
		tmp >>= 1;
	}

	return reverse;
}

int is_leap_year(int year)
{
	if (((year % 400) == 0) || (((year % 4) == 0) && ((year % 100) != 0)))
		return 1;
	else
		return 0;
}


const char *str_invalid(U1 value)
{
	static char invalid_t[10][12];
	static int invalid_n = 0;
	int n ;

	n = invalid_n;
	sprintf(invalid_t[n], "%02X invalid", value);
	if (++invalid_n >= 10)
		invalid_n = 0;

	return invalid_t[n];
}

/* exam: 0x20050630 => "2005/06/30" */
const char *str_date(U4 yyyymmdd)
{
	static char s_date[12];

	sprintf(s_date, "%04X/%02X/%02X", U4_H(yyyymmdd), U4_1(yyyymmdd), U4_0(yyyymmdd));
	return s_date;
}

/* exam: 0x00201135 => "20:11:35" */
const char *str_time(U4 hhmmss)
{
	static char s_time[12];

	sprintf(s_time, "%02X:%02X:%02X", U4_2(hhmmss), U4_1(hhmmss), U4_0(hhmmss));
	return s_time;
}

// nanosleep wrapper function
void my_delay(long nsec)
{
	U2 i;
	long dt;
	
	dt = nsec;
    while(--dt)
    {
        //i=1234;	//ORIGIN
        i=5;
        while(--i);
    }
	return;
}


// nanosleep wrapper function
void my_nanosleep(time_t sec,long nsec)
{
    struct timespec req;

    //struct timespec rem;

    if ((sec==0) && (nsec==0)) {
        req.tv_sec=0;
        req.tv_nsec=999999999L; // 999 999 999
    }
    else {
        req.tv_sec=sec;
        req.tv_nsec=nsec; // 999 999 999
    }

    //rem.tv_sec=0;
    //rem.tv_nsec=0;

    //while (nanosleep(&req, &rem))
    while (nanosleep(&req, &req))
    {
        if (errno != EINTR)
            break;
    }
    return;
}

U4 myclock(void)
{
	struct timeval tv;
	gettimeofday (&tv, NULL);
	return (tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

char *strmhz (char *buf, long hz)
{
    long l, n;
    long m;

    n = hz / 1000000L;
    l = sprintf (buf, "%ld", n);
    m = (hz % 1000000L) / 1000L;
    if (m != 0)
        sprintf (buf + l, ".%03ld", m);
    return (buf);
}

/* exam: high = 0x1234, low = 0x5678  => Return 0x12345678 */
U4 get_u4_from_u2(U2 high, U2 low)
{
    U4_T data;
    
    //little endian
    data.b2[1] = high;
    data.b2[0] = low;
    return (data.b4);
}

/* exam: data = 0x12345678  => Return 0x1234 */
U2 get_u2_high_from_u4(U4 a)
{
    U4_T data;
    
    //printf("[get_u2_high_from_u4] a = 0x%08x\n", a);
    
    data.b4 = a;
    
    //printf("[get_u2_high_from_u4] data.b2[0] = 0x%04x\n", data.b2[0]);
    //printf("[get_u2_high_from_u4] data.b2[1] = 0x%04x\n", data.b2[1]);
    
    //little endian
    return (data.b2[1]);
}

/* exam: data = 0x12345678  => Return 0x5678 */
U2 get_u2_low_from_u4(U4 a)
{
    U4_T data;
    
    data.b4 = a;
    
    //little endian
    return (data.b2[0]);
}

/*
 기능: 입력으로 주어진 월의 영문자 3개로부터 16진수의 월로 변환한다.
*/
U4 month2hex(const char *month)
{
	int i;

	for (i = 0; i < 12; i++)
	{
		if (memcmp(month, t_month[i], 3) == S_OK)
			return dec2bcd(1 + i);
	}

	return 0;
}

/*
 기능: 입력으로 주어진 월(1~12)에 해당하는 3자리 영문자열을 리턴한다.
*/
const char *month2str(int month)
{
	if (month >= 1 && month <= 12)
		return t_month[month - 1];

	return "   ";
}

/*
 기능: 입력으로 주어진 __DATE__ 형식의 문자열로부터 16진수의 yyyymmdd 형식의 년월일 숫자로 변환한다.
 입력: e.g. "Feb 16 2006"
 리턴: e.g. 0x20060216
*/
U4 __DATE__to_yyyymmdd(const char *date)
{
	U4 yyyymmdd;
	char b[5];

	// year
	b[0] = date[7];
	b[1] = date[8];
	b[2] = date[9];
	b[3] = date[10];
	b[4] = 0;
	yyyymmdd = strtoul(b, NULL, 16) << 16;

	// month
	yyyymmdd |= month2hex(date) << 8;

	// day
	b[0] = date[4];
	b[1] = date[5];
	b[2] = 0;
	yyyymmdd |= strtoul(b, NULL, 16);

	return yyyymmdd;
}

/*
 기능: 입력으로 주어진 __TIME__ 형식의 문자열로부터 16진수의 hhmmss 형식의 시분초 숫자로 변환한다.
 입력: e.g. "18:31:03"
 리턴: e.g. 0x00183103
*/
U4 __TIME__to_hhmmss(const char *time)
{
	U4 hhmmss;
	char b[3];

	// hour
	b[0] = time[0];
	b[1] = time[1];
	b[2] = 0;
	hhmmss = strtoul(b, NULL, 16) << 16;

	// minute
	b[0] = time[3];
	b[1] = time[4];
	hhmmss |= strtoul(b, NULL, 16) << 8;

	// sec
	b[0] = time[6];
	b[1] = time[7];
	hhmmss |= strtoul(b, NULL, 16);

	return hhmmss;
}

/*
	reg_width :0 -> 25ns
	reg_width :1 -> 50ns
	reg_width :0x3FF -> 25.6 us
*/
U4 get_high_pulse_width_nano_sec_from_reg_value(U4 reg_width)
{
	U4 ns;
	
	ns = (reg_width * 25) + 25;
	return ns;
	
}

/*
	ns :25ns -> 0
	ns :50ns -> 1
	ns :25600ns -> 0x3FF
*/
U4 get_reg_value_from_high_pulse_width_nano_sec(U4 ns)
{
	U4 reg_value;
	U4 remain;
	
	if (ns < 25)
		ns = 25;
		
	if (ns >= 25600)
		return(0x3FF);
		
	remain = ns % 25;
	
	if(remain > 12)
	{
		ns = ((ns + 24)/25) * 25; // ns를 25의 배수로 만듬
		reg_value = (ns/25) - 1;
	}
	else
	{
		reg_value = (ns/25) - 1;
	}
	return reg_value;
	
}

/*
	ns :25ns -> 0
	ns :50ns -> 1
*/
U4 get_reg_value_from_low_pulse_width_nano_sec(U4 ns)
{
	U4 reg_value;
	U4 remain;
	
	if (ns < 25)
		ns = 25;
		
		
	remain = ns % 25;
	
	if(remain > 12)
	{
		ns = ((ns + 24)/25) * 25; // ns를 25의 배수로 만듬
		reg_value = (ns/25) - 1;
	}
	else
	{
		reg_value = (ns/25) - 1;
	}
	return reg_value;
	
}


/*
	reg_delay :2 -> 0ns
	reg_delay :3 -> 25ns
	reg_delay :0x61A7C -> 10ms
*/
U4 get_high_pulse_delay_nano_sec_from_reg_value(U4 reg_delay)
{
	U4 ns;
	
	if (reg_delay < 2)
	{
		printf("[get_high_pulse_delay_nano_sec_from_reg_value] Invalid reg_delay=%d\n",reg_delay);
		printf("[get_high_pulse_delay_nano_sec_from_reg_value] reg_delay must bigger than 1\n");
		return 0;
	}
	else
	{
		ns = (reg_delay - 2) * 25;
	}
	return ns;
	
}

/*
	ns :0ns -> 2
	ns :25ns -> 3
	ns :10ms -> 0x61A7C
*/
U4 get_reg_value_from_high_pulse_delay_micro_sec(float us)
{
	U4 reg_value;
	U4 remain;
	U4 ns;
	
	ns = (U4)(1000*us);
	
	if (us >= 10000) // 10ms보다 크거나 같으면
		return (0x61A7C);
	
	if (ns < 25)
		ns = 0;
		
	remain = ns % 25;
	
	if(remain > 12)
	{
		ns = ((ns + 24)/25) * 25; // ns를 25의 배수로 만듬
		reg_value = (ns/25) + 2;
	}
	else
	{
		reg_value = (ns/25) + 2;
	}
	return reg_value;	
}


U2 get_spi_gain_data(float gain)
{
	U2 spi_gain = 0;
	int diff = 0;
	
	if ((gain < -20.0) || (gain >= 60.0))
	{
		printf("[get_spi_gain_data]Invalid gain=%f\n", gain);
		return 0xFFFF;
	}
	
	if(gain < 0.0)
	{
		diff = 200 - (int)(-gain*10);
		spi_gain = (U2)Gain_table[diff];
	}
	else if((gain >= 0.0)&&(gain < 20.0))
	{
		diff = (int)(gain*10);
		spi_gain = (0x0001 << 8) | (U2)Gain_table[diff];
	}
	else if((gain >= 20.0)&&(gain < 40.0))
	{
		diff = (int)(gain*10) - 200;
		spi_gain = (0x0002 << 8) | (U2)Gain_table[diff];
	}
	else if((gain >= 40.0)&&(gain < 60.0))
	{
		diff = (int)(gain*10) - 400;
		spi_gain = (0x0003 << 8) | (U2)Gain_table[diff];
	}
	
	return(spi_gain);	
	
} 

/* 10000 us --> 100Hz*/
U4 get_freq_from_micro_sec_period(U4 us)
{
	U4 freq;
	
	freq = 1000000/us;
	return freq;
}

/* 200MHz -> 0, 100MHz -> 1, 50MHz -> 2, 25MHz -> 3 */
U4 get_sampling_rate_reg_value_from_mhz(float mhz)
{
	U4 reg_value;
	
	if(mhz > 150.0)
	{
		reg_value = 0;
	}
	else if(mhz > 75.0)
	{
		reg_value = 1;
	}
	else if(mhz > 37.5)
	{
		reg_value = 2;
	}
	else
	{
		reg_value = 3;
	}
	return reg_value;
	
}


/* 1000 -> 1024, 2000 -> 2048, 3000 -> 3072, 4000 -> 4096 */
U4 get_kbyte_unit_len_frome_length(U4 length)
{
	U4 length_ext;
	U4 a;
	
	a = KB(1) - 1;
	
	length_ext = (length + a) & ~a;
	return length_ext;
	
}

/* SHKO Added */
/*
 기능: 입력 address의 데이터 내용을 주어진 정수 단위로 읽어서 인쇄한다.
 입력: title: 제목
       address: 읽을 주소
       num_of_items: 읽을 항목 개수
       flags: & 0x07 = unit, 읽기 단위, 1=byte, 2=short, 4=int, 0=previous access unit
	          & DUMP_ADDR = print address
	          & DUMP_OFFSET = print offset
			  & DUMP_CHAR = print char
			  & DUMP_INDENT = print indent always (including ':' char)
 note: dump brief mode 이면 dump_lines 줄 수만큼만 프린트 한다.
*/
void memory_dump(const char *title, const void *address, int num_of_items, int flags)
{
	static int read_unit = 4;
	U1 u1;
	U2 u2;
	U4 u4;
	U4 addr = (U4)address;
	int i, j, k;
	int print_addr = 0, print_addr_in_title = 0, print_offset = 0, print_char = 0, print_space = 0, print_indent = 0;
	int dump_reduced = 0;
	char tb[17];

	if (num_of_items <= 0)
	{
		printf("%s len=0\n\r", title);
		return;
	}

	// get unit
	if (flags & 4)
		read_unit = 4;
	else if (flags & 2)
		read_unit = 2;
	else if (flags & 1)
		read_unit = 1;

	if (flags & DUMP_SPACE)
		print_space = 1;

	// get other options
	if (flags & DUMP_ADDR)
		print_addr = 1;

	if (flags & DUMP_OFFSET)
		print_offset = 1;

	if (print_addr && print_offset)
	{
		print_addr_in_title = 1;
		print_addr = 0;
	}

	if (flags & DUMP_INDENT)
		print_indent = 1;

	if (flags & DUMP_CHAR)
		print_char = 1;

	// limit to 16MB
	if (num_of_items * read_unit > MB(16))
		num_of_items = MB(16) / read_unit;

	// print title
	if (title)
	{
		while (*title == '\n')								// 줄 넘김은 미리 표시해서 안섞이게 함
		{
			printf("%c", *title);
			title++;
		}


		if (print_addr_in_title)
			printf("Dump %u: %s at %p\n\r", read_unit * num_of_items, title, address);
		else
			printf("Dump %u: %s\n\r", read_unit * num_of_items, title);

		// dump briefly
		if (debug_control & _LOG_F_DUMP_BRIEF)
		{
			int lines_needed;

			if (dump_lines < 1)
				return;

			lines_needed = (num_of_items + 15) / 16;

			if (lines_needed > dump_lines)
			{
				dump_reduced = 1;
				num_of_items = (dump_lines << 4) / read_unit;
			}
		}
	}

	switch (read_unit)
	{
	case 1:
		if (num_of_items < 2)
		{
			u1 = reg_readb(addr);
			if (print_offset)
				printf(" %8X :", 0);
			else if (print_addr)
				printf(" %08X :", addr);

			printf(" %02X  (%s)\n\r", u1, make_binary((U4)u1, 8));
		}
		else
		{
			for (i = j = k = 0; i < num_of_items; i++, j++)
			{
				u1 = reg_readb(addr);
				if (j % 16 == 0)
				{
					if (print_char)
					{
						if (k > 0)
						{
							tb[k] = 0;
							if (print_char)
								printf(" | %s |", tb);
						}
						k = 0;
					}

					if (i > 0)
						putchar('\n');

					// Fitted for TeraTermPro(8 tab)
					if (debug_control & _LOG_F_TIME)
					{
						if (print_addr)
							printf("       %08X :", addr);
						else if (print_offset)
							printf("       %8X :", i);
						else
							printf("\t\t:");
					}
					else
					{
						if (print_addr)
							printf(" %08X :", addr);
						else if (print_offset)
							printf(" %8X :", i);
						else if (print_indent)
							printf("\t  :");
					}
				}
				else if (j % 4 == 0)
				{
					if (print_space)
						putchar(' ');
				}

				printf (" %02X", u1);
				addr++;
				if (print_char)
					tb[k++] = putchar(u1);
			}

			// 마지막 16 바이트미만 인쇄
			if (print_char && k > 0)
			{
				for (j = k; j < 16; j++)
				{
					if (j % 4 == 0)
					{
						if (print_space)
							putchar(' ');
					}

					printf ("   ");

					tb[k++] = ' ';
				}
				tb[k] = 0;
				printf(" | %s |", tb);
			}
			putchar('\n');

			// 인쇄가 생략됬음을 표시
			if (dump_reduced)
			{
				printf("\t ...\n\r");
			}
		}
		break;

	case 2:
		if (num_of_items < 2)
		{
			u2 = reg_readw(addr);
			printf(" %08X : %04X  (%s)\n\r", addr, u2, make_binary((U4)u2, 16));
		}
		else
		{
			for (i = j = 0; i < num_of_items; i++, j++)
			{
				if (j % 8 == 0)
				{
					if (i > 0)
						printf("\n");

					// Fitted for TeraTermPro(8 tab)
					if (debug_control & _LOG_F_TIME)
					{
						if (print_addr)
							printf("       %08X :", addr);
						else if (print_offset)
							printf("       %8X :", i);
						else
							printf("\t\t:");
					}
					else
					{
						if (print_addr)
							printf(" %08X :", addr);
						else if (print_offset)
							printf(" %8X :", i);
						else if (print_indent)
							printf("\t  :");
					}
				}
				printf (" %04X", reg_readw(addr));
				addr += 2;
			}
			printf("\n");
		}
		break;

	case 4:
		if (num_of_items < 2)
		{
			u4 = reg_readl(addr);
			printf(" %08X : %08X  (%s)\n\r", addr, u4, make_binary(u4, 32));
		}
		else
		{
			for (i = j = 0; i < num_of_items; i++, j++)
			{
				if (j % 4 == 0)
				{
					if (i > 0)
						printf("\r\n");

					// Fitted for TeraTermPro(8 tab)
					if (debug_control & _LOG_F_TIME)
					{
						if (print_addr)
							printf("       %08X :", addr);
						else if (print_offset)
							printf("       %8X :", i);
						else
							printf("\t\t:");
					}
					else
					{
						if (print_addr)
							printf(" %08X :", addr);
						else if (print_offset)
							printf(" %8X :", i);
						else if (print_indent)
							printf("\t  :");
					}
				}
				printf (" %08X", reg_readl(addr));
				addr += 4;
			}
			printf("\r\n");
		}
		break;
	}

	printf("\n\r");
}

static int which_number(char *s)
{
	int len, i;

	len = strlen(s);

	for ( i = 0; i < len; i++)
	{
		if ((s[i] < '0' || s[i] > '9'))
			return(-1);
	}

	return(atoi(s));
}


int get_pid_from_proc_by_name(char *str)
{
	DIR *dp;
	struct dirent *dir;
	char buf[100], line[1024], tag[100], name[100];
	int pid;
	FILE *fp;

	dp = opendir("/proc");
	if (!dp)
		return(-1);

	while((dir = readdir(dp)))
	{
		//printf("dir->d_name=%s\n", dir->d_name);
		pid = which_number(dir->d_name);

		if (pid == -1)
			continue;

		/* Open /proc/pid/status file. */
		snprintf(buf, 100, "/proc/%d/status", pid);
		fp = fopen(buf, "r");
		if (fp == NULL)
			continue;

		/* Get first line with name. */
		fgets(line, 1024, fp);

		/* Close stream */
		fclose(fp);

		sscanf(line, "%s %s", tag, name);
		//printf("name=%s\n", name);
		if (!strcmp(name, str))
		{
			closedir(dp);
			return(pid);
		}
	}
	closedir(dp);
	return(-1);
	
}

/* 입력 : "000102030405060708", 출력 : 0x012345678 */
int convert_string_to_hex(char *in, unsigned char *out, int len)
{
	int i, j;

	i = 0;
	j = 0;
	while (*in &&  i < len)
	{
		if (*in >= '0' && *in <= '9')
		{
			if ( (i % 2) == 0 )
				out[j] = *in - '0';
			else
				out[j] |= *in - '0';
		}
		else if (*in >= 'a' && *in <= 'f')
		{
			if ( (i % 2) == 0 )
				out[j] = *in - 'a' + 10;
			else
				out[j] |= *in - 'a' + 10;
		}
		else if (*in >= 'A' && *in <= 'F')
		{
			if ( (i % 2) == 0 )
				out[j] = *in - 'A' + 10;
			else
				out[j] |= *in - 'A' + 10;
		}
		else
		{
			out[j] >>= 4;
			break;
		}

		if ( (i % 2) == 0 )
			out[j] <<= 4;
		else
			j++;


		in++;
		i++;
	}
	return 0;
}



/* 입력인자 data는 2's complement형태의 데이터이다. */
/* 입력인자 bit는 2's complement형태의 데이터를 표시하는 총 비트수를 의미한다. */
int tows_complement(int data, int bit)			/*Ctuner_BS2F7VZ0180::tows_complement*/
{
	int	DATA	;
	int		def	;
	
	def = (int)(pow(2,bit)/2);/* bit 값이 8일 때, def == 128 */
	DATA = data;
	if(data > def)
		DATA = (int)(data - (def*2));
	return( DATA );
}

/* unsigned int 데이터를 입력으로 받아서 이진수를 리턴하는 소스 */
char *uintToBinary(unsigned int i) {
  static char s[32 + 1] = { '0', };
  int count = 32;

  do { s[--count] = '0' + (char) (i & 1);
       i = i >> 1;
  } while (count);

  return s;
}








