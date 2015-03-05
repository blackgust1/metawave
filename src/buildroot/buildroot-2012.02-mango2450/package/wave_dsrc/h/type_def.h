/*
 * basic constants, types, macros for MCC project
 *
 *
 */

#ifndef _TYPE_DEF_H_
#define _TYPE_DEF_H_

//
// Constants, Macros
//

#ifndef S_OK
	#define S_OK							0
#endif

#ifndef TRUE
	#define TRUE							1
#endif

#ifndef FALSE
	#define FALSE							0
#endif

#define		WAVE_FPGA_VER											0
#define		WAVE_ASIC_VER											1


#define	WAVE_MODEM			0
#define	WAVE_ECC				0
#define	WAVE_MERGE			1

#define		WAVE_SECURITY_16BIT_ENABLE				1


/*
 ASCII
 -------------------------------------------------------------------------
	00  NUL  ^@          20  SPACE            40  @                60  `
	01  SOH  ^A          21  !                41  A                61  a
	02  STX  ^B          22  "                42  B                62  b
	03  ETX  ^C          23  #                43  C                63  c
	04  EOT  ^D          24  $                44  D                64  d
	05  ENQ  ^E          25  %                45  E                65  e
	06  ACK  ^F          26  &                46  F                66  f
	07  BEL  ^G          27  '                47  G                67  g
	08  BS   ^H          28  (                48  H                68  h
	09  HT   ^I          29  )                49  I                69  I
	0A  LF   ^J          2A  *                4A  J                6A  j
	0B  VT   ^K          2B  +                4B  K                6B  k
	0C  FF   ^L          2C  ,                4C  L                6C  l
	0D  CR   ^M          2D  -                4D  M                6D  m
	0E  SO   ^N          2E  .                4E  N                6E  n
	0F  SI   ^O          2F  /                4F  O                6F  o
	10  DLE  ^P          30  0                50  P                70  p
	11  DC1  ^Q          31  1                51  Q                71  q
	12  DC2  ^R          32  2                52  R                72  r
	13  DC3  ^S          33  3                53  S                73  s
	14  DC4  ^T          34  4                54  T                74  t
	15  NAK  ^U          35  5                55  U                75  u
	16  SYN  ^V          36  6                56  V                76  v
	17  ETB  ^W          37  7                57  W                77  w
	18  CAN  ^X          38  8                58  X                78  x
	19  EM   ^Y          39  9                59  Y                79  y
	1A  SUB  ^Z          3A  :                5A  Z                7A  z
	1B  ESC  ^[          3B  ;                5B  [                7B  {
	1C  FS   ^\          3C  <                5C  \                7C  |
	1D  GS   ^]          3D  =                5D  ]                7D  }
	1E  RS   ^^          3E  >                5E  ^                7E  ~
	1F  US   ^_          3F  ?                5F  _                7F  DEL
 -------------------------------------------------------------------------
*/
#define ASCII_BACK_SPC						0x08			// Backspace
#define ASCII_TAB							0x09			// Tab
#define ASCII_LF							0x0A			// Line Feed
#define ASCII_CR							0x0D			// Carriage Return
#define ASCII_ESC							0x1B			// ESC

#define CRC_OK								0	

#define SEC2MS(s)							((s) * 1000)	// millisecond

#define KB(k)								((k) << 10)		// 1024 bytes

#define MB(m)								((m) << 20)		// 1048576 bytes

// bit weight
#define BIT_WEIGHT(bit_position)	  (1 << (bit_position)) 

#define BITS_HI(n, bits)		 (((n) & (bits)) == (bits)) 
#define BITS_LOW(n, bits)			  (((n) & (bits)) == 0) 

#define U2_HL(H, L)			   ((U2)(U1)(H) << 8 | (U1)(L)) 
#define U4_HL(H, L)			  ((U4)(U2)(H) << 16 | (U2)(L)) 
#define U4_3210(b3, b2, b1, b0)	((U4)(U1)(b3) << 24 | (U4)(U1)(b2) << 16 | (U4)(U1)(b1) << 8 | (U1)b0)

#define U2_H(u2)						(U1)((u2) >> 8)		
#define U2_L(u2)						(U1)(u2)		

#define U4_H(u4)						(U2)((u4) >> 16)	
#define U4_L(u4)						(U2)(u4)			

#define U4_3(u4)						(U1)((u4) >> 24)
#define U4_2(u4)						(U1)((u4) >> 16)
#define U4_1(u4)						(U1)((u4) >> 8)	
#define U4_0(u4)						(U1)(u4)	

#define U1_MAX								0xFF
#define U2_MAX								0xFFFF
#define U4_MAX								0xFFFFFFFF
#define S1_MAX								0x7F
#define S2_MAX								0x7FFF
#define S4_MAX								0x7FFFFFFF
#define S1_MIN								0x80
#define S2_MIN								0x8000
#define S4_MIN								0x80000000

#define U1_DIFF(s, e)						(((s) < (e)) ? (e) - (s) : U1_MAX - (s) + (e) + 1)
#define U2_DIFF(s, e)						(((s) < (e)) ? (e) - (s) : U2_MAX - (s) + (e) + 1)
#define U4_DIFF(s, e)						(((s) < (e)) ? (e) - (s) : U4_MAX - (s) + (e) + 1)
#define S1_DIFF(s, e)						(((s) < (e)) ? (e) - (s) : S1_MAX - (s) + (e) - (S1)S1_MIN + 1)
#define S2_DIFF(s, e)						(((s) < (e)) ? (e) - (s) : S2_MAX - (s) + (e) - (S2)S2_MIN + 1)
#define S4_DIFF(s, e)						(((s) < (e)) ? (e) - (s) : S4_MAX - (s) + (e) - (S4)S4_MIN + 1)

#define MHZ									1000000			// 10^6

// Rotate n bits
#define ROTATE_LEFT(x, n)					(((x) << (n)) | ((x) >> (32-(n))))	
#define	ROTATE_RIGHT(x, n)					(((x) >> (n)) | ((x) << (32-(n))))

#define STRINGIZING(x) 						#x
#define MACRO_STR(x) 						STRINGIZING(x)

#ifndef MIN
	#define MIN(a,b)						(((a) < (b)) ? (a): (b))
#endif

#ifndef MAX
	#define MAX(a,b)						(((a) > (b)) ? (a): (b))
#endif

#ifndef ABS
	#define ABS(a)							(((a) < 0) ? -(a): (a))
#endif

#ifdef _MSC_VER
#define offsetof(s, m)   					(size_t)&(((s *)0)->m)
#else
#define offsetof(type, member) 				((unsigned int) &((type *)0)->member)
#endif

#define ENDIAN_SWAP16(A)    ((((unsigned short)(A) & 0xff00) >> 8) | \
                             (((unsigned short)(A) & 0x00ff) << 8))

#define ENDIAN_SWAP32(A)    ((((unsigned int)(A) & 0xff000000) >> 24) | \
                             (((unsigned int)(A) & 0x00ff0000) >> 8) | \
                             (((unsigned int)(A) & 0x0000ff00) << 8) | \
                             (((unsigned int)(A) & 0x000000ff) << 24))


//
// Only for C
//
#ifndef __ASSEMBLY__

// physical memory access without optimization by compiler
#define PMA1(x) 							(*(volatile U1 *)(x))	
#define PMA2(x) 							(*(volatile U2 *)(x))
#define PMA4(x) 							(*(volatile U4 *)(x))

//
// New Types
//

typedef unsigned char						U1, B1;
typedef unsigned short						U2, U16;
typedef unsigned int						U4, B4, BF, U32;	

typedef signed char							S1;
typedef signed short						S2;
typedef signed int							S4;

#ifdef _MSC_VER
	#define HAVE_UINT64_T					1		
	typedef unsigned __int64 U8;
	typedef signed __int64 S8;
#elif __GNUC__
	#define HAVE_UINT64_T					1	
	typedef unsigned long long U8;
	typedef signed long long S8;
#else
	#define HAVE_UINT64_T					0
#endif

typedef struct U8_S
{
	U4 Lo;
	U4 Hi;
} U8_T;

typedef union U2_U
{
	U1 b1[2];	
	U2 b2;	
} U2_T;

typedef union U4_U
{
	U1 b1[4];
	U2 b2[2];	
	U4 b4;	
} U4_T;

typedef union UPTR_U
{
	U1 *p1;
	U2 *p2;
	U4 *p4;
} UPTR_T;

typedef union UFLOAT_U 
{
	float	f;
	U4		b4;
	U1		b1[4];
} UFLOAT_T;

/* NDS specific types */
#ifndef H_NDSTYPES
#define H_NDSTYPES
typedef unsigned char           			NDS_BYTE;
typedef unsigned char           			NDS_BOOLEAN;
typedef unsigned short             			NDS_STATUS;
typedef unsigned short          			NDS_USHORT;
typedef unsigned long           			NDS_ULONG;
#endif

/* return valuse of NDS API */
#ifndef NDS_OK
	#define NDS_OK							0
	#define NDS_FAIL						1
#endif

/* GCC specific keywords */
#ifndef __GNUC__
	#define inline
	#define __attribute__(x)
#endif

#define _ALIGNED2_							__attribute__((aligned(2)))	
#define _ALIGNED4_							__attribute__((aligned(4)))	
#define _PACKED_							__attribute__((packed))	
#define _UNUSED_							__attribute__((unused))

#endif // !__ASSEMBLY__

#endif	// _TYPE_DEF_H_
