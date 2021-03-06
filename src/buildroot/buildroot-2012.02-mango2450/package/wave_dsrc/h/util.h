

/* memory_dump 시 사용되는 플래그 */
#define DUMP_INDENT							0x80			// offset 이나 address를 인쇄하지 않을 때에도 indent를 넣음
#define DUMP_CHAR							0x40			// ASCII 문자 인쇄
#define DUMP_OFFSET							0x20			// offset 값 인쇄
#define	DUMP_ADDR							0x10			// address 값 인쇄
#define DUMP_SPACE							0x08			// 4바이트 마다 공백 삽입
#define DUMP_4								0x04			// 4바이트 단위 헥사 출력
#define DUMP_2								0x02			// 2바이트 단위 헥사 출력
#define DUMP_1								0x01			// 1바이트 단위 헥사 출력

/* 위 플래그 조합(인쇄되는 컬럼 순서대로 이름 첫자를 결합함) */
#define DUMP_1C								(DUMP_1 | DUMP_CHAR)
#define DUMP_2C								(DUMP_2 | DUMP_CHAR)
#define DUMP_4C								(DUMP_4 | DUMP_CHAR)
#define DUMP_O1								(DUMP_OFFSET | DUMP_1)
#define DUMP_O1C							(DUMP_OFFSET | DUMP_1 | DUMP_CHAR)
#define DUMP_A1								(DUMP_ADDR | DUMP_1)
#define DUMP_A1C							(DUMP_ADDR | DUMP_1 | DUMP_CHAR)
#define DUMP_A2C							(DUMP_ADDR | DUMP_2 | DUMP_CHAR)
#define DUMP_A4C							(DUMP_ADDR | DUMP_4 | DUMP_CHAR)
#define DUMP_A4								(DUMP_ADDR | DUMP_4)

/* memory_dump 시 줄수 제한 범위 */
#define DUMP_LINES_MIN						1				// 1 x 16 = 16 바이트
#define DUMP_LINES_DEFAULT					5				// 5 x 16 = 80 바이트
#define DUMP_LINES_MAX						256				// 256 x 16 = 4KB

/* debug control 플래그: bit 16 ~ 31 */
#define _LOG_F_ON							BIT_WEIGHT(16)
#define _LOG_F_TIME							BIT_WEIGHT(17)
#define _LOG_F_DUMP						BIT_WEIGHT(18)
#define _LOG_F_DUMP_BRIEF					BIT_WEIGHT(19)	// 1=memory_dump 시 dump_lines만큼 함
#define _LOG_F_EVENT						BIT_WEIGHT(20)
#define _LOG_F_INFO							BIT_WEIGHT(21)
#define _LOG_F_DETAIL						BIT_WEIGHT(22)
#define _LOG_F_TRACE						BIT_WEIGHT(23)
#define _LOG_F_WARNING						BIT_WEIGHT(29)	// * Warning * 메시지 추가시킴
#define _LOG_F_ERROR						BIT_WEIGHT(30)	// ** Error ** 메시지 추가시킴
#define _LOG_F_EXCEPTION					BIT_WEIGHT(31)	// *** EXCEPTION *** 메시지 추가시킴

#define make_binary(n,b)					_make_binary((n),(b),'.')
#define make_binary_o(n,b)					_make_binary((n),(b),'o')
#define make_binary_0(n,b)					_make_binary((n),(b),'0')

extern U4 debug_control;					// 해당 bit가 '1'인 경우 print
extern int dump_lines;						// brief 모드에서는 dump_lines 줄만큼만 인쇄한다.

extern int get_pid_from_proc_by_name(char *str);
extern int convert_string_to_hex(char *in, unsigned char *out, int len);
extern int tows_complement(int data, int bit);
#define clear_bit(data, loc)		((data) &= ~(0x1 << (loc)))


char *uintToBinary(unsigned int i);