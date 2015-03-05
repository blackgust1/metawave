
#define SM_START_FRAME			0x16
#define SM_END_FRAME			0xF5

#define MAX_SM_QUEUE_SIZE                      256
#define MAX_SM_ENTRI_SIZE                      32

typedef struct
{
  int count;
  int front;
  int rear;
} SM_QUEUE_LIST;


extern serial_init(void);
extern int uart1_send(unsigned char *buf, int len);

extern unsigned short update_crc16(unsigned short crc_accum, unsigned char *data_blk_ptr, int data_blk_size);
extern void crc16_main(void);
extern int SendFrameToHost(unsigned char cmd, unsigned char *send_buf, int len)
;
