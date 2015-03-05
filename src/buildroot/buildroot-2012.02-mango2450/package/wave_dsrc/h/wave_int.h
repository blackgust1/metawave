
/* interrupts generated from the external interrupts sources */
#define S3C2410_CPUIRQ_OFFSET	 (16)

#define S3C2410_IRQ(x) ((x) + S3C2410_CPUIRQ_OFFSET)

/* interrupts generated from the external interrupts sources */
#define IRQ_EINT4      		S3C2410_IRQ(32)	   /* 48 */
#define EXTINT_OFF			(IRQ_EINT4 - 4)


#define WAVE_IRQ      		59			/* IRQ_EINT15 */

#define S3C24XX_GPIO_EINTMASK_OFFSET       0xA4		/* SHKO : 0x560000a4 */
#define S3C24XX_GPIO_EINTPEND_OFFSET       0xA8		/* SHKO : 0x560000a8 */

/* Waveint.c (drivers\char)	파일을 참조하라. */
#define DEVICE_FILENAME	"/dev/waveint"

#define IOCTLWAVE_MAGIC		't'

typedef struct
{
	unsigned int wave_tx_queue_write_index;
	unsigned int wave_tx_queue_read_index;
	unsigned int wave_tx_write_success_index;
}	IOCTLWAVE_INFO;

typedef struct
{
	unsigned int wave_rx_queue_write_index;
	unsigned int wave_rx_queue_read_index;
}	IOCTLWAVE_RX_INFO;

typedef struct
{
	unsigned char *buf;
}	IOCTLWAVE_RX_CH2;



#define IOCTLWAVE_READ					_IOR(IOCTLWAVE_MAGIC, 0, IOCTLWAVE_INFO)
#define IOCTLWAVE_WAIT_TX				_IO(IOCTLWAVE_MAGIC, 1)
#define IOCTLWAVE_WRITE	  			_IOW(IOCTLWAVE_MAGIC, 2, IOCTLWAVE_INFO)
#define IOCTLWAVE_READ_RX				_IOR(IOCTLWAVE_MAGIC, 3, IOCTLWAVE_RX_INFO)
#define IOCTLWAVE_WRITE_RX			_IOR(IOCTLWAVE_MAGIC, 4, IOCTLWAVE_RX_INFO)
#define IOCTLWAVE_READ_CH2_RX			_IOR(IOCTLWAVE_MAGIC, 5, IOCTLWAVE_RX_CH2)
#define IOCTLWAVE_ECC_CMD_WRITE	  	_IOW(IOCTLWAVE_MAGIC, 6, unsigned int)
#define IOCTLWAVE_ECC_INT_READ		_IOR(IOCTLWAVE_MAGIC, 7, unsigned int)
#define IOCTLWAVE_MAXNR				8




