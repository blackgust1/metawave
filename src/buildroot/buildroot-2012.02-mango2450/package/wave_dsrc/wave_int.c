
#if 0
#define __LINUX_ARM_ARCH__ 4
#include <generated/autoconf.h>
#include <linux/interrupt.h>
#endif

#include <pthread.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include "type_def.h"
#include "task.h"
#include "cpu_reg.h"
#include "wave_reg.h"
#include "wave_int.h"
#include "wave_mac.h"
#include "linked_list.h"
#include "util.h"



int wave_rcv_thread_id;
int wave_rcv_thread2_id;
int wave_int_thread_id;
int dev;
//struct file *ext_int_file;
int mac_rx_count = 0;
int total_wave_mac_rx_count;

extern U1 *gpio_base;
extern U1 *interrupt_controller_base;
extern U1 *wave_dsrc_base;


WAVE_MAC_RX_DATA	wave_mac_rx_queue[WAVE_MAC_RX_QUEUE_NUM];
int wave_mac_rx_queue_read_index = 0;
int wave_mac_rx_queue_write_index = 0;

extern int sr5500_rx_test_flag;



#if 0
static irqreturn_t ext2_int_handler( int irq, void *dev_id, struct pt_regs * regs)
{
	printf("[ext2_int_handler] OK\n");

	return IRQ_HANDLED;

}
#endif

#if 0
static irqreturn_t ext4_int_handler( int irq, void *dev_id, struct pt_regs * regs)
{
	printf("[ext4_int_handler] OK\n");

	return IRQ_HANDLED;

}
#endif

#if 0
int wave_interrupt_init(void)
{
	int rc;						//return code
	
	if ((rc = request_irq(IRQ_EINT2, &ext2_int_handler,IRQF_DISABLED, "ext2_int", NULL)))
	{
		printf( "[wave_interrupt_init] ext2_int: unable to get IRQ %d (irqval=%d).\n",IRQ_EINT2, rc);
		return ( -1);
	}

	if ((rc = request_irq(IRQ_EINT4, &ext4_int_handler,IRQF_DISABLED, "ext4_int", NULL)))
	{
		printf( "[wave_interrupt_init] ext4_int: unable to get IRQ %d (irqval=%d).\n",IRQ_EINT4, rc);
		return ( -2);
	}
	
	return(0);
}
#endif

int wave_externel_interrupt_init(void)
{
	int i;
	unsigned int val;

  #if WAVE_MERGE
	val = reg_readl((gpio_base + EXTINT1_OFFSET));
	val &= 0xFFFFF88F;	/* 4,5,6, 8,9,10번째 비트를 0으로 만든다. */
	val |= 0x00000220;	/* EINT9, EINT10 Falling Edge Triggered */
	reg_writel((gpio_base + EXTINT1_OFFSET), val);
  
  	val = reg_readl((gpio_base + GPGCON_OFFSET));
	val &= 0xFFFFFFCF;	/* 4, 5번째 비트를 0으로 만든다. */
	val |= 0x00000020;	/* GPG2을 EINT10으로 세팅한다. 모뎀 A RTX Switch 인터럽트 */
	reg_writel((gpio_base + GPGCON_OFFSET), val);

	val = reg_readl((gpio_base + GPGCON_OFFSET));
	val &= 0xFFFFFFF3;	/* 2, 3번째 비트를 0으로 만든다. */
	val |= 0x00000008;	/* GPG1을 EINT9으로 세팅한다. 모뎀 B RTX Switch 인터럽트 */
	reg_writel((gpio_base + GPGCON_OFFSET), val);
	
	val = reg_readl((gpio_base + GPGCON_OFFSET));
	val &= 0xFFFCFFFF;	/* 16, 17번째 비트를 0으로 만든다. */
	val |= 0x00020000;	/* GPG8을 EINT16으로 세팅한다. */
	reg_writel((gpio_base + GPGCON_OFFSET), val);

	val = reg_readl((gpio_base + GPGCON_OFFSET));
	val &= 0xFFF3FFFF;	/* 18, 19번째 비트를 0으로 만든다. */
	val |= 0x00080000;	/* GPG9을 EINT17으로 세팅한다. */
	reg_writel((gpio_base + GPGCON_OFFSET), val);

	val = reg_readl((gpio_base + GPGCON_OFFSET));
    printf("[wave_externel_interrupt_init] GPGCON=0x%08x\n", val);
	
	val = reg_readl((gpio_base + EINTMASK_OFFSET));
	val &= 0xFFFEFFFF;	/* 16번째 비트를 0으로 만든다. */
	reg_writel((gpio_base + EINTMASK_OFFSET), val);		/* EINT16 인터럽트 Enable */

	val = reg_readl((gpio_base + EINTMASK_OFFSET));
	val &= 0xFFFFF3FF;	/* 10, 11번째 비트를 0으로 만든다. */
	reg_writel((gpio_base + EINTMASK_OFFSET), val);		/* EINT10, EINT11 인터럽트 Enable */

	val = reg_readl((gpio_base + EINTMASK_OFFSET));
    printf("[wave_externel_interrupt_init] EINTMASK=0x%08x\n", val);
  #endif

#if 1
	dev = open(DEVICE_FILENAME, O_RDWR|O_NDELAY);	/* O_NDELAY : Non-Blocking Mode */
	
	if(dev >= 0)
		printf("[wave_externel_interrupt_init]%s open Success, [%d]!!\n", DEVICE_FILENAME, dev);
	else
	{
		//printf("[wave_externel_interrupt_init]%s open Fail!!\n", DEVICE_FILENAME);
		perror("[wave_externel_interrupt_init]\n");
		return(-1);
	}
#endif

  

#if 1
	//ext_int_file = fget(dev);
	val = reg_readl((interrupt_controller_base + INT_SRCPND1_OFFSET));
	printf("[wave_externel_interrupt_init] SRCPND1=0x%08x\n", val);
	
	if (val)
		reg_writel((interrupt_controller_base + INT_SRCPND1_OFFSET), val);		/* Interrupt Clear */

	val = reg_readl((interrupt_controller_base + INT_SRCPND2_OFFSET));
	printf("[wave_externel_interrupt_init] SRCPND2=0x%08x\n", val);
	
	if (val)
		reg_writel((interrupt_controller_base + INT_SRCPND2_OFFSET), val);		/* Interrupt Clear */


	val = reg_readl((interrupt_controller_base + INT_INTPND1_OFFSET));
	printf("[wave_externel_interrupt_init] INT_INTPND1=0x%08x\n", val);
	
	if (val)
		reg_writel((interrupt_controller_base + INT_INTPND1_OFFSET), val);		/* Interrupt Clear */

	val = reg_readl((interrupt_controller_base + INT_INTPND2_OFFSET));
	printf("[wave_externel_interrupt_init] INTPND2=0x%08x\n", val);
	
	if (val)
		reg_writel((interrupt_controller_base + INT_INTPND2_OFFSET), val);		/* Interrupt Clear */

	val = reg_readl((interrupt_controller_base + INT_SUBSRCPND_OFFSET));
	printf("[wave_externel_interrupt_init] INT_SUBSRCPND=0x%08x\n", val);
	
	if (val)
		reg_writel((interrupt_controller_base + INT_SUBSRCPND_OFFSET), val);		/* Interrupt Clear */

	val = reg_readl((gpio_base + EINTPEND_OFFSET));
	printf("[wave_externel_interrupt_init] EINTPEND=0x%08x\n", val);
	
	if (val)
		reg_writel((gpio_base + EINTPEND_OFFSET), val);		/* Interrupt Clear */


	//reg_writew((wave_dsrc_base + WAVE_MAC_A_INT_MASK_H_REG_OFFSET), 0x11);	/* Interrupt Disable */
	//write_wave_ecc_reg32(WAVE_MAC_INT_MASK_M_REG_OFFSET, 0xE0000000);		/* Interrupt Disable */
	
	

	
	
#if 0
	/* GPIO12는 External Interrupt 4로 사용한다. GPIO10는 External Interrupt 2로 사용한다.*/
	reg_writel(S3C2510_IOPCON1, 0x0fffeb00);
	
	/* xINT2인 경우, active low, filtering on, rising edge detection으로 세팅. */
	/* xINT4인 경우, active low, filtering on, level detection으로 세팅.*/
	reg_writel(S3C2510_IOPINT, 0x40500);
	
	/* EXT2, EXT4 인터럽트는 Enable */
	//reg_writel(S3C2510_EXTINTMASK, 0x0000002B);
	
	/* EXT4 인터럽트만 Enable */
	reg_writel(S3C2510_EXTINTMASK, 0x0000002F);
#endif
#endif

	return(0);
	
		
}

#if 1	//SHKO_ORIGIN
void *wave_rcv_thread(void *data)   
{   
 	//unsigned char message[BUFSIZE];   
 	int n;
	int i;
	volatile unsigned int status;
	volatile unsigned int len;
	volatile unsigned int rx_info;
	U4_T rssi;
	U4_T data_rate;
	RX_DATA_FRAME_INFO *ptrRxInfo;
	U1 *org_data_ptr;
	//struct timeval start_point, end_point;
	//volatile double operating_time;
 	
 	printf("[wave_rcv_thread] Start\n");

 	while( 1 )
	{  
     		n = read(dev, wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr, WAVE_MAC_RX_QUEUE_SIZE);	/* Tcp.c (net\ipv4)	파일내의 tcp_recvmsg 함수가 호출된다. */
		//gettimeofday(&start_point, NULL);
		//operating_time = (double)(start_point.tv_sec)+(double)(start_point.tv_usec)/1000000.0;
		//printf("\nSignature Generation Operation Time : %f\n",operating_time);
		
     		if (n > 0)
     		{   
     			pthread_mutex_lock(&ether_rx_mutex);

     			
#if 1 //SHKO_TEST
     			org_data_ptr = wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr;
     			//if( print_flag & WAVE_MAC_RX_DEBUG_MODE == WAVE_MAC_RX_DEBUG_MODE)
     			//	printf("[wave_rcv_thread]1\n");
			mac_rx_count++;

			if (sr5500_rx_test_flag)
				total_wave_mac_rx_count++;
     			//ptrRxInfo = (RX_DATA_FRAME_INFO *) ext_int_file->private_data;

        		wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_len = n;

        		rssi.b1[3] = wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr[0];
        		rssi.b1[2] = wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr[1];
        		rssi.b1[1] = wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr[2];
        		rssi.b1[0] = wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr[3];

        		wave_mac_rx_queue[wave_mac_rx_queue_write_index].rssi = rssi.b4;

        		data_rate.b1[3] = wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr[4];
        		data_rate.b1[2] = wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr[5];
        		data_rate.b1[1] = wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr[6];
        		data_rate.b1[0] = wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr[7];

        		wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_rate= data_rate.b4;
        		wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr += 8;					/* 8 = rssi(4) + data_rate(4) */
        		wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_len -= 8;
        		wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_len -= 4;					/* 4 = MAC CRC */

#if 0
        		if( print_flag & WAVE_MAC_RX_DEBUG_MODE == WAVE_MAC_RX_DEBUG_MODE)
     				printf("[wave_rcv_thread]rssi=0x%x, data_rate=0x%x, n=%d\n", rssi.b4, data_rate.b4, n);

     			if( print_flag & WAVE_MAC_RX_DEBUG_MODE )
     				print_dump_data(wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr, wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_len, "[wave_rcv_thread] Recv Data");
#endif

        		wave_mac_rx_proc(wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr, wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_len);

        		wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr = org_data_ptr;

        		wave_mac_rx_queue_write_index++;
			if (wave_mac_rx_queue_write_index == WAVE_MAC_RX_QUEUE_NUM)
			{
				wave_mac_rx_queue_write_index = 0;
			}

#else
			wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_len = n;

			wave_mac_rx_queue_write_index++;
			if (wave_mac_rx_queue_write_index == WAVE_MAC_RX_QUEUE_NUM)
			{
				wave_mac_rx_queue_write_index = 0;
			}

			if ( wave_mac_rx_queue_write_index == wave_mac_rx_queue_read_index )
			{
				printf("[wave_rcv_thread] WAVE MAC Rx Queue Full\n");
			}
        		
#endif  //SHKO_TEST
			

			

			//if( print_flag & WAVE_MAC_RX_DEBUG_MODE == WAVE_MAC_RX_DEBUG_MODE)
     			//	printf("[wave_rcv_thread]2\n");
 
     			pthread_mutex_unlock(&ether_rx_mutex);

     			//print_dump_data((U1 *)message, 8, "[wave_rcv_thread] Recv Data");
			
		}
		else
		{
			//printf("[net_rcv_thread] n=%d\n", n);
			//my_nanosleep(0, 10000000);	// 10ms Sleep 	
			//my_nanosleep(0, 5000000);	// 5ms Sleep 	
			//if( print_flag & WAVE_MAC_RX_DEBUG_MODE == WAVE_MAC_RX_DEBUG_MODE)
     			//	printf("[wave_rcv_thread]3\n");
		}   
		//close(clnt_sock);   
 	}   
 	return 0;   
}

#endif


#if 1	//SHKO_ORIGIN
void *wave_rcv_thread2(void *data)   
{   
 	//unsigned char message[BUFSIZE];   
 	int n;
	int i;
	volatile unsigned int status;
	volatile unsigned int len;
	volatile unsigned int rx_info;
	U4_T rssi;
	U4_T data_rate;
	//RX_DATA_FRAME_INFO *ptrRxInfo;
	U1 *org_data_ptr;
	IOCTLWAVE_RX_CH2 ctr_rx_ch2;
	//struct timeval start_point, end_point;
	//volatile double operating_time;
 	
 	printf("[wave_rcv_thread2] Start\n");

 	while( 1 )
	{  
     		//n = read(dev, wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr, WAVE_MAC_RX_QUEUE_SIZE);	/* Tcp.c (net\ipv4)	파일내의 tcp_recvmsg 함수가 호출된다. */
     		n  = ioctl(dev, IOCTLWAVE_READ_CH2_RX, wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr);
		//gettimeofday(&start_point, NULL);
		//operating_time = (double)(start_point.tv_sec)+(double)(start_point.tv_usec)/1000000.0;
		//printf("\nSignature Generation Operation Time : %f\n",operating_time);
		
     		if (n > 0)
     		{   
     			pthread_mutex_lock(&ether_rx_mutex);

     			
#if 1 //SHKO_TEST
     			org_data_ptr = wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr;
     			//if( print_flag & WAVE_MAC_RX_DEBUG_MODE == WAVE_MAC_RX_DEBUG_MODE)
     			//	printf("[wave_rcv_thread]1\n");
			mac_rx_count++;

			if (sr5500_rx_test_flag)
				total_wave_mac_rx_count++;
     			//ptrRxInfo = (RX_DATA_FRAME_INFO *) ext_int_file->private_data;

        		wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_len = n;

        		rssi.b1[3] = wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr[0];
        		rssi.b1[2] = wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr[1];
        		rssi.b1[1] = wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr[2];
        		rssi.b1[0] = wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr[3];

        		wave_mac_rx_queue[wave_mac_rx_queue_write_index].rssi = rssi.b4;

        		data_rate.b1[3] = wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr[4];
        		data_rate.b1[2] = wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr[5];
        		data_rate.b1[1] = wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr[6];
        		data_rate.b1[0] = wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr[7];

        		wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_rate= data_rate.b4;
        		wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr += 8;					/* 8 = rssi(4) + data_rate(4) */
        		wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_len -= 8;
        		wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_len -= 4;					/* 4 = MAC CRC */

#if 0
        		if( print_flag & WAVE_MAC_RX_DEBUG_MODE == WAVE_MAC_RX_DEBUG_MODE)
     				printf("[wave_rcv_thread]rssi=0x%x, data_rate=0x%x, n=%d\n", rssi.b4, data_rate.b4, n);

     			if( print_flag & WAVE_MAC_RX_DEBUG_MODE )
     				print_dump_data(wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr, wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_len, "[wave_rcv_thread] Recv Data");
#endif

        		wave_mac_rx_proc(wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr, wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_len);

        		wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr = org_data_ptr;

        		wave_mac_rx_queue_write_index++;
			if (wave_mac_rx_queue_write_index == WAVE_MAC_RX_QUEUE_NUM)
			{
				wave_mac_rx_queue_write_index = 0;
			}

#else
			wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_len = n;

			wave_mac_rx_queue_write_index++;
			if (wave_mac_rx_queue_write_index == WAVE_MAC_RX_QUEUE_NUM)
			{
				wave_mac_rx_queue_write_index = 0;
			}

			if ( wave_mac_rx_queue_write_index == wave_mac_rx_queue_read_index )
			{
				printf("[wave_rcv_thread] WAVE MAC Rx Queue Full\n");
			}
        		
#endif  //SHKO_TEST
			

			

			//if( print_flag & WAVE_MAC_RX_DEBUG_MODE == WAVE_MAC_RX_DEBUG_MODE)
     			//	printf("[wave_rcv_thread]2\n");
 
     			pthread_mutex_unlock(&ether_rx_mutex);

     			//print_dump_data((U1 *)message, 8, "[wave_rcv_thread] Recv Data");
			
		}
		else
		{
			//printf("[net_rcv_thread] n=%d\n", n);
			//my_nanosleep(0, 10000000);	// 10ms Sleep 	
			//my_nanosleep(0, 5000000);	// 5ms Sleep 	
			//if( print_flag & WAVE_MAC_RX_DEBUG_MODE == WAVE_MAC_RX_DEBUG_MODE)
     			//	printf("[wave_rcv_thread]3\n");
		}   
		//close(clnt_sock);   
 	}   
 	return 0;   
}

#endif


#if 0
void *wave_int_thread(void *data)   
{   
	volatile unsigned int status, val;
#if WAVE_MERGE
	volatile unsigned short status1;
#endif
	volatile unsigned int len, len_org;
	volatile unsigned int rx_info;
	unsigned char rssi;
	unsigned char data_rate;
	volatile unsigned int rx_data;
	int i, j;
	unsigned int irqno = WAVE_IRQ - EXTINT_OFF;
	unsigned long mask;
 	
 	int n;
 	
 	printf("[wave_int_thread] Start\n");

 	while( 1 )
	{  
     		n = read(dev, wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr, WAVE_MAC_RX_QUEUE_SIZE);	/* Tcp.c (net\ipv4)	파일내의 tcp_recvmsg 함수가 호출된다. */

     		if (n > 0)
     		{   
			/* EXT15 인터럽트만 Disable */
			mask = reg_readl((gpio_base + S3C24XX_GPIO_EINTMASK_OFFSET));
			mask |= ( 1UL << irqno);
			reg_writel((gpio_base + S3C24XX_GPIO_EINTMASK_OFFSET), mask);

		#if WAVE_MODEM
			status = read_wave_dsrc_reg32(WAVE_MAC_A_INT_STATUS_H_REG_OFFSET);	/* Interrupt Clear */
		#endif

		#if WAVE_MERGE
			//status1 = read_wave_dsrc_reg32(WAVE_MAC_A_INT_STATUS_H_REG_OFFSET);	/* Interrupt Clear */
			status1 = reg_readw((wave_dsrc_base + WAVE_MAC_A_INT_STATUS_H_REG_OFFSET));
			status = read_wave_dsrc_reg32(WAVE_MAC_INT_STATUS_M_REG_OFFSET);	/* Interrupt Clear */
		#endif

			if( print_flag & WAVE_MAC_RX_DEBUG_MODE )
				printf("[wave_int_thread] status = 0x%08x\n", status);
  
			//printk("[wave_rx_int] status=0x%08x\n", status);
			if ( status & SCH_AC1_TX_COMPLETE_INT)
			{
				printf("[wave_rx_int] SCH_AC1_TX_COMPLETE_INT!!\n");
			}
			if ( status & SCH_AC2_TX_COMPLETE_INT)
			{
				printf("[wave_rx_int] SCH_AC2_TX_COMPLETE_INT!!\n");
			}
			if ( status & SCH_AC3_TX_COMPLETE_INT)
			{
				printf("[wave_rx_int] SCH_AC3_TX_COMPLETE_INT!!\n");
			}
			if ( status & SCH_AC4_TX_COMPLETE_INT)
			{
				printf("[wave_rx_int] SCH_AC4_TX_COMPLETE_INT!!\n");
			}
			if ( status & SCH_AC1_RETX_LIMIT_OVERFLOW_INT)
			{
				printf("[wave_rx_int] SCH_AC1_RETX_LIMIT_OVERFLOW_INT!!\n");
			}
			if ( status & SCH_AC2_RETX_LIMIT_OVERFLOW_INT)
			{
				printf("[wave_rx_int] SCH_AC2_RETX_LIMIT_OVERFLOW_INT!!\n");
			}
			if ( status & SCH_AC3_RETX_LIMIT_OVERFLOW_INT)
			{
				printf("[wave_rx_int] SCH_AC3_RETX_LIMIT_OVERFLOW_INT!!\n");
			}
			if ( status & SCH_AC4_RETX_LIMIT_OVERFLOW_INT)
			{
				printf("[wave_rx_int] SCH_AC4_RETX_LIMIT_OVERFLOW_INT!!\n");
			}
			if ( status & CCH_AC1_TX_COMPLETE_INT)
			{
				printf("[wave_rx_int] CCH_AC1_TX_COMPLETE_INT!!\n");
			}
			if ( status & CCH_AC2_TX_COMPLETE_INT)
			{
				printf("[wave_rx_int] CCH_AC2_TX_COMPLETE_INT!!\n");
			}
			if ( status & CCH_AC3_TX_COMPLETE_INT)
			{
				printf("[wave_rx_int] CCH_AC3_TX_COMPLETE_INT!!\n");
			}
			if ( status & CCH_AC4_TX_COMPLETE_INT)
			{
				//printf("[wave_rx_int] CCH_AC4_TX_COMPLETE_INT!!\n");
			}
			if ( status & CCH_AC1_RETX_LIMIT_OVERFLOW_INT)
			{
				printf("[wave_rx_int] CCH_AC1_RETX_LIMIT_OVERFLOW_INT!!\n");
			}
			if ( status & CCH_AC2_RETX_LIMIT_OVERFLOW_INT)
			{
				printf("[wave_rx_int] CCH_AC2_RETX_LIMIT_OVERFLOW_INT!!\n");
			}
			if ( status & CCH_AC3_RETX_LIMIT_OVERFLOW_INT)
			{
				printf("[wave_rx_int] CCH_AC3_RETX_LIMIT_OVERFLOW_INT!!\n");
			}
			if ( status & CCH_AC4_RETX_LIMIT_OVERFLOW_INT)
			{
				printf("[wave_rx_int] CCH_AC4_RETX_LIMIT_OVERFLOW_INT!!\n");
			}
			if ( status & RX_DATA_FRAME_INT)
			{
				rx_info = read_wave_dsrc_reg32(WAVE_MAC_A_RX_INFO_QUEUE_FOR_DATA_FRAME_H_REG_OFFSET);
						
				len_org = rx_info & 0xFFF;
				rssi = (rx_info >> 16) & 0xFF;
				data_rate = (rx_info >> 12) & 0xF;

				//printf("[wave_rx_int] rcv_len = %d\n", len_org);
				
				wave_mac_rx_queue[wave_mac_rx_queue_write_index].rssi = (unsigned int)rssi;
				wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_rate= (unsigned int)data_rate;
				wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_len= (unsigned int)len_org;

				i = 0;
				wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr[i++] = (unsigned int)rssi;
				wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr[i++] = (unsigned int)data_rate;
			
				if ( (len_org%4) == 0)
				{
					len = len_org/4;
					for ( j = 0; j < len; j++)
					{
					#if WAVE_RX_TX_BUF_UPDATE
						wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr[i] = read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_QUEUE_DATA_FRAME_H_REG_OFFSET);

					#else
						rx_data = read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_QUEUE_DATA_FRAME_H_REG_OFFSET);
						wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr[i] = ENDIAN_SWAP32(rx_data);
						//printf("[%08x]",wave_rx_data_frame[wave_rx_data_frame_write_count].buf[i]);
					#endif
					
						i++;
					}
				}
				else
				{
					len = (len_org/4) + 1;
					for ( j = 0; j < len; j++)
					{
					#if WAVE_RX_TX_BUF_UPDATE
						wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr[i] = read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_QUEUE_DATA_FRAME_H_REG_OFFSET);
					#else
						rx_data = read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_QUEUE_DATA_FRAME_H_REG_OFFSET);
						wave_mac_rx_queue[wave_mac_rx_queue_write_index].data_ptr[i] = ENDIAN_SWAP32(rx_data);
						//printf("[%08x]",wave_rx_data_frame[wave_rx_data_frame_write_count].buf[i]);
					#endif
				
						i++;
					}
				}
				//printf("\n");
		
				wave_mac_rx_queue_write_index++;
				if (wave_mac_rx_queue_write_index == WAVE_RX_QUEUE_NUM)
					wave_mac_rx_queue_write_index = 0;
     		
			}
			if ( status & RX_MANAGEMENT_FRAME_INT)
			{
				printf("[wave_rx_int] RX_MANAGEMENT_FRAME_INT!!\n");
			}
			if ( status & DATA_QUEUE_OVERFLOW_INT)
			{
				rx_info = read_wave_dsrc_reg32(WAVE_MAC_A_RX_INFO_QUEUE_FOR_DATA_FRAME_H_REG_OFFSET);
					
				len_org = rx_info & 0xFFF;
				
				if ( (len_org%4) == 0)
				{
					len = len_org/4;
					for ( j = 0; j < len; j++)
					{
						rx_data = read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_QUEUE_DATA_FRAME_H_REG_OFFSET);
					}
				}
				else
				{
					len = (len_org/4) + 1;
					for ( j = 0; j < len; j++)
					{
						rx_data = read_wave_dsrc_reg32(WAVE_MAC_A_RX_DATA_QUEUE_DATA_FRAME_H_REG_OFFSET);
					}
				}
				printf("[wave_rx_int] Data Queue Overflow Interrupt!!\n");
			}
#if WAVE_MERGE
			if ( status1 & MANAGEMENT_QUEUE_OVERFLOW_INT)
			{
				printf("[wave_rx_int] Management Queue Overflow Interrupt!!\n");
			}
			if ( status1 & DATA_QUEUE_OVERFLOW_CLEAR_INT)
			{
				printf("[wave_rx_int] Data Queue Overflow Clear Interrupt!!\n");
			}
			if ( status1 & MANAGEMENT_QUEUE_OVERFLOW_CLEAR_INT)
			{
				printf("[wave_rx_int] Management Queue Overflow Clear Interrupt!!\n");
			}
			if ( status1 & TX_START_OF_EXTRA_QUEUE_INT)
			{
				printf("[wave_rx_int] TX_START_OF_EXTRA_QUEUE_INT!!\n");
			}
#endif

			/* EXT15 인터럽트만 Enable */
			mask = reg_readl((gpio_base + S3C24XX_GPIO_EINTMASK_OFFSET));
			mask &= ~(1UL << irqno);
			reg_writel((gpio_base + S3C24XX_GPIO_EINTMASK_OFFSET), mask);

		}
		else
		{
			my_nanosleep(0, 5000000);	// 5ms Sleep 	
		}
	}

   
}
#endif




