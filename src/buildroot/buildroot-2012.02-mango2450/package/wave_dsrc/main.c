/* vi: set sw=4 ts=4: */
/*
 * Poweroff reboot and halt, oh my.
 *
 * Copyright 2006 by Rob Landley <rob@landley.net>
 *
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>		/* mmap */
#include "type_def.h"
#include "cpu_reg.h"
#include "wave_reg.h"
#include "wave_int.h"
#include "ecdsa_ecc.h"
#include "linked_list.h"
#include "util.h"
#include "task.h"
#include "serial.h"

pthread_t p_thread[6];

char compiled_date_time[] = __DATE__ " " __TIME__;
U4 built_date;									// 모듈이 컴파일된 날짜 (0xYYYYMMDD)
U4 built_time;									// 모듈이 컴파일된 시각 (0x00HHMMSS)

U1 *system_control_base;
int system_control_fd;

U1 *gpio_base;
U1 *static_memory_controller_base;
U1 *interrupt_controller_base;
U1 *wave_dsrc_base;
U1 *ethernet_base;
U1 *hs_spi0_base;
U1 *hs_spi1_base;

int shell_process_pid;

pthread_mutex_t ether_rx_mutex;

extern int Init_Soft_ECIES(void);


void FPGA_RESET(void)
{
	volatile U4 val;
#if 0
	SetPadFunc(FPGA_RESET_GPIO_NUM, 0);	/* GPIO 모드로 세팅하고, output mode로 세팅함. */

	SetGpioOut(FPGA_RESET_GPIO_NUM, 0);

	time_delay(1000);
	
	SetGpioOut(FPGA_RESET_GPIO_NUM, 1);
#else
	val = reg_readl((gpio_base + GPCCON_OFFSET));
	val &= 0xFFFFFFF3;		/* GPC1 : GPIO Output Mode */
	val |= 0x00000004;
	reg_writel((gpio_base + GPCCON_OFFSET), val);

	printf("GPC Control Register : 0x%08x\n", reg_readl((gpio_base + GPCCON_OFFSET)));


	val = reg_readl((gpio_base + GPCDAT_OFFSET));
	val &= 0xFFFFFFFD;		/* GPC1 : Output 0 */
	reg_writel((gpio_base + GPCDAT_OFFSET), val);
	
	//time_delay(1000);
	
	//val = reg_readl((gpio_base + GPCDAT_OFFSET));
	//val |= 0x00000002;		/* GPC1 : Output 1 */
	//reg_writel((gpio_base + GPCDAT_OFFSET), val);

	
#endif
}

/* val: 1이면 HPI Interface, 0이면 SPI 인터페이스 */
/* GPC2 */
void Set_FPGA_Interface_Mode(void)
{
	volatile U4 val;
	
	val = reg_readl((gpio_base + GPCCON_OFFSET));
	val &= 0xFFFFFFCF;		
	val |= 0x00000010;		/* GPC2 : GPIO Output Mode */
	reg_writel((gpio_base + GPCCON_OFFSET), val);

	printf("GPC Control Register : 0x%08x\n", reg_readl((gpio_base + GPCCON_OFFSET)));


	val = reg_readl((gpio_base + GPCDAT_OFFSET));
	val &= 0xFFFFFFFB;		/* GPC2 : Output 0 */
	reg_writel((gpio_base + GPCDAT_OFFSET), val);
	
	
}

int main(int argc, char *argv[])
{
	int thr_id;
   	int status;
   	int a = 1;
   	int b = 2;
   	int c = 3;
   	int d = 4;
   	int e = 5;
   	int f = 6;
   	int ret=0;
   	volatile unsigned int val;
   	char system_cmd[256];
   	U2 u2;
   	

	printf("wave_main start!!\n");

	system_control_fd = open("/dev/mem", O_RDWR|O_SYNC);

 	/* FND_SIZE 는 PAGE 크기의 배수이어야 한다. */
	system_control_base = mmap((void *)0,FND_SIZE,PROT_WRITE|PROT_READ,MAP_SHARED,system_control_fd,S3C2450_SYSCON);
	gpio_base = mmap((void *)0,FND_SIZE,PROT_WRITE|PROT_READ,MAP_SHARED,system_control_fd,S3C2450_IO_PORT);
	static_memory_controller_base = mmap((void *)0,FND_SIZE,PROT_WRITE|PROT_READ,MAP_SHARED,system_control_fd,S3C2412_PA_SSMC);
	interrupt_controller_base = mmap((void *)0,FND_SIZE,PROT_WRITE|PROT_READ,MAP_SHARED,system_control_fd,S3C2450_INTC);
	wave_dsrc_base = mmap((void *)0,WAVE_DSRC_REG_SIZE,PROT_WRITE|PROT_READ,MAP_SHARED,system_control_fd,S3C2410_CS1);
	ethernet_base = mmap((void *)0,FND_SIZE,PROT_WRITE|PROT_READ,MAP_SHARED,system_control_fd,S3C2410_CS5);
	hs_spi0_base= mmap((void *)0,FND_SIZE,PROT_WRITE|PROT_READ,MAP_SHARED,system_control_fd,S3C2450_HSI_SPI0);
	hs_spi1_base= mmap((void *)0,FND_SIZE,PROT_WRITE|PROT_READ,MAP_SHARED,system_control_fd,S3C2450_HSI_SPI1);

	
	Set_FPGA_Interface_Mode();
	
	FPGA_RESET();


  #if WAVE_MODEM || WAVE_MERGE
	system("mknod /dev/waveint c 240 1");
	system("insmod /usr/sbin/wave_drv.ko");
  #endif
  
	built_date = __DATE__to_yyyymmdd(compiled_date_time);
	built_time = __TIME__to_hhmmss(compiled_date_time + 12);
	

	printf("Built on %s %s \n", str_date(built_date), str_time(built_time));

	
#if 0 //SHKO_TEST
	val = reg_readl((wave_dsrc_base + WAVE_MAC_A_INT_STATUS_H_REG_OFFSET));
	printf("[main] WAVE_MAC_INT_STATUS_REG=0x%08x\n", val);		/* Interrupt Clear */

	val = read_wave_dsrc_reg32(WAVE_MAC_HW_VERSION_H_REG_OFFSET);
	printf("[main] WAVE MAC Hardware Version=0x%08x\n", val);

	val = read_wave_dsrc_reg32(WAVE_MODEM_A_VERSION_H_REG_OFFSET);
	printf("[main] WAVE Modem Version=0x%08x\n", val);

	write_wave_dsrc_reg32(WAVE_MAC_A_INT_MASK_H_REG_OFFSET, 0x0);	/* Interrupt Disable */
#endif 
	printf("system_control_base : %p\n", system_control_base);
	printf("gpio_base : %p\n", gpio_base);
	printf("static_memory_controller_base : %p\n", static_memory_controller_base);
	printf("interrupt_controller_base : %p\n", interrupt_controller_base);
	printf("wave_dsrc_base : %p\n", wave_dsrc_base);
	printf("ethernet_base : %p\n", ethernet_base);

	shell_process_pid = get_pid_from_proc_by_name("sh");
	printf("SHELL Process PID = %d\n", shell_process_pid);

	if (shell_process_pid > 0)
	{
		sprintf(system_cmd, "kill -STOP %d", shell_process_pid);
		system(system_cmd);
	}

	/* SMIC SMCLK 세팅 */
	//reg_writel((static_memory_controller_base + 0x204), 0); /* 이렇게 해야 Throughput 테스트 시 효과가 있음. */

	val = reg_readl((gpio_base + 0x1C));
	val &= 0xFFFFFFF7;		/* GPB9 : GPIO Mode */
	reg_writel((gpio_base + 0x10), val);

	printf("GPB Control Register : 0x%08x\n", reg_readl((gpio_base + 0x10)));


	val = reg_readl((gpio_base + 0x10));
	val |= 0x00040000;		/* GPB9 : Output Mode Setting */
	reg_writel((gpio_base + 0x10), val);

	printf("GPB Control Register : 0x%08x\n", reg_readl((gpio_base + 0x10)));


	pthread_mutex_init(&ether_rx_mutex,NULL); 

	/* Software RESET */
#if 0
	u2 = reg_readw((wave_dsrc_base + WAVE_CONTROL_L_REG_OFFSET));
	u2 |= 0x1FFF;
	reg_writew((wave_dsrc_base + WAVE_CONTROL_L_REG_OFFSET), u2);

	u2 = reg_readw((wave_dsrc_base + WAVE_CONTROL_L_REG_OFFSET));
	u2 |= 0x1FFF;
	reg_writew((wave_dsrc_base + WAVE_CONTROL_L_REG_OFFSET), u2);

	time_delay(1000);
#endif



#if WAVE_MODEM || WAVE_MERGE
	/* 처음에, WAVE_MAC_INT_STATUS_REG 레지스터를 읽어야만, EXT_INT4로 사용하는 GPIO12 핀의 초기값이 1이 되어 */
	/* 처음에, EXT_INT4 인터럽트를 enable하자 마자 계속 EXT_INT4 인터럽트가 발생하는 것을 막을 수 있다. */
	/* 즉, 이 레지스터를 읽어야만 발생된 인터럽트가 clear 되는 것 같다. */
	/* val = reg_readl(WAVE_MAC_INT_STATUS_REG); */
	val = reg_readl((wave_dsrc_base + WAVE_MAC_A_INT_STATUS_H_REG_OFFSET));
	printf("[main] WAVE_MAC_A_INT_STATUS_REG=0x%08x\n", val);		/* Interrupt Clear */

#if WAVE_MERGE
	/* 처음에, WAVE_MAC_INT_STATUS_REG 레지스터를 읽어야만, EXT_INT4로 사용하는 GPIO12 핀의 초기값이 1이 되어 */
	/* 처음에, EXT_INT4 인터럽트를 enable하자 마자 계속 EXT_INT4 인터럽트가 발생하는 것을 막을 수 있다. */
	/* 즉, 이 레지스터를 읽어야만 발생된 인터럽트가 clear 되는 것 같다. */
	/* val = reg_readl(WAVE_MAC_INT_STATUS_REG); */
	val = reg_readl((wave_dsrc_base + WAVE_MAC_B_INT_STATUS_H_REG_OFFSET));
	printf("[main] WAVE_MAC_B_INT_STATUS_REG=0x%08x\n", val);		/* Interrupt Clear */
#endif

	val = read_wave_dsrc_reg32(WAVE_MAC_HW_VERSION_H_REG_OFFSET);
	printf("[main] WAVE MAC Hardware Version=0x%08x\n", val);

	val = read_wave_dsrc_reg32(WAVE_MODEM_A_VERSION_H_REG_OFFSET);
	printf("[main] WAVE Modem Version=0x%08x\n", val);

#if WAVE_MERGE

	val = read_wave_dsrc_reg32(WAVE_MODEM_B_VERSION_H_REG_OFFSET);
	printf("[main] WAVE Modem Version=0x%08x\n", val);
#endif

	

	wave_mac_init();

#if WAVE_MERGE
	wave_mac_b_init();
#endif

	wave_modem_init();

#if WAVE_MERGE
	wave_modem_b_init();
#endif

	reg_writew((wave_dsrc_base + WAVE_MAC_A_INT_MASK_H_REG_OFFSET), 0x0);	/* Interrupt Disable */

#if WAVE_MERGE
	reg_writew((wave_dsrc_base + WAVE_MAC_B_INT_MASK_H_REG_OFFSET), 0x0);	/* Interrupt Disable */
#endif


#if 0 //SHKO_TEST
	write_wave_dsrc_reg32(WAVE_MAC_A_INT_MASK_H_REG_OFFSET, 0x0);	/* Interrupt Disable */
#endif
	
	ret = wave_externel_interrupt_init();
	val = read_wave_dsrc_reg32(WAVE_MAC_A_INT_MASK_H_REG_OFFSET);
	printf("[main] WAVE_MAC_A_INT_MASK_H_REG_OFFSET=0x%08x\n", val);

#if WAVE_MERGE
	val = read_wave_dsrc_reg32(WAVE_MAC_B_INT_MASK_H_REG_OFFSET);
	printf("[main] WAVE_MAC_B_INT_MASK_H_REG_OFFSET=0x%08x\n", val);
#endif
#endif

#if WAVE_ECC || WAVE_MERGE
	write_wave_ecc_reg32(ECDSA_ECC_STAT_H_REG_OFFSET, ALL_STATUS_CLEAR_BIT);	/* ECDSA, ECIES, SHA, AES Clear */
#endif

	/* ECDSA, ECIES, AES Interrupt Pin Disable */
	val = reg_readl((gpio_base + GPGCON_OFFSET));
	val &= 0xFFF3FFFF;	/* 18, 19번째 비트를 0으로 만든다. */
	val |= 0x00040000;	/* GPG9을 Output Mode으로 세팅한다. */
	reg_writel((gpio_base + GPGCON_OFFSET), val);

	Init_Soft_ECIES();


#if 0
	serial_init();
#endif

	thr_id = pthread_create(&p_thread[0], NULL, monitor_thread, (void *)&a);
	if (thr_id < 0)    	
	{        
		printf("[main]monitor_thread create fail:%d\n",thr_id);        
		exit(0);    
	}

#if 0
	thr_id = pthread_create(&p_thread[1], NULL, uart1_rcv_thread, (void *)&a);    	
	if (thr_id < 0)    		
	{		
		printf("[main]uart1_rcv_thread create fail:%d\n",thr_id);        		
		exit(0);    	
	}
#endif

#if WAVE_MODEM || WAVE_MERGE
#if 0	/* SHKO_ORIGIN == 0 */
	if (ret == 0)
	{
		wave_int_thread_id = pthread_create(&p_thread[1], NULL, wave_int_thread, (void *)&b);
		if (wave_int_thread_id < 0)
		{
			printf("[main]wave_int_thread create fail:%d\n",wave_int_thread_id);
			exit(0);
		}
	}
#endif
#if 1
	if (ret == 0)
	{
		wave_rcv_thread_id = pthread_create(&p_thread[1], NULL, wave_rcv_thread, (void *)&b);
		if (wave_rcv_thread_id < 0)
		{
			printf("[main]wave_rcv_thread create fail:%d\n",wave_rcv_thread_id);
			exit(0);
		}
	}

#if 0
	if (ret == 0)
	{
		wave_rcv_thread2_id = pthread_create(&p_thread[2], NULL, wave_rcv_thread2, (void *)&c);
		if (wave_rcv_thread2_id < 0)
		{
			printf("[main]wave_rcv_thread create fail:%d\n",wave_rcv_thread2_id);
			exit(0);
		}
	}
#endif

#if 0
	if (ret == 0)
	{
		wave_mac_thread_id = pthread_create(&p_thread[3], NULL, wave_mac_thread, (void *)&d);
	    if (wave_mac_thread_id < 0)
	    {
	        printf("[main]wave_mac_thread create fail:%d\n",wave_mac_thread_id);
	        exit(0);
	    }
	}
#endif
#endif
#endif

#if 1
	net_main();

	net_rcv_thread_id = pthread_create(&p_thread[4], NULL, net_rcv_thread, (void *)&e);
	if (net_rcv_thread_id < 0)
	{
		printf("[main]net_rcv_thread create fail:%d\n",net_rcv_thread_id);
		exit(0);
	}
#endif

#if 1
	ether_rx_proc_thread_id = pthread_create(&p_thread[5], NULL, ether_rx_proc_thread, (void *)&f);
	if (ether_rx_proc_thread_id < 0)
	{
		printf("[main]ether_rx_proc_thread create fail:%d\n", ether_rx_proc_thread_id);
		exit(0);
	}
#endif

#if 0
    net_wait_tcp_connect_thread_id = pthread_create(&p_thread[3], NULL, net_wait_tcp_connect_thread, (void *)&b);
    if (net_wait_tcp_connect_thread_id < 0)
    {
        printf("[main]net_rcv_thread create fail:%d\n",net_wait_tcp_connect_thread_id);
        exit(0);
    }

    
#endif
 
	pthread_join(p_thread[0], (void *)&status);
	pthread_join(p_thread[1], (void *)&status);
	//pthread_join(p_thread[2], (void *)&status);
	pthread_join(p_thread[3], (void *)&status);
	pthread_join(p_thread[4], (void *)&status);
	pthread_join(p_thread[5], (void *)&status);
	printf("SHKO2\n");
    //pthread_join(p_thread[1], (void *)&status);
	//printf("SHKO3\n");
	return 0;
}
