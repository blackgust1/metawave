/* s3c2510.h - SAMSUNG S3C2510 header file */ 
 
/* Copyright 2002 SAMSUNG ELECTRONICS */ 
 
/* 
modification history 
-------------------- 
01b,10July02,jwchoi 
01a,08feb02,jmLee created. 
*/ 
 
 
#ifndef INCs3c2510h 
#define INCs3c2510h 
 
#ifdef  __cplusplus 
extern  "C" { 
#endif 
 
 
#ifndef S3C2450ABBREVIATIONS 
#define S3C2450ABBREVIATIONS 
 
#ifdef   _ASMLANGUAGE 
#define CAST(x) 
#else /* _ASMLANGUAGE */
#define CAST(x) (x) 
#endif  /* _ASMLANGUAGE */ 
 
#endif /* S3C2510ABBREVIATIONS */ 


/* physical addresses of all the chip-select areas */

#define S3C2410_CS0 (0x00000000)
#define S3C2410_CS1 (0x08000000)
#define S3C2410_CS2 (0x10000000)
#define S3C2410_CS3 (0x18000000)
#define S3C2410_CS4 (0x20000000)
#define S3C2410_CS5 (0x28000000)
#define S3C2410_CS6 (0x30000000)
#define S3C2410_CS7 (0x38000000)

#define S3C2410_SDRAM_PA    (S3C2410_CS6)
 
 
/******************************************************************************* 
        S3C2450(Mango24R2) System Configuration Special Registers 
*******************************************************************************/
#define S3C2450_SDRAM				0x48000000
#define S3C2450_EBI					0x48800000
#define S3C2450_INTC				0x4A000000  /* Interrupt Controller Register */  
#define S3C2450_SYSCON				0x4C000000  /* System Controller Register */
#define S3C2412_PA_SSMC			0x4F000000  /* Static Memory Controller Register */
#define S3C2450_UART				0x50000000
#define S3C2450_HSI_SPI0			0x52000000
#define S3C2450_HSI_SPI1			0x59000000
#define S3C2450_IO_PORT			0x56000000	/* GPIO */



/******************************************************************************* 
        S3C2450(Mango24R2) External Interrupt Offset 
        Base Address = 0x56000000
*******************************************************************************/
#define EXTINT0_OFFSET				0x00000088
#define EXTINT1_OFFSET				0x0000008C
#define EXTINT2_OFFSET				0x00000090
#define EINTFLT2_OFFSET				0x0000009C
#define EINTFLT3_OFFSET				0x000000a0
#define EINTMASK_OFFSET			0x000000a4
#define EINTPEND_OFFSET			0x000000a8
#define GSTATUS0_OFFSET			0x000000ac
#define GSTATUS1_OFFSET			0x000000b0


/******************************************************************************* 
        S3C2450(Mango24R2) Interrupt Offset 
        Base Address = 0x4A000000
*******************************************************************************/
#define INT_SRCPND1_OFFSET				0x00000000
#define INT_INTMOD1_OFFSET				0x00000004
#define INT_INTMSK1_OFFSET				0x00000008
#define INT_INTPND1_OFFSET				0x00000010
#define INT_INTOFFSET1_OFFSET			0x00000014
#define INT_SUBSRCPND_OFFSET			0x00000018
#define INT_INTSUBMSK_OFFSET			0x0000001C
#define INT_PRIORITY_MODE1_OFFSET		0x00000030
#define INT_PRIORITY_UPDATE1_OFFSET	0x00000034
#define INT_SRCPND2_OFFSET				0x00000040
#define INT_INTMOD2_OFFSET				0x00000044
#define INT_INTMSK2_OFFSET				0x00000048
#define INT_INTPND2_OFFSET				0x00000050
#define INT_INTOFFSET2_OFFSET			0x00000054
#define INT_PRIORITY_MODE2_OFFSET		0x00000070
#define INT_PRIORITY_UPDATE2_OFFSET	0x00000074

/* GPIO PORT C Control Registers */
#define	GPCCON_OFFSET			0x0020
#define	GPCDAT_OFFSET			0x0024
#define	GPCUDP_OFFSET			0x0028

/******************************************************************************* 
        S3C2450(Mango24R2) GPIO Offset 
        Base Address = 0x56000000
*******************************************************************************/
#define GPGCON_OFFSET					0x00000060
#define GPGDAT_OFFSET					0x00000064
#define GPGUDP_OFFSET					0x00000068




/* S3C2510 ASIC Base Address */ 
 
#define S3C2510_REG_BASE_ADRS           0xF0000000          /* Internal Register Base Address */ 
#define S3C2510_REG_SIZE                0x00200000          /* Internal Register Size */ 
 
#define REG_32(_off)                    (CAST(volatile U4 *)(S3C2510_REG_BASE_ADRS + _off)) 
#define REG_16(_off)                    (CAST(volatile U2 *)(S3C2510_REG_BASE_ADRS + _off)) 
#define REG_8(_off)                     (CAST(volatile U1 *)(S3C2510_REG_BASE_ADRS + _off)) 

/******************************************************************************* 
        S3C2510 I/O Port Special Registers 
*******************************************************************************/ 
 
#define S3C2510_IOPMOD1                 REG_32(0x00030000)  /* I/O Port Mode Select Lower Register */ 
#define S3C2510_IOPMOD2                 REG_32(0x00030004)  /* I/O Port Mode Select Upper Register */ 
#define S3C2510_IOPCON1                REG_32(0x00030008)  /* I/O Port Function Select Lower Register */ 
#define S3C2510_IOPCON2                REG_32(0x0003000C)  /* I/O Port Function Select Upper Register */ 
#define S3C2510_IOPDMA                  REG_32(0x00030010)  /* I/O Port Special Function for DMA */ 
#define S3C2510_IOPINT                  REG_32(0x00030014)  /* I/O Port Special Function for External Interrupt */ 
#define S3C2510_IOPINTPEND              REG_32(0x00030018)  /* External Interrupt Clear Register */ 
#define S3C2510_IOPDATA1                REG_32(0x0003001C)  /* I/O Port Data Register */ 
#define S3C2510_IOPDATA2                REG_32(0x00030020)  /* I/O Port Data Register */ 
#define S3C2510_IOPDRV1                 REG_32(0x00030024)  /* I/O Port Drive Control Register */ 
#define S3C2510_IOPDRV2                 REG_32(0x00030028)  /* I/O Port Drive Control Register */

/******************************************************************************* 
        S3C2510 Interrupt Controller Special Registers 
*******************************************************************************/ 
 
#define S3C2510_INTINTMOD               REG_32(0x00140000)  /* Internal Interrupt Mode Register */ 
#define S3C2510_EXTINTMOD               REG_32(0x00140004)  /* External Interrupt Mode Register */ 
#define S3C2510_INTINTMASK              REG_32(0x00140008)  /* Internal Interrupt Mask Register */ 
#define S3C2510_EXTINTMASK              REG_32(0x0014000C)  /* External Interrupt Mask Register */ 
#define S3C2510_IPRIORHI                REG_32(0x00140010)  /* Interrupt by Priority High Register */ 
#define S3C2510_IPRIORLO                REG_32(0x00140014)  /* Interrupt by Priority Low Register */ 
#define S3C2510_INTOFFSET_FIQ           REG_32(0x00140018)  /* FIQ Interrupt Offset Register */ 
#define S3C2510_INTOFFSET_IRQ           REG_32(0x0014001C)  /* IRQ Interrupt Offset Register */ 
#define S3C2510_INTPRIOR0               REG_32(0x00140020)  /* Interrupt Priority Register 0 */ 
#define S3C2510_INTPRIOR1               REG_32(0x00140024)  /* Interrupt Priority Register 1 */ 
#define S3C2510_INTPRIOR2               REG_32(0x00140028)  /* Interrupt Priority Register 2 */ 
#define S3C2510_INTPRIOR3               REG_32(0x0014002C)  /* Interrupt Priority Register 3 */ 
#define S3C2510_INTPRIOR4               REG_32(0x00140030)  /* Interrupt Priority Register 4 */ 
#define S3C2510_INTPRIOR5               REG_32(0x00140034)  /* Interrupt Priority Register 5 */ 
#define S3C2510_INTPRIOR6               REG_32(0x00140038)  /* Interrupt Priority Register 6 */ 
#define S3C2510_INTPRIOR7               REG_32(0x0014003C)  /* Interrupt Priority Register 7 */ 
#define S3C2510_INTPRIOR8               REG_32(0x00140040)  /* Interrupt Priority Register 8 */ 
/* jwchoi, check */ 
#define S3C2510_INTTSTHI                REG_32(0x00140048)  /* Interrupt Test High Register */ 
#define S3C2510_INTTSTLO                REG_32(0x0014004C)  /* Interrupt Test Low Register */

 
 
#ifdef  __cplusplus 
} 
#endif 
 
#endif  /* INCs3c2510h */ 


