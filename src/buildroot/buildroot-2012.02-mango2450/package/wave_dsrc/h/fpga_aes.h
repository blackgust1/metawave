
#define		AES_BASE_ADDR											(0x40000)

#if 0
#define		AES_ENABLE_H_REG_OFFSET								(AES_BASE_ADDR+0x0000)
#define		AES_ENABLE_L_REG_OFFSET								(AES_BASE_ADDR+0x0002)

#define		AES_INITIAL_FLAG_H_REG_OFFSET						(AES_BASE_ADDR+0x0004)
#define		AES_INITIAL_FLAG_L_REG_OFFSET						(AES_BASE_ADDR+0x0006)


#define		AES_STATUS_H_REG_OFFSET								(AES_BASE_ADDR+0x0008)
#define		AES_STATUS_L_REG_OFFSET								(AES_BASE_ADDR+0x000A)

#define		AES_KEY0_H_REG_OFFSET								(AES_BASE_ADDR+0x0010)
#define		AES_KEY0_L_REG_OFFSET								(AES_BASE_ADDR+0x0012)

#define		AES_KEY1_H_REG_OFFSET								(AES_BASE_ADDR+0x0014)
#define		AES_KEY1_L_REG_OFFSET								(AES_BASE_ADDR+0x0016)

#define		AES_KEY2_H_REG_OFFSET								(AES_BASE_ADDR+0x0018)
#define		AES_KEY2_L_REG_OFFSET								(AES_BASE_ADDR+0x001A)

#define		AES_KEY3_H_REG_OFFSET								(AES_BASE_ADDR+0x001C)
#define		AES_KEY3_L_REG_OFFSET								(AES_BASE_ADDR+0x001E)

#define		AES_DATA0_H_REG_OFFSET								(AES_BASE_ADDR+0x0020)
#define		AES_DATA0_L_REG_OFFSET								(AES_BASE_ADDR+0x0022)

#define		AES_DATA1_H_REG_OFFSET								(AES_BASE_ADDR+0x0024)
#define		AES_DATA1_L_REG_OFFSET								(AES_BASE_ADDR+0x0026)

#define		AES_DATA2_H_REG_OFFSET								(AES_BASE_ADDR+0x0028)
#define		AES_DATA2_L_REG_OFFSET								(AES_BASE_ADDR+0x002A)

#define		AES_DATA3_H_REG_OFFSET								(AES_BASE_ADDR+0x002C)
#define		AES_DATA3_L_REG_OFFSET								(AES_BASE_ADDR+0x002E)

#define		AES_OUT0_H_REG_OFFSET								(AES_BASE_ADDR+0x0030)
#define		AES_OUT0_L_REG_OFFSET								(AES_BASE_ADDR+0x0032)

#define		AES_OUT1_H_REG_OFFSET								(AES_BASE_ADDR+0x0034)
#define		AES_OUT1_L_REG_OFFSET								(AES_BASE_ADDR+0x0036)

#define		AES_OUT2_H_REG_OFFSET								(AES_BASE_ADDR+0x0038)
#define		AES_OUT2_L_REG_OFFSET								(AES_BASE_ADDR+0x003A)

#define		AES_OUT3_H_REG_OFFSET								(AES_BASE_ADDR+0x003C)
#define		AES_OUT3_L_REG_OFFSET								(AES_BASE_ADDR+0x003E)


#define		AES_ENCRYPTION_DONE_STATUS_BIT						0x00010000
#endif


#define 		AES_BLOCK_SIZE 										16


extern int fpga_aes_encrypt(const unsigned char *in, unsigned char *out, int flag);

extern int formatting_block0(unsigned int nounce_len, unsigned char *nounce, unsigned int associate_data_len, unsigned int payload_len, 
					 unsigned int mac_len, unsigned char *block);

extern int formatting_associated_data(U8 associate_data_len, unsigned char *associate_data, unsigned char *block);

extern int formatting_payload_data(unsigned int payload_len, unsigned char *payload, unsigned char *block);

extern int formatting_counter_blocks(unsigned int nounce_len, unsigned char *nounce, int counter_block_cnt, unsigned char *counter_block);

extern int formatting_block(unsigned int nounce_len, unsigned char *nounce, U8 associate_data_len, unsigned char *associate_data, unsigned int payload_len, 
					 unsigned char *payload, unsigned int mac_len, unsigned char *block);

