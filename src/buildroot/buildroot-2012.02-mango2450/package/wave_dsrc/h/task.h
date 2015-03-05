

#define	TCP_SERVER 			0
#define	TCP_CLIENT 				0
#define	RAW_SOCKET 			1



#define BUFSIZE	1024			/* 2048로 하면 처음 한번만 수신한다. */

extern pthread_t p_thread[6];
extern int serv_sock;
extern int clnt_sock;
extern int uart1_fd;
extern int net_rcv_thread_id;
extern int net_wait_tcp_connect_thread_id;
extern int ether_rx_proc_thread_id;
extern int wave_rcv_thread_id;
extern int wave_rcv_thread2_id;
extern int wave_mac_thread_id;
extern int wave_int_thread_id;
extern int capture_thread_id;
extern int memFd;
extern void *fpga_base_addr;
extern S2 monitor_ch;
extern int print_flag;
extern U4 capture_size;
extern U2 ddr_read_cap_size;
extern U2 ddr_write_cap_size;
extern char compiled_date_time[];
extern U4 built_date;									// 모듈이 컴파일된 날짜 (0xYYYYMMDD)
extern U4 built_time;									// 모듈이 컴파일된 시각 (0x00HHMMSS)
extern U4 ddr_memory_test_loop_num;
extern int capture_data_send_unit;						// 0->8bit, 1->12bit
extern U4 axis_info_index;

extern pthread_mutex_t ether_rx_mutex;
extern U1 *wave_dsrc_base;




/* util.c */
extern U4 __DATE__to_yyyymmdd(const char *date);
extern U4 __TIME__to_hhmmss(const char *time);
extern U4 get_high_pulse_width_nano_sec_from_reg_value(U4 reg_width);
extern U4 get_reg_value_from_high_pulse_width_nano_sec(U4 ns);
extern U4 get_reg_value_from_low_pulse_width_nano_sec(U4 ns);
extern U4 get_high_pulse_delay_nano_sec_from_reg_value(U4 reg_delay);
extern U4 get_reg_value_from_high_pulse_delay_micro_sec(float us);
extern U2 get_p4(U4 *d4, const U1 *s1);
extern void my_nanosleep(time_t sec,long nsec);
extern void print_dump_data(U1 *data, int len, char *title);
extern void print_dump_char_data(char *data, int len, char *title);
extern void print_dump_data2(U2 *data, int len, char *title);
extern void print_dump_data4(U4 *data, int len, char *title);
extern char *strmhz (char *buf, long hz);
extern int twos_complement(int data, int bit);
extern int twos_complement_from_u4_to_int(U4 data);
extern U4 twos_complement_from_int_to_u4(int data);
extern U4 get_freq_from_micro_sec_period(U4 us);
extern U4 get_sampling_rate_reg_value_from_mhz(float mhz);
extern U4 get_kbyte_unit_len_frome_length(U4 length);
extern U4 get_max_capture_size_from_prf_sampling_rate(float fSampleFreq_mhz, int prf_hz);
extern U4 myclock(void);

/* wave_modem.c */
extern void wave_modem_init(void);
extern void wave_modem_b_init(void);

/* wave_mac.c */
extern void wave_mac_init(void);
extern void wave_mac_b_init(void);

extern int wave_externel_interrupt_init(void);


extern int net_main(void);
extern U2 get_i4(U4 *d4, const U1 *s1);
extern U2 put_u4(U1 *d1, const U4 s4);
extern U2 put_u2(U1 *d1, const U2 s2);
extern U2 net_put_u4(U1 *d1, const U4 s4);
extern U2 net_put_u2(U1 *d1, const U2 s2);
extern void *memcpy4(void *dst, const void *src, size_t size);
extern void *memcpy2(void *dst, const void *src, size_t size);
extern void ExternalMemoryInit(void);
extern void ReadExternalBus_16(unsigned int Offset, unsigned short *Value);
extern void WriteExternalBus_16(U32 Offset, U16 Value);
extern void ReadExternalBus_32(unsigned int Offset, unsigned int *Value);
extern void WriteExternalBus_32(U32 Offset, U32 Value);
extern int init_adc(void);
extern int read_cmd_from_ddr2_to_buf(int ch_num, U4 ddr2_addr);
extern int read_cmd_from_ddr2_to_buf0(int ch_num, U4 ddr2_addr, U2 len );
extern int read_cmd_from_ddr2_to_buf1(int ch_num, U4 ddr2_addr, U2 len);
extern int read_adc_buffer(int ch_num, U4 ddr2_addr, U1 *buf);
extern int read_adc_buffer0(int ch_num, U4 ddr2_addr, U1 *buf, U2 len);
extern int read_adc_buffer1(int ch_num, U4 ddr2_addr, U1 *buf, U2 len);
extern U4 read_adc_control_reg(int ch_num, U4 offset);
extern U4 read_ddr2_control_reg(int ch_num, U4 offset);
extern U4 read_epg_control_reg(int ch_num, U4 offset);
extern const char *str_date(U4 yyyymmdd);
extern const char *str_time(U4 hhmmss);
extern U4 wait_ddr2_capture_done(int ch_num);
extern int write_adc_control_reg(int ch_num, U4 offset, U4 data);
extern int write_ddr2_control_reg(int ch_num, U4 offset, U4 data);
extern int write_epg_control_reg(int ch_num, U4 offset, U4 data);
extern U4 get_u4_from_u2 (U2 high, U2 low);
extern U2 get_u2_high_from_u4(U4 a);
extern U2 get_u2_low_from_u4(U4 a);
extern int init_ddr2sdram(int ch_num);
extern int ddr2_read(int ch_num, int buf_num, U4 ddr2_addr);
extern U2 put_cap_data_u4(U1 *d1, const U4 s4);
extern U2 put_cap_data_u2(U1 *d1, const U4 s4);
extern int set_adc_clock_sampling_rate(int ch_num, U4 rate);
extern U4 read_adc_clock_sampling_rate(int ch_num);
extern int set_ddr2_start_address_for_reading_buf0(int ch_num, U4 ddr2_addr);
extern U4 read_ddr2_start_address_for_reading_buf0(int ch_num);
extern int set_ddr2_start_address_for_reading_buf1(int ch_num, U4 ddr2_addr);
extern U4 read_ddr2_start_address_for_reading_buf1(int ch_num);
extern int set_ddr2_start_address_for_writing_from_buf0(int ch_num, U4 ddr2_addr);
extern U4 read_ddr2_start_address_for_writing_from_buf0(int ch_num);
extern int set_ddr2_start_address_for_writing_from_buf1(int ch_num, U4 ddr2_addr);
extern U4 read_ddr2_start_address_for_writing_from_buf1(int ch_num);
extern int set_size_of_read_from_ddr2_to_buf0(int ch_num, U2 size);
extern U2 read_size_of_read_from_ddr2_to_buf0(int ch_num);
extern int set_size_of_read_from_ddr2_to_buf1(int ch_num, U2 size);
extern U2 read_size_of_read_from_ddr2_to_buf1(int ch_num);
extern int set_size_of_write_from_buf0_to_ddr2(int ch_num, U2 size);
extern U2 read_size_of_write_from_buf0_to_ddr2(int ch_num);
extern int set_size_of_write_from_buf1_to_ddr2(int ch_num, U2 size);
extern U2 read_size_of_write_from_buf1_to_ddr2(int ch_num);
extern int set_high_pulse_width(int ch_num, U4 width);
extern U4 read_high_pulse_width(int ch_num);
extern int set_low_pulse_width(int ch_num, U4 width);
extern U4 read_low_pulse_width(int ch_num);
extern int set_start_pulse(int ch_num);
extern int set_pulse_test_mode(int ch_num, U4 mode);
extern U4 read_pulse_test_mode(int ch_num);
extern int set_pulse_axis_mode(int ch_num, U4 mode);
extern U4 read_pulse_axis_mode(int ch_num);
extern int set_pulse_auto_mode(int ch_num, U4 mode);
extern U4 read_pulse_auto_mode(int ch_num);
extern int set_prd_xaxis(int ch_num, int count);
extern U4 read_prd_xaxis(int ch_num);
extern int set_prd_yaxis(int ch_num, int count);
extern U4 read_prd_yaxis(int ch_num);
extern int set_cur_xaxis(int ch_num, U4 count);
extern U4 read_cur_xaxis(int ch_num);
extern int set_cur_yaxis(int ch_num, U4 count);
extern U4 read_cur_yaxis(int ch_num);
extern int set_high_pulse_delay(int ch_num, U4 width);
extern U4 read_high_pulse_delay(int ch_num);
extern void my_delay(long nsec);
extern int read_cmd_from_ddr2_to_buf(int ch_num, U4 ddr2_addr);
extern int set_spi_ctrl_start_trans(void);
extern int set_spi_ctrl_clk(U4 clk);
extern U4 read_spi_ctrl_clk(void);
extern int set_spi_data(U1 *data);
extern U4 read_spi_data(U1 *data);
extern int set_spi_data_ch(U4 ch);
extern U4 read_spi_data_ch(void);
extern void init_linked_list(void);
extern void fpga_reset(void);
extern U2 get_spi_gain_data(float gain);
extern int set_periodic_start_pulse_low_width(int ch_num, U4 hz);
extern int set_periodic_axis_start_pulse(int ch_num, int count, U4 axis_mode);
extern void init_channel_info(void);
extern int send_spi_data(int ch_num);
extern int set_start_pulse_enable(int ch_num);
extern int set_start_pulse_disable(int ch_num);
extern int clear_start_pulse_enable(void);
extern int set_select_encoder_ch(int ch_num);
extern int clear_select_encoder_ch(void);
extern int set_axis_buf_wr_pointer(int ch_num, U4 wr_pointer);
extern U4 read_axis_buf_wr_pointer(int ch_num);
extern int set_axis_buf_rd_pointer(int ch_num, U4 rd_pointer);
extern U4 read_axis_buf_rd_pointer(int ch_num);
extern int test_performance(void);	//SHKO_TEST
extern int uart1_read(unsigned char *buf);
extern int get_sample_freq200_cnt(void);
extern U4 get_u4_swap_u2(U4 data);
extern int CSFP_Serial_Close(int fd);
extern int send_ethernet_raw_data(U1 *tx_buf, U4 tx_len);

/* Thread 관련 */
extern void *uart1_rcv_thread(void *data);
extern void *ether_rx_proc_thread(void *data);
extern void *monitor_thread(void *data);
extern void *net_rcv_thread(void *data);
extern void *net_wait_tcp_connect_thread(void *data);
extern void *wave_rcv_thread(void *data);
extern void *wave_rcv_thread2(void *data);
extern void *wave_mac_thread(void *data);
extern void *wave_int_thread(void *data);