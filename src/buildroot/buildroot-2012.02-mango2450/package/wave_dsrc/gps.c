#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <termios.h>
#include <fcntl.h>

#include "serial.h"

int uart1_fd = -1;


union
{
	unsigned short w;
	unsigned char b[2];
} sm_msg_len;
SM_QUEUE_LIST  sm_queue_list;
unsigned char sm_queue[MAX_SM_QUEUE_SIZE][MAX_SM_ENTRI_SIZE];
int sm_rcv_header=0;
int sm_preamble_detection;
int sm_preamble_count;
int sm_data_count;
int sm_frame_end_flag;

int serial_init(void)
{
	struct termios newtio;

	uart1_fd = open("/dev/ttySAC3", O_RDWR | O_NOCTTY | O_NONBLOCK);
	printf("[serial_init] uart1_fd=%d\n", uart1_fd);
	memset(&newtio, 0, sizeof(newtio));
	newtio.c_cflag = B9600 | CS8 | CLOCAL | CREAD;
	newtio.c_iflag = IGNPAR;
	newtio.c_oflag = 0;
	newtio.c_lflag = 0;
	newtio.c_cc[VTIME] = 0;
	newtio.c_cc[VMIN] = 1;

	tcflush(uart1_fd, TCIFLUSH);
	tcsetattr(uart1_fd, TCSANOW, &newtio);
	return 0;
}

int uart1_send(unsigned char *buf, int len)
{
	int ret=-1;

	ret = write( uart1_fd, buf, len);
	printf("[uart1_send] ret=%d\n", ret);
	return(ret);
}

int MakeSMFrame( unsigned char rxch )
{
        if((rxch==SM_START_FRAME)&&(sm_preamble_detection==0))
        {
                sm_preamble_count++;
                if( sm_preamble_count == 4)
                {
                        sm_preamble_detection = 1;
                }
                sm_msg_len.w=0;
        }
        else
        {
                sm_preamble_count=0;

                if(sm_preamble_detection==1)
                {
                        sm_data_count++;

                        if(sm_data_count==2)
                        {
                                sm_msg_len.b[1]= rxch;
                        }
                        else if(sm_data_count==3)
                        {
                                sm_msg_len.b[0]= rxch;
                        }

                        /*203=Download Len(200)+MSG_ID(1)+CRC(2)*/
                        if(sm_msg_len.w > 32)
                        {
                                printf("Length Err;%d\n",sm_msg_len.w);
                                sm_rcv_header=0;
                                sm_data_count=0;
                                sm_preamble_detection=0;
                                sm_frame_end_flag=0;
                                sm_preamble_count=0;
                                sm_msg_len.w=0;
                                return(0);
                        }
			/* 4=cmd(1)+len(2)+end(1)*/
                        if( sm_data_count < (sm_msg_len.w+5))
                        {
                                if(sm_queue_list.count==MAX_SM_QUEUE_SIZE)
                                {
                                        printf("SM Queue is Full\n");
                                        return(0);
                                }

                                if(!sm_frame_end_flag)
                                {
                                  sm_queue[sm_queue_list.rear+1][sm_rcv_header] = rxch;
				}

                                sm_rcv_header = sm_rcv_header+1;
                                if(sm_rcv_header >= MAX_SM_ENTRI_SIZE)
					sm_rcv_header = 0;

                          	/* 3=cmd(1)+len(2)*/
                                if(sm_data_count == (sm_msg_len.w+3))
                                {
                                        sm_frame_end_flag=1;
                                }
                                else
                                {
                                  if(sm_frame_end_flag)
                                  {
                                    if(rxch==SM_END_FRAME)
                                    {
                                        sm_rcv_header=0;
                                        sm_queue_list.count++; 
                                    	sm_queue_list.rear = sm_queue_list.rear + 1 ;
                                    	if(sm_queue_list.rear>=(MAX_SM_QUEUE_SIZE-1))
                                   	{
                                        	sm_queue_list.rear=-1;
                                   	}
                                        sm_data_count=0;
                                        sm_preamble_detection=0;
                                        sm_preamble_count=0;
                                        sm_frame_end_flag=0;
                                        sm_msg_len.w=0;
                                        return(1);
                                     }
                                     else
                                     {
                                         printf("Not Receive End Frame:0x%02x\n",rxch);
                                         sm_rcv_header=0;
                                         sm_data_count=0;
                                         sm_preamble_detection=0;
                                         sm_frame_end_flag=0;
                                         sm_preamble_count=0;
                                         sm_msg_len.w=0;
                                         return(0);
                                     }
                                  }
                                }
                        }
                }/*if(sm_preamble_detection==1)*/
        }/*else*/
        return(0);
}
	

int SM_Add_CRC(unsigned char *buf, unsigned short data_len)
{
	unsigned short crc;
	int i;
			
	i=0;
					
	//crc = update_crc16(0, &buf[4], (int)data_len);/*preamble 4byte*/
							
	i= 4+data_len;/*preamble 4byte*/
	buf[i++] = (crc & 0xFF00) >> 8;
	buf[i++] = (crc & 0x00FF);
											
	return(i);
}

int Build_SM_Header(unsigned char *buf, unsigned char cmd)
{
	int	i;
		
	i=0;
					
	buf[i++] = SM_START_FRAME;					/*preamble*/
	buf[i++] = SM_START_FRAME;					/*preamble*/
	buf[i++] = SM_START_FRAME;					/*preamble*/
	buf[i++] = SM_START_FRAME;					/*preamble*/
										
	buf[i++] = cmd;										/*cmd*/
												
	buf[i++] = 0;/*length*/
	buf[i++] = 0;/*length*/
															
	return(i);	
}

int SendFrameToHost(unsigned char cmd, unsigned char *send_buf, int len)
{
	int	total_len,i,k,cmd_len,data_len;
	unsigned char buf[256];
			 	
	i=0;
	total_len=0;
						
	i=Build_SM_Header(buf, cmd);

	for(k=0;k<len;k++)
	{
		buf[i++] = send_buf[k];
	}

	cmd_len = i-7+2;/*9=Start(4)+Cmd(1)+Length(2), 2=CRC(2)*/

	buf[5] =((cmd_len & 0xFF00) >> 8);/*length*/
	buf[6] = (cmd_len & 0x00FF);/*length*/
			
	data_len = i-4;/*preamble 4byte*/
					
	i = SM_Add_CRC(buf, (unsigned short)data_len);
							
								
	buf[i++]=SM_END_FRAME;
										
	total_len=i;
	printf("Send Total Length:%d\n",total_len);
	for(k=0;k<total_len;k++)
	{
		if(k%10==0)
			printf("\n");
		printf("[%02x]",buf[k]);
	}
	printf("\n");

	uart1_send(&buf[0], total_len);
	return 0;
}

void uart1_rcv_thread(void *data)
{
	int id;
	int i = 0;
	int ndx;
	int cnt;
	int ret;
	unsigned short check, total_len;
	union
	{
		unsigned short w;
		unsigned char b[2];
	}ie_len;
	unsigned char buf[1024];
	unsigned char send_buf[10] = {1,2,3,4,5,6,7,8,9,10};
	struct termios newtio;
	struct pollfd poll_events;
	int poll_state;

	id = *((int *)data);

	//crc16_main();

	sm_queue_list.count=0;
        sm_queue_list.front=0;
        sm_queue_list.rear=-1;

	fcntl(uart1_fd, F_SETFL, FNDELAY);

	poll_events.fd = uart1_fd;
	poll_events.events = POLLIN | POLLERR;
	poll_events.revents = 0;

	while(1)
	{
		poll_state = poll( (struct pollfd *)&poll_events, 1, 1000);
		/* printf("[uart1_rcv_thread] poll_state=%d\n", poll_state);*/


		if( poll_state > 0 )
		{
			if( poll_events.revents & POLLIN)
			{
				cnt = read( uart1_fd, buf, 1024);
				printf("data received - %d \n", cnt);
				for (i=0;i<cnt;i++)
				{
					if( (i!=0) && ((i%10)==0) )
						printf("\n");
					printf("[%02x]",buf[i]);
				}
				printf("\n");
	
			}
			else if(poll_events.revents & POLLERR)
			{
				printf("uart1_rcv_thread Receive Error, Terminate This Program\n");
				break;
			}
		}
#if 0 /* SHKO */
		else if( poll_state == 0)
		{
			if( SendFrameToHost(1,send_buf,10) < 0 )
			{
				printf("[uart1_rcv_thread] Send Fail!!\n");
				exit(0);
			}
		}
#endif
		
	}
	close(uart1_fd);
	exit(0);
}

