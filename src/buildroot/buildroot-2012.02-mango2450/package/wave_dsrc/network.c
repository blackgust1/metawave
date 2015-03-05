 
/* TCP Sever Program */ 
#include <stdio.h>   
#include <stdlib.h>   
#include <string.h>   
#include <unistd.h>   
#include <arpa/inet.h>
#include <sys/types.h>   
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

 
#include "type_def.h"
#include "linked_list.h"
#include "task.h"
#include "wave_reg.h"
#include "wave_mac.h"

#define TCP_DEFAULT_PORT 		6000 
//#define BUFSIZE 				6144
   
void error_handling(char *message);

int serv_sock;
int clnt_sock;
int net_rcv_thread_id;
int net_wait_tcp_connect_thread_id;
int ether_rx_proc_thread_id;

S2 monitor_ch = 0;

static char *tcp_server_ip = "192.168.0.36";

unsigned char my_eth0_mac_addr[ETH_MAC_ADDR_LEN];

unsigned char device_mac_addr[ETH_MAC_ADDR_LEN];	/* WAVE 단말기와 이더넷으로 일대일로 연결된 PC의 Ethernet MAC 주소 */

__attribute__((aligned(4))) ETHER_RX_DATA	ether_rx_queue[ETHER_RX_QUEUE_NUM];
int ether_rx_queue_read_index = 0;
int ether_rx_queue_write_index = 0;

int eth_rx_broadcast_discard_flag = 0;

extern U1 WSA_DEST_MAC_ADDR[ETH_MAC_ADDR_LEN];	/* WSA를 송신한 기지국과 연결된 PC MAC 주소 */

extern int wsa_received_flag;

int wave_mac_addr_auto_flag = 0;

extern int auto_dest_mac_flag;



int Init_Ether_Rx_Queue(void)
{
	int i;

	for ( i = 0; i < ETHER_RX_QUEUE_NUM; i++ )
	{
		ether_rx_queue[i].data_len = 0;
		ether_rx_queue[i].data_ptr = &ether_rx_queue[i].packet[ETHER_RX_DATA_INITIAL_INDEX];
	}
	ether_rx_queue_read_index = 0;
	ether_rx_queue_write_index = 0;
}

#if TCP_SERVER	/* TCP sever setting */
int net_main(void)
{
 	struct sockaddr_in serv_addr;

	serv_sock=socket(PF_INET, SOCK_STREAM, 0);
 	if(serv_sock == -1)
  		error_handling("socket() error");

 	memset(&serv_addr, 0, sizeof(serv_addr));
 	serv_addr.sin_family=AF_INET;
 	serv_addr.sin_addr.s_addr=htonl(INADDR_ANY);
 	serv_addr.sin_port=htons(TCP_DEFAULT_PORT);

 	if(bind(serv_sock, (struct sockaddr*) &serv_addr, sizeof(serv_addr))==-1)
 	{
 		perror("bind error\n");
 		close(serv_sock);
 		
 		if(clnt_sock!=-1)
 			close(clnt_sock);
 			
  		error_handling("bind() error");
  	}

 	if(listen(serv_sock, 5)==-1)
 	{
 		close(serv_sock);
  		error_handling("listen() error");
  	}

	//printf("[net_main]MSGHDR size=%d\n", sizeof(MSGHDR));
	return 0;

}
#endif

#if TCP_CLIENT
int net_main(void)
{
 	struct sockaddr_in serv_addr;
 	int fresult;
 	int len;
 	struct in_addr laddr;
    int stat;


	//clnt_sock=socket(PF_INET, SOCK_STREAM, 0);
	clnt_sock=socket(AF_INET, SOCK_STREAM, 0);
 	if(clnt_sock == -1)
  		error_handling("socket() error");

 	memset(&serv_addr, 0, sizeof(serv_addr));
 	serv_addr.sin_family=AF_INET;
 	//serv_addr.sin_addr.s_addr=inet_addr(tcp_server_ip);
 	stat = inet_aton(tcp_server_ip, &laddr);
 	serv_addr.sin_addr.s_addr=laddr.s_addr;
 	
 	printf("[net_main]serv_addr.sin_addr.s_addr=0x%08x\n",serv_addr.sin_addr.s_addr);
 	serv_addr.sin_port=htons(TCP_DEFAULT_PORT);
 	printf("[net_main]serv_addr.sin_port=0x%08x\n",serv_addr.sin_port);
 	len=sizeof(serv_addr);
	printf("[net_main]clnt_sock=%d\n",clnt_sock);
	
	/* 아래 connect 함수를 호출하면, Tcp_output.c (net\ipv4) 파일안의 tcp_connect 함수가 호출된다. */
 	fresult= connect(clnt_sock,(struct sockaddr *)&serv_addr,len);

	if(fresult==-1)
	{
       perror("oops: client ");
       return -1;
	}
	return 0;

}
#endif

#if RAW_SOCKET
int SetPromiscMode(int Sockfd)
{
	struct ifreq IfInfo;

	strcpy(IfInfo.ifr_ifrn.ifrn_name, "eth0");
	if ( ioctl(Sockfd, SIOCGIFFLAGS, &IfInfo) < 0 )
	{
		return 0;
	}

	IfInfo.ifr_ifru.ifru_flags ^= IFF_PROMISC;
	if ( ioctl(Sockfd, SIOCSIFFLAGS, &IfInfo) < 0 )
	{
		return 0;
	}

	return 1;
}
#endif

#if RAW_SOCKET
int net_main(void)
{
 	struct sockaddr_in serv_addr;
 	struct ifreq ifr;

    	Init_Ether_Rx_Queue();


#if 0	//SHKO: 이렇게 하면 이더넷 헤더의 목적지 이더넷 주소가 내 주소와 같거나 broadcast 주소인 경우만 수신된다. 
	serv_sock=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
 	if(serv_sock == -1)
  		error_handling("socket() error");
#else
	//serv_sock=socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL));
	serv_sock=socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
 	if(serv_sock == -1)
  		error_handling("socket() error");

  	/* 네트워크 디바이스를 promiscous 모드로 변경 */
  	if(!SetPromiscMode(serv_sock))
  	{
  		error_handling("set promiscous mode error");
  	}
#endif

	strcpy(ifr.ifr_name, "eth0");
	ioctl(serv_sock, SIOCGIFHWADDR, &ifr);
     
	//hwaddr = (unsigned char*)ifr.ifr_hwaddr.sa_data;

	memcpy(my_eth0_mac_addr, ifr.ifr_hwaddr.sa_data, ETH_MAC_ADDR_LEN);
     
	printf("ETH0 MAC Addr = %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X\n",
            my_eth0_mac_addr[0],
            my_eth0_mac_addr[1],
            my_eth0_mac_addr[2],
            my_eth0_mac_addr[3],
            my_eth0_mac_addr[4],
            my_eth0_mac_addr[5]);


 	

	//printf("[net_main]MSGHDR size=%d\n", sizeof(MSGHDR));
	return 0;

}
#endif

#if TCP_SERVER
void *net_wait_tcp_connect_thread(void *data)
{
	struct sockaddr_in clnt_addr;   
 	socklen_t clnt_addr_size;	

 	while( 1 )   
	{  
		clnt_addr_size=sizeof(clnt_addr);
		clnt_sock=accept(serv_sock, (struct sockaddr*)&clnt_addr,&clnt_addr_size);   
		if(clnt_sock==-1)  
		{
		     	my_nanosleep(0, 10000000);	// 10ms Sleep 
		      	printf("accept() error\n");
		}
		else
		{
			printf("[net_rcv_thread]accept success\n");
			my_nanosleep(0, 10000000);	// 10ms Sleep 
		}
		
	}

 	
}
#endif


#if TCP_SERVER  
void *net_rcv_thread(void *data)   
{   
 	unsigned char message[BUFSIZE];   
 	int n;
	int i;
	//int accept_flag = 0;
    
 	struct sockaddr_in clnt_addr;   
 	socklen_t clnt_addr_size;
 	
 	printf("[net_rcv_thread] Start\n");

#if 0
 	clnt_addr_size=sizeof(clnt_addr);       
	clnt_sock=accept(serv_sock, (struct sockaddr*)&clnt_addr,&clnt_addr_size);   
	if(clnt_sock==-1)  
	{
		my_nanosleep(0, 10000000);	// 10ms Sleep 
		//error_handling("accept() error");   
		printf("accept() error\n");
	}
	else
	{
		printf("[net_rcv_thread]accept success\n");
		//accept_flag = 1;
	}
#endif 
    
 	while( 1 )   
	{  
#if 0
		//if (accept_flag == 0)
		//{
		    	clnt_addr_size=sizeof(clnt_addr);
		    	clnt_sock=accept(serv_sock, (struct sockaddr*)&clnt_addr,&clnt_addr_size);   
		     	if(clnt_sock==-1)  
		     	{
		     		my_nanosleep(0, 10000000);	// 10ms Sleep 
		      		//error_handling("accept() error");   
		      		printf("accept() error\n");
		      	}
		      	else
		      	{
		      		printf("[net_rcv_thread]accept success\n");
		      		//accept_flag = 1;
		    	}
		//}
#endif
		//else
		//{
    
		     	//while( (n=read(clnt_sock,message, BUFSIZE)) > 0)
		     	//n=read(clnt_sock,message, BUFSIZE);
		     	n = recv(clnt_sock, message, BUFSIZE, 0);	/* Tcp.c (net\ipv4)	파일내의 tcp_recvmsg 함수가 호출된다. */
		     	if (n > 0)
		     	{   
		      		//write(clnt_sock, message, str_len);   
		      		//write(1, message, str_len);
		      		if( print_flag & ETHERNET_RX_DEBUG_MODE )
					print_dump_data(message, n, "[net_rcv_thread] Recv Data");
				my_nanosleep(0, 10000000);	// 10ms Sleep
					
			}
			else
			{
				my_nanosleep(0, 10000000);	// 10ms Sleep 	
			}
		//}
		//close(clnt_sock);   
	}   
	return 0;   
}   
#endif

#if RAW_SOCKET 
void *net_rcv_thread(void *data)   
{   
 	int n;
	int i;
	U2_T high_mac_addr;
	U4_T low_mac_addr;
	U2_T ether_type;
	//int accept_flag = 0;
    
 	struct sockaddr_in clnt_addr;   
 	socklen_t clnt_addr_size;
 	
 	printf("[net_rcv_thread] Start\n");
    
 	while( 1 )
	{  
		n = recvfrom(serv_sock, ether_rx_queue[ether_rx_queue_write_index].data_ptr, ETH_FRAME_LEN, 0, NULL, NULL);	/* Tcp.c (net\ipv4)	파일내의 tcp_recvmsg 함수가 호출된다. */
		//printf("[net_rcv_thread] n = %d\n", n);
		if (n > 0)
		{
			pthread_mutex_lock(&ether_rx_mutex);
			//if( print_flag & ETHERNET_RX_DEBUG_MODE )
			//	printf("[net_rcv_thread] 1\n");
		#if 0	//SHKO, Origin
			if( (memcmp( ether_rx_queue[ether_rx_queue_write_index].data_ptr, my_eth0_mac_addr, ETH_MAC_ADDR_LEN ) != 0 ) &&
				( ((memcmp( ether_rx_queue[ether_rx_queue_write_index].data_ptr, Broadcast_MAC_ADDR, ETH_MAC_ADDR_LEN ) == 0 ) && (eth_rx_broadcast_discard_flag == 0))  || 
					(find_wave_rx_dest_mac_table_with_mac_addr(ether_rx_queue[ether_rx_queue_write_index].data_ptr) >= 0)
					|| (memcmp( ether_rx_queue[ether_rx_queue_write_index].data_ptr, WSA_DEST_MAC_ADDR, ETH_MAC_ADDR_LEN ) == 0 )))
		#else
			#if 0 //SHKO, Origin
			if( (memcmp( ether_rx_queue[ether_rx_queue_write_index].data_ptr, my_eth0_mac_addr, ETH_MAC_ADDR_LEN ) != 0 ) &&
				( ((memcmp( ether_rx_queue[ether_rx_queue_write_index].data_ptr, Broadcast_MAC_ADDR, ETH_MAC_ADDR_LEN ) == 0 ) && (eth_rx_broadcast_discard_flag == 0))  || 
					( (wsa_received_flag == 0) && (find_wave_rx_dest_mac_table_with_mac_addr(ether_rx_queue[ether_rx_queue_write_index].data_ptr) >= 0)   )
					|| ( (wsa_received_flag == 1) && (memcmp( ether_rx_queue[ether_rx_queue_write_index].data_ptr, WSA_DEST_MAC_ADDR, ETH_MAC_ADDR_LEN ) == 0 )  )          ))
			#else
			  #if 0 
				if( (memcmp( ether_rx_queue[ether_rx_queue_write_index].data_ptr, my_eth0_mac_addr, ETH_MAC_ADDR_LEN ) != 0 ) &&
					( ((memcmp( ether_rx_queue[ether_rx_queue_write_index].data_ptr, Broadcast_MAC_ADDR, ETH_MAC_ADDR_LEN ) == 0 ) && (eth_rx_broadcast_discard_flag == 0))  || 
					( (wsa_received_flag == 0) && (find_wave_rx_dest_mac_table_with_mac_addr(ether_rx_queue[ether_rx_queue_write_index].data_ptr) >= 0)   )
					|| (wsa_received_flag == 1)           ))
			  #else
			  	if( (memcmp( ether_rx_queue[ether_rx_queue_write_index].data_ptr, my_eth0_mac_addr, ETH_MAC_ADDR_LEN ) != 0 ) &&
				( ((memcmp( ether_rx_queue[ether_rx_queue_write_index].data_ptr, Broadcast_MAC_ADDR, ETH_MAC_ADDR_LEN ) == 0 ) && (eth_rx_broadcast_discard_flag == 0))  || 
					( (wsa_received_flag == 0) && (find_wave_rx_dest_mac_table_with_mac_addr(ether_rx_queue[ether_rx_queue_write_index].data_ptr) >= 0)   )
					|| ( (wsa_received_flag == 1) && (auto_dest_mac_flag == 0) && (memcmp( ether_rx_queue[ether_rx_queue_write_index].data_ptr, WSA_DEST_MAC_ADDR, ETH_MAC_ADDR_LEN ) == 0 )  )          
					|| ( (wsa_received_flag == 1) && (auto_dest_mac_flag == 1)   )         ))
			  #endif

			#endif
		#endif
			{
				//pthread_mutex_lock(&ether_rx_mutex);
				if (memcmp( ether_rx_queue[ether_rx_queue_write_index].data_ptr, Broadcast_MAC_ADDR, ETH_MAC_ADDR_LEN ) == 0)
				{
					ether_type.b1[1] = ether_rx_queue[ether_rx_queue_write_index].data_ptr[12];
					ether_type.b1[0] = ether_rx_queue[ether_rx_queue_write_index].data_ptr[13];
					
					/* 0x0806 : ARP, 0x0835 : RARP */
					if ((ether_type.b2 != 0x0806) && (ether_type.b2 != 0x0835))
					{
						pthread_mutex_unlock(&ether_rx_mutex);
						continue;
					}
				}

				

				/* WAVE 단말기와 이더넷으로 일대일로 연결된 PC의 Ethernet MAC 주소가 변경된 경우 아래 if문으로 들어간다. */
				if (wave_mac_addr_auto_flag)
				{
					if (memcmp(device_mac_addr, &ether_rx_queue[ether_rx_queue_write_index].data_ptr[6], ETH_MAC_ADDR_LEN) != 0)
					{
						/* WAVE 단말기와 이더넷으로 일대일로 연결된 PC의 Ethernet MAC 주소를 저장 */
						memcpy(device_mac_addr, &ether_rx_queue[ether_rx_queue_write_index].data_ptr[6], ETH_MAC_ADDR_LEN);

						high_mac_addr.b1[1] = ether_rx_queue[ether_rx_queue_write_index].data_ptr[6];
						high_mac_addr.b1[0] = ether_rx_queue[ether_rx_queue_write_index].data_ptr[7];

						low_mac_addr.b1[3] = ether_rx_queue[ether_rx_queue_write_index].data_ptr[8];
						low_mac_addr.b1[2] = ether_rx_queue[ether_rx_queue_write_index].data_ptr[9];
						low_mac_addr.b1[1] = ether_rx_queue[ether_rx_queue_write_index].data_ptr[10];
						low_mac_addr.b1[0] = ether_rx_queue[ether_rx_queue_write_index].data_ptr[11];

					#if 1
						printf("[net_rcv_thread] src mac addr = 0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x\n", ether_rx_queue[ether_rx_queue_write_index].data_ptr[6],
							ether_rx_queue[ether_rx_queue_write_index].data_ptr[7], ether_rx_queue[ether_rx_queue_write_index].data_ptr[8], ether_rx_queue[ether_rx_queue_write_index].data_ptr[9],
							ether_rx_queue[ether_rx_queue_write_index].data_ptr[10], ether_rx_queue[ether_rx_queue_write_index].data_ptr[11]);
					#endif
						
						reg_writew((wave_dsrc_base + WAVE_MAC_A_ADDR16_REG_OFFSET), high_mac_addr.b2);
						write_wave_dsrc_reg32(WAVE_MAC_A_ADDR32_H_REG_OFFSET, low_mac_addr.b4);
					}
				}
				else
				{
					if (memcmp(device_mac_addr, &ether_rx_queue[ether_rx_queue_write_index].data_ptr[6], ETH_MAC_ADDR_LEN) != 0)
					{
						pthread_mutex_unlock(&ether_rx_mutex);
						continue;
					}
				}

#if 0
				if ( memcmp( ether_rx_queue[ether_rx_queue_write_index].data_ptr, WSA_DEST_MAC_ADDR, ETH_MAC_ADDR_LEN ) == 0 )
				{
					printf("[net_rcv_thread] WSA_DEST_MAC_ADDR=%02x:%02x:%02x:%02x:%02x:%02x\n", 
					WSA_DEST_MAC_ADDR[0],WSA_DEST_MAC_ADDR[1],WSA_DEST_MAC_ADDR[2],WSA_DEST_MAC_ADDR[3],WSA_DEST_MAC_ADDR[4],WSA_DEST_MAC_ADDR[5]);
				}
#endif
				

				ether_rx_queue[ether_rx_queue_write_index].data_len = n;

				if( print_flag & ETHERNET_RX_DEBUG_MODE )
					print_dump_data(ether_rx_queue[ether_rx_queue_write_index].data_ptr, n, "[net_rcv_thread] Recv Data");

				ether_rx_queue_write_index++;
				if (ether_rx_queue_write_index == ETHER_RX_QUEUE_NUM)
				{
					ether_rx_queue_write_index = 0;
				}

				if ( ether_rx_queue_write_index == ether_rx_queue_read_index )
				{
					ether_rx_queue_write_index = ether_rx_queue_read_index;
					printf("[net_rcv_thread] ether_rx_queue OverFlow !!\n");
				}
				//printf("[net_rcv_thread] %d, %d\n", ether_rx_queue_write_index, ether_rx_queue_read_index);
				//if( print_flag & ETHERNET_RX_DEBUG_MODE )
				//	printf("[net_rcv_thread] 2\n");
				pthread_mutex_unlock(&ether_rx_mutex);
			}
			else
			{
				pthread_mutex_unlock(&ether_rx_mutex);
				//my_nanosleep(0, 5000000);	// 5ms Sleep
			//	print_flag = 1;
			//	print_dump_data(ether_rx_queue[ether_rx_queue_write_index].data_ptr, n, "[net_rcv_thread] Recv Data");
			//	print_flag = 0;
			}
		}
		else
		{
			//my_nanosleep(0, 5000000);	// 5ms Sleep
		}
	}   
	return 0;   
}   
#endif
  
void error_handling(char *message)   
{   
 	fputs(message, stderr);   
	fputc('\n', stderr);   
 	exit(1);   
}  
