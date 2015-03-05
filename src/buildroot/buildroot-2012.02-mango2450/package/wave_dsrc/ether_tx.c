

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
#include "wave_mac.h"
#include "wsmp.h"

extern ETHER_RX_DATA	ether_rx_queue[ETHER_RX_QUEUE_NUM];
extern int ether_rx_queue_read_index;
extern int ether_rx_queue_write_index;

U1 wave_mac_dest_addr[ETH_MAC_ADDR_LEN];
U1 wave_mac_src_addr[ETH_MAC_ADDR_LEN];

extern int serv_sock;

int send_ethernet_pause_frame(void);

#if 0	//SHKO, Origin
int send_ethernet_raw_data(U1 *tx_buf, U4 tx_len)
{
	/*target address*/
	struct sockaddr_ll socket_address;

	/*pointer to ethenet header*/
	U1 *etherhead = tx_buf;

	/*userdata in ethernet frame*/
	U1 *data = tx_buf + 14;

	/*another pointer to ethernet header*/
	struct ethhdr *eh = (struct ethhdr *)etherhead;
 
	int send_result = 0;

#if 0
	/*our MAC address*/
	unsigned char src_mac[6] = {0x00, 0x01, 0x02, 0xFA, 0x70, 0xAA};

	/*other host MAC address*/
	unsigned char dest_mac[6] = {0x00, 0x04, 0x75, 0xC8, 0x28, 0xE5};
#endif


	/*prepare sockaddr_ll*/

	/*RAW communication*/
	socket_address.sll_family   = PF_PACKET;	
	/*we don't use a protocoll above ethernet layer
  	->just use anything here*/
	socket_address.sll_protocol = htons(ETH_P_IP);	

	/*index of the network device
	see full code later how to retrieve it*/
	socket_address.sll_ifindex  = 2;

	/*ARP hardware identifier is ethernet*/
	socket_address.sll_hatype   = ARPHRD_ETHER;
	
	/*target is another host*/
	socket_address.sll_pkttype  = PACKET_OTHERHOST;

	/*address length*/
	socket_address.sll_halen    = ETH_ALEN;		
	/*MAC - begin*/
	socket_address.sll_addr[0]  = tx_buf[0];		/* Ethernet Mac Destination Address */
	socket_address.sll_addr[1]  = tx_buf[1];		
	socket_address.sll_addr[2]  = tx_buf[2];
	socket_address.sll_addr[3]  = tx_buf[3];
	socket_address.sll_addr[4]  = tx_buf[4];
	socket_address.sll_addr[5]  = tx_buf[5];
	/*MAC - end*/
	socket_address.sll_addr[6]  = 0x00;/*not used*/
	socket_address.sll_addr[7]  = 0x00;/*not used*/


	/*set the frame header*/
#if 0
	memcpy((void*)buffer, (void*)dest_mac, ETH_ALEN);
	memcpy((void*)(buffer+ETH_ALEN), (void*)src_mac, ETH_ALEN);
	eh->h_proto = 0x00;
	/*fill the frame with some data*/
	for (j = 0; j < 1500; j++) 
	{
		data[j] = (unsigned char)((int) (255.0*rand()/(RAND_MAX+1.0)));
	}
#endif

	/*send the packet*/
	//send_result = sendto(s, buffer, ETH_FRAME_LEN, 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
	print_dump_data(tx_buf, tx_len, "[send_ethernet_raw_data] Send Data");
	send_result = sendto(serv_sock, tx_buf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
	
	if (send_result == -1) 
	{
		perror("[send_ethernet_raw_data] Send Error:\n");
		//print_dump_data(tx_buf, tx_len, "[send_ethernet_raw_data] Send Data");
		error_handling("[send_ethernet_raw_data] Send Fail !!\n");
		return(-1);
	}
	return(0);

}
#else
int send_ethernet_raw_data(U1 *tx_buf, U4 tx_len)
{
	struct ifreq ifr;
	
	/*target address*/
	struct sockaddr_ll socket_address;
	int send_result = 0;

	memset(&ifr, 0, sizeof(ifr));
	strncpy (ifr.ifr_name, "eth0", sizeof(ifr.ifr_name) - 1);
	ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';

	if (ioctl(serv_sock, SIOCGIFINDEX, &ifr) == -1) 
	{
    		printf("[send_ethernet_raw_data] No such interface:\n");
    		close(serv_sock);
	}

	ioctl(serv_sock, SIOCGIFFLAGS, &ifr);
	if ( (ifr.ifr_flags & 0x1) == 0) 
	{
    		printf("[send_ethernet_raw_data] Interface is down\n");
    		close(serv_sock);
	}

	ioctl(serv_sock, SIOCGIFINDEX, &ifr);


	memset(&socket_address, 0, sizeof (socket_address));


	/*prepare sockaddr_ll*/

	/*RAW communication*/
	//socket_address.sll_family   = PF_PACKET;
	socket_address.sll_family   = AF_PACKET;	
	/*we don't use a protocoll above ethernet layer
  	->just use anything here*/
	socket_address.sll_protocol = htons(ETH_P_ALL);	

	/*index of the network device
	see full code later how to retrieve it*/
	socket_address.sll_ifindex  = ifr.ifr_ifindex;

	/*ARP hardware identifier is ethernet*/
	socket_address.sll_hatype   = ARPHRD_ETHER;
	
	/*target is another host*/
	socket_address.sll_pkttype  = PACKET_OTHERHOST;

	/*address length*/
	socket_address.sll_halen    = ETH_ALEN;		
	/*MAC - begin*/
	socket_address.sll_addr[0]  = tx_buf[0];		/* Ethernet Mac Destination Address */
	socket_address.sll_addr[1]  = tx_buf[1];		
	socket_address.sll_addr[2]  = tx_buf[2];
	socket_address.sll_addr[3]  = tx_buf[3];
	socket_address.sll_addr[4]  = tx_buf[4];
	socket_address.sll_addr[5]  = tx_buf[5];
	/*MAC - end*/
	socket_address.sll_addr[6]  = 0x00;/*not used*/
	socket_address.sll_addr[7]  = 0x00;/*not used*/

#if 0
	if (bind(serv_sock,(struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) == -1)
	{
    		perror("bind:");
    		return(-1);
	}
#endif


	

	/*send the packet*/
	//send_result = sendto(s, buffer, ETH_FRAME_LEN, 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
	if( print_flag & ETHERNET_TX_DEBUG_MODE)
		print_dump_data(tx_buf, tx_len, "[send_ethernet_raw_data] Send Data");
	send_result = sendto(serv_sock, tx_buf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
	
	if (send_result == -1) 
	{
		perror("[send_ethernet_raw_data] Send Error:\n");
		//print_dump_data(tx_buf, tx_len, "[send_ethernet_raw_data] Send Data");
		error_handling("[send_ethernet_raw_data] Send Fail !!\n");
		return(-1);
	}
	return(0);

}
#endif

int send_ethernet_pause_frame(void)
{
	struct ifreq ifr;
	
	/*target address*/
	struct sockaddr_ll socket_address;
	int send_result = 0;
	int i = 0;

	U1 tx_buf[60];
	int tx_len = 60;

	memset(&ifr, 0, sizeof(ifr));
	strncpy (ifr.ifr_name, "eth0", sizeof(ifr.ifr_name) - 1);
	ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';

	if (ioctl(serv_sock, SIOCGIFINDEX, &ifr) == -1) 
	{
    		printf("[send_ethernet_raw_data] No such interface:\n");
    		close(serv_sock);
	}

	ioctl(serv_sock, SIOCGIFFLAGS, &ifr);
	if ( (ifr.ifr_flags & 0x1) == 0) 
	{
    		printf("[send_ethernet_raw_data] Interface is down\n");
    		close(serv_sock);
	}

	ioctl(serv_sock, SIOCGIFINDEX, &ifr);


	memset(&socket_address, 0, sizeof (socket_address));


	/*prepare sockaddr_ll*/

	/*RAW communication*/
	//socket_address.sll_family   = PF_PACKET;
	socket_address.sll_family   = AF_PACKET;	
	/*we don't use a protocoll above ethernet layer
  	->just use anything here*/
	socket_address.sll_protocol = htons(ETH_P_ALL);	

	/*index of the network device
	see full code later how to retrieve it*/
	socket_address.sll_ifindex  = ifr.ifr_ifindex;

	/*ARP hardware identifier is ethernet*/
	socket_address.sll_hatype   = ARPHRD_ETHER;
	
	/*target is another host*/
	socket_address.sll_pkttype  = PACKET_OTHERHOST;

	/*address length*/
	socket_address.sll_halen    = ETH_ALEN;

	/* Reserved MAC Control Address : 6bytes */
	tx_buf[i++] = 0x01;
	tx_buf[i++] = 0x80;
	tx_buf[i++] = 0xC2;
	tx_buf[i++] = 0x00;
	tx_buf[i++] = 0x00;
	tx_buf[i++] = 0x01;

	memcpy(&tx_buf[6], my_eth0_mac_addr, 6);
	i += 6;

	/* MAC Control Type : 2bytes */
	tx_buf[i++] = 0x88;
	tx_buf[i++] = 0x08;

	/* PAUSE Frame : 2bytes */
	tx_buf[i++] = 0x00;
	tx_buf[i++] = 0x01;

	/* PAUSE Time : 2bytes */
	tx_buf[i++] = 0x03;
	tx_buf[i++] = 0x2E;

	for ( ; i < tx_len; i++)
		tx_buf[i] = 0;
	
	/*MAC - begin*/
	socket_address.sll_addr[0]  = tx_buf[0];		/* Ethernet Mac Destination Address */
	socket_address.sll_addr[1]  = tx_buf[1];		
	socket_address.sll_addr[2]  = tx_buf[2];
	socket_address.sll_addr[3]  = tx_buf[3];
	socket_address.sll_addr[4]  = tx_buf[4];
	socket_address.sll_addr[5]  = tx_buf[5];
	/*MAC - end*/
	socket_address.sll_addr[6]  = 0x00;/*not used*/
	socket_address.sll_addr[7]  = 0x00;/*not used*/

#if 0
	if (bind(serv_sock,(struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) == -1)
	{
    		perror("bind:");
    		return(-1);
	}
#endif


	

	/*send the packet*/
	//send_result = sendto(s, buffer, ETH_FRAME_LEN, 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
	if( print_flag & ETHERNET_TX_DEBUG_MODE)
		print_dump_data(tx_buf, tx_len, "[send_ethernet_raw_data] Send Data");
	send_result = sendto(serv_sock, tx_buf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
	
	if (send_result == -1) 
	{
		perror("[send_ethernet_raw_data] Send Error:\n");
		//print_dump_data(tx_buf, tx_len, "[send_ethernet_raw_data] Send Data");
		error_handling("[send_ethernet_raw_data] Send Fail !!\n");
		return(-1);
	}
	return(0);

}