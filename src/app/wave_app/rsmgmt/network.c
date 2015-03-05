#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <termio.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include "rsmgmt.h"

static pthread_mutex_t send_nl_mutex;

int GetNetLinkInterface(int prototype,int group,int pid)
{
	struct sockaddr_nl sock_addr;
	int sockfd;

	sockfd = socket(AF_NETLINK, SOCK_RAW, prototype);
	if(sockfd == -1){
		printf("socket create error\n");
		return -1;
	}

	memset(&sock_addr,0,sizeof(struct sockaddr_nl));
	sock_addr.nl_family = AF_NETLINK;
	sock_addr.nl_groups = group;
	sock_addr.nl_pid = pid;  /* self pid */
	if(bind(sockfd, (struct sockaddr *)&sock_addr,sizeof(sock_addr)) < 0){
		printf("%d netlink client bind error !!!!\n",prototype);
        return -1;
	}

	if(pthread_mutex_init(&send_nl_mutex,NULL)){
        printf("send_nl_mutex error\n");
		close(sockfd);
        return -1;
    }

	DBG_MSG(BASIC_MSG_LEVEL,"GetNetLinkInterface : protocol type (%d), PID (%d)\n",prototype,pid); 
	return sockfd;
} // GetNetLinkInterface

int RecvNetLinkData(int sockfd,int length,int pid, unsigned char *buffer)
{
	struct sockaddr_nl nladdr;
	struct msghdr msg;
	struct iovec iov;
	struct nlmsghdr *nlh=NULL;
	int ret;

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(length));  
	memset(nlh, 0, NLMSG_SPACE(length));  
	nlh->nlmsg_len = NLMSG_LENGTH(0);  
	nlh->nlmsg_pid = pid;  
	nlh->nlmsg_flags = 0;

	memset(&nladdr, 0, sizeof(nladdr));  
	nladdr.nl_family = AF_NETLINK;  
	nladdr.nl_pid = 0;   /* For Linux Kernel */  
	nladdr.nl_groups = 0; /* unicast */

	iov.iov_base = (void *)nlh;
	iov.iov_len = length;	//	nlh->nlmsg_len;  

	msg.msg_name = (void *)&(nladdr);
	msg.msg_namelen = sizeof(nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	ret=recvmsg(sockfd, &msg, 0);
	if (ret<=0) {
		free(nlh);
		return 0;
	}
	ret -= NLMSG_LENGTH(0);
	memcpy(buffer,NLMSG_DATA(nlh),ret);  
/*
	printf("Type: %i (%s)\n",(nlh.nlmsg_type),lookup_name(typenames,nlh.nlmsg_type));
	printf("Flag:");
	printf("\n");
	printf("Seq : %i\n",nlh.nlmsg_seq);
	printf("Pid : %i\n",nlh.nlmsg_pid);
	printf("\n");
*/
	free(nlh);
	return ret;
}

int SendNetLinkData(int sockfd,int length,int pid, unsigned char *buffer)
{
	struct sockaddr_nl sAddr;
	struct nlmsghdr *nlh = NULL;
	struct msghdr msg;
	struct iovec iov;
	int retval;

	pthread_mutex_lock(&send_nl_mutex);
	memset(&sAddr, 0, sizeof(struct sockaddr_nl));  
	sAddr.nl_family = AF_NETLINK;  
	sAddr.nl_pid = 0;   /* For Linux Kernel */  
	sAddr.nl_groups = 0; /* unicast */  

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(length));  
	memset(nlh, 0, NLMSG_SPACE(length));  
	nlh->nlmsg_len = NLMSG_LENGTH(0);  
	nlh->nlmsg_pid = pid;  
	nlh->nlmsg_flags = 0;

	memcpy(NLMSG_DATA(nlh),buffer,length);  

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len; // length;  

	msg.msg_name = &sAddr;  
	msg.msg_namelen = sizeof(sAddr);  
	msg.msg_iov = &iov;  
	msg.msg_iovlen = 1;  

	retval = send(sockfd, nlh, (nlh->nlmsg_len+length), 0);
//	printf("pid(%d), nlmsg_len (%d), data len (%d) : retval(%d)\n",nlh->nlmsg_pid,nlh->nlmsg_len,length,retval);
	free(nlh);
	pthread_mutex_unlock(&send_nl_mutex);
	return retval;
} // SendNetLinkData(int sockfd,int length,int pid, unsigned char *buffer)
