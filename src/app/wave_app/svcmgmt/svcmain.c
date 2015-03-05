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
#include "svcmgmt.h"
#include "../comm_inc/svcdefs.h"

unsigned char Hex(unsigned char ch)
{
    unsigned char hex;

    if ('0'<=ch && ch<='9')
        hex = ch -'0';
    else if('A'<=ch && ch<='F')
        hex = ch - 'A' + 0xa;
    else if('a'<=ch && ch<='f')
        hex = ch - 'a' + 0xa;

    return hex;
}

char * get_conf_value(char *mark, char *buf)
{
    char *str=NULL;

    if(strncmp(buf, mark, (strlen(mark)-1)))    return NULL;
    str = strstr(buf,mark);
    if(str == 0x0)  return NULL;
    str = strchr(buf,'=');
    str++;
    while(*str != NULL){
        if(*str != 0x20)    return str;
        str++;
    } // while(*str == NULL)
}

static int GetNetLinkInterface(int prototype,int group,int pid)
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
//  printf("GetNetLinkInterface : protocol type (%d), PID (%d)\n",prototype,pid);
    return sockfd;
} // GetNetLinkInterface

int GetInterfaceMacAddress(unsigned char *mac, char *infname)
{
	struct ifreq if_hwaddr;
	int sock = socket(PF_PACKET,SOCK_RAW,0);

	strcpy(if_hwaddr.ifr_name,infname);
	ioctl(sock,SIOCGIFHWADDR,&if_hwaddr);
	close(sock);

    memcpy(mac,(unsigned char *)if_hwaddr.ifr_hwaddr.sa_data,ETH_ALEN);
	return 0;
}

int GetInterfaceIPAddress(void *pAddr,char *infname)
{
	struct ifreq ifr;
	int skfd=0, found=0;
	struct sockaddr_in *addr;

	if((skfd = socket(AF_INET, SOCK_DGRAM, 0)) == 1){
		close(skfd);
		return 0;
	}

	strcpy(ifr.ifr_name, infname);
	if(ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0){
		close(skfd);
        return (0);
    }

	if(ioctl(skfd, SIOCGIFADDR, &ifr) == 0){
		addr = ((struct sockaddr_in *)&ifr.ifr_addr);
		*((struct in_addr *)pAddr) = *((struct in_addr *)&addr->sin_addr);
	}

	close(skfd);
	return 1;
}

int SendSvcMsg(int prototype,unsigned char *bufptr,int length,int repeat, int msdelay)
{
    struct sockaddr_nl sAddr;
    struct nlmsghdr *nlh = NULL;
    struct msghdr msg;
    struct iovec iov;
    int retval;
    int netSock;
	int svcpid = getpid();

//	printf("svcpid = %d\n",svcpid);
	if((netSock = GetNetLinkInterface(prototype,0,svcpid)) == -1){
        printf("netSock create error !!!!\n");
	}

    memset(&sAddr, 0, sizeof(struct sockaddr_nl));
    sAddr.nl_family = AF_NETLINK;
    sAddr.nl_pid = 0;   /* For Linux Kernel */
    sAddr.nl_groups = 0; /* unicast */

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(length));
    memset(nlh, 0, NLMSG_SPACE(length));
    nlh->nlmsg_len = NLMSG_LENGTH(0);
    nlh->nlmsg_pid = svcpid;
    nlh->nlmsg_flags = 0;

    memcpy(NLMSG_DATA(nlh),bufptr,length);

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len; // length;  

    msg.msg_name = &sAddr;
    msg.msg_namelen = sizeof(sAddr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

	while(repeat>0){
    	retval = send(netSock, nlh, (nlh->nlmsg_len+length), 0);
		repeat -= 1;
		usleep(1000 * msdelay);
		//  printf("pid(%d), nlmsg_len (%d), data len (%d) : retval(%d)\n",nlh->nlmsg_pid,nlh->nlmsg_len,length,retval);
	}

    free(nlh);
	close(netSock);
	return 0;
} // SendSvcMsg

