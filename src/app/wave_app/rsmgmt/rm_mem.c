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

struct rsmgmt_pkt * rsmgmt_nl_Dequeue(struct rsmgmt_wave *rsmgmt)
{
    struct rsmgmt_pkt *head = rsmgmt->rmpkt_nl;

	pthread_mutex_lock(&rsmgmt->rsmgmt_nl_mutex);
    if(head == NULL){
        printf("rsmgmt_pkt : head is NULL\n");
        goto _Exit;
    }

    if(head->valid == QUEUE_EMPTY){
        head = NULL;
    }else if(head->valid == QUEUE_OCCUPIED){
        printf("rsmgmtbuf_Dequeue : QUEUE_OCCUPIED\n");
        rsmgmt->rmpkt_nl = head->link;
        head = NULL;
    }

_Exit:
	pthread_mutex_unlock(&rsmgmt->rsmgmt_nl_mutex);
    return head;
}

int rsmgmt_nl_FreeDequeue(struct rsmgmt_wave *rsmgmt)
{
    struct rsmgmt_pkt *head = rsmgmt->rmpkt_nl;

	pthread_mutex_lock(&rsmgmt->rsmgmt_nl_mutex);

    if(head->valid != QUEUE_OCCUPIED){
        head->valid = QUEUE_EMPTY;
    }

    rsmgmt->rmpkt_nl = head->link;
	pthread_mutex_unlock(&rsmgmt->rsmgmt_nl_mutex);
    return 0;
}

struct rsmgmt_pkt * rsmgmt_nl_NewQueue(struct rsmgmt_wave *rsmgmt)
{
    struct rsmgmt_pkt *head = rsmgmt->rmpkt_nl;

	pthread_mutex_lock(&rsmgmt->rsmgmt_nl_mutex);

    if(head == NULL){
        printf("rsmgmt_nl_Newqueue: head is NULL\n");
        goto _Exit;
    }

    while(head->valid != QUEUE_EMPTY){
        head = head->link;
        if(head->link == rsmgmt->rmpkt_nl){
            printf("rsmgmt_nl_Newqueue: buffer is FULL\n");
            head = NULL;
            goto _Exit;
        }
    }

_Exit:
	pthread_mutex_unlock(&rsmgmt->rsmgmt_nl_mutex);
    return head;
}

int rsmgmt_nl_SetEnqueue(struct rsmgmt_wave *rsmgmt)
{
    struct rsmgmt_pkt *head = rsmgmt->rmpkt_nl;

	pthread_mutex_lock(&rsmgmt->rsmgmt_nl_mutex);

    head->valid = QUEUE_AVAILABLE;

	pthread_mutex_unlock(&rsmgmt->rsmgmt_nl_mutex);
    return 0;
}

struct rsmgmt_pkt * Net_nodeAllocate(struct rsmgmt_pkt *head,int size)
{
	struct rsmgmt_pkt *new;

	if((new = malloc(size)) == NULL){
		printf ("Unable to alloc memory for rsmgmt_pkt !!!\n");
		return NULL;
	}
	memset(new,0,sizeof(struct rsmgmt_pkt));

	if(head == NULL){
//		printf("First nodeAllocate at %p\n",new);
		return new;
	}
	head->link = new;
//	printf("%p and valid (%d) Next link nodeAllocate at %p\n",head,head->valid,head->link);
	return new;
} //  Net_nodeAllocate

void rsmgmt_mem_free(struct rsmgmt_wave *rsmgmt)
{
	struct rsmgmt_pkt *rmpkt = NULL;
	struct rsmgmt_pkt *next = NULL;

	rmpkt = rsmgmt->rmpkt_nl;
	while(1){
		if(rmpkt == NULL)	break;
		if(rmpkt->link == rsmgmt->rmpkt_nl){
	//		printf("%p free \n",rmpkt);
			free(rmpkt);
			break;
		}
		next = rmpkt->link;
	//	printf("%p free \n",rmpkt);
		free(rmpkt);
		rmpkt = next;
	}
} //  rsmgmt_mem_free(struct rsmgmt_wave *rsmgmt)

int rsmgmt_mem_init(struct rsmgmt_wave *rsmgmt)
{
	struct rsmgmt_pkt *rmpkt = NULL;
	int i;

	if((rmpkt = Net_nodeAllocate(rmpkt,sizeof(struct rsmgmt_pkt))) != NULL){
        rsmgmt->rmpkt_nl = rmpkt;
        for(i=0; i<WAVE_RM_MAX_QUEUE; i++){
            if((rmpkt = Net_nodeAllocate(rmpkt,sizeof(struct rsmgmt_pkt))) == NULL){
                printf("[%d] rsmgmt_pkt Queue allocate fail !!!\n",i);
				rsmgmt_mem_free(rsmgmt);
				return -1;
            }
        }
        rmpkt->link = rsmgmt->rmpkt_nl;

		if(pthread_mutex_init(&rsmgmt->rsmgmt_nl_mutex,NULL)){
			printf("rsmgmt mutext init error\n");
			rsmgmt_mem_free(rsmgmt);
			return -1;
		}
#if 0
		rmpkt = rsmgmt->rmpkt_nl;
		while(rmpkt->link != (struct rsmgmt_pkt *)rsmgmt->rmpkt_nl){
			printf("rmpkt is %p, valid(%d) and link (%p) !!!\n",rmpkt,rmpkt->valid,rmpkt->link);
			rmpkt = rmpkt->link;
		}
		printf("rmpkt is %p and link (%p) !!!\n",rmpkt,rmpkt->link);
#endif
    } 
	return 0;
} // rsmgmt_mem_init

int rsmgmt_mutex_init(struct rsmgmt_wave *rsmgmt)
{
	if(pthread_mutex_init(&rsmgmt->bsmMsg_mutex,NULL)){
		printf("bsmMsg_mutex init error\n");
		goto _Exit;
	}
	if(pthread_mutex_init(&rsmgmt->wsmHeader_mutex,NULL)){
		printf("wsmHeader_mutex init error\n");
		goto _Exit;
	}

	return 0;

_Exit:
	pthread_mutex_destroy(&rsmgmt->bsmMsg_mutex);		
	pthread_mutex_destroy(&rsmgmt->wsmHeader_mutex);		

	return -1;
} //  rsmgmt_mutex_init(struct rsmgmt_wave *rsmgmt)
