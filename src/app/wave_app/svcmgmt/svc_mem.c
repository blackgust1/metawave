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

struct svcReqQueue *SVCReqQ=NULL;
static struct _WaveServiceFunc *WaveServiceFunc= NULL;
static struct _WSM_WaveShortMessage *WSM_WaveShortMessage=NULL;
pthread_mutex_t	svcreq_mutex;
pthread_t   svcEventThread;
static int  svc_Event_Running = 0;
static int  svc_Event_Max_Q = 0;

static void putErrorLogToFile(char *err)
{
	char log[100]={0,};

	sprintf(log,"echo %s>>/var/tmp/svc.log\n",err);
	system(log); 
}

struct svcEvent * svcReq_Dequeue(void)
{
	struct svcEvent *reqPtr=NULL;
    struct svcReqQueue *head;

	pthread_mutex_lock(&svcreq_mutex);
    head = SVCReqQ;
    if(head == NULL){
		printf("svcReqQueue : head is NULL\n");
        goto _Exit;
    }

   	if(head->Event != NULL){
		reqPtr = head->Event;
	}

_Exit:
	pthread_mutex_unlock(&svcreq_mutex);
    return reqPtr;
}

void svcReq_FreeDequeue(struct svcEvent *svc)
{
    struct svcReqQueue *head;
	struct svcEvent *next;

	pthread_mutex_lock(&svcreq_mutex);

	head = SVCReqQ;
    if(head == NULL){
        printf("svcReq_FreeDequeue : head is NULL\n");
        goto _Exit;
    }
	SVCReqQ = head->link;

	while(1){
		if(svc == NULL)	break;
		free(svc->EventReq);
		next = svc->link;
		free(svc);
		svc = next;
	}

_Exit:
	pthread_mutex_unlock(&svcreq_mutex);
}

#if 1
struct svcEvent * svcReq_Alloc(void *root,int size)
{
	struct svcEvent *new=NULL;
	struct svcEvent *next=NULL;
	void * ptr;

	if((new = malloc(sizeof(struct svcEvent))) == NULL){
		printf ("Unable to alloc memory for svcEvent !!!\n");
		return NULL;
	}
	memset(new,0,sizeof(struct svcEvent));
	if((ptr = malloc(size)) == NULL){
		printf ("Unable to alloc memory for svcEvent !!!\n");
		return NULL;
	}
	new->EventReq = ptr;
	new->length = size;

	if(root != NULL){
	//	printf ("svc Req alloc memory for Child (root:%p) !!!\n",root);
		next = root;
		while(next->link != NULL){
			next = next->link;
		}
		next->link = new;
#if 0
		next = root;	// for debug print
		while(next->link != NULL){
			printf("svcEvent is %p, svcEvent->EventReq(%p), svcEvent->svcname(%d), svcEvent->length(%d) and link (%p) !!!\n",
				next,next->EventReq,next->svcname,next->length,next->link);
			next = next->link;
		}
		printf("svcEvent is %p, svcEvent->EventReq(%p), svcEvent->svcname(%d), svcEvent->length(%d) and link (%p) !!!\n",
				next,next->EventReq,next->svcname,next->length,next->link);
#endif
	}

	return new;
}
#else
static struct svcEvent * svcReq_Alloc(int svcname, int size, int node)
{
	struct svcEvent *new=NULL;
	void * ptr;

	if(node == ROOT_NODE){
		if((new = malloc(sizeof(struct svcEvent))) == NULL){
			printf ("Unable to alloc memory for svcEvent !!!\n");
			return NULL;
		}
		memset(new,0,sizeof(struct svcEvent));
		if((ptr = malloc(size)) == NULL){
			printf ("Unable to alloc memory for svcEvent !!!\n");
			return NULL;
		}
		new->EventReq = ptr;
		new->svcname = svcname;
	}

	return new;
}
#endif

static int svcReq_SetEnqueue(struct svcEvent *svc)
{
    struct svcReqQueue *head;

	pthread_mutex_lock(&svcreq_mutex);
    head = SVCReqQ;
    if(head == NULL){
        printf("svcReq_SetEnqueue : head is NULL\n");
        goto _Exit;
    }

    while(head->Event != NULL){
        if(head->link == SVCReqQ){
            printf("svcReq_SetEnqueue: buffer is FULL\n");
            head = NULL;
            goto _Exit;
        }
        head = head->link;
    }
   	head->Event = svc;

_Exit:
	pthread_mutex_unlock(&svcreq_mutex);
    return 0;
}

static struct svcReqQueue * SVC_nodeAllocate(struct svcReqQueue *head,int size)
{
	struct svcReqQueue *new;

	if((new = malloc(size)) == NULL){
		printf ("unable to alloc memory for svcreqqueue !!!\n");
		return NULL;
	}
	memset(new,0,sizeof(struct svcReqQueue));

	if(head == NULL){
		return new;
	}
	head->link = new;
	return new;
} //  SVC_nodeAllocate

static void svcReq_mem_free(struct svcReqQueue *svcReq)
{
	struct svcReqQueue *svc = NULL;
	struct svcReqQueue *next = NULL;

	svc = svcReq;
	while(1){
		if(svc == NULL)	break;
		if(svc->link == svcReq){
	//		printf("%p free \n",rmpkt);
			free(svc);
			break;
		}
		next = svc->link;
	//	printf("%p free \n",rmpkt);
		free(svc);
		svc = next;
	}
} //  svcReq_mem_free

static int _wsm_request(struct svcEvent *svcReq)
{
	printf("_wsm_request !!!!\n");
	svcReq->svcname = WSM_REQUEST;
	svcReq_SetEnqueue(svcReq);

	return 0;
}

static int svcFuncInit(void)
{
	if((WaveServiceFunc = malloc(sizeof(struct _WaveServiceFunc))) == NULL){
		printf ("unable to alloc memory for svcfunc !!!\n");
		putErrorLogToFile("unable to alloc memory for svcfunc");
		return -1;
	}
	memset(WaveServiceFunc,0,sizeof(struct _WaveServiceFunc));

	WSM_WaveShortMessage = (struct _WSM_WaveShortMessage *)&WaveServiceFunc->WSM_WaveShortMessage;

	WSM_WaveShortMessage->request = _wsm_request;
	printf("svcFuncInit : WSM_WaveShortMessage(%p), WSM_WaveShortMessage->request (%p)\n",WSM_WaveShortMessage,WSM_WaveShortMessage->request);

	return 0;
} //  SVC_nodeAllocate

void * get_svcFunc(int func)
{
	switch(func){
	case WSM_REQUEST:
	case WSM_CONFIRM:
	case WSM_INDICATION:
		printf("get_svcFunc : WSM_WaveShortMessage(%p : %p)\n",&WaveServiceFunc->WSM_WaveShortMessage,WSM_WaveShortMessage);
/*
		WSM_WaveShortMessage = (struct _WSM_WaveShortMessage *)&WaveServiceFunc->WSM_WaveShortMessage;
		printf("get_svcFunc : WSM_WaveShortMessage->request (%p)\n",WSM_WaveShortMessage->request);
*/
		return (void *)WSM_WaveShortMessage;
	} // 
	
	return NULL;
}

#if 0
void * svcEvent_Thread(void * arg)
{
	struct svcReqQueue *svcReq = NULL;
	int i;

	if((svcReq = SVC_nodeAllocate(SVCReqQ,sizeof(struct svcReqQueue))) != NULL){
        SVCReqQ = svcReq;
        for(i=0; i<svc_Event_Max_Q; i++){
            if((svcReq = SVC_nodeAllocate(svcReq,sizeof(struct svcReqQueue))) == NULL){
                printf("[%d] svcReqQueue allocate fail !!!\n",i);
				svcReq_mem_free(SVCReqQ);
				return -1;
            }
        }
        svcReq->link = SVCReqQ;

		if(pthread_mutex_init(&svcreq_mutex,NULL)){
			printf("svcreq_mutex init error\n");
			svcReq_mem_free(SVCReqQ);
			return -1;
		}
#if 0
		svcReq = SVCReqQ;
		while(svcReq->link != SVCReqQ){
			printf("svcReq is %p, Event(%p), and link (%p) !!!\n",svcReq,svcReq->Event,svcReq->link);
			svcReq = svcReq->link;
		}
		printf("svcReq is %p and link (%p) !!!\n",svcReq,svcReq->link);
#endif
		svcFuncInit();

		svc_Event_Running = 1;
		while(svc_Event_Running);
    } 
	pthread_exit("end");
	pthread_mutex_destroy(&svcreq_mutex);
}
#else
void * svcEvent_Thread(void * arg)
{

}
#endif

int svcReqQ_init(int max)
{
	struct svcReqQueue *svcReq = NULL;
	int i;

	svc_Event_Max_Q = max;
	if(pthread_create(&svcEventThread, NULL, svcEvent_Thread, NULL) != 0){
        printf("svcEvent_Thread create error");
    }
	return 0;
} // main

