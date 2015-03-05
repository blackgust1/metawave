/* 
http://www.informit.com/articles/article.aspx?p=23618&seqNum=14
*/



#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include "type_def.h"
#include "task.h"
#include "wave_reg.h"
#include "wave_mac.h"
#include "wave_int.h"

extern int dev;

timer_t wave_tx_timer_id = 0;
timer_t SR5500_TEST_RX_TIMER_ID = 0;

#if 0	//SHKO, Origin
int start_timer(int timer_id);
int stop_timer(int timer_id);
#else
int start_timer( timer_t *timerID, void (*handler)(), int sec, int msec );
int stop_timer( timer_t *timerID );
#endif

extern int sr5500_prev_mac_rx_cnt;
extern int mac_rx_count;
extern U1 sr5500_rx_test_end_flag;
extern int total_wave_mac_rx_count;



void sr5500_rx_test_timer_handler(int signum)
{
	stop_timer(&SR5500_TEST_RX_TIMER_ID);

	if ( sr5500_rx_test_end_flag )
	{
		return;
	}
	else
	{
		if (sr5500_prev_mac_rx_cnt == total_wave_mac_rx_count)
		{
			printf("[sr5500_rx_test_timer_handler] No Rx Data for 3 second\n");
			print_sr5500_test_result();
		}
	}
	//else
	//{
	//	start_timer(&SR5500_TEST_RX_TIMER_ID, sr5500_rx_test_timer_handler, 3, 0);
	//}
}

void wave_tx_timer_handler(int signum)
{
	//static int count = 0;
	int ret;
	IOCTLWAVE_INFO ctrl_info;
	
	//printf("[wave_tx_timer_handler]timer expired\n");

#if 1
	ret  = ioctl(dev, IOCTLWAVE_READ, &ctrl_info);
	if (ret != 0)
	{
		perror("[wave_tx_timer_handler]ioctl read:");
	}
	else
	{
		if ( ctrl_info.wave_tx_write_success_index != ctrl_info.wave_tx_queue_read_index )
		{
			printf("[wave_tx_timer_handler]wave_tx_write_success_index=%d, wave_tx_queue_read_index=%d\n", ctrl_info.wave_tx_write_success_index, ctrl_info.wave_tx_queue_read_index);
			ctrl_info.wave_tx_queue_read_index = ctrl_info.wave_tx_write_success_index ;
			printf("[wave_tx_timer_handler]wave_tx_write_success_index=%d, wave_tx_queue_read_index=%d\n", ctrl_info.wave_tx_write_success_index, ctrl_info.wave_tx_queue_read_index);
			ret  = ioctl(dev, IOCTLWAVE_WRITE, &ctrl_info);
			if (ret != 0)
			{
				perror("[wave_tx_timer_handler]ioctl write:");
			}
		}
	}
#endif
}


#if 0
int start_timer(int timer_id)
{
	struct sigaction sa;
	struct itimerval timer;
	int ret;

 	/* Install timer_handler as the signal handler for SIGVTALRM. */
 	memset (&sa, 0, sizeof (sa));
 	sa.sa_handler = &wave_tx_timer_handler;
 	sigaction (SIGVTALRM, &sa, NULL);
 	
 	/* ... and every 250 msec after that. */
   #if 0	/* 아래 것을 열면 주기적으로 발생한다. */
 	//timer.it_interval.tv_sec = 0;
 	//timer.it_interval.tv_usec = 250000;
 	/* Start a virtual timer. It counts down whenever this process is
   	executing. */
  #else
	/* Configure the timer to expire after 250 msec... */
 	timer.it_value.tv_sec = 1;
 	timer.it_value.tv_usec = 0;
  #endif
 	ret = setitimer (ITIMER_VIRTUAL, &timer, NULL);
 	
 	if (ret)
 	{
 		perror("[start_timer] Fail");
	}
 	return(ret);
}
#else
int start_timer( timer_t *timerID, void (*handler)(), int sec, int msec )
{
	struct sigevent         te;      
	struct itimerspec       its;      
	struct sigaction        sa;      
	int                     sigNo = SIGRTMIN;
	int ret;

	if (*timerID != 0)
		return(-4);

	if (timerID == &wave_tx_timer_id)
	{
		sigNo = SIGRTMIN;
	}
	else if (timerID == &SR5500_TEST_RX_TIMER_ID)
	{
		sigNo = SIGRTMIN+1;
	}


#if 1
	/* Set up signal handler. */      
	sa.sa_flags = SA_SIGINFO;      
	sa.sa_sigaction = handler;      
	sigemptyset(&sa.sa_mask);

	if (sigaction(sigNo, &sa, NULL) == -1)      
	{          
		printf("sigaction error\n");        
		return -1;       
	}

	/* Set and enable alarm */      
	te.sigev_notify = SIGEV_SIGNAL;       
	te.sigev_signo = sigNo;      
	te.sigev_value.sival_ptr = timerID;      
	ret = timer_create(CLOCK_REALTIME, &te, timerID);
	if (ret)
	{
		perror("[start_timer] timer_create fail");
		return(-2);
	}
#endif

	/* 반복적으로 핸들러를 부르고 싶을 때 */
#if 1
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;
#endif
	its.it_value.tv_sec = sec;
	its.it_value.tv_nsec = msec * 1000000;
	//printf("[start_timer] timerID = %d\n", *timerID);
	ret = timer_settime(*timerID, 0, &its, NULL);
	if (ret)
	{
		perror("[start_timer] timer_settime fail");
		return(-3);
	}
	//printf("[start_timer] timerID=%d\n", *timerID);
	return(0);

	
}

#endif

#if 0
int stop_timer(int timer_id)
{
	struct sigaction sa;
	struct itimerval timer;
	int ret;

 	/* Install timer_handler as the signal handler for SIGVTALRM. */
 	memset (&sa, 0, sizeof (sa));
 	sa.sa_handler = &wave_tx_timer_handler;
 	sigaction (SIGVTALRM, &sa, NULL);
 	
 	/* ... and every 250 msec after that. */
   #if 0	/* 아래 것을 열면 주기적으로 발생한다. */
 	//timer.it_interval.tv_sec = 0;
 	//timer.it_interval.tv_usec = 250000;
 	/* Start a virtual timer. It counts down whenever this process is
   	executing. */
  #else
	/* Configure the timer to expire after 250 msec... */
 	timer.it_value.tv_sec = 0;
 	timer.it_value.tv_usec = 0;
  #endif
 	ret = setitimer (ITIMER_VIRTUAL, &timer, NULL);
 	
 	if (ret)
 	{
 		perror("[stop_timer] Fail");
	}
 	return(ret);
}
#else
int stop_timer( timer_t *timerID )
{
	int 					temp;

	if (*timerID == 0)
		return(-1);

	temp = timer_delete(*timerID);

	*timerID = 0;

	if (temp)
	{
		perror("[stop_timer] fail");
		return(-2);
	}

	return(0);
	
}
#endif
