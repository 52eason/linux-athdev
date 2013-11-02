#include "utils.h"

int PLATFORM_CreateTimer(unsigned long ulTriggerSec, unsigned long ulIntervalSec)
{
	struct itimerval itv, oldtv;
	
	// it_value: timeout to run function first time
	itv.it_value.tv_sec = ulTriggerSec;     // sec.
	itv.it_value.tv_usec = 0;               // micro sec.
	// it_interval: interval time to run function
	itv.it_interval.tv_sec = ulIntervalSec; // sec.
	itv.it_interval.tv_usec = 0;            // micro sec.

	// set timer, ITIMER_REAL: real-time to decreate timer send
	// SIGALRM when timeout
	if (setitimer(ITIMER_REAL, &itv, &oldtv) != 0)
	{
		perror("setitimer");
		return -1;
	}
	else
		return 0;
}

void PLATFORM_SleepSec(unsigned int uiSecond)
{
	sleep(uiSecond);
}

void PLATFORM_SleepMSec(unsigned int uiMilliSecond)
{
	usleep(uiMilliSecond * 1000);
}

int PLATFORM_ThreadCreate(struct platformThread_t* tPlatform)//, void *(*pFnStartRoutine)(void *), void *pThreadParm)
{
	int iReturn = 0;
	iReturn = pthread_create(&tPlatform->hThread, NULL, tPlatform->pfFnStartRoutine, tPlatform->pThreadParm);
	if (iReturn != 0)
	{
		printf("PLATFORM_ThreadCreate is fail!!\n");
		return -1;
	}
	else
	return 0;
}

int PLATFORM_ThreadCancel(struct platformThread_t* tPlatform)
{
	int iReturn = 0;
	iReturn = pthread_cancel(tPlatform->hThread);
	if (iReturn != 0)
		return -1;
	else
		return 0;
}
