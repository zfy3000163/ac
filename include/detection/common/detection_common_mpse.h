
#ifndef __DETECTION_COMMON_MPSE_H__
#define __DETECTION_COMMON_MPSE_H__



/*
*   Move these defines to a generic Win32/Unix compatability file, 
*   there must be one somewhere...
*/

/*
*  Pattern Matching Methods 
*/
#define DETECTION_COMMON_MPSE_AC        2

#define DETECTION_COMMON_MPSE_LOWMEM    4

#define DETECTION_COMMON_MPSE_ACF       6
#define DETECTION_COMMON_MPSE_ACS       7
#define DETECTION_COMMON_MPSE_ACB       8
#define DETECTION_COMMON_MPSE_ACSB      9
#define DETECTION_COMMON_MPSE_AC_BNFA   10 
#define DETECTION_COMMON_MPSE_AC_BNFA_Q 11 
#define DETECTION_COMMON_MPSE_ACF_Q     12 
#define DETECTION_COMMON_MPSE_LOWMEM_Q  13 

#define DETECTION_COMMON_MPSE_INCREMENT_GLOBAL_CNT 1
#define DETECTION_COMMON_MPSE_DONT_INCREMENT_GLOBAL_COUNT 0

VOID * Detection_Common_MpseNew(ULONG ulMethod, ULONG ulUseGobalCounterFlag,VOID (*pvFuncUserFree)(VOID *pvObj));
VOID    Detection_Common_MpseSetOpt(VOID *pvVoid, ULONG ulFlag );
VOID    Detection_Common_MpseFree(VOID *pvVoid );
ULONG  Detection_Common_MpsePrepPatterns(VOID *pvVoid);
DETECTION_SIGINFO_S *  Detection_Common_MpseSearch(VOID *pvVoid, const UCHAR *pucKey, ULONG ulLen, 
                                                                    DETECTION_SIGINFO_S * (*plFuncAction )(VOID* pvId, ULONG ulIndex, VOID *pvData), 
                                                                    VOID *pvData, LONG *plCurrentState );
ULONG Detection_Common_MpseGetPatternCount(VOID *pvoid);
ULONG Detection_Common_MpsePrintInfo( VOID *pvoid );
ULONG Detection_Common_MpsePrintSummary(ULONG ulExecID );
ULONG  Detection_Common_MpseAddPattern ( VOID * pvVoid, VOID * P, ULONG ulM, 
             ULONG ulNoCase,LONG lOffset, LONG lDepth,  VOID* pvID, ULONG ulIID );

#endif

