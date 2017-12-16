  
#ifndef __DETECTION_COMMON_ACSMX_H__
#define __DETECTION_COMMON_ACSMX_H__



/*
*   Prototypes
*/


#define DETECTION_DETECT_ALPHABET_SIZE    256     

#define DETECTION_DETECT_ACSM_FAIL_STATE   -1     


typedef struct stAcsmPattern {      

    struct  stAcsmPattern *pstNext;
    UCHAR         *pucPatrn;
    UCHAR         *pucCasepatrn;
    ULONG      ulN;
    ULONG      ulNocase;
    LONG      lOffset;
    LONG      lDepth;
    VOID   * pvId;
    ULONG      ulIid;

} DETECTION_ACSM_PATTERN_S;


typedef struct  {    

    /* Next state - based on input character */
    ULONG      ulNextState[ DETECTION_DETECT_ALPHABET_SIZE ];  

    /* Failure state - used while building NFA & DFA  */
    ULONG      ulFailState;   

    /* List of patterns that end here, if any */
    DETECTION_ACSM_PATTERN_S *pstMatchList;   

}DETECTION_ACSM_STATETABLE_S; 


/*
* State machine Struct
*/
typedef struct stAcsm
{
  
    ULONG ulAcsmMaxStates;  
    ULONG ulAcsmNumStates;  

    DETECTION_ACSM_PATTERN_S    * pstAcsmPatterns;
    DETECTION_ACSM_STATETABLE_S * pstAcsmStateTable;

    ULONG   ulBcSize;
    USHORT  usBcShift[256];

    ULONG   ulNumPatterns;

}DETECTION_ACSM_S;

VOID Detection_Common_AcsmFree (DETECTION_ACSM_S * pstAcsm) ;
ULONG Detection_Common_AcsmCompile (DETECTION_ACSM_S * pstAcsm) ;
DETECTION_ACSM_S * Detection_Common_AcsmNew (VOID) ;
ULONG Detection_Common_AcsmAddPattern (DETECTION_ACSM_S * pstAcsm, UCHAR *pucPat, ULONG ulN, ULONG ulNocase,
            LONG lOffset, LONG lDepth, VOID * pvId, ULONG ulIid) ;
ULONG Detection_Common_AcsmCompile (DETECTION_ACSM_S * pstAcsm) ;
ULONG Detection_Common_AcsmPrintDetailInfo(DETECTION_ACSM_S * pstAcsmp);

#endif


