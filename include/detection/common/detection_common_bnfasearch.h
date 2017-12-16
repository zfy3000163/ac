
  
#ifndef __DETECTION_COMMON_BNFASEARCH_H__
#define __DETECTION_COMMON_BNFASEARCH_H__

#include <detection/common/detection_mod.h>

#define DETECTION_COMMON_BNFA_MAX_ALPHABET_SIZE          256     
#define DETECTION_COMMON_BNFA_FAIL_STATE                 0xffffffff
#define DETECTION_COMMON_BNFA_SPARSE_LINEAR_SEARCH_LIMIT 6

#define DETECTION_COMMON_BNFA_SPARSE_MAX_STATE           0x00ffffff
#define DETECTION_COMMON_BNFA_SPARSE_COUNT_SHIFT         24
#define DETECTION_COMMON_BNFA_SPARSE_VALUE_SHIFT         24

#define DETECTION_COMMON_BNFA_SPARSE_MATCH_BIT           0x80000000
#define DETECTION_COMMON_BNFA_SPARSE_FULL_BIT            0x40000000
#define DETECTION_COMMON_BNFA_SPARSE_COUNT_BITS          0x3f000000
#define DETECTION_COMMON_BNFA_SPARSE_MAX_ROW_TRANSITIONS 0x3f

typedef   ULONG   ulBnfaState;

/*
*   Internal Pattern Representation
*/
typedef struct stBnfaPattern 
{      
    struct stBnfaPattern * pstNext;

    UCHAR       * pucCasepatrn; /* case specific */
    ULONG                   ulPatternLen;         /* pattern len */ 
    ULONG                   ulNocase;    /* nocase flag */
    VOID                * pvUserdata;  /* ptr to users pattern data/info  =PMX*/

} DETECTION_BNFAPATTERN_S;

/*
*  List format transition node
*/
typedef struct stBnfaTransNode
{
  ulBnfaState               ulKey;           
  ulBnfaState               ulNextState;    
  struct stBnfaTransNode * pstNext; 

} DETECTION_BNFA_TRANSNODE_S;

/*
*  List format patterns 
*/
typedef struct stBnfaMatchNode 
{
  void                     * pvData;
  struct stBnfaMatchNode * pstNext; 

} DETECTION_BNFA_MATCHNODE_S;

/*
*  Final storage type for the state transitions
*/
enum {
  DETECTION_COMMON_BNFA_FULL,
  DETECTION_COMMON_BNFA_SPARSE
};

enum { 
  DETECTION_COMMON_BNFA_PER_PAT_CASE,
  DETECTION_COMMON_BNFA_CASE,
  DETECTION_COMMON_BNFA_NOCASE
};

/*
*   Aho-Corasick State Machine Struct 
*/

#define DETECTION_COMMON_MAX_INQ 32 
typedef struct stbnfa 
{
	ULONG                ulBnfaMethod;
	ULONG                ulBnfaCaseMode;
	ULONG                ulBnfaFormat;
	ULONG                ulBnfaAlphabetSize;
	ULONG                ulBnfaOpt;

	ULONG                ulBnfaPatternCnt;
	DETECTION_BNFAPATTERN_S     * pstBnfaPatterns;

	ULONG                ulBnfaMaxStates;
	ULONG                ulBnfaNumStates;
	ULONG		     ulBnfaNumTrans;
	ULONG                ulBnfaMatchStates;

	DETECTION_BNFA_TRANSNODE_S  ** ppstBnfaTransTable;

	ulBnfaState       ** ppulBnfaNextState;
	DETECTION_BNFA_MATCHNODE_S  ** ppstBnfaMatchList;
	ulBnfaState       * ppulBnfaFailState;

	ulBnfaState       * ppulBnfaTransList;
   	ULONG                ulBnfaForceFullZeroState;

	ULONG 			   ulBnfaMemory;
	ULONG 			   ulPatMemory;
	ULONG 			   ulListMemory;
	ULONG 			   ulQueueMemory;
	ULONG 			   ulNextstateMemory;
	ULONG 			   ulFailstateMemory;
	ULONG 			   ulMatchlistMemory;

       VOID               (*pvFuncUserfree)(void *);
       ULONG ulInq;
       ULONG ulInqFlush;
       VOID * pvQ[DETECTION_COMMON_MAX_INQ];
}DETECTION_BNFA_S;
#define SSP_IsPrint(a) ((a >=' ')&&(a <= '~'))  

VOID Detection_Common_BnfaPrintInfo( DETECTION_BNFA_S * pstBnfa );
VOID Detection_Common_BnfaPrintSummary( ULONG ulExecID );
ULONG Detection_Common_BnfaPatternCount( DETECTION_BNFA_S * pstBnfa);
DETECTION_SIGINFO_S * Detection_Common_BnfaSearch(    DETECTION_BNFA_S * pstBnfa, UCHAR *pucTx, ULONG ulN,
            DETECTION_SIGINFO_S * (*plFuncMatch) ( VOID * pvId, ULONG ulIndex, VOID *pvData), 
            VOID *pvData, ULONG ulSindex, ULONG* pulCurrent_state );
ULONG Detection_Common_BnfaCompile (DETECTION_BNFA_S * pstBnfa) ;
ULONG Detection_Common_BnfaAddPattern (DETECTION_BNFA_S * pstBnfa,  UCHAR *pucPat,  ULONG ulN, ULONG ulNocase,VOID * pvUserdata );
VOID Detection_Common_BnfaFree (DETECTION_BNFA_S * pstBnfa) ;
VOID Detection_Common_BnfaSetOpt(DETECTION_BNFA_S  * pstP, ULONG ulFlag);
DETECTION_BNFA_S * Detection_Common_BnfaNew(VOID (*pvFuncUserFree)(VOID *p));

#endif

