
  
#ifndef __DETECTION_COMMON_ACSMX2_H__
#define __DETECTION_COMMON_ACSMX2_H__


/*
*   DEFINES and Typedef's
*/
#define DETECTION_COMMON_MAX_ALPHABET_SIZE 256     

/*
   FAIL STATE for 1,2,or 4 bytes for state transitions

   Uncomment this define to use 32 bit state values
   #define AC32
*/

/* #define AC32 */

#ifdef AC32

typedef   ULONG   ulAcstate;
#define DETECTION_COMMON_ACSM_FAIL_STATE2  0xffffffff

#else

typedef   USHORT ulAcstate;
#define DETECTION_COMMON_ACSM_FAIL_STATE2 0xffff

#endif

/*
*
*/
typedef 
struct stAcsmPattern2
{      
    struct  stAcsmPattern2 *pstNext;

    UCHAR         *pucPatrn;
    UCHAR         *pucCasepatrn;
    ULONG      ulN;
    ULONG      ulNocase;
    LONG      lOffset;
    LONG      lDepth;
    VOID *     pvId;
    ULONG      ulIid;

} DETECTION_ACSM_PATTERN2_S;

/*
*    transition nodes  - either 8 or 12 bytes
*/
typedef 
struct stTransNode
{

  ulAcstate    ulKey;           /* The character that got us here - sized to keep structure aligned on 4 bytes */
                              /* to better the caching opportunities. A value that crosses the cache line */
                              /* forces an expensive reconstruction, typing this as acstate_t stops that. */
  ulAcstate    ulNextState;    /*  */
  struct stTransNode * pstNext; /* next transition for this state */

} DETECTION_TRANS_NODE_S;


/*
*  User specified final storage type for the state transitions
*/
enum {
  DETECTION_COMMON_ACF_FULL,
  DETECTION_COMMON_ACF_SPARSE,
  DETECTION_COMMON_ACF_BANDED,
  DETECTION_COMMON_ACF_SPARSEBANDS,
  DETECTION_COMMON_ACF_FULLQ
};

/*
*   User specified machine types
*
*   TRIE : Keyword trie
*   NFA  : 
*   DFA  : 
*/
enum {
  DETECTION_COMMON_FSA_TRIE,
  DETECTION_COMMON_FSA_NFA,
  DETECTION_COMMON_FSA_DFA
};

#define DETECTION_COMMON_AC_MAX_INQ 32
typedef struct 
{
    ULONG ulInq;
    ULONG ulInqFlush;
    VOID * pvQ[DETECTION_COMMON_AC_MAX_INQ];
} DETECTION_PMQ_S;

/*
*   Aho-Corasick State Machine Struct - one per group of pattterns
*/
typedef struct stAcsm2
{
  
    ULONG ulAcsmMaxStates;  
    ULONG ulAcsmNumStates;  

    DETECTION_ACSM_PATTERN2_S    * pstAcsmPatterns;
    ulAcstate        * pulAcsmFailState;
    DETECTION_ACSM_PATTERN2_S   ** ppstAcsmMatchList;

    /* list of transitions in each state, this is used to build the nfa & dfa */
    /* after construction we convert to sparse or full format matrix and free */
    /* the transition lists */
    DETECTION_TRANS_NODE_S ** ppstAcsmTransTable;

    ulAcstate ** ppulAcsmNextState;
    ULONG          ulAcsmFormat;
    ULONG          ulAcsmSparseMaxRowNodes;
    ULONG          ulAcsmSparseMaxZcnt;
    
    ULONG          ulAcsmNumTrans;
    ULONG          ulAcsmAlphabetSize;
    ULONG          ulAcsmFSA;
    ULONG          ulNumPatterns;
    VOID         (*pFuncUserfree)(VOID *pvP);
    DETECTION_PMQ_S pstQ;

}DETECTION_ACSM2_S;

ULONG Detection_Common_AcsmPatternCount2 ( DETECTION_ACSM2_S * pstAcsm );
VOID Detection_Common_AcsmPrintInfo2( DETECTION_ACSM2_S * pstAcsm2);
ULONG Detection_Common_AcsmPrintDetailInfo2( DETECTION_ACSM2_S * pstAcsm2 );
ULONG  Detection_Common_AcsmPrintSummaryInfo2(ULONG ulExecID );
VOID Detection_Common_AcsmFree2 (DETECTION_ACSM2_S * pstAcsm) ;
ULONG Detection_Common_AcsmCompile2 (DETECTION_ACSM2_S * pstAcsm) ;
ULONG Detection_Common_AcsmAddPattern2 (DETECTION_ACSM2_S * pstAcsm2, UCHAR *pstPat, ULONG ulN, ULONG ulNocase,
        LONG lOffset, LONG lDepth, VOID * pvId, ULONG ulIid) ;

#endif


