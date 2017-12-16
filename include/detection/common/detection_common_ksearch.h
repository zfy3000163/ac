
  
#ifndef __DETECTION_COMMON_KSEARCH_H__
#define __DETECTION_COMMON_KSEARCH_H__




#define DETECTION_COMMON_ALPHABET_SIZE 256


#ifdef WIN32
#define inline __inline
#endif

#define DETECTION_COMMON_KTRIEMETHOD_STD 0
#define DETECTION_COMMON_KTRIEMETHOD_QUEUE 1

/*
*
*/
typedef struct stKtriepattern {

  struct  stKtriepattern * pstNext;  /* global list of all patterns */
  struct  stKtriepattern * pstMnext;  /* matching list of duplicate keywords */
  
  UCHAR * pucP;    /* no case */
  UCHAR * pucPcase; /* case sensitive */
  ULONG             ulN;
  ULONG             ulNocase;
  VOID          * pvId;

} DETECTION_KTRIEPATTERN_S;


/*
*
*/
typedef struct stKtrienode {

  ULONG     ulEdge; /* character */

  struct  stKtrienode * pstSibling; 
  struct  stKtrienode * pstChild; 

  DETECTION_KTRIEPATTERN_S *pstKeyword; 

} DETECTION_KTRIENODE_S;


#define DETECTION_COMMON_KTRIE_ROOT_NODES     256

#define DETECTION_COMMON_SFK_MAX_INQ 32
typedef struct 
{
    ULONG ulInq;
    ULONG ulInqFlush;
    VOID * pvQ[DETECTION_COMMON_SFK_MAX_INQ];
} DETECTION_SFK_PMQ_S;

/*
*
*/
typedef struct stKtrie{

  DETECTION_KTRIEPATTERN_S * pstPatrn; /* List of patterns, built as they are added */

  
  DETECTION_KTRIENODE_S    * pstRoot[DETECTION_COMMON_KTRIE_ROOT_NODES];  /* KTrie nodes */
 
  ULONG            ulMemory;
  ULONG            ulNchars;
  ULONG            ulNpats;
  ULONG            ulDuplicates;
  ULONG            ulMethod;
  ULONG            ulEndStates; /* should equal npats - duplicates */

  ULONG            ulBcSize;
  USHORT          usBcShift[DETECTION_COMMON_KTRIE_ROOT_NODES];  
  VOID           (*pvFuncUserfree)(VOID *p);
  DETECTION_SFK_PMQ_S        stQ;
 
} DETECTION_KTRIE_S;

DETECTION_KTRIE_S * Detection_Common_KTrieNew(ULONG ulMethod, VOID (*pvFuncUserfree)(VOID *pvP));
VOID Detection_Common_KTrieDelete(DETECTION_KTRIE_S *pstKtrie);
ULONG Detection_Common_KTrieAddPattern( DETECTION_KTRIE_S * pstTs, UCHAR * pucP, ULONG ulN, 
                      ULONG ulNocase, VOID * pvId );
ULONG Detection_Common_KTrieCompile(DETECTION_KTRIE_S * pstKtrie);
ULONG Detection_Common_KTrieMemUsed(VOID) ;
ULONG Detection_Common_KTriePatternCount(DETECTION_KTRIE_S *pstKtrie);
#endif

