#include <detection/common/detection_com.h>
#include <detection/common/detection_pub.h>
#include <detection/common/detection_debug.h>
#include <detection/common/detection_common_mem.h>
#include <detection/common/detection_common_acsmx.h>


#ifdef IS_DETECTION_DEBUG_ON
static ULONG g_ulMaxMemory = 0;
#endif

static VOID *
Detection_Common_ACMalloc (ULONG ulN) 
{
  VOID *pvP = NULL;
  pvP = (ULONG*)Detection_GlobalMalloc(ulN, DETECTION_MEM_TAG);
  if(!pvP )
#ifdef IS_DETECTION_DEBUG_ON
       if (pvP)
       g_ulMaxMemory += ulN;
#endif
  MemSet(pvP, 0, ulN);

  return pvP;
}


static VOID
Detection_Common_ACFree (VOID *pvP) 
{
  if (pvP)
    Detection_GlobalFree (pvP);
}


/*
*    Simple DETECTION_QUEUE_S NODE
*/ 
typedef struct stQnode
{
    ULONG ulState;
    struct stQnode *pstNext;
}
DETECTION_QNODE_S;

/*
*    Simple QUEUE Structure
*/ 
typedef struct stQueue
{
    DETECTION_QNODE_S * pstHead, *pstTail;
    ULONG ulCount;
}
DETECTION_QUEUE_S;

/*
*
*/ 
static VOID
Detection_Common_QueueInit (DETECTION_QUEUE_S * pstQueue) 
{
    pstQueue->pstHead = pstQueue->pstTail = 0;
    pstQueue->ulCount = 0;
}


/*
*  Add Tail Item to queue
*/ 
static VOID
Detection_Common_QueueAdd (DETECTION_QUEUE_S * pstQueue, ULONG ulState) 
{
  DETECTION_QNODE_S * pstQnode = NULL;
  if (pstQueue->pstHead == NULL)
    {
      pstQnode = pstQueue->pstTail = pstQueue->pstHead = (DETECTION_QNODE_S *) Detection_Common_ACMalloc (sizeof (DETECTION_QNODE_S));
      if(!pstQnode)
      {
           DETECTION_DEBUG(DETECTION_DEBUGTYPE_ERR, "Detection_Common_QueueAdd:ACSM-No Memory!\n");
           return ;
      }
      pstQnode->ulState = ulState;
      pstQnode->pstNext = 0;
    }
  else
    {
      pstQnode = (DETECTION_QNODE_S *) Detection_Common_ACMalloc (sizeof (DETECTION_QNODE_S));
      if(pstQnode == NULL)
      {
           DETECTION_DEBUG(DETECTION_DEBUGTYPE_ERR, "queue_add:ACSM-No Memory!\n");
           return ;
      }
      pstQnode->ulState = ulState;
      pstQnode->pstNext = 0;
      pstQueue->pstTail->pstNext = pstQnode;
      pstQueue->pstTail = pstQnode;
    }
  pstQueue->ulCount++;
}


/*
*  Remove Head Item from queue
*/ 
static ULONG
Detection_Common_QueueRemove (DETECTION_QUEUE_S * pstQueue) 
{
  ULONG ulState = 0;
  DETECTION_QNODE_S * pstQnode = NULL;
  if (pstQueue->pstHead)
    {
      pstQnode = pstQueue->pstHead;
      ulState = pstQnode->ulState;
      pstQueue->pstHead = pstQueue->pstHead->pstNext;
      pstQueue->ulCount--;
      if (pstQueue->pstHead == NULL)
      {
          pstQueue->pstTail = 0;
          pstQueue->ulCount = 0;
      }
      Detection_Common_ACFree (pstQnode);
    }
  return ulState;
}

static ULONG
Detection_Common_QueueCount (DETECTION_QUEUE_S * pstQueue) 
{
  return pstQueue->ulCount;
}


/*
*
*/ 
static VOID
Detection_Common_QueueFree (DETECTION_QUEUE_S * pstQueue) 
{
  while (Detection_Common_QueueCount (pstQueue))
    {
      Detection_Common_QueueRemove (pstQueue);
    }
}


/*
** Case Translation Table 
*/ 
static UCHAR g_ucXlatcase[256];

 static VOID
Detection_Common_InitXlatcase (VOID) 
{
  ULONG i;
  for (i = 0; i < 256; i++)
    {
      g_ucXlatcase[i] = (UCHAR)ToUpper (i);
    }
}


static inline VOID
Detection_Common_ConvertCaseEx (UCHAR *pucD, UCHAR *pucS, ULONG ulM) 
{
    ULONG i;
    for (i = 0; i < ulM; i++)
    {
      pucD[i] = g_ucXlatcase[pucS[i]];
    }
}



static DETECTION_ACSM_PATTERN_S *
Detection_Common_CopyMatchListEntry (DETECTION_ACSM_PATTERN_S * pstPx) 
{
  DETECTION_ACSM_PATTERN_S * pstAcsmp = NULL;
  pstAcsmp = (DETECTION_ACSM_PATTERN_S *) Detection_Common_ACMalloc (sizeof (DETECTION_ACSM_PATTERN_S));
  if(pstAcsmp == NULL)
  {
       DETECTION_DEBUG(DETECTION_DEBUGTYPE_ERR, "CopyMatchListEntry:ACSM-No Memory!\n");
       return NULL;
  }
  MemCpy (pstAcsmp, pstPx, sizeof (DETECTION_ACSM_PATTERN_S));
  pstAcsmp->pstNext = 0;
  return pstAcsmp;
}


/*
*  Add a pattern to the list of patterns terminated at this state.
*  Insert at front of list.
*/ 
static VOID
Detection_Common_AddMatchListEntry (DETECTION_ACSM_S * pstAcsm, ULONG ulState, DETECTION_ACSM_PATTERN_S * pstPx) 
{
  DETECTION_ACSM_PATTERN_S * pstAcsmp = NULL;
  pstAcsmp = (DETECTION_ACSM_PATTERN_S *) Detection_Common_ACMalloc (sizeof (DETECTION_ACSM_PATTERN_S));
    if(pstAcsmp == NULL)
  {
       DETECTION_DEBUG(DETECTION_DEBUGTYPE_ERR, "AddMatchListEntry:ACSM-No Memory!\n");
       return ;
  }
  MemCpy (pstAcsmp, pstPx, sizeof (DETECTION_ACSM_PATTERN_S));
  pstAcsmp->pstNext = pstAcsm->pstAcsmStateTable[ulState].pstMatchList;
  pstAcsm->pstAcsmStateTable[ulState].pstMatchList = pstAcsmp;
}


/* 
   Add Pattern States
*/ 
static VOID
Detection_Common_AddPatternStates (DETECTION_ACSM_S * pstAcsm, DETECTION_ACSM_PATTERN_S * pstAcsmp) 
{
  UCHAR *pucPattern = NULL;
  ULONG ulState=0, ulNext = 0;
  ULONG n = pstAcsmp->ulN;
  pucPattern = pstAcsmp->pucPatrn;
  
    /* 
     *  Match up pattern with existing states
     */ 
    for (; n > 0; pucPattern++, n--)
    {
      ulNext = pstAcsm->pstAcsmStateTable[ulState].ulNextState[*pucPattern];
      if (ulNext == DETECTION_DETECT_ACSM_FAIL_STATE)
        break;
      ulState = ulNext;
    }
  
    /*
     *   Add new states for the rest of the pattern bytes, 1 ulState per byte
     */ 
    for (; n > 0; pucPattern++, n--)
    {
      pstAcsm->ulAcsmNumStates++;
      pstAcsm->pstAcsmStateTable[ulState].ulNextState[*pucPattern] = pstAcsm->ulAcsmNumStates;
      ulState = pstAcsm->ulAcsmNumStates;
    }
    
    Detection_Common_AddMatchListEntry (pstAcsm, ulState, pstAcsmp);
}


/*
*   Build Non-Deterministic Finite Automata
*/ 
static VOID
Detection_Common_BuildNFA (DETECTION_ACSM_S * pstAcsm) 
{
  ULONG ulR = 0, ulS = 0;
  ULONG i;
  DETECTION_QUEUE_S stQueue , *pstQueue = &stQueue;
  DETECTION_ACSM_PATTERN_S * pstMlist= NULL;
  DETECTION_ACSM_PATTERN_S * pstPx= NULL;
  
    /* Init a Queue */ 
    Detection_Common_QueueInit (pstQueue);
  
    /* Add the state 0 transitions 1st */ 
    for (i = 0; i < DETECTION_DETECT_ALPHABET_SIZE; i++)
    {
      ulS = pstAcsm->pstAcsmStateTable[0].ulNextState[i];
      if (ulS)
      {

        Detection_Common_QueueAdd (pstQueue, ulS);

        pstAcsm->pstAcsmStateTable[ulS].ulFailState = 0;
      }
    }
  
    /* Build the fail state transitions for each valid state */ 
    while (Detection_Common_QueueCount (pstQueue) > 0)
    {
      ulR = Detection_Common_QueueRemove (pstQueue);
      
      /* Find Final States for any Failure */ 
      for (i = 0; i < DETECTION_DETECT_ALPHABET_SIZE; i++)
      {
        ULONG ulFs = 0, ulNext = 0;
        if ((ulS = pstAcsm->pstAcsmStateTable[ulR].ulNextState[i]) != DETECTION_DETECT_ACSM_FAIL_STATE)
        {
            Detection_Common_QueueAdd (pstQueue, ulS);

            ulFs = pstAcsm->pstAcsmStateTable[ulR].ulFailState;

          /* 
           *  Locate the ulNext valid state for 'i' starting at s 
           */ 
          while ((ulNext=pstAcsm->pstAcsmStateTable[ulFs].ulNextState[i]) ==
                 DETECTION_DETECT_ACSM_FAIL_STATE)
          {
            ulFs = pstAcsm->pstAcsmStateTable[ulFs].ulFailState;
          }

          /*
           *  Update 's' state failure state to point to the ulNext valid state
           */ 
          pstAcsm->pstAcsmStateTable[ulS].ulFailState = ulNext;

          /*
           *  Copy 'ulNext'states pstMatchList to 's' states pstMatchList, 
           *  we copy them so each list can be Detection_Common_ACFree'd later,
           *  else we could just manipulate pointers to fake the copy.
           */ 
          for (pstMlist  = pstAcsm->pstAcsmStateTable[ulNext].pstMatchList; 
               pstMlist != NULL ;
               pstMlist  = pstMlist->pstNext)
          {
              pstPx = Detection_Common_CopyMatchListEntry (pstMlist);

              if( pstPx == NULL)
              {
                DETECTION_DEBUG(DETECTION_DEBUGTYPE_ERR, "*** Out of memory Initializing Aho Corasick in acsmx.c ****");
                return ;
              }

              /* Insert at front of pstMatchList */ 
              pstPx->pstNext = pstAcsm->pstAcsmStateTable[ulS].pstMatchList;
              pstAcsm->pstAcsmStateTable[ulS].pstMatchList = pstPx;
          }
        }
      }
    }
  
    /* Clean up the queue */ 
    Detection_Common_QueueFree (pstQueue);
}


/*
*   Build Deterministic Finite Automata from NFA
*/ 
static VOID
Detection_Common_ConvertNFAToDFA (DETECTION_ACSM_S * pstAcsm) 
{
  ULONG ulR = 0, ulS = 0;
  ULONG i = 0;
  DETECTION_QUEUE_S stQueue, *pstQueue = &stQueue;
  
    /* Init a Queue */ 
    Detection_Common_QueueInit (pstQueue);
  
    /* Add the state 0 transitions 1st */ 
    for (i = 0; i < DETECTION_DETECT_ALPHABET_SIZE; i++)
    {
      ulS = pstAcsm->pstAcsmStateTable[0].ulNextState[i];
      if (ulS)
      {
           Detection_Common_QueueAdd (pstQueue, ulS);
      }
    }
  
    /* Start building the pstNext layer of transitions */ 
    while (Detection_Common_QueueCount (pstQueue) > 0)
    {
      ulR = Detection_Common_QueueRemove (pstQueue);
      
      /* State is a branch state */ 
      for (i = 0; i < DETECTION_DETECT_ALPHABET_SIZE; i++)
      {
        if ((ulS = pstAcsm->pstAcsmStateTable[ulR].ulNextState[i]) != DETECTION_DETECT_ACSM_FAIL_STATE)
        {
            Detection_Common_QueueAdd (pstQueue, ulS);
        }
        else
        {
            pstAcsm->pstAcsmStateTable[ulR].ulNextState[i] =
            pstAcsm->pstAcsmStateTable[pstAcsm->pstAcsmStateTable[ulR].ulFailState].ulNextState[i];
        }
      }
    }
  
    /* Clean up the pstQueue */ 
    Detection_Common_QueueFree (pstQueue);
}



DETECTION_ACSM_S * Detection_Common_AcsmNew () 
{
  DETECTION_ACSM_S * pstAcsm = NULL;
  Detection_Common_InitXlatcase ();
  pstAcsm = (DETECTION_ACSM_S *) Detection_Common_ACMalloc (sizeof (DETECTION_ACSM_S));
  if( pstAcsm  == NULL)
  {
     DETECTION_DEBUG(DETECTION_DEBUGTYPE_ERR, "acsmNew:ACSM-No Memory!\n");
     return NULL;
  }
  
  return pstAcsm;
}


/*
*   Add a pattern to the list of patterns for this state machine
*/ 
ULONG
Detection_Common_AcsmAddPattern (DETECTION_ACSM_S * pstAcsm, UCHAR *pucPat, ULONG ulN, ULONG ulNocase,
            LONG lOffset, LONG lDepth, VOID * pvId, ULONG ulIid) 
{
  DETECTION_ACSM_PATTERN_S * pstList = NULL;
  pstList = (DETECTION_ACSM_PATTERN_S *) Detection_Common_ACMalloc (sizeof (DETECTION_ACSM_PATTERN_S));
  if( pstList  == NULL)
  {
     DETECTION_DEBUG(DETECTION_DEBUGTYPE_ERR, "acsmAddPattern:ACSM-No Memory!\n");
     return 1;
  }
  pstList->pucPatrn = (UCHAR *) Detection_Common_ACMalloc (ulN);
  Detection_Common_ConvertCaseEx (pstList->pucPatrn, pucPat, ulN);
  pstList->pucCasepatrn = (UCHAR *) Detection_Common_ACMalloc (ulN);
  MemCpy (pstList->pucCasepatrn, pucPat, ulN);
  pstList->ulN = ulN;
  pstList->ulNocase = ulNocase;
  pstList->lOffset = lOffset;
  pstList->lDepth = lDepth;
  pstList->pvId = pvId;
  pstList->ulIid = ulIid;
  pstList->pstNext = pstAcsm->pstAcsmPatterns;
  pstAcsm->pstAcsmPatterns = pstList;
  pstAcsm->ulNumPatterns++;
  return 0;
}
    

/*
*   Compile State Machine
*/ 
ULONG Detection_Common_AcsmCompile (DETECTION_ACSM_S * pstAcsm) 
{
    ULONG i, k;
    DETECTION_ACSM_PATTERN_S * pstList = NULL;
  
    /* Count number of states */ 
    pstAcsm->ulAcsmMaxStates = 1;
    for (pstList = pstAcsm->pstAcsmPatterns; pstList != NULL; pstList = pstList->pstNext)
    {
        pstAcsm->ulAcsmMaxStates += pstList->ulN;
    }
    pstAcsm->pstAcsmStateTable =
        (DETECTION_ACSM_STATETABLE_S *) Detection_Common_ACMalloc (sizeof (DETECTION_ACSM_STATETABLE_S) *
                                        pstAcsm->ulAcsmMaxStates);
   if( pstAcsm->pstAcsmStateTable == NULL )
   {
      DETECTION_DEBUG(DETECTION_DEBUGTYPE_ERR, "acsmCompile:ACSM-No Memory!\n");
      return 1;
   }

    /* Initialize state zero as a branch */ 
    pstAcsm->ulAcsmNumStates = 0;

    /* Initialize all States NextStates to FAILED */ 
    for (k = 0; k < pstAcsm->ulAcsmMaxStates; k++)
    {
        for (i = 0; i < DETECTION_DETECT_ALPHABET_SIZE; i++)
        {
            pstAcsm->pstAcsmStateTable[k].ulNextState[i] = DETECTION_DETECT_ACSM_FAIL_STATE;
        }
    }
 
    /* Add each Pattern to the State Table */ 
    for (pstList = pstAcsm->pstAcsmPatterns; pstList != NULL; pstList = pstList->pstNext)
    {
        Detection_Common_AddPatternStates (pstAcsm, pstList);
    }
 
    /* Set all failed state transitions to return to the 0'th state */ 
    for (i = 0; i < DETECTION_DETECT_ALPHABET_SIZE; i++)
    {
        if (pstAcsm->pstAcsmStateTable[0].ulNextState[i] == DETECTION_DETECT_ACSM_FAIL_STATE)
        {
            pstAcsm->pstAcsmStateTable[0].ulNextState[i] = 0;
        }
    }
 
    /* Build the NFA  */ 
    Detection_Common_BuildNFA (pstAcsm);
    /* Convert the NFA to a DFA */ 
    Detection_Common_ConvertNFAToDFA (pstAcsm);
    /*
      printf ("ACSMX-Max Memory: %d bytes, %d states\n", max_memory,
        pstAcsm->ulAcsmMaxStates);
     */

    //Print_DFA( pstAcsm );

    return 0;
}






/*
*   Free all memory
*/
VOID
Detection_Common_AcsmFree (DETECTION_ACSM_S * pstAcsm) 
{
    ULONG i;
    DETECTION_ACSM_PATTERN_S * pstMlist = NULL, *pstIlist = NULL;
    for (i = 0; i < pstAcsm->ulAcsmMaxStates; i++)
    {
        pstMlist = pstAcsm->pstAcsmStateTable[i].pstMatchList;
        while (pstMlist)
        {
            pstIlist = pstMlist;
            pstMlist = pstMlist->pstNext;
            Detection_Common_ACFree (pstIlist);
        }
    }
    Detection_Common_ACFree (pstAcsm->pstAcsmStateTable);
    pstMlist = pstAcsm->pstAcsmPatterns;
    while(pstMlist)
    {
        pstIlist = pstMlist;
        pstMlist = pstMlist->pstNext;
        Detection_Common_ACFree(pstIlist->pucPatrn);
        Detection_Common_ACFree(pstIlist->pucCasepatrn);
        Detection_Common_ACFree(pstIlist);
    }
    Detection_Common_ACFree (pstAcsm);
}


    

ULONG Detection_Common_AcsmPrintDetailInfo(DETECTION_ACSM_S * pstAcsmp)
{
    if(pstAcsmp)
        pstAcsmp = pstAcsmp;
    return 0;
}
