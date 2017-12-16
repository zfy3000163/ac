
#include <detection/common/detection_com.h>
#include <detection/common/detection_pub.h>
#include <detection/common/detection_debug.h>
#include <detection/common/detection_common_mem.h>
#include <detection/common/detection_common_acsmx2.h>
#include <detection/common/detection_common_bnfasearch.h>


static ULONG g_ulMaxMemory = 0;
static ULONG g_ulSverbose=0;

typedef struct stAcsmSummary
{
      ULONG    ulNumStates;
      ULONG    ulNumTransitions;
      DETECTION_ACSM2_S stAcsm;

}DETECTION_ACSM_SUMMARY_S;

static DETECTION_ACSM_SUMMARY_S g_stAppSummary={0,0}; 

/*
** Case Translation Table 
*/ 
static UCHAR g_ucXlatcase[256];

static
VOID
Detection_Common_InitXlatcase(VOID) 
{
  ULONG i;
  for (i = 0; i < 256; i++)
    {
      g_ucXlatcase[i] = (UCHAR)ToUpper(i);
    }
}
/*
*    Case Conversion
*/ 
static 
inline 
VOID
Detection_Common_ConvertCaseEx (UCHAR *pucD, UCHAR *pucS, ULONG ulM) 
{
  ULONG i;
#ifdef XXXX
  ULONG ulN;
  ulN   = ulM & 3;
  ulM >>= 2;

  for (i = 0; i < ulM; i++ )
    {
      pucD[0] = g_ucXlatcase[ pucS[0] ];
      pucD[2] = g_ucXlatcase[ pucS[2] ];
      pucD[1] = g_ucXlatcase[ pucS[1] ];
      pucD[3] = g_ucXlatcase[ pucS[3] ];
      pucD+=4;
      pucS+=4;
    }

  for (i=0; i < ulN; i++)
    {
      pucD[i] = g_ucXlatcase[ pucS[i] ];
    }
#else
  for (i=0; i < ulM; i++)
    {
      pucD[i] = g_ucXlatcase[ pucS[i] ];
    }

#endif
}



/*
*    Case Conversion
*/ 
static VOID *
Detection_Common_ACMalloc (ULONG ulN) 
{
  VOID *pvP = NULL;
  pvP = (ULONG*)Detection_GlobalMalloc(ulN, DETECTION_MEM_TAG);
  if (pvP)
    {
        g_ulMaxMemory += ulN;
    }
  return pvP;
}


/*
*    Case Conversion
*/ 
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
*    Simple DETECTION_QUEUE_S Structure
*/ 
typedef struct _queue
{
  DETECTION_QNODE_S * pstHead, *pstTail;
  ULONG ulCount;
}
DETECTION_QUEUE_S;

/*
*   Initialize the queue
*/ 

static VOID
Detection_Common_QueueInit (DETECTION_QUEUE_S * pstQueue) 
{
  pstQueue->pstHead = pstQueue->pstTail = 0;
  pstQueue->ulCount= 0;
}

/*
*  Find a State in the queue
*/ 

static ULONG
Detection_Common_QueueFind (DETECTION_QUEUE_S * pstQueue, ULONG ulState) 
{
  DETECTION_QNODE_S * pstQ = NULL;
  pstQ = pstQueue->pstHead;
  while( pstQ )
  {
      if( pstQ->ulState == ulState ) return 1;
      pstQ = pstQ->pstNext;
  }
  return 0;
}

/*
*  Add Tail Item to queue (FiFo/LiLo)
*/ 
static VOID
Detection_Common_QueueAdd (DETECTION_QUEUE_S * pstQueue, ULONG ulState) 
{
  DETECTION_QNODE_S * pstQ = NULL;

  if( Detection_Common_QueueFind( pstQueue, ulState ) ) return;  

  if (pstQueue->pstHead == NULL)
  {
      pstQ = pstQueue->pstTail = pstQueue->pstHead = (DETECTION_QNODE_S *) Detection_Common_ACMalloc (sizeof (DETECTION_QNODE_S));
      if(pstQ == NULL)
      {
           DETECTION_DEBUG(DETECTION_DEBUGTYPE_ERR, "Detection_Common_QueueAdd:ACSM-No Memory!\n");
           return ;
      }
      pstQ->ulState = ulState;
      pstQ->pstNext = 0;
  }
  else
  {
      pstQ = (DETECTION_QNODE_S *) Detection_Common_ACMalloc (sizeof (DETECTION_QNODE_S));
      if(pstQ == NULL)
      {
           DETECTION_DEBUG(DETECTION_DEBUGTYPE_ERR, "Detection_Common_QueueAdd:ACSM-No Memory!\n");
           return ;
      }
      pstQ->ulState = ulState;
      pstQ->pstNext = 0;
      pstQueue->pstTail->pstNext = pstQ;
      pstQueue->pstTail = pstQ;
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
  DETECTION_QNODE_S * pstQ = NULL;
  if (pstQueue->pstHead)
  {
      pstQ       = pstQueue->pstHead;
      ulState   = pstQ->ulState;
      pstQueue->pstHead = pstQueue->pstHead->pstNext;
      pstQueue->ulCount--;

      if( pstQueue->pstHead  == NULL)
      {
          pstQueue->pstTail = 0;
          pstQueue->ulCount = 0;
      }
      Detection_Common_ACFree (pstQ);
  }
  return ulState;
}


/*
*   Return items in the queue
*/ 
static ULONG
Detection_Common_QueueCount (DETECTION_QUEUE_S * pstQueue) 
{
  return pstQueue->ulCount;
}


/*
*  Free the queue
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
*  Get Next State-NFA
*/
static 
ULONG Detection_Common_ListGetNextState( DETECTION_ACSM2_S * pstAcsm, ULONG ulState, ULONG ulInput )
{
  DETECTION_TRANS_NODE_S * pstTransNode = pstAcsm->ppstAcsmTransTable[ulState];

  while( pstTransNode )
  {
    if( pstTransNode->ulKey == ulInput )
    {
        return pstTransNode->ulNextState;
    }
    pstTransNode=pstTransNode->pstNext;
  }

  if( ulState == 0 ) return 0;
  
  return DETECTION_COMMON_ACSM_FAIL_STATE2; /* Fail ulState ??? */
}

/*
*  Get Next State-DFA
*/
static 
ULONG Detection_Common_ListGetNextState2( DETECTION_ACSM2_S * pstAcsm, ULONG ulState, ULONG ulInput )
{
  DETECTION_TRANS_NODE_S * pstTransNode = pstAcsm->ppstAcsmTransTable[ulState];

  while( pstTransNode )
  {
    if( pstTransNode->ulKey == ulInput )
    {
      return pstTransNode->ulNextState;
    }
    pstTransNode = pstTransNode->pstNext;
  }

  return 0; /* default ulState */
}
/*
*  Put Next State - Head insertion, and transition updates
*/

static 
ULONG Detection_Common_ListPutNextState( DETECTION_ACSM2_S * pstAcsm, ULONG ulState, ULONG ulInput, ULONG ulNextState )
{
  DETECTION_TRANS_NODE_S * pstTransNode = NULL;
  DETECTION_TRANS_NODE_S * pstTnew = NULL;

 // printf("   List_PutNextState: ulState=%d, ulInput='%c', ulNextState=%d\n",ulState,ulInput,ulNextState);


  /* Check if the transition already exists, if so just update the ulNextState */
  pstTransNode = pstAcsm->ppstAcsmTransTable[ulState];
  while( pstTransNode )
  {
    if( pstTransNode->ulKey == ulInput )  /* transition already exists- reset the next ulState */
    {
        pstTransNode->ulNextState = ulNextState;
        return 0;    
    }
    pstTransNode=pstTransNode->pstNext;
  }

  /* Definitely not an existing transition - add it */
  pstTnew = (DETECTION_TRANS_NODE_S*)Detection_Common_ACMalloc(sizeof(DETECTION_TRANS_NODE_S));
  if( pstTnew  == NULL) return 1; 

  pstTnew->ulKey        = ulInput;
  pstTnew->ulNextState = ulNextState;
  pstTnew->pstNext       = 0;

  pstTnew->pstNext = pstAcsm->ppstAcsmTransTable[ulState];
  pstAcsm->ppstAcsmTransTable[ulState] = pstTnew; 

  pstAcsm->ulAcsmNumTrans++;
  
  return 0; 
}
/*
*   Free the entire transition table 
*/

static 
ULONG Detection_Common_ListFreeTransTable( DETECTION_ACSM2_S * pstAcsm )
{
  ULONG i;
  DETECTION_TRANS_NODE_S * pstTransNode = NULL, *pstP = NULL;

  if( pstAcsm->ppstAcsmTransTable == NULL ) return 0;

  for(i=0;i< pstAcsm->ulAcsmMaxStates;i++)
  {  
     pstTransNode = pstAcsm->ppstAcsmTransTable[i];

     while( pstTransNode )
     {
       pstP = pstTransNode->pstNext;
       Detection_GlobalFree(pstTransNode);      
       pstTransNode = pstP;
       g_ulMaxMemory -= sizeof(DETECTION_TRANS_NODE_S);
     }
   }

   Detection_GlobalFree(pstAcsm->ppstAcsmTransTable);

   g_ulMaxMemory -= sizeof(VOID*) * pstAcsm->ulAcsmMaxStates;

   pstAcsm->ppstAcsmTransTable = 0;

   return 0;
}



/*
*    Print the trans table to stdout
*/
static 
ULONG Detection_Common_ListPrintTransTable( DETECTION_ACSM2_S * pstAcsm )
{
  ULONG i;
  DETECTION_TRANS_NODE_S * pstTransNode = NULL;
  DETECTION_ACSM_PATTERN2_S * pucPatrn = NULL;

  if( pstAcsm->ppstAcsmTransTable  == NULL) return 0;

   DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"Print Transition Table- %lu active states\n",pstAcsm->ulAcsmNumStates);

  for(i=0;i< pstAcsm->ulAcsmNumStates;i++)
  {  
     pstTransNode = pstAcsm->ppstAcsmTransTable[i];

	 /*
     DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"ulState %3d: ",i);
	 */

     while( pstTransNode )
     { 
       if( IsPrint(pstTransNode->ulKey) )
       {
          DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"%3c->%-5d\t",pstTransNode->ulKey,pstTransNode->ulNextState);
       }
       else
       {
          DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"%3d->%-5d\t",pstTransNode->ulKey,pstTransNode->ulNextState);
       }

       pstTransNode = pstTransNode->pstNext;
     }

     pucPatrn =pstAcsm->ppstAcsmMatchList[i];

     while( pucPatrn )
     {
		 /*
          DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"%.*s ",pucPatrn->ulN,pucPatrn->pucPatrn);
 		*/
         pucPatrn = pucPatrn->pstNext;
     }

      DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"\n");
   }
   return 0;
}


/*
*   Converts row of states from list to a full vector format
*/ 
static 
ULONG Detection_Common_ListConvToFull(DETECTION_ACSM2_S * pstAcsm, ulAcstate ulState, ulAcstate * pulFull )
{
    ULONG ulTcnt = 0;
    DETECTION_TRANS_NODE_S * pstTransNode = pstAcsm->ppstAcsmTransTable[ ulState ];

    MemSet(pulFull,0,sizeof(ulAcstate)*pstAcsm->ulAcsmAlphabetSize);
   
    if( pstTransNode == NULL ) return 0;

    while(pstTransNode)
    {
      pulFull[ pstTransNode->ulKey ] = pstTransNode->ulNextState;
      ulTcnt++;
      pstTransNode = pstTransNode->pstNext;
    }
    return ulTcnt;
}

/*
*   Copy a Match List Entry - don't dup the pattern data
*/ 
static DETECTION_ACSM_PATTERN2_S*
Detection_Common_CopyMatchListEntry (DETECTION_ACSM_PATTERN2_S * pstPx) 
{
  DETECTION_ACSM_PATTERN2_S * pstAcsmPattern2 = NULL;

  pstAcsmPattern2 = (DETECTION_ACSM_PATTERN2_S *) Detection_Common_ACMalloc (sizeof (DETECTION_ACSM_PATTERN2_S));
  if(pstAcsmPattern2 == NULL)
  {
       DETECTION_DEBUG(DETECTION_DEBUGTYPE_ERR, "CopyMatchListEntry:ACSM-No Memory!\n");
       return NULL;
  }

  MemCpy (pstAcsmPattern2, pstPx, sizeof (DETECTION_ACSM_PATTERN2_S));

  pstAcsmPattern2->pstNext = 0;

  return pstAcsmPattern2;
}

/*
*  Check if a pattern is in the list already,
*  validate it using the 'id' field. This must be unique
*  for every pattern.
*/
/*
static
ULONG FindMatchListEntry (DETECTION_ACSM2_S * pstAcsm, ULONG ulState, DETECTION_ACSM_PATTERN2_S * pstPx) 
{
  DETECTION_ACSM_PATTERN2_S * p;

  p = pstAcsm->ppstAcsmMatchList[ulState];
  while( p )
  {
    if( p->id == pstPx->id ) return 1;
    p = p->next;
  }    

  return 0;
}
*/

static VOID
Detection_Common_AddMatchListEntry (DETECTION_ACSM2_S * pstAcsm, ULONG ulState, DETECTION_ACSM_PATTERN2_S * pstPx) 
{
  DETECTION_ACSM_PATTERN2_S * pstAcsmPattern2 = NULL;

  pstAcsmPattern2 = (DETECTION_ACSM_PATTERN2_S *) Detection_Common_ACMalloc (sizeof (DETECTION_ACSM_PATTERN2_S));
  if(pstAcsmPattern2 == NULL)
  {
       DETECTION_DEBUG(DETECTION_DEBUGTYPE_ERR, "Detection_Common_AddMatchListEntry:ACSM-No Memory!\n");
       return ;
  }

  MemCpy (pstAcsmPattern2, pstPx, sizeof (DETECTION_ACSM_PATTERN2_S));

  pstAcsmPattern2->pstNext = pstAcsm->ppstAcsmMatchList[ulState];

  pstAcsm->ppstAcsmMatchList[ulState] = pstAcsmPattern2;
}


static VOID
Detection_Common_AddPatternStates (DETECTION_ACSM2_S * pstAcsm, DETECTION_ACSM_PATTERN2_S * pstAcsmPattern2) 
{
  ULONG            ulState = 0, pstNext = 0, ulN = 0;
  UCHAR *pucPattern = NULL;

  ulN       = pstAcsmPattern2->ulN;
  pucPattern = pstAcsmPattern2->pucPatrn;
  ulState   = 0;

  /*
  if(g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS," Begin AddPatternStates: ulAcsmNumStates=%lu\n",pstAcsm->ulAcsmNumStates);
  if(g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"    adding '%.*s', ulNocase=%lu\n", ulN,pstAcsmPattern2->pucPatrn, pstAcsmPattern2->ulNocase );
  */
  
  /* 
  *  Match up pattern with existing states
  */ 
  for (; ulN > 0; pucPattern++, ulN--)
  {
      if(g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS," find char='%c'\n", *pucPattern );

      pstNext = Detection_Common_ListGetNextState(pstAcsm,ulState,*pucPattern);
      if (pstNext == DETECTION_COMMON_ACSM_FAIL_STATE2 || pstNext == 0)
      {
             break;
      }
      ulState = pstNext;
  }
  
  /*
  *   Add new states for the rest of the pattern bytes, 1 ulState per byte
  */ 
  for (; ulN > 0; pucPattern++, ulN--)
  {
      if(g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS," add char='%c' ulState=%lu NumStates=%lu\n", *pucPattern, ulState, pstAcsm->ulAcsmNumStates );

      pstAcsm->ulAcsmNumStates++; 
      Detection_Common_ListPutNextState(pstAcsm,ulState,*pucPattern,pstAcsm->ulAcsmNumStates);
      ulState = pstAcsm->ulAcsmNumStates;
  }

  Detection_Common_AddMatchListEntry (pstAcsm, ulState, pstAcsmPattern2 );

  if(g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS," End AddPatternStates: ulAcsmNumStates=%lu\n",pstAcsm->ulAcsmNumStates);
}

/*
*   Build A Non-Deterministic Finite Automata
*   The keyword ulState table must already be built, via AddPatternStates().
*/ 
static VOID
Detection_Common_BuildNFA (DETECTION_ACSM2_S * pstAcsm) 
{
    ULONG ulR = 0, ulS = 0, i;
    DETECTION_QUEUE_S stQ, *pstQueue = &stQ;
    ulAcstate     * pulFailState = pstAcsm->pulAcsmFailState;
    DETECTION_ACSM_PATTERN2_S ** ppstMatchList = pstAcsm->ppstAcsmMatchList;
    DETECTION_ACSM_PATTERN2_S  * pstMlist = NULL,* pstPx = NULL;
  
    /* Init a Queue */ 
    Detection_Common_QueueInit (pstQueue);

  
    /* Add the ulState 0 transitions 1st, the states at ulDepth 1, fail to ulState 0 */ 
    for (i = 0; i < pstAcsm->ulAcsmAlphabetSize; i++)
    {
      ulS = Detection_Common_ListGetNextState2(pstAcsm,0,i);
      if( ulS )
      {
          Detection_Common_QueueAdd (pstQueue, ulS);
          pulFailState[ulS] = 0;
      }
    }
  
    /* Build the fail ulState successive layer of transitions */ 
    while (Detection_Common_QueueCount (pstQueue) > 0)
    {
        ulR = Detection_Common_QueueRemove (pstQueue);
      
        /* Find Final States for any Failure */ 
        for (i = 0; i < pstAcsm->ulAcsmAlphabetSize; i++)
        {
           ULONG ulFs = 0, pstNext = 0;

           ulS = Detection_Common_ListGetNextState(pstAcsm,ulR,i);

           if( ulS != DETECTION_COMMON_ACSM_FAIL_STATE2 )
           { 
                Detection_Common_QueueAdd (pstQueue, ulS);
         
                ulFs = pulFailState[ulR];

                /* 
                 *  Locate the pstNext valid ulState for 'i' starting at ulFs 
                 */ 
                while( (pstNext=Detection_Common_ListGetNextState(pstAcsm,ulFs,i)) == DETECTION_COMMON_ACSM_FAIL_STATE2 )
                {
                  ulFs = pulFailState[ulFs];
                }

                /*
                 *  Update 'ulS' ulState failure ulState to point to the pstNext valid ulState
                 */ 
                pulFailState[ulS] = pstNext;

                /*
                 *  Copy 'pstNext'states MatchList to 's' states MatchList, 
                 *  we copy them so each list can be AC_FREE'd later,
                 *  else we could just manipulate pointers to fake the copy.
                 */ 
                for( pstMlist = ppstMatchList[pstNext]; 
                     pstMlist;
                     pstMlist = pstMlist->pstNext)
                {
                    pstPx = Detection_Common_CopyMatchListEntry (pstMlist);
                    if(!pstPx)
                    {
                        return ;
                    }

                    /* Insert at front of ppstMatchList */ 
                    pstPx->pstNext = ppstMatchList[ulS];
                    ppstMatchList[ulS] = pstPx;
                }
           }
        }
    }
  
    /* Clean up the queue */ 
    Detection_Common_QueueFree (pstQueue);

    if( g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"End Build_NFA: NumStates=%lu\n",pstAcsm->ulAcsmNumStates);
}

/*
*   Build Deterministic Finite Automata from the NFA
*/ 
static VOID
Detection_Common_ConvertNFAToDFA (DETECTION_ACSM2_S * pstAcsm) 
{
    ULONG i, ulR, ulS, cFailState = 0;
    DETECTION_QUEUE_S  stQ, *pstQueue = &stQ;
    ulAcstate * pulFailState = pstAcsm->pulAcsmFailState;
  
    /* Init a Queue */
    Detection_Common_QueueInit (pstQueue);
  
    /* Add the ulState 0 transitions 1st */
    for(i=0; i<pstAcsm->ulAcsmAlphabetSize; i++)
    {
      ulS = Detection_Common_ListGetNextState(pstAcsm,0,i);
      if ( ulS != 0 )
      {
        Detection_Common_QueueAdd (pstQueue, ulS);
      }
    }
  
    /* Start building the pstNext layer of transitions */
    while( Detection_Common_QueueCount(pstQueue) > 0 )
    {
        ulR = Detection_Common_QueueRemove(pstQueue);
      
        /* Process this states layer */ 
        for (i = 0; i < pstAcsm->ulAcsmAlphabetSize; i++)
        {
          ulS = Detection_Common_ListGetNextState(pstAcsm,ulR,i);

          if( ulS != DETECTION_COMMON_ACSM_FAIL_STATE2 && ulS!= 0)
          {
             Detection_Common_QueueAdd (pstQueue, ulS);
          }
          else
          {
              cFailState = Detection_Common_ListGetNextState(pstAcsm,pulFailState[ulR],i);

              if( cFailState != 0 && cFailState != DETECTION_COMMON_ACSM_FAIL_STATE2 )
              {
                  Detection_Common_ListPutNextState(pstAcsm,ulR,i,cFailState);
              }
          }
        }
    }
  
    /* Clean up the queue */ 
    Detection_Common_QueueFree (pstQueue);

    if(g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"End Convert_NFA_To_DFA: NumStates=%lu\n",pstAcsm->ulAcsmNumStates);

}

/*
*
*  Convert a row lists for the ulState table to a full vector format
*
*/
static ULONG 
Detection_Common_ConvListToFull(DETECTION_ACSM2_S * pstAcsm) 
{
  ULONG         ulK= 0;
  ulAcstate * pulP = NULL;
  ulAcstate ** ppulNextState = pstAcsm->ppulAcsmNextState;

  for(ulK=0;ulK<pstAcsm->ulAcsmMaxStates;ulK++)
  {
    pulP = Detection_Common_ACMalloc( sizeof(ulAcstate) * (pstAcsm->ulAcsmAlphabetSize+2) );
    if(pulP == NULL) return 1;

    Detection_Common_ListConvToFull( pstAcsm, (ulAcstate)ulK, (ulAcstate*)pulP+2 );

    pulP[0] = DETECTION_COMMON_ACF_FULL;
    pulP[1] = 0; /* no matches yet */

    ppulNextState[ulK] = pulP; /* now we have a full format row vector  */
  }

  return 0;
}

/*
*   Convert DFA memory usage from list based storage to a sparse-row storage.  
*
*   The Sparse format allows each row to be either full or sparse formatted.  If the sparse row has
*   too many transitions, performance or space may dictate that we use the standard full formatting 
*   for the row.  More than 5 or 10 transitions per ulState ought to really whack performance. So the  
*   user can specify the max ulState transitions per ulState allowed in the sparse format. 
*
*   Standard Full Matrix Format
*   ---------------------------
*   ULONG ** ppulNextState ( 1st index is row/ulState, 2nd index is column=event/ulInput)
*
*   example:   
*  
*        events -> a b c d e f g h i j k l m n o p
*   states 
*     N            1 7 0 0 0 3 0 0 0 0 0 0 0 0 0 0
*        
*   Sparse Format, each row : Words     Value
*                            1-1       fmt(0-full,1-sparse,2-banded,3-sparsebands)
*                            2-2       bool match flag (indicates this ulState has pattern matches)
*                            3-3       sparse ulState ulCount ( # of ulInput/pstNext-ulState pairs )
*                            4-3+2*cnt 'ulInput,pstNext-ulState' pairs... each sizof(ULONG)
*     
*   above example case yields:
*     Full Format:    0, 1 7 0 0 0 3 0 0 0 0 0 0 0 0 0 0 ...
*     Sparse format:  1, 3, 'a',1,'b',7,'f',3  - uses 2+2*ntransitions (non-default transitions)
*/
static ULONG 
Detection_Common_ConvFullDFAToSparse(DETECTION_ACSM2_S * pstAcsm) 
{
  ULONG          ulCnt= 0, ulM=0, ulK, i;
  ulAcstate  * pulP = NULL, ulState = 0, ulMaxStates=0;
  ulAcstate ** ppulNextState = pstAcsm->ppulAcsmNextState;
  ulAcstate    ulFull[DETECTION_COMMON_MAX_ALPHABET_SIZE];

  for(ulK=0;ulK<pstAcsm->ulAcsmMaxStates;ulK++)
  {
    ulCnt=0;

    Detection_Common_ListConvToFull(pstAcsm, (ulAcstate)ulK, ulFull );

    for (i = 0; i < pstAcsm->ulAcsmAlphabetSize; i++)
    {
       ulState = ulFull[i];
       if( ulState != 0 && ulState != DETECTION_COMMON_ACSM_FAIL_STATE2 ) ulCnt++;
    }

    if( ulCnt > 0 ) ulMaxStates++;

    if( ulK== 0 || ulCnt > pstAcsm->ulAcsmSparseMaxRowNodes )
    {
       pulP = Detection_Common_ACMalloc(sizeof(ulAcstate)*(pstAcsm->ulAcsmAlphabetSize+2) );
       if(pulP == NULL) return 1;

       pulP[0] = DETECTION_COMMON_ACF_FULL;
       pulP[1] = 0;
       MemCpy(&pulP[2],ulFull,pstAcsm->ulAcsmAlphabetSize*sizeof(ulAcstate));       
    }
    else
    {
       pulP = Detection_Common_ACMalloc(sizeof(ulAcstate)*(3+2*ulCnt));
       if(pulP == NULL) return 1;

       ulM      = 0;
       pulP[ulM++] = DETECTION_COMMON_ACF_SPARSE;   
       pulP[ulM++] = 0;   /* no matches */
       pulP[ulM++] = ulCnt;

       for(i = 0; i < pstAcsm->ulAcsmAlphabetSize ; i++)
       {
         ulState = ulFull[i];  
         if( ulState != 0 && ulState != DETECTION_COMMON_ACSM_FAIL_STATE2 )
         {
           pulP[ulM++] = i;
           pulP[ulM++] = ulState;
         }
      }
    }

    ppulNextState[ulK] = pulP; /* now we are a sparse formatted ulState transition array  */
  }

  return 0;
}
/*
    Convert Full matrix to Banded row format.

    Word     values
    1        2  -> banded
    2        n  number of values
    3        i  index of 1st value (0-256)
    4 - 3+n  pstNext-ulState values at each index

*/

static ULONG 
Detection_Common_ConvFullDFAToBanded(DETECTION_ACSM2_S * pstAcsm) 
{
  LONG lFirst = -1, lLast = 0;
  ulAcstate * pulP = NULL, ulState = 0, ulFull[DETECTION_COMMON_MAX_ALPHABET_SIZE];
  ulAcstate ** ppulNextState = pstAcsm->ppulAcsmNextState;
  LONG       ulCnt,ulM=0,ulK=0,i;

  for(ulK=0;ulK<pstAcsm->ulAcsmMaxStates;ulK++)
  {
    ulCnt=0;

    Detection_Common_ListConvToFull(pstAcsm, (ulAcstate)ulK, (ulAcstate*)ulFull );

    lFirst=-1;
    lLast =-2;

    for (i = 0; i < pstAcsm->ulAcsmAlphabetSize; i++)
    {
       ulState = ulFull[i];

       if( ulState !=0 && ulState != DETECTION_COMMON_ACSM_FAIL_STATE2 )
       {
           if( lFirst < 0 ) lFirst = i;
           lLast = i;
       }
    }

    /* calc band width */
    ulCnt= lLast - lFirst + 1;

    pulP = Detection_Common_ACMalloc(sizeof(ulAcstate)*(4+ulCnt));

    if(pulP == NULL) return 1;

    ulM      = 0;
    pulP[ulM++] = DETECTION_COMMON_ACF_BANDED;   
    pulP[ulM++] = 0;   /* no matches */
    pulP[ulM++] = ulCnt;
    pulP[ulM++] = lFirst;

    for(i = lFirst; i <= lLast; i++)
    {
       pulP[ulM++] = ulFull[i]; 
    }

    ppulNextState[ulK] = pulP; /* now we are a banded formatted ulState transition array  */
  }

  return 0;
}

/*
*   Convert full matrix to Sparse Band row format.
*
*   pstNext  - Full formatted row of pstNext states
*   asize - size of alphabet
*   ulZcnt - max number of zeros in a run of zeros in any given band.
*
*  Word Values
*  1    DETECTION_COMMON_ACF_SPARSEBANDS
*  2    number of bands
*  repeat 3 - 5+ ....once for each band in this row.
*  3    number of items in this band*  4    start index of this band
*  5-   pstNext-ulState values in this band...
*/

static 
ULONG Detection_Common_CalcSparseBands( ulAcstate * pstNext, ULONG * pulBegin, ULONG * pulEnd, ULONG ulAsize, ULONG ulZmax )
{
   ULONG i, ulNbands = 0,ulZcnt = 0,ulLast=0;
   ulAcstate ulState = 0;

   ulNbands=0;
   for( i=0; i<ulAsize; i++ )
   {
       ulState = pstNext[i];
       if( ulState !=0 && ulState != DETECTION_COMMON_ACSM_FAIL_STATE2 )
       {
           pulBegin[ulNbands] = i;
           ulZcnt=0;
           for( ; i< ulAsize; i++ )
           {
              ulState = pstNext[i];
              if( ulState ==0 || ulState == DETECTION_COMMON_ACSM_FAIL_STATE2 ) 
              {
                  ulZcnt++;
                  if( ulZcnt > ulZmax ) break;
              }
              else 
              {
                  ulZcnt=0;
                  ulLast = i;                  
              }
           }
           pulEnd[ulNbands++] = ulLast;
       }
   }
   return ulNbands;
}


/*
*   Sparse Bands
*
*   Row Format:
*   Word
*   1    SPARSEBANDS format indicator
*   2    bool indicates a pattern match in this ulState
*   3    number of sparse bands
*   4    number of elements in this band
*   5    start index of this band
*   6-   list of next states
*   
*   m    number of elements in this band
*   m+1  start index of this band
*   m+2- list of next states
*/
 
static  ULONG       ulBand_begin[DETECTION_COMMON_MAX_ALPHABET_SIZE] ={0};
static  ULONG       ulBand_end[DETECTION_COMMON_MAX_ALPHABET_SIZE]={0};
static  ulAcstate ulFull[DETECTION_COMMON_MAX_ALPHABET_SIZE]={0};
 
static ULONG 
Detection_Common_ConvFullDFAToSparseBands(DETECTION_ACSM2_S * pstAcsm) 
{
  ulAcstate  * pulP = NULL;
  ulAcstate ** ppulNextState = pstAcsm->ppulAcsmNextState;
  ULONG          ulCnt,ulM,ulK,i,ulZcnt=pstAcsm->ulAcsmSparseMaxZcnt;
  
  ULONG       ulNbands=0,j;

  memset( ulBand_begin, 0x00, sizeof(ULONG) * DETECTION_COMMON_MAX_ALPHABET_SIZE );
  memset( ulBand_end, 0x00, sizeof(ULONG) * DETECTION_COMMON_MAX_ALPHABET_SIZE );
  memset( ulFull, 0x00, sizeof(ulAcstate) * DETECTION_COMMON_MAX_ALPHABET_SIZE );

 
  for(ulK=0;ulK<pstAcsm->ulAcsmMaxStates;ulK++)
  {
    ulCnt=0;

    Detection_Common_ListConvToFull(pstAcsm, (ulAcstate)ulK, ulFull );

    ulNbands = Detection_Common_CalcSparseBands( ulFull, ulBand_begin, ulBand_end, pstAcsm->ulAcsmAlphabetSize, ulZcnt );
    
    /* calc band width space*/
    ulCnt = 3;
    for(i=0;i<ulNbands;i++)
    {
       ulCnt += 2;
       ulCnt += ulBand_end[i] - ulBand_begin[i] + 1;

       /*printf("ulState %d: sparseband %d,  first=%d, ulLast=%d, ulCnt=%d\n",ulK,i,ulBand_begin[i],ulBand_end[i],ulBand_end[i]-ulBand_begin[i]+1); */
    }

    pulP = Detection_Common_ACMalloc(sizeof(ulAcstate)*(ulCnt));

    if(pulP==NULL) 
	{
		return 1;
	}

    ulM      = 0;
    pulP[ulM++] = DETECTION_COMMON_ACF_SPARSEBANDS;   
    pulP[ulM++] = 0; /* no matches */
    pulP[ulM++] = ulNbands;

    for( i=0;i<ulNbands;i++ )
    {
      pulP[ulM++] = ulBand_end[i] - ulBand_begin[i] + 1;  /* # states in this band */
      pulP[ulM++] = ulBand_begin[i];   /* start index */
 
      for( j=ulBand_begin[i]; j<=ulBand_end[i]; j++ )
      {
         if (j >= DETECTION_COMMON_MAX_ALPHABET_SIZE)
		 {	
             return 1;
		 }

         pulP[ulM++] = ulFull[j];  /* some states may be ulState zero */
      }
    }

    ppulNextState[ulK] = pulP; /* now we are a sparse-banded formatted ulState transition array  */
  }

  return 0;
}

VOID 
Detection_Common_PrintDFAMatchList( DETECTION_ACSM2_S * pstAcsm, ULONG ulState )
{
     DETECTION_ACSM_PATTERN2_S * pstMlist = NULL;

     for (pstMlist = pstAcsm->ppstAcsmMatchList[ulState]; 
          pstMlist;
          pstMlist = pstMlist->pstNext)
     {

         //DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"%.*s ", pstMlist->ulN, pstMlist->pucPatrn);
     }
}
/*
*
*/

static VOID
Detection_Common_PrintDFA(DETECTION_ACSM2_S * pstAcsm) 
{
  ULONG  ulK,i;
  ulAcstate * pulP = NULL, ulState=0, ulN=0, ulFmt=0, ulIndex=0, ulNb=0, ulBmatch=0;
  ulAcstate ** ppulNextState = pstAcsm->ppulAcsmNextState;

   DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"Print DFA - %lu active states\n",pstAcsm->ulAcsmNumStates);

  for(ulK=0;ulK<pstAcsm->ulAcsmNumStates;ulK++)
  {
    pulP   = ppulNextState[ulK];

    if( pulP==NULL ) continue;

    ulFmt = *pulP++; 

    ulBmatch = *pulP++;
  
    // DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"ulState %3d, ulFmt=%lu: ",ulK,ulFmt);

    if( ulFmt ==DETECTION_COMMON_ACF_SPARSE )
    {
       ulN = *pulP++; 
       for( ; ulN>0; ulN--, pulP+=2 )
       { 
         if( IsPrint(pulP[0]) )
         {
          DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"%3c->%-5d\t",pulP[0],pulP[1]);
         }
         else
         {
          DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"%3d->%-5d\t",pulP[0],pulP[1]);
         }
      }
    }
    else if( ulFmt ==DETECTION_COMMON_ACF_BANDED )
    {

       ulN = *pulP++; 
       ulIndex = *pulP++;

       for( ; ulN>0; ulN--, pulP++ )
       { 
         if( IsPrint(pulP[0]) )
        {
          DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"%3c->%-5d\t",ulIndex++,pulP[0]);
        } 
        else
        {
          DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"%3d->%-5d\t",ulIndex++,pulP[0]);
        }
      }
    }
    else if( ulFmt ==DETECTION_COMMON_ACF_SPARSEBANDS )
    {
       ulNb    = *pulP++; 
       for(i=0;i<ulNb;i++)
       {
         ulN     = *pulP++;
         ulIndex = *pulP++;
         for( ; ulN>0; ulN--, pulP++ )
         { 
           if( IsPrint(ulIndex) )
           {
            DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"%3c->%-5d\t",ulIndex++,pulP[0]);
           }
           else
           {
            DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"%3d->%-5d\t",ulIndex++,pulP[0]);
           }
         }
       }
    }
    else if( ulFmt == DETECTION_COMMON_ACF_FULL ) 
    {

      for( i=0; i<pstAcsm->ulAcsmAlphabetSize; i++ )
      {
         ulState = pulP[i];

         if( ulState != 0 && ulState != DETECTION_COMMON_ACSM_FAIL_STATE2 )
         {
           if( IsPrint(i) )
           {
         //     DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"%3c->%-5d\t",i,ulState);
           }
           else
           {
          //    DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"%3d->%-5d\t",i,ulState);
           }
         }
      }
    }

    Detection_Common_PrintDFAMatchList( pstAcsm, ulK);

     DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"\n");
  }
}






/*
*   Add a pattern to the list of patterns for this ulState machine
*
*/ 

ULONG Detection_Common_AcsmAddPattern2 (DETECTION_ACSM2_S * pstAcsm2, UCHAR *pstPat, ULONG ulN, ULONG ulNocase,
        LONG lOffset, LONG lDepth, VOID * pvId, ULONG ulIid) 
{
  DETECTION_ACSM_PATTERN2_S * pstList = NULL;

  pstList = (DETECTION_ACSM_PATTERN2_S *) Detection_Common_ACMalloc (sizeof (DETECTION_ACSM_PATTERN2_S));
  if(pstList==NULL)
  {
       DETECTION_DEBUG(DETECTION_DEBUGTYPE_ERR, "acsmAddPattern:ACSM-No Memory!\n");
       return 1;
  }
  pstList->pucPatrn = (UCHAR *) Detection_Common_ACMalloc ( ulN );
  if(pstList==NULL)
  {
       DETECTION_DEBUG(DETECTION_DEBUGTYPE_ERR, "acsmAddPattern:ACSM-No Memory!\n");
       return 1;
  }

  Detection_Common_ConvertCaseEx(pstList->pucPatrn, pstPat, ulN);
  
  pstList->pucCasepatrn = (UCHAR *) Detection_Common_ACMalloc ( ulN );
  if(pstList==NULL)
  {
       DETECTION_DEBUG(DETECTION_DEBUGTYPE_ERR, "acsmAddPattern:ACSM-No Memory!\n");
       return 1;
  }
  MemCpy (pstList->pucCasepatrn, pstPat, ulN);

  pstList->ulN      = ulN;
  pstList->ulNocase = ulNocase;
  pstList->lOffset = lOffset;
  pstList->lDepth  = lDepth;
  pstList->pvId     = pvId;
  pstList->ulIid    = ulIid;

  pstList->pstNext     = pstAcsm2->pstAcsmPatterns;
  pstAcsm2->pstAcsmPatterns = pstList;
  pstAcsm2->ulNumPatterns++;

  return 0;
}

/*
*  Copy a boolean match flag ULONG ppulNextState table, for caching purposes.
*/

static
VOID Detection_Common_AcsmUpdateMatchStates( DETECTION_ACSM2_S * pstAcsm )
{
  ulAcstate        ulState = 0;
  ulAcstate     ** ppulNextState = pstAcsm->ppulAcsmNextState;
  DETECTION_ACSM_PATTERN2_S ** ppstMatchList = pstAcsm->ppstAcsmMatchList;

  for( ulState=0; ulState<pstAcsm->ulAcsmNumStates; ulState++ )
  {
     if( ppstMatchList[ulState] )
     {
         ppulNextState[ulState][1] = 1;
     }
     else 
     {
         ppulNextState[ulState][1] = 0;
     }
  }
}

/*
*   Compile State Machine - NFA or DFA and Full or Banded or Sparse or SparseBands
*/ 

ULONG Detection_Common_AcsmCompile2 (DETECTION_ACSM2_S * pstAcsm) 
{
    ULONG               ulK;
    DETECTION_ACSM_PATTERN2_S    * pstList = NULL;
  
    /* Count number of states */ 
    for (pstList = pstAcsm->pstAcsmPatterns; pstList != NULL; pstList = pstList->pstNext)
    {
     pstAcsm->ulAcsmMaxStates += pstList->ulN;
     /* pstAcsm->ulAcsmMaxStates += pstList->n*2; if we handle case in the table */
    }
    pstAcsm->ulAcsmMaxStates++; /* one extra */

    /* Alloc a List based State Transition table */
    pstAcsm->ppstAcsmTransTable =(DETECTION_TRANS_NODE_S**) Detection_Common_ACMalloc(sizeof(DETECTION_TRANS_NODE_S*) * pstAcsm->ulAcsmMaxStates );
    if(pstAcsm->ppstAcsmTransTable==NULL)
    {
        DETECTION_DEBUG(DETECTION_DEBUGTYPE_ERR, "acsmCompile:ACSM-No Memory!\n");
        return 1;
    }


    if(g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"ACSMX-Max Memory-TransTable Setup: %lu bytes, %lu states, %lu active states\n", g_ulMaxMemory,pstAcsm->ulAcsmMaxStates,pstAcsm->ulAcsmNumStates);

    /* Alloc a failure table - this has a failure ulState, and a match list for each ulState */
    pstAcsm->pulAcsmFailState =(ulAcstate*) Detection_Common_ACMalloc(sizeof(ulAcstate) * pstAcsm->ulAcsmMaxStates );
    if(pstAcsm->pulAcsmFailState==NULL)
    {
        DETECTION_DEBUG(DETECTION_DEBUGTYPE_ERR, "acsmCompile:ACSM-No Memory!\n");
        return 1;
    }


    /* Alloc a MatchList table - this has a lis tof pattern matches for each ulState, if any */
    pstAcsm->ppstAcsmMatchList=(DETECTION_ACSM_PATTERN2_S**) Detection_Common_ACMalloc(sizeof(DETECTION_ACSM_PATTERN2_S*) * pstAcsm->ulAcsmMaxStates );
    if(pstAcsm->ppstAcsmMatchList==NULL)
    {
        DETECTION_DEBUG(DETECTION_DEBUGTYPE_ERR, "acsmCompile:ACSM-No Memory!\n");
        return 1;
    }


    if(g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"ACSMX-Max Memory- MatchList Table Setup: %lu bytes, %lu states, %lu active states\n", g_ulMaxMemory,pstAcsm->ulAcsmMaxStates,pstAcsm->ulAcsmNumStates);
 
    /* Alloc a separate ulState transition table == in ulState 's' due to event 'ulK', transition to 'next' ulState */
    pstAcsm->ppulAcsmNextState=(ulAcstate**)Detection_Common_ACMalloc( pstAcsm->ulAcsmMaxStates * sizeof(ulAcstate*) );
    if(pstAcsm->ppulAcsmNextState==NULL)
    {
        DETECTION_DEBUG(DETECTION_DEBUGTYPE_ERR, "acsmCompile-ppulNextState:ACSM-No Memory!\n");
        return 1;
    }

    for (ulK = 0; ulK < pstAcsm->ulAcsmMaxStates; ulK++)
    {
      pstAcsm->ppulAcsmNextState[ulK]=(ulAcstate*)0;
    }

    if(g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"ACSMX-Max Memory-Table Setup: %lu bytes, %lu states, %lu active states\n", g_ulMaxMemory,pstAcsm->ulAcsmMaxStates,pstAcsm->ulAcsmNumStates);
     
    /* Initialize ulState zero as a branch */ 
    pstAcsm->ulAcsmNumStates = 0;
  
    /* Add the 0'th ulState,  */
    //pstAcsm->ulAcsmNumStates++; 
 
    /* Add each Pattern to the State Table - This forms a keywords ulState table  */ 
    for (pstList = pstAcsm->pstAcsmPatterns; pstList != NULL; pstList = pstList->pstNext)
    {
        Detection_Common_AddPatternStates (pstAcsm, pstList);
    }

    pstAcsm->ulAcsmNumStates++;

    if(g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"ACSMX-Max Trie List Memory : %lu bytes, %lu states, %lu active states\n", 
                 g_ulMaxMemory,pstAcsm->ulAcsmMaxStates,pstAcsm->ulAcsmNumStates);

    if(g_ulSverbose)Detection_Common_ListPrintTransTable( pstAcsm );
  
    if( pstAcsm->ulAcsmFSA == DETECTION_COMMON_FSA_DFA || pstAcsm->ulAcsmFSA == DETECTION_COMMON_FSA_NFA )
    {
      /* Build the NFA */
      if(g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"Build_NFA\n");

      Detection_Common_BuildNFA (pstAcsm);

      if(g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"NFA-Trans-Nodes: %lu\n",pstAcsm->ulAcsmNumTrans);
      if(g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"ACSMX-Max NFA List Memory  : %lu bytes, %lu states / %lu active states\n", g_ulMaxMemory,pstAcsm->ulAcsmMaxStates,pstAcsm->ulAcsmNumStates);

      if(g_ulSverbose)Detection_Common_ListPrintTransTable( pstAcsm );
    }
  
    if( pstAcsm->ulAcsmFSA == DETECTION_COMMON_FSA_DFA )
    {
       /* Convert the NFA to a DFA */ 
       if(g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"Convert_NFA_To_DFA\n");

       Detection_Common_ConvertNFAToDFA (pstAcsm);
  
       if(g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"DFA-Trans-Nodes: %lu\n",pstAcsm->ulAcsmNumTrans);
       if(g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"ACSMX-Max NFA-DFA List Memory  : %lu bytes, %lu states / %lu active states\n", g_ulMaxMemory,pstAcsm->ulAcsmMaxStates,pstAcsm->ulAcsmNumStates);

       if(g_ulSverbose)Detection_Common_ListPrintTransTable( pstAcsm );
    }

    /*
    *
    *  Select Final Transition Table Storage Mode
    *
    */

    if(g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"Converting Transition Lists -> Transition table, ulFmt=%lu\n",pstAcsm->ulAcsmFormat);

    if( pstAcsm->ulAcsmFormat == DETECTION_COMMON_ACF_SPARSE )
    {
      /* Convert DFA Full matrix to a Sparse matrix */
      if( Detection_Common_ConvFullDFAToSparse(pstAcsm) )
          return 1;
   
      if(g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"ACSMX-Max Memory-Sparse: %lu bytes, %lu states, %lu active states\n", g_ulMaxMemory,pstAcsm->ulAcsmMaxStates,pstAcsm->ulAcsmNumStates);
      if(g_ulSverbose)Detection_Common_PrintDFA(pstAcsm);
    }

    else if( pstAcsm->ulAcsmFormat == DETECTION_COMMON_ACF_BANDED )
    {
      /* Convert DFA Full matrix to a Sparse matrix */
      if( Detection_Common_ConvFullDFAToBanded(pstAcsm) )
          return 1;
   
       if(g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"ACSMX-Max Memory-banded: %lu bytes, %lu states, %lu active states\n", g_ulMaxMemory,pstAcsm->ulAcsmMaxStates,pstAcsm->ulAcsmNumStates);
       if(g_ulSverbose)Detection_Common_PrintDFA(pstAcsm);
    }

    else if( pstAcsm->ulAcsmFormat == DETECTION_COMMON_ACF_SPARSEBANDS )
    {
      /* Convert DFA Full matrix to a Sparse matrix */
      if( Detection_Common_ConvFullDFAToSparseBands(pstAcsm) )
          return 1;
   
       if(g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"ACSMX-Max Memory-sparse-bands: %lu bytes, %lu states, %lu active states\n", g_ulMaxMemory,pstAcsm->ulAcsmMaxStates,pstAcsm->ulAcsmNumStates);
       if(g_ulSverbose)Detection_Common_PrintDFA(pstAcsm);
    }
    else if( ( pstAcsm->ulAcsmFormat == DETECTION_COMMON_ACF_FULL ) ||
             ( pstAcsm->ulAcsmFormat == DETECTION_COMMON_ACF_FULLQ ) )
    {
      if( Detection_Common_ConvListToFull( pstAcsm ) )
            return 1;

       if(g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"ACSMX-Max Memory-Full: %lu bytes, %lu states, %lu active states\n", g_ulMaxMemory,pstAcsm->ulAcsmMaxStates,pstAcsm->ulAcsmNumStates);
       if(g_ulSverbose)Detection_Common_PrintDFA(pstAcsm);
    }

    Detection_Common_AcsmUpdateMatchStates( pstAcsm ); /* load boolean match flags into ulState table */

    /* Free up the Table Of Transition Lists */
    Detection_Common_ListFreeTransTable( pstAcsm ); 

    if(g_ulSverbose) DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"ACSMX-Max Memory-Final: %lu bytes, %lu states, %lu active states\n", g_ulMaxMemory,pstAcsm->ulAcsmMaxStates,pstAcsm->ulAcsmNumStates);

    /* For now -- show this info */
    /*
    *  acsmPrintInfo( pstAcsm );
    */


    /* Accrue Summary State Stats */
    g_stAppSummary.ulNumStates      += pstAcsm->ulAcsmNumStates;
    g_stAppSummary.ulNumTransitions += pstAcsm->ulAcsmNumTrans;

    MemCpy( &g_stAppSummary.stAcsm, pstAcsm, sizeof(DETECTION_ACSM2_S));
    
    return 0;
}


/*
*   Free all memory
*/ 

  VOID
Detection_Common_AcsmFree2 (DETECTION_ACSM2_S * pstAcsm) 
{
  ULONG i;
  DETECTION_ACSM_PATTERN2_S * pstMlist= NULL, *pstIlist= NULL, *pstList= NULL;
  for (i = 0; i < pstAcsm->ulAcsmMaxStates; i++)
  {
      pstMlist = pstAcsm->ppstAcsmMatchList[i];

      while (pstMlist)
      {
          pstIlist = pstMlist;
          pstMlist = pstMlist->pstNext;
          if (pstAcsm->pFuncUserfree && pstIlist->pvId)
              pstAcsm->pFuncUserfree(pstIlist->pvId);
          Detection_Common_ACFree (pstIlist);
      }
      Detection_Common_ACFree(pstAcsm->ppulAcsmNextState[i]);
  }
  for (pstList = pstAcsm->pstAcsmPatterns; pstList; )
  {
      DETECTION_ACSM_PATTERN2_S *pstTmpPlist = pstList->pstNext;
      Detection_Common_ACFree(pstList->pucPatrn);
      Detection_Common_ACFree(pstList->pucCasepatrn);
      Detection_Common_ACFree(pstList);
      pstList = pstTmpPlist;
  }
  Detection_Common_ACFree(pstAcsm->ppulAcsmNextState);

  Detection_Common_ACFree(pstAcsm->pulAcsmFailState);
  Detection_Common_ACFree(pstAcsm->ppstAcsmMatchList);

  Detection_Common_ACFree(pstAcsm);
}

ULONG Detection_Common_AcsmPatternCount2 ( DETECTION_ACSM2_S * pstAcsm )
{
    return pstAcsm->ulNumPatterns;
}



ULONG Detection_Common_AcsmPrintDetailInfo2( DETECTION_ACSM2_S * pstAcsm2 )
{

    return 0;
}

/*
 *   Global sumary of all info and all ulState machines built during this run
 *   This feeds off of the ulLast pattern groupd built within snort,
 *   all groups use the same format, ulState size, etc..
 *   Combined with accrued stats, we get an average picture of things.
 */

ULONG  Detection_Common_AcsmPrintSummaryInfo2(ULONG ulExecID )
{
	
    CHAR * sf[]={
      "Full",
      "Sparse",
      "Banded",
      "Sparse-Bands",
      "Full-Q"
    };

    CHAR * fsa[]={
      "TRIE",
      "NFA",
      "DFA"
    };
	

    DETECTION_ACSM2_S * pstAcsm2 = &g_stAppSummary.stAcsm;

    if( g_stAppSummary.ulNumStates ==0)
        return 0;
    
	 
     DETECTION_PARSER_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "+--[Pattern Matcher:Aho-Corasick Summary]----------------------\n");
     DETECTION_PARSER_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "| Alphabet Size    : %lu Chars\n",pstAcsm2->ulAcsmAlphabetSize);
     DETECTION_PARSER_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "| Sizeof State     : %lu bytes\n",(ULONG)(sizeof(ULONG)));
     DETECTION_PARSER_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "| Storage Format   : %s \n",sf[ pstAcsm2->ulAcsmFormat ]);
     DETECTION_PARSER_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "| Num States       : %lu\n",g_stAppSummary.ulNumStates);
     DETECTION_PARSER_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "| Num Transitions  : %lu\n",g_stAppSummary.ulNumTransitions);
     DETECTION_PARSER_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "| State Density    : %lu%%\n",(ULONG)100.0*g_stAppSummary.ulNumTransitions/(g_stAppSummary.ulNumStates*pstAcsm2->ulAcsmAlphabetSize));
     DETECTION_PARSER_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "| Finite Automatum : %s\n", fsa[pstAcsm2->ulAcsmFSA]);
	 
     if( g_ulMaxMemory < 1024*1024 )
     {
         DETECTION_PARSER_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "| Memory           : %luKbytes\n", g_ulMaxMemory/1024 );
     }
     else
     {
         DETECTION_PARSER_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "| Memory           : %luMbytes\n", g_ulMaxMemory/(1024*1024) );
     }
     DETECTION_PARSER_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "+-------------------------------------------------------------\n");


    return 0;
}

