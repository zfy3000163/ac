#include <detection/common/detection_com.h>
#include <detection/common/detection_pub.h>
//#include <detection/common/detection_config.h>
//#include <detection/detect/detection_detect_pub.h>
#include <detection/common/detection_mod.h>
#include <detection/common/detection_debug.h>
#include <detection/common/detection_common_mem.h>
#include <detection/common/detection_common_bnfasearch.h>

VOID Detection_Common_BnfaAccumInfo( DETECTION_BNFA_S * pstBnfa );
VOID Detection_Common_BnfaInitSummary( VOID );
/*
 * Used to initialize last ulState, states are limited to 0-16M
 * so this will not conflict.
 */
#define DETECTION_COMMON_LAST_STATE_INIT  0xffffffff

/*
 * Case Translation Table - his guarantees we use 
 * indexed lookups for case conversion
 */ 
static UCHAR g_ucXlatcase[DETECTION_COMMON_BNFA_MAX_ALPHABET_SIZE];
static  VOID Detection_Common_InitXlatcase(VOID) 
{
	ULONG i;
	static ULONG ulFirst=1;

	if( ulFirst ==0) 
		return;

	for(i=0; i<DETECTION_COMMON_BNFA_MAX_ALPHABET_SIZE; i++)
	{
		g_ucXlatcase[i] = (UCHAR)ToUpper(i);
	}

	ulFirst=0;
}

/*
 * Custom memory allocator
 */ 
	static
VOID * Detection_Common_Bnfa_Alloc( ULONG ulN, ULONG * pulM )
{
	VOID * pvP = (ULONG*)Detection_GlobalMalloc(ulN, DETECTION_MEM_TAG);
	if( pvP )
	{
		if(pulM)
		{
			pulM[0] += ulN;
		}
	}
	return pvP;
}
	static
VOID Detection_Common_Bnfa_Free( VOID *pvP, ULONG ulN, ULONG * pulM )
{
	if( pvP )
	{
		Detection_GlobalFree(pvP);
		if(pulM)
		{
			pulM[0] -= ulN;
		}
	}
}
#define DETECTION_COMMON_BNFA_MALLOC(ulN,memory) Detection_Common_Bnfa_Alloc(ulN,&(memory))
#define DETECTION_COMMON_BNFA_FREE(pvP,ulN,memory) Detection_Common_Bnfa_Free(pvP,ulN,&(memory))


/* queue memory traker */
static ULONG g_ulQueueMemory=0;

/*
 *    simple queue node
 */ 
typedef struct stQnode
{
	ULONG ulState;
	struct stQnode *pstNext;
}
DETECTION_QNODE_S;
/*
 *    simple fifo queue structure
 */ 
typedef struct stQueue
{
	DETECTION_QNODE_S * pstHead, *pstTail;
	ULONG ulCount;
	ULONG ulMaxcnt;
}
DETECTION_QUEUE_S;
/*
 *   Initialize the fifo queue
 */ 
	static
VOID Detection_Common_QueueInit (DETECTION_QUEUE_S * pstQueue) 
{
	pstQueue->pstHead = pstQueue->pstTail = 0;
	pstQueue->ulCount= 0;
	pstQueue->ulMaxcnt=0;
}
/*
 *  Add items to pstTail of queue (fifo)
 */ 
	static
ULONG Detection_Common_QueueAdd (DETECTION_QUEUE_S * pstQueue, ULONG ulState) 
{
	DETECTION_QNODE_S * pstQnode= NULL;
	if (pstQueue->pstHead==NULL)
	{
		pstQnode = pstQueue->pstTail = pstQueue->pstHead = (DETECTION_QNODE_S *) DETECTION_COMMON_BNFA_MALLOC (sizeof(DETECTION_QNODE_S),g_ulQueueMemory);
		if(!pstQnode) return 1;
		pstQnode->ulState = ulState;
		pstQnode->pstNext = 0;
	}
	else
	{
		pstQnode = (DETECTION_QNODE_S *) DETECTION_COMMON_BNFA_MALLOC (sizeof(DETECTION_QNODE_S),g_ulQueueMemory);
		pstQnode->ulState = ulState;
		pstQnode->pstNext = 0;
		pstQueue->pstTail->pstNext = pstQnode;
		pstQueue->pstTail = pstQnode;
	}
	pstQueue->ulCount++;

	if( pstQueue->ulCount > pstQueue->ulMaxcnt )
		pstQueue->ulMaxcnt = pstQueue->ulCount;

	return 0;
}
/*
 *  Remove items from pstHead of queue (fifo)
 */ 
	static 
ULONG Detection_Common_QueueRemove (DETECTION_QUEUE_S * pstQueue) 
{
	ULONG ulState = 0;
	DETECTION_QNODE_S * pstQnode= NULL;
	if (pstQueue->pstHead)
	{
		pstQnode       = pstQueue->pstHead;
		ulState   = pstQnode->ulState;
		pstQueue->pstHead = pstQueue->pstHead->pstNext;
		pstQueue->ulCount--;

		if( pstQueue->pstHead==NULL )
		{
			pstQueue->pstTail = 0;
			pstQueue->ulCount = 0;
		}
		DETECTION_COMMON_BNFA_FREE (pstQnode,sizeof(DETECTION_QNODE_S),g_ulQueueMemory);
	}
	return ulState;
}
/*
 *   Return ulCount of items in the queue
 */ 
	static 
ULONG Detection_Common_QueueCount (DETECTION_QUEUE_S * pstQueue) 
{
	return pstQueue->ulCount;
}
/*
 *  Free the queue
 */ 
	static
VOID Detection_Common_QueueFree (DETECTION_QUEUE_S * pstQueue) 
{
	while (Detection_Common_QueueCount (pstQueue))
	{
		Detection_Common_QueueRemove (pstQueue);
	}
}

/*
 *  Get pstNext ulState from transition list
 */
	static 
ULONG Detection_Common_BnfaListGetNextState( DETECTION_BNFA_S * pstBnfa, ULONG ulState, ULONG ulInput )
{
	if ( ulState == 0 ) /* Full set of states  always */
	{
		ulBnfaState * pulBnfaState = (ulBnfaState*)pstBnfa->ppstBnfaTransTable[0];
		if(pulBnfaState==NULL) 
		{
			return 0;
		}
		return pulBnfaState[ulInput];
	}
	else
	{
		DETECTION_BNFA_TRANSNODE_S * pstBnfaTransNode = pstBnfa->ppstBnfaTransTable[ulState];
		while( pstBnfaTransNode )
		{
			if( pstBnfaTransNode->ulKey == (ULONG)ulInput )
			{
				return pstBnfaTransNode->ulNextState;
			}
			pstBnfaTransNode=pstBnfaTransNode->pstNext;
		}
		return DETECTION_COMMON_BNFA_FAIL_STATE; /* Fail ulState */
	}
}

/*
 *  Put pstNext ulState - pstHead insertion, and transition updates
 */
	static 
ULONG Detection_Common_BnfaListPutNextState( DETECTION_BNFA_S * pstBnfa, ULONG ulState, ULONG ulInput, ULONG ulNextState )
{
	if( ulState >= pstBnfa->ulBnfaMaxStates )
	{
		return 1;
	}

	if( ulInput >= pstBnfa->ulBnfaAlphabetSize )
	{
		return 1;
	}

	if( ulState == 0 )
	{
		ulBnfaState * pulBnfaState; 

		pulBnfaState = (ulBnfaState*)pstBnfa->ppstBnfaTransTable[0];
		if( pulBnfaState==NULL )
		{
			pulBnfaState = (ulBnfaState*)DETECTION_COMMON_BNFA_MALLOC(sizeof(ulBnfaState)*pstBnfa->ulBnfaAlphabetSize,pstBnfa->ulListMemory);
			if( pulBnfaState ==NULL) 
			{
				return 1; 
			}

			pstBnfa->ppstBnfaTransTable[0] = (DETECTION_BNFA_TRANSNODE_S*)pulBnfaState;
		}
		if( pulBnfaState[ulInput] )
		{
			pulBnfaState[ulInput] =  ulNextState;
			return 0;
		}
		pulBnfaState[ulInput] =  ulNextState;
	}
	else
	{
		DETECTION_BNFA_TRANSNODE_S * pstBnfaTransNode;
		DETECTION_BNFA_TRANSNODE_S * pstTnew;

		/* Check if the transition already exists, if so just update the ulNextState */
		pstBnfaTransNode = pstBnfa->ppstBnfaTransTable[ulState];
		while( pstBnfaTransNode )
		{
			if( pstBnfaTransNode->ulKey == (ULONG)ulInput )  /* transition already exists- reset the pstNext ulState */
			{
				pstBnfaTransNode->ulNextState = ulNextState;
				return 0; 
			}
			pstBnfaTransNode=pstBnfaTransNode->pstNext;
		}

		/* Definitely not an existing transition - add it */
		pstTnew = (DETECTION_BNFA_TRANSNODE_S*)DETECTION_COMMON_BNFA_MALLOC(sizeof(DETECTION_BNFA_TRANSNODE_S),pstBnfa->ulListMemory);
		if( pstTnew ==NULL)
		{
			return 1; 
		}

		pstTnew->ulKey        = ulInput;
		pstTnew->ulNextState = ulNextState;
		pstTnew->pstNext       = pstBnfa->ppstBnfaTransTable[ulState];

		pstBnfa->ppstBnfaTransTable[ulState] = pstTnew; 
	}

	pstBnfa->ulBnfaNumTrans++;

	return 0; 
}

/*
 *   Free the entire transition list table 
 */
	static 
ULONG Detection_Common_BnfaListFreeTable( DETECTION_BNFA_S * pstBnfa )
{
	ULONG i;
	DETECTION_BNFA_TRANSNODE_S * pstBnfaTransNode= NULL, *pstP= NULL;

	if( pstBnfa->ppstBnfaTransTable ==NULL) return 0;

	if( pstBnfa->ppstBnfaTransTable[0] )
	{
		DETECTION_COMMON_BNFA_FREE(pstBnfa->ppstBnfaTransTable[0],sizeof(ulBnfaState)*pstBnfa->ulBnfaAlphabetSize,pstBnfa->ulListMemory);
	}

	for(i=1; i<pstBnfa->ulBnfaMaxStates; i++)
	{  
		pstBnfaTransNode = pstBnfa->ppstBnfaTransTable[i];

		while( pstBnfaTransNode )
		{
			pstP = pstBnfaTransNode;
			pstBnfaTransNode = pstBnfaTransNode->pstNext;
			DETECTION_COMMON_BNFA_FREE(pstP,sizeof(DETECTION_BNFA_TRANSNODE_S),pstBnfa->ulListMemory);      
		}
	}

	if( pstBnfa->ppstBnfaTransTable )
	{
		DETECTION_COMMON_BNFA_FREE(pstBnfa->ppstBnfaTransTable,sizeof(DETECTION_BNFA_TRANSNODE_S*)*pstBnfa->ulBnfaMaxStates,pstBnfa->ulListMemory);
		pstBnfa->ppstBnfaTransTable = 0;
	}

	return 0;
}
/*
 * Converts a single row of states from list format to a full format
 */ 
	static 
ULONG Detection_Common_BnfaListConvRowToFull(DETECTION_BNFA_S * pstBnfa, ulBnfaState ulState, ulBnfaState * pulFull )
{
	if( (ULONG)ulState >= pstBnfa->ulBnfaMaxStates ) /* protects 'full' against overflow */
	{
		return 1;
	}

	if( ulState == 0 )
	{
		if( pstBnfa->ppstBnfaTransTable[0] )
			MemCpy(pulFull,pstBnfa->ppstBnfaTransTable[0],sizeof(ulBnfaState)*pstBnfa->ulBnfaAlphabetSize);
		else
			MemSet(pulFull,0,sizeof(ulBnfaState)*pstBnfa->ulBnfaAlphabetSize);

		return pstBnfa->ulBnfaAlphabetSize;
	}
	else
	{
		ULONG ulTcnt = 0;

		DETECTION_BNFA_TRANSNODE_S * pstBnfaTransNode = pstBnfa->ppstBnfaTransTable[ ulState ];

		MemSet(pulFull,0,sizeof(ulBnfaState)*pstBnfa->ulBnfaAlphabetSize);

		if( pstBnfaTransNode ==NULL)
		{
			return 0;
		}

		while(pstBnfaTransNode && (pstBnfaTransNode->ulKey < DETECTION_COMMON_BNFA_MAX_ALPHABET_SIZE ) )
		{
			pulFull[ pstBnfaTransNode->ulKey ] = pstBnfaTransNode->ulNextState;
			ulTcnt++;
			pstBnfaTransNode = pstBnfaTransNode->pstNext;
		}
		return ulTcnt;
	}
}

/*
 *  Add pucPattern characters to the initial upper case trie
 *  unless Exact has been specified, in  which case all patterns
 *  are assumed to be case specific.
 */
	static 
ULONG Detection_Common_BnfaAddPatternStates (DETECTION_BNFA_S * pstBnfa, DETECTION_BNFAPATTERN_S * pstBnfaPattern) 
{
	ULONG             ulState= 0, ulNext= 0, ulN= 0;
	UCHAR * pucPattern= NULL;
	DETECTION_BNFA_MATCHNODE_S  * pstPmn= NULL;

	ulN       = pstBnfaPattern->ulPatternLen;
	pucPattern = pstBnfaPattern->pucCasepatrn;
	ulState   = 0;

	/* 
	 *  Match up pucPattern with existing states
	 */ 
	for (; ulN > 0; pucPattern++, ulN--)
	{
		if( pstBnfa->ulBnfaCaseMode == DETECTION_COMMON_BNFA_CASE )
			ulNext = Detection_Common_BnfaListGetNextState(pstBnfa,ulState,*pucPattern);
		else
			ulNext = Detection_Common_BnfaListGetNextState(pstBnfa,ulState,g_ucXlatcase[*pucPattern]);

		if( ulNext == DETECTION_COMMON_BNFA_FAIL_STATE || ulNext == 0 )
		{
			break;
		}
		ulState = ulNext;
	}

	/*
	 *   Add new states for the rest of the pucPattern bytes, 1 ulState per byte, uppercase
	 */ 
	for (; ulN > 0; pucPattern++, ulN--)
	{
		pstBnfa->ulBnfaNumStates++; 

		if( pstBnfa->ulBnfaCaseMode == DETECTION_COMMON_BNFA_CASE )
		{
			if( Detection_Common_BnfaListPutNextState(pstBnfa,ulState,*pucPattern,pstBnfa->ulBnfaNumStates)  >0 )
				return 1;
		}
		else
		{
			if( Detection_Common_BnfaListPutNextState(pstBnfa,ulState,g_ucXlatcase[*pucPattern],pstBnfa->ulBnfaNumStates)  >0 )
				return 1;
		}
		ulState = pstBnfa->ulBnfaNumStates;

		if ( pstBnfa->ulBnfaNumStates >= pstBnfa->ulBnfaMaxStates )
		{
			return 1;
		}
	}

	/*  Add a pattern to the list of patterns terminated at this ulState */
	pstPmn = (DETECTION_BNFA_MATCHNODE_S*)DETECTION_COMMON_BNFA_MALLOC(sizeof(DETECTION_BNFA_MATCHNODE_S),pstBnfa->ulMatchlistMemory);
	if( pstPmn==NULL )
	{
		return 1;
	}

	pstPmn->pvData = pstBnfaPattern;
	pstPmn->pstNext = pstBnfa->ppstBnfaMatchList[ulState];

	pstBnfa->ppstBnfaMatchList[ulState] = pstPmn;

	return 0;
}

static /* used only by Detection_Common_KcontainsJ() */
	ULONG 
Detection_Common_BnfaConvNodeToFull(DETECTION_BNFA_TRANSNODE_S *pstBnfaTransNode, ulBnfaState * pulFull )
{
	ULONG ulTcnt = 0;

	MemSet(pulFull,0,sizeof(ulBnfaState)*DETECTION_COMMON_BNFA_MAX_ALPHABET_SIZE);

	if( pstBnfaTransNode==NULL )
	{
		return 0;
	}

	while(pstBnfaTransNode && (pstBnfaTransNode->ulKey < DETECTION_COMMON_BNFA_MAX_ALPHABET_SIZE ) )  
	{
		pulFull[ pstBnfaTransNode->ulKey ] = pstBnfaTransNode->ulNextState;
		ulTcnt++;
		pstBnfaTransNode = pstBnfaTransNode->pstNext;
	}
	return ulTcnt;
}
/*
 *  containment test -
 *  test if all of tj transitions are in tk
 */
	static 
ULONG Detection_Common_KcontainsJ(DETECTION_BNFA_TRANSNODE_S * pstTk, DETECTION_BNFA_TRANSNODE_S *pstTj )
{
	ulBnfaState       ulFull[DETECTION_COMMON_BNFA_MAX_ALPHABET_SIZE];

	if( Detection_Common_BnfaConvNodeToFull(pstTk,ulFull) ==0 )
		return 1; /* emtpy ulState */

	while( pstTj )
	{
		if( ulFull[pstTj->ulKey]==0 )
			return 0;

		pstTj=pstTj->pstNext; /* get pstNext tj ulKey */
	}
	return 1;
}
/*
 * 1st optimization - eliminate duplicate fail states
 *
 * check if a fail ulState is a subset of the current ulState,
 * if so recurse to the pstNext fail ulState, and so on.
 */
	static 
ULONG Detection_Common_BnfaOptNfa (DETECTION_BNFA_S * pstBnfa) 
{
	ULONG            ulCnt=0;
	ULONG            ulK, ulFs, ulFr;
	ulBnfaState * pstFailState = pstBnfa->ppulBnfaFailState;

	for(ulK=2;ulK<pstBnfa->ulBnfaNumStates;ulK++)
	{
		ulFr = ulFs = pstFailState[ulK];
		while( ulFs &&  Detection_Common_KcontainsJ(pstBnfa->ppstBnfaTransTable[ulK],pstBnfa->ppstBnfaTransTable[ulFs]) )
		{
			ulFs = pstFailState[ulFs];
		}
		if( ulFr != ulFs ) 
		{
			ulCnt++;
			pstFailState[ ulK ] = ulFs;
		}
	}
	if( ulCnt)DETECTION_PARSER_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"ac-pstBnfa: %lu nfa optimizations found in %lu states\n",ulCnt,pstBnfa->ulBnfaNumStates);
	return 0;
}

/*
 *   Build a non-deterministic finite automata using Aho-Corasick construction
 *   The keyword trie must already be built via Detection_Common_BnfaAddPatternStates()
 */ 
	static 
ULONG Detection_Common_BnfaBuildNfa (DETECTION_BNFA_S * pstBnfa) 
{
	ULONG             ulR, ulS, i;
	DETECTION_QUEUE_S           stQnode, *pstQueue = &stQnode;
	ulBnfaState     * pstFailState = pstBnfa->ppulBnfaFailState;
	DETECTION_BNFA_MATCHNODE_S ** ppstMatchList = pstBnfa->ppstBnfaMatchList;
	DETECTION_BNFA_MATCHNODE_S  * pstMlist= NULL;
	DETECTION_BNFA_MATCHNODE_S  * pstPx= NULL;

	/* Init a Queue */ 
	Detection_Common_QueueInit (pstQueue);

	/* Add the ulState 0 transitions 1st, 
	 * the states at depth 1, fail to ulState 0 
	 */ 
	for (i = 0; i < pstBnfa->ulBnfaAlphabetSize; i++)
	{
		/* note that ulState zero deos not fail, 
		 *  it just returns 0..nstates-1 
		 */
		ulS = Detection_Common_BnfaListGetNextState(pstBnfa,0,i); 
		if( ulS ) /* don'pstBnfaTransNode bother adding ulState zero */
		{
			if( Detection_Common_QueueAdd (pstQueue, ulS) ) 
			{
				return 1;
			}
			pstFailState[ulS] = 0;
		}
	}

	/* Build the fail ulState successive layer of transitions */
	while (Detection_Common_QueueCount (pstQueue) > 0)
	{
		ulR = Detection_Common_QueueRemove (pstQueue);

		/* Find Final States for any Failure */ 
		for(i = 0; i<pstBnfa->ulBnfaAlphabetSize; i++)
		{
			ULONG ulFs, pstNext;

			ulS = Detection_Common_BnfaListGetNextState(pstBnfa,ulR,i);

			if( ulS == DETECTION_COMMON_BNFA_FAIL_STATE )
				continue;

			if( Detection_Common_QueueAdd (pstQueue, ulS) ) 
			{
				return 1;
			}

			ulFs = pstFailState[ulR];

			/* 
			 *  Locate the pstNext valid ulState for 'i' starting at ulFs 
			 */ 
			while( (pstNext=Detection_Common_BnfaListGetNextState(pstBnfa,ulFs,i)) == DETECTION_COMMON_BNFA_FAIL_STATE )
			{
				ulFs = pstFailState[ulFs];
			}

			/*
			 *  Update 's' ulState failure ulState to point to the pstNext valid ulState
			 */ 
			pstFailState[ulS] = pstNext;

			/*
			 *  Copy 'pstNext'states ppstMatchList into 's' states ppstMatchList, 
			 *  we just create a new list nodes, the patterns are not copied.
			 */ 
			for( pstMlist = ppstMatchList[pstNext];pstMlist;pstMlist = pstMlist->pstNext)
			{
				/* Dup the node, don't copy the data */
				pstPx = (DETECTION_BNFA_MATCHNODE_S*)DETECTION_COMMON_BNFA_MALLOC(sizeof(DETECTION_BNFA_MATCHNODE_S),pstBnfa->ulMatchlistMemory);
				if( !pstPx )
				{
					return 0;
				}

				pstPx->pvData = pstMlist->pvData; 

				pstPx->pstNext = ppstMatchList[ulS]; /* insert at pstHead */

				ppstMatchList[ulS] = pstPx;
			}
		}
	}

	/* Clean up the queue */
	Detection_Common_QueueFree (pstQueue);

	/* optimize the failure states */
	if( pstBnfa->ulBnfaOpt )
		Detection_Common_BnfaOptNfa(pstBnfa);

	return 0;
}

/*
 *  Convert ulState machine to csparse format
 *
 *  Merges ulState/transition/failure arrays into one.
 *
 *  For each ulState we use a ulState-word followed by the transition list for
 *  the ulState sw(ulState 0 )...tl(ulState 0) sw(ulState 1)...tl(state1) sw(state2)...
 *  tl(state2) ....
 *  
 *  The transition and failure states are replaced with the start index of
 *  transition ulState, this eliminates the NextState[] lookup....
 *
 *  The compaction of multiple arays into a single array reduces the total
 *  number of states that can be handled since the max index is 2^24-1,
 *  whereas without compaction we had 2^24-1 states.  
 */

ulBnfaState      ulFull[DETECTION_COMMON_BNFA_MAX_ALPHABET_SIZE]={0};

	static 
ULONG Detection_Common_BnfaConvListToCsparseArray(DETECTION_BNFA_S * pstBnfa) 
{
	ULONG            ulM=0, ulK, i, ulNc=0;
	ulBnfaState      ulState=0;
	ulBnfaState    * pstFailState = (ulBnfaState  *)pstBnfa->ppulBnfaFailState;
	ulBnfaState    * pstPs= NULL; /* transition list */
	ulBnfaState    * pstPi= NULL; /* ulState indexes into pstPs */
	ulBnfaState      ulPsIndex=0;
	ULONG       ulNps=0;
	/*ulBnfaState      ulFull[DETECTION_COMMON_BNFA_MAX_ALPHABET_SIZE]={0};*/

	memset( ulFull, 0x00, sizeof(ulBnfaState) * DETECTION_COMMON_BNFA_MAX_ALPHABET_SIZE );

	/* ulCount total ulState transitions, account for ulState and control words  */
	ulNps = 0;
	for(ulK=0;ulK<pstBnfa->ulBnfaNumStates;ulK++)
	{
		ulNps++; /* ulState word */
		ulNps++; /* control word */

		/* ulCount transitions */
		ulNc = 0;
		Detection_Common_BnfaListConvRowToFull(pstBnfa, (ulBnfaState)ulK, ulFull );
		for( i=0; i<pstBnfa->ulBnfaAlphabetSize; i++ )
		{
			ulState = ulFull[i] & DETECTION_COMMON_BNFA_SPARSE_MAX_STATE;
			if( ulState != 0 )
			{
				ulNc++;
			}    
		}

		/* add in transition ulCount */
		if( (ulK == 0 && pstBnfa->ulBnfaForceFullZeroState) || ulNc > DETECTION_COMMON_BNFA_SPARSE_MAX_ROW_TRANSITIONS )
		{
			ulNps += DETECTION_COMMON_BNFA_MAX_ALPHABET_SIZE;
		}
		else
		{
			for( i=0; i<pstBnfa->ulBnfaAlphabetSize; i++ )
			{
				ulState = ulFull[i] & DETECTION_COMMON_BNFA_SPARSE_MAX_STATE;
				if( ulState != 0 )
				{
					ulNps++;
				}    
			}
		}
	}

	/* check if we have too many states + transitions */
	if( ulNps > DETECTION_COMMON_BNFA_SPARSE_MAX_STATE )
	{
		/* Fatal */
		return 1;
	}

	/*
	   Alloc The Transition List - we need an array of ulBnfaState items of size 'ulNps'
	 */
	pstPs = DETECTION_COMMON_BNFA_MALLOC( ulNps*sizeof(ulBnfaState),pstBnfa->ulNextstateMemory);
	if( pstPs ==NULL) 
	{
		/* Fatal */
		return 1;
	}
	pstBnfa->ppulBnfaTransList = pstPs;

	/* 
	   State Index list for pstPi - we need an array of ulBnfaState items of size 'NumStates' 
	 */
	pstPi = DETECTION_COMMON_BNFA_MALLOC( pstBnfa->ulBnfaNumStates*sizeof(ulBnfaState),pstBnfa->ulNextstateMemory);
	if( pstPi ==NULL) 
	{
		/* Fatal */
		return 1;
	}

	/* 
	   Build the Transition List Array
	 */
	for(ulK=0;ulK<pstBnfa->ulBnfaNumStates;ulK++)
	{
		pstPi[ulK] = ulPsIndex; /* save index of start of ulState 'ulK' */

		pstPs[ ulPsIndex ] = ulK; /* save the ulState were in as the 1st word */

		ulPsIndex++;  /* skip past ulState word */

		/* conver ulState 'ulK' to full format */
		Detection_Common_BnfaListConvRowToFull(pstBnfa, (ulBnfaState)ulK, ulFull );

		/* ulCount transitions */
		ulNc = 0;
		for( i=0; i<pstBnfa->ulBnfaAlphabetSize; i++ )
		{
			ulState = ulFull[i] & DETECTION_COMMON_BNFA_SPARSE_MAX_STATE;
			if( ulState != 0 )
			{
				ulNc++;
			}    
		}

		/* add a ulFull ulState or a sparse ulState  */
		if( (ulK == 0 && pstBnfa->ulBnfaForceFullZeroState) || 
				ulNc > DETECTION_COMMON_BNFA_SPARSE_MAX_ROW_TRANSITIONS )
		{
			/* set the control word */
			pstPs[ulPsIndex]  = DETECTION_COMMON_BNFA_SPARSE_FULL_BIT;
			pstPs[ulPsIndex] |= pstFailState[ulK] & DETECTION_COMMON_BNFA_SPARSE_MAX_STATE;
			if( pstBnfa->ppstBnfaMatchList[ulK] )
			{
				pstPs[ulPsIndex] |= DETECTION_COMMON_BNFA_SPARSE_MATCH_BIT;
			}
			ulPsIndex++;  

			/* copy the transitions */
			Detection_Common_BnfaListConvRowToFull(pstBnfa, (ulBnfaState)ulK, &pstPs[ulPsIndex] );

			ulPsIndex += DETECTION_COMMON_BNFA_MAX_ALPHABET_SIZE;  /* add in 256 transitions */

		}
		else
		{
			/* set the control word */
			pstPs[ulPsIndex]  = ulNc<<DETECTION_COMMON_BNFA_SPARSE_COUNT_SHIFT ;
			pstPs[ulPsIndex] |= pstFailState[ulK]&DETECTION_COMMON_BNFA_SPARSE_MAX_STATE;
			if( pstBnfa->ppstBnfaMatchList[ulK] )
			{
				pstPs[ulPsIndex] |= DETECTION_COMMON_BNFA_SPARSE_MATCH_BIT;
			}
			ulPsIndex++;

			/* add in the transitions */
			for( ulM=0, i=0; i<pstBnfa->ulBnfaAlphabetSize && ulM<ulNc; i++ )
			{
				ulState = ulFull[i] & DETECTION_COMMON_BNFA_SPARSE_MAX_STATE;
				if( ulState != 0 )
				{
					pstPs[ulPsIndex++] = (i<<DETECTION_COMMON_BNFA_SPARSE_VALUE_SHIFT) | ulState;
					ulM++;
				}
			}
		}
	}

	/* sanity check we have not overflowed our buffer */
	if( ulPsIndex > ulNps ) 
	{
		/* Fatal */
		return 1;
	}

	/* 
	   Replace Transition states with Transition Indices. 
	   This allows us to skip using NextState[] to locate the pstNext ulState
	   This limits us to <16M transitions due to 24 bit ulState sizes, and the fact
	   we have now converted pstNext-ulState fields to pstNext-index fields in this array,
	   and we have merged the pstNext-ulState and ulState arrays.
	 */
	ulPsIndex=0;
	for(ulK=0; ulK< pstBnfa->ulBnfaNumStates; ulK++ )
	{
		if( pstPi[ulK] >= ulNps )
		{
			/* Fatal */
			return 1;
		}

		//ulPsIndex = pstPi[ulK];  /* get index of pstNext ulState */
		ulPsIndex++;        /* skip ulState id */

		/* Full Format */
		if( pstPs[ulPsIndex] & DETECTION_COMMON_BNFA_SPARSE_FULL_BIT )
		{
			/* Do the fail-ulState */
			pstPs[ulPsIndex] = ( pstPs[ulPsIndex] & 0xff000000 ) | 
				( pstPi[ pstPs[ulPsIndex] & DETECTION_COMMON_BNFA_SPARSE_MAX_STATE ] ) ; 
			ulPsIndex++;

			/* Do the transition-states */
			for(i=0;i<DETECTION_COMMON_BNFA_MAX_ALPHABET_SIZE;i++)
			{
				pstPs[ulPsIndex] = ( pstPs[ulPsIndex] & 0xff000000 ) | 
					( pstPi[ pstPs[ulPsIndex] & DETECTION_COMMON_BNFA_SPARSE_MAX_STATE ] ) ; 
				ulPsIndex++;
			}
		}

		/* Sparse Format */
		else
		{
			ulNc = (pstPs[ulPsIndex] & DETECTION_COMMON_BNFA_SPARSE_COUNT_BITS)>>DETECTION_COMMON_BNFA_SPARSE_COUNT_SHIFT;

			/* Do the cw = [cb | fail-ulState] */
			pstPs[ulPsIndex] =  ( pstPs[ulPsIndex] & 0xff000000 ) |
				( pstPi[ pstPs[ulPsIndex] & DETECTION_COMMON_BNFA_SPARSE_MAX_STATE ] ); 
			ulPsIndex++;

			/* Do the transition-states */
			for(i=0;i<ulNc;i++)
			{
				pstPs[ulPsIndex] = ( pstPs[ulPsIndex] & 0xff000000 ) |
					( pstPi[ pstPs[ulPsIndex] & DETECTION_COMMON_BNFA_SPARSE_MAX_STATE ] );
				ulPsIndex++;
			}
		}

		/* check for buffer overflow again */
		if( ulPsIndex > ulNps )
		{
			/* Fatal */
			return 1;
		}

	}

	DETECTION_COMMON_BNFA_FREE(pstPi,pstBnfa->ulBnfaNumStates*sizeof(ulBnfaState),pstBnfa->ulNextstateMemory);

	return 0;
}




DETECTION_BNFA_S * Detection_Common_BnfaNew(VOID (*pvFuncUserFree)(VOID *p))
{
	DETECTION_BNFA_S * pstBnfa= NULL;
	static ULONG ulFirst=1;
	ULONG ulBnfaMemory=0;

	if( ulFirst )
	{
		Detection_Common_BnfaInitSummary();
		ulFirst=0;
	}

	Detection_Common_InitXlatcase ();

	pstBnfa = (DETECTION_BNFA_S *) DETECTION_COMMON_BNFA_MALLOC(sizeof(DETECTION_BNFA_S),ulBnfaMemory);
	if(pstBnfa==NULL) 
		return 0;

	if( pstBnfa )
	{
		pstBnfa->ulBnfaOpt                = 0;
		pstBnfa->ulBnfaCaseMode           = DETECTION_COMMON_BNFA_PER_PAT_CASE;
		pstBnfa->ulBnfaFormat             = DETECTION_COMMON_BNFA_SPARSE;
		pstBnfa->ulBnfaAlphabetSize       = DETECTION_COMMON_BNFA_MAX_ALPHABET_SIZE;
		pstBnfa->ulBnfaForceFullZeroState = 1;
		pstBnfa->ulBnfaMemory            = sizeof(DETECTION_BNFA_S);
		pstBnfa->pvFuncUserfree               = pvFuncUserFree;
	}

	g_ulQueueMemory = 0;
	return pstBnfa;
}

VOID Detection_Common_BnfaSetOpt(DETECTION_BNFA_S  * pstP, ULONG ulFlag)
{
	pstP->ulBnfaOpt=ulFlag;
}

/*
 *   Fee all memory 
 */ 

VOID Detection_Common_BnfaFree (DETECTION_BNFA_S * pstBnfa) 
{
	ULONG i;
	DETECTION_BNFAPATTERN_S * pstPatrn= NULL, *pstIpatrn= NULL;
	DETECTION_BNFA_MATCHNODE_S   * pstMlist= NULL, *pstIlist= NULL;

	for(i = 0; i < pstBnfa->ulBnfaNumStates; i++)
	{
		/* free match list entries */
		pstMlist = pstBnfa->ppstBnfaMatchList[i];

		while (pstMlist)
		{
			pstIlist = pstMlist;
			pstMlist = pstMlist->pstNext;
			DETECTION_COMMON_BNFA_FREE(pstIlist,sizeof(DETECTION_BNFA_MATCHNODE_S),pstBnfa->ulMatchlistMemory);
		}
		pstBnfa->ppstBnfaMatchList[i] = 0;

#ifdef ALLOW_NFA_FULL
		/* free pstNext ulState entries */
		if( pstBnfa->ulBnfaFormat==DETECTION_COMMON_BNFA_FULL )/* Full format */
		{
			if( pstBnfa->ppulBnfaNextState[i] )
			{
				DETECTION_COMMON_BNFA_FREE(pstBnfa->ppulBnfaNextState[i],pstBnfa->ulBnfaAlphabetSize*sizeof(ulBnfaState),pstBnfa->ulNextstateMemory);
			}
		}
#endif
	}

	/* Free patterns */
	pstPatrn = pstBnfa->pstBnfaPatterns;
	while(pstPatrn)
	{
		pstIpatrn=pstPatrn;
		pstPatrn=pstPatrn->pstNext;
		DETECTION_COMMON_BNFA_FREE(pstIpatrn->pucCasepatrn,pstIpatrn->ulPatternLen,pstBnfa->ulPatMemory);
		if(pstBnfa->pvFuncUserfree && pstIpatrn->pvUserdata)
			pstBnfa->pvFuncUserfree(pstIpatrn->pvUserdata);
		DETECTION_COMMON_BNFA_FREE(pstIpatrn,sizeof(DETECTION_BNFAPATTERN_S),pstBnfa->ulPatMemory);
	}

	/* Free arrays */
	DETECTION_COMMON_BNFA_FREE(pstBnfa->ppulBnfaFailState,pstBnfa->ulBnfaNumStates*sizeof(ulBnfaState),pstBnfa->ulFailstateMemory);
	DETECTION_COMMON_BNFA_FREE(pstBnfa->ppstBnfaMatchList,pstBnfa->ulBnfaNumStates*sizeof(DETECTION_BNFAPATTERN_S*),pstBnfa->ulMatchlistMemory);
	DETECTION_COMMON_BNFA_FREE(pstBnfa->ppulBnfaNextState,pstBnfa->ulBnfaNumStates*sizeof(ulBnfaState*),pstBnfa->ulNextstateMemory);
	DETECTION_COMMON_BNFA_FREE(pstBnfa->ppulBnfaTransList,(2*pstBnfa->ulBnfaNumStates+pstBnfa->ulBnfaNumTrans)*sizeof(ulBnfaState*),pstBnfa->ulNextstateMemory);
	Detection_GlobalFree( pstBnfa ); /* cannot update memory tracker when deleting pstBnfa so just 'Detection_Common_GlobalFree' it !*/
}

/*
 *   Add a pattern to the pattern list
 */ 

ULONG Detection_Common_BnfaAddPattern (DETECTION_BNFA_S * pstBnfa, 
		UCHAR *pucPat, 
		ULONG ulN,
		ULONG ulNocase,
		VOID * pvUserdata )
{
	DETECTION_BNFAPATTERN_S * pstList= NULL;

	pstList = (DETECTION_BNFAPATTERN_S *)DETECTION_COMMON_BNFA_MALLOC(sizeof(DETECTION_BNFAPATTERN_S),pstBnfa->ulPatMemory);
	if(pstList==NULL) return 1;

	pstList->pucCasepatrn = (UCHAR *)DETECTION_COMMON_BNFA_MALLOC(ulN,pstBnfa->ulPatMemory );
	if(pstList->pucCasepatrn==NULL) return 1;

	MemCpy (pstList->pucCasepatrn, pucPat, ulN);

	pstList->ulPatternLen        = ulN;
	pstList->ulNocase   = ulNocase;
	pstList->pvUserdata = pvUserdata;

	pstList->pstNext     = pstBnfa->pstBnfaPatterns; /* insert at front of list */
	pstBnfa->pstBnfaPatterns = pstList;

	pstBnfa->ulBnfaPatternCnt++;

	return 0;
}

/*
 *   Compile the patterns into an nfa ulState machine 
 */ 

ULONG Detection_Common_BnfaCompile (DETECTION_BNFA_S * pstBnfa) 
{
	DETECTION_BNFAPATTERN_S  * pstList;
	DETECTION_BNFA_MATCHNODE_S   ** ppstTmpMatchList;
	ULONG          ulCntMatchStates;
	ULONG               i;
	static ULONG ulFirst=1;

	if( ulFirst )
	{
		Detection_Common_BnfaInitSummary();
		ulFirst=0;
	}
	g_ulQueueMemory =0;

	/* Count number of states */ 
	for(pstList = pstBnfa->pstBnfaPatterns; pstList != NULL; pstList = pstList->pstNext)
	{
		pstBnfa->ulBnfaMaxStates += pstList->ulPatternLen;
	}
	pstBnfa->ulBnfaMaxStates++; /* one extra */

	/* Alloc a List based State Transition table */
	pstBnfa->ppstBnfaTransTable =(DETECTION_BNFA_TRANSNODE_S**) DETECTION_COMMON_BNFA_MALLOC(sizeof(DETECTION_BNFA_TRANSNODE_S*) * pstBnfa->ulBnfaMaxStates,pstBnfa->ulListMemory );
	if(pstBnfa->ppstBnfaTransTable==NULL)
	{
		return 1;
	}

	/* Alloc a ppstMatchList table - this has a list of pattern matches for each ulState */
	pstBnfa->ppstBnfaMatchList=(DETECTION_BNFA_MATCHNODE_S**) DETECTION_COMMON_BNFA_MALLOC(sizeof(VOID*)*pstBnfa->ulBnfaMaxStates,pstBnfa->ulMatchlistMemory );
	if(pstBnfa->ppstBnfaMatchList==NULL)
	{
		return 1;
	}

	/* Add each Pattern to the State Table - This forms a keyword trie using lists */ 
	pstBnfa->ulBnfaNumStates = 0;
	for (pstList = pstBnfa->pstBnfaPatterns; pstList != NULL; pstList = pstList->pstNext)
	{
		Detection_Common_BnfaAddPatternStates (pstBnfa, pstList);
	}
	pstBnfa->ulBnfaNumStates++;

	if( pstBnfa->ulBnfaNumStates > DETECTION_COMMON_BNFA_SPARSE_MAX_STATE )
	{
		return 1;  /* Call bnfaFree to clean up */
	}

	/* ReAlloc a smaller ppstMatchList table -  only need NumStates  */
	ppstTmpMatchList=pstBnfa->ppstBnfaMatchList;

	pstBnfa->ppstBnfaMatchList=(DETECTION_BNFA_MATCHNODE_S**)DETECTION_COMMON_BNFA_MALLOC(sizeof(VOID*) * pstBnfa->ulBnfaNumStates,pstBnfa->ulMatchlistMemory);
	if(pstBnfa->ppstBnfaMatchList==NULL)
	{
		return 1;
	}

	MemCpy(pstBnfa->ppstBnfaMatchList,ppstTmpMatchList,sizeof(VOID*) * pstBnfa->ulBnfaNumStates);

	DETECTION_COMMON_BNFA_FREE(ppstTmpMatchList,sizeof(VOID*) * pstBnfa->ulBnfaMaxStates,pstBnfa->ulMatchlistMemory);

	/* Alloc a failure ulState table -  only need NumStates */
	pstBnfa->ppulBnfaFailState =(ulBnfaState*)DETECTION_COMMON_BNFA_MALLOC(sizeof(ulBnfaState) * pstBnfa->ulBnfaNumStates,pstBnfa->ulFailstateMemory);
	if(pstBnfa->ppulBnfaFailState==NULL)
	{
		return 1;
	}

#ifdef ALLOW_NFA_FULL
	if( pstBnfa->ulBnfaFormat == DETECTION_COMMON_BNFA_FULL )
	{
		/* Alloc a ulState transition table -  only need NumStates  */
		pstBnfa->ppulBnfaNextState=(ulBnfaState**)DETECTION_COMMON_BNFA_MALLOC(sizeof(ulBnfaState*) * pstBnfa->ulBnfaNumStates,pstBnfa->ulNextstateMemory);
		if(!pstBnfa->ppulBnfaNextState) 
		{
			return 1;
		}
	}
#endif

	/* Build the nfa w/failure states - time the nfa construction */
	if( Detection_Common_BnfaBuildNfa (pstBnfa) ) 
	{
		return 1;
	}

	/* Convert nfa storage format from list to full or sparse */
	if( pstBnfa->ulBnfaFormat == DETECTION_COMMON_BNFA_SPARSE )
	{
		if( Detection_Common_BnfaConvListToCsparseArray(pstBnfa)  )
		{
			return 1;
		}
		DETECTION_COMMON_BNFA_FREE(pstBnfa->ppulBnfaFailState,sizeof(ulBnfaState)*pstBnfa->ulBnfaNumStates,pstBnfa->ulFailstateMemory);
		pstBnfa->ppulBnfaFailState=0;
	}
	else
	{
		return 1;
	}

	/* Free up the Table Of Transition Lists */
	Detection_Common_BnfaListFreeTable( pstBnfa ); 

	/* Count states with Pattern Matches */
	ulCntMatchStates=0;
	for(i=0;i<pstBnfa->ulBnfaNumStates;i++)
	{
		if( pstBnfa->ppstBnfaMatchList[i] )
			ulCntMatchStates++;
	}

	pstBnfa->ulBnfaMatchStates = ulCntMatchStates;
	pstBnfa->ulQueueMemory    = g_ulQueueMemory;

	Detection_Common_BnfaAccumInfo( pstBnfa  );
	return 0;
}

/*
   binary array search on sparse transition array

   O(logN) search times..same as a binary tree.
   pvData must be in sorted order in the array.

return:  = -1 => not found
>= 0  => index of element 'ulVal' 

notes:
ulVal is tested against the high 8 bits of the 'a' array entry,
this is particular to the storage format we are using.
 */
static
	inline 
LONG Detection_Common_BnfaBinearch( ulBnfaState * pulBnfaState, ULONG ulAlen, ULONG ulVal )
{
	LONG lM=0, l, lR=0;
	ULONG ulC=0;

	l = 0;
	lR = ulAlen - 1;

	while( lR >= l )
	{
		lM = ( lR + l ) >> 1;

		ulC = pulBnfaState[lM] >> DETECTION_COMMON_BNFA_SPARSE_VALUE_SHIFT;

		if( ulVal == ulC )
		{
			return lM;
		}

		else if( ulVal <  ulC )
		{
			lR = lM - 1;
		}

		else /* ulVal > ulC */
		{
			l = lM + 1; 
		}
	}
	return -1;
}



/*
 *   Sparse format for ulState table using single array storage
 *
 *   word 1: ulState
 *   word 2: control-word = cb<<24| ulFs
 *           cb    : control-byte
 *                : mb | fb | nt
 *                mb : bit 8 set if match ulState, zero otherwise
 *                fb : bit 7 set if using full format, zero otherwise
 *                nt : number of transitions 0..63 (more than 63 requires full format)
 *            ulFs: failure-transition-ulState 
 *   word 3+: byte-value(0-255) << 24 | transition-ulState
 */
static
inline 
	ULONG 
Detection_Common_BnfaGetNextStateCsparseNfa(ulBnfaState * pulPcx, ULONG ulSindex, ULONG  ulInput)
{
	ULONG ulK =0;
	ULONG ulNc =0; 
	LONG lIndex =0;
	register ulBnfaState * pulPc =NULL;

	for(;;)
	{
		pulPc = pulPcx + ulSindex + 1; /* skip ulState-id == 1st word */

		if( pulPc[0] & DETECTION_COMMON_BNFA_SPARSE_FULL_BIT )
		{   
			if( ulSindex == 0 )
			{
				return pulPc[1+ulInput] & DETECTION_COMMON_BNFA_SPARSE_MAX_STATE; 
			}
			else
			{
				if( pulPc[1+ulInput] & DETECTION_COMMON_BNFA_SPARSE_MAX_STATE ) 
					return pulPc[1+ulInput] & DETECTION_COMMON_BNFA_SPARSE_MAX_STATE;
			}
		}
		else
		{
			ulNc = (pulPc[0]>>DETECTION_COMMON_BNFA_SPARSE_COUNT_SHIFT) & DETECTION_COMMON_BNFA_SPARSE_MAX_ROW_TRANSITIONS;
			if( ulNc > DETECTION_COMMON_BNFA_SPARSE_LINEAR_SEARCH_LIMIT )
			{
				/* binary search... */
				lIndex = Detection_Common_BnfaBinearch( pulPc+1, ulNc, ulInput );
				if( lIndex >= 0 )
				{
					return pulPc[lIndex+1] & DETECTION_COMMON_BNFA_SPARSE_MAX_STATE;
				}
			}
			else
			{
				/* linear search... */
				for( ulK=0; ulK<ulNc; ulK++ ) 
				{   
					if( (pulPc[ulK+1]>>DETECTION_COMMON_BNFA_SPARSE_VALUE_SHIFT) == ulInput )
					{
						return pulPc[ulK+1] & DETECTION_COMMON_BNFA_SPARSE_MAX_STATE;
					}
				}
			}
		}

		/* no transition found ... get the failure ulState and try again  */
		ulSindex = pulPc[0] & DETECTION_COMMON_BNFA_SPARSE_MAX_STATE;
	} 
}






/*
 *  Per Pattern case search, case is on per pattern basis
 *  standard snort search
 *
 *  retval: 
 *                    0:  no match
 *                  >0:  AppProtId value of  matched rule
 */
static  INLINE DETECTION_SIGINFO_S * Detection_Common_BnfaSearchCsparseNfa1(   DETECTION_BNFA_S * pstBnfa, UCHAR *pucTx, ULONG ulN,
		DETECTION_SIGINFO_S * (*plFuncMatch)(DETECTION_BNFAPATTERN_S * pstId, ULONG ulIndex, VOID *pvData), 
		VOID *pvData, ULONG ulSindex, ULONG *pulCurrent_state ) 
{
	DETECTION_BNFA_MATCHNODE_S  * pstMlist= NULL;
	UCHAR      * pucTend= NULL;
	UCHAR      * pucT= NULL;
	UCHAR        ucT=0;
	ULONG             ulIndex=0;
	DETECTION_BNFA_MATCHNODE_S ** ppstMatchList = pstBnfa->ppstBnfaMatchList;
	DETECTION_BNFAPATTERN_S     * pstPatrn= NULL;
	ulBnfaState       * pulTransList = pstBnfa->ppulBnfaTransList;

	ULONG ulLastMatch=DETECTION_COMMON_LAST_STATE_INIT;

	DETECTION_SIGINFO_S *ret;

	DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"%s\n",__FUNCTION__);                   

	pucT    = pucTx;
	pucTend = pucT + ulN;

	for(; pucT<pucTend; pucT++)
	{
		ucT = g_ucXlatcase[ *pucT ];
		//DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "%c ", ucT);
		/* Transition to pstNext ulState index */
		ulSindex = Detection_Common_BnfaGetNextStateCsparseNfa(pulTransList,ulSindex,ucT);

		/* Log matches in this ulState - if any */
		if( ulSindex && (pulTransList[ulSindex+1] & DETECTION_COMMON_BNFA_SPARSE_MATCH_BIT) )
		{
			DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"(%s:%d)find ulSindex: %lu\n",__FUNCTION__, __LINE__, ulSindex);                   

			if( ulSindex == ulLastMatch )
				continue;

			ulLastMatch = ulSindex;

			for(pstMlist = ppstMatchList[ pulTransList[ulSindex] ];
					pstMlist!= NULL;
					pstMlist = pstMlist->pstNext )
			{
				pstPatrn = (DETECTION_BNFAPATTERN_S*)pstMlist->pvData;

				DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"(%s:%d):Nocase, loop : \n",__FUNCTION__, __LINE__/*, pstPatrn->pucCasepatrn*/);                   

				ulIndex = pucT - pucTx - pstPatrn->ulPatternLen + 1;
				if( pstPatrn->ulNocase )
				{
					ret = plFuncMatch (pstPatrn->pvUserdata, ulIndex, pvData);
					if(ret){
	//					printf("mpsl ids found attrack, msg:%s, detail:%s\n", ret->pcMessage, ret->detail);
						return ret;
					}
						
				}
				else
				{      
					/* If case sensitive pattern, do an exact match test */
					if( MemCmp (pstPatrn->pucCasepatrn, pucT - pstPatrn->ulPatternLen + 1, pstPatrn->ulPatternLen) == 0 )
					{						
						ret = plFuncMatch (pstPatrn->pvUserdata, ulIndex, pvData);
						if(ret){
	//						printf("%x mpsl ids found attrack, msg:%s, detail:%s\n", ret, ret->pcMessage, ret->detail);
							return ret;
						}
							
					}               
				}
			}
		}
	}
	DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"%s--->%d, sid:%x\n",__FUNCTION__, __LINE__, ret);                         
	return NULL;
}



DETECTION_SIGINFO_S * Detection_Common_BnfaSearchCsparseNfa(   DETECTION_BNFA_S * pstBnfa, UCHAR *pucTx, ULONG ulN,
		DETECTION_SIGINFO_S * (*plFuncMatch)(DETECTION_BNFAPATTERN_S * pstId, ULONG ulIndex, VOID *pvData), 
		VOID *pvData, ULONG ulSindex, ULONG *pulCurrent_state ) 
{
	DETECTION_BNFA_MATCHNODE_S  * pstMlist= NULL;
	UCHAR      * pucTend= NULL;
	UCHAR      * pucT= NULL;
	UCHAR        ucT=0;
	ULONG             ulIndex=0;
	DETECTION_BNFA_MATCHNODE_S ** ppstMatchList = pstBnfa->ppstBnfaMatchList;
	DETECTION_BNFAPATTERN_S     * pstPatrn= NULL;
	ulBnfaState       * pulTransList = pstBnfa->ppulBnfaTransList;

	ULONG ulLastMatch=DETECTION_COMMON_LAST_STATE_INIT;

	DETECTION_SIGINFO_S *ret;
	int i;

	DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"%s\n",__FUNCTION__);                   

	pucT    = pucTx;
	pucTend = pucT + ulN;

	for(; pucT<pucTend; pucT++)
	{
		ucT = g_ucXlatcase[ *pucT ];
//		DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "%c  ", ucT);

		/* Transition to pstNext ulState index */
		ulSindex = Detection_Common_BnfaGetNextStateCsparseNfa(pulTransList,ulSindex,ucT);

		/* Log matches in this ulState - if any */
		if( ulSindex && (pulTransList[ulSindex+1] & DETECTION_COMMON_BNFA_SPARSE_MATCH_BIT) )
		{
			DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"(%s:%d)find ulSindex: %lu\n",__FUNCTION__, __LINE__, ulSindex);                   

			//if( ulSindex == ulLastMatch )
			//	continue;


			ulLastMatch = ulSindex;

			for(pstMlist = ppstMatchList[ pulTransList[ulSindex] ];
					pstMlist!= NULL;
					pstMlist = pstMlist->pstNext )
			{
				pstPatrn = (DETECTION_BNFAPATTERN_S*)pstMlist->pvData;

				DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"(%s:%d)Nocase:  ",__FUNCTION__, __LINE__);  
				
#if 1
				for(i = 0; i < pstPatrn->ulPatternLen; i++){
					DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"%c",  pstPatrn->pucCasepatrn[i]);                   
				}
				DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"\n");
#endif

				ulIndex = pucT - pucTx - pstPatrn->ulPatternLen + 1;
				if( pstPatrn->ulNocase )
				{
				printf("userdata:%s\n", pstPatrn->pvUserdata);
			#if 	0
					ret = plFuncMatch (pstPatrn->pvUserdata, ulIndex, pvData);
					if(ret){
	//					printf("mpsl ids found attrack, msg:%s, detail:%s\n", ret->pcMessage, ret->detail);
						return ret;
					}
			#endif		
						
				}
				else
				{   
				printf("userdata:%s\n", pstPatrn->pvUserdata);
				#if 0
					/* If case sensitive pattern, do an exact match test */
					if( MemCmp (pstPatrn->pucCasepatrn, pucT - pstPatrn->ulPatternLen + 1, pstPatrn->ulPatternLen) == 0 )
					{						
						ret = plFuncMatch(pstPatrn->pvUserdata, ulIndex, pvData);
						if(ret){
	//						printf("%x mpsl ids found attrack, msg:%s, detail:%s\n", ret, ret->pcMessage, ret->detail);
							return ret;
						}
							
					}               
				#endif 
				
				}
			}
		}
	}
	DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"%s--->%d, sid:%x\n",__FUNCTION__, __LINE__, ret);                         
	return NULL;
}






/*
 *  
 *  
 *
 *  retval: 
 *                    0:  no match
 *                  >0:  AppProtId value of  matched rule
 */
DETECTION_SIGINFO_S * Detection_Common_BnfaSearch(    DETECTION_BNFA_S * pstBnfa, UCHAR *pucTx, ULONG ulN,
		DETECTION_SIGINFO_S * (*plFuncMatch) ( VOID * pvId, ULONG ulIndex, VOID *pvData), 
		VOID *pvData, ULONG ulSindex, ULONG* pulCurrent_state )
{
	DETECTION_SIGINFO_S *ret = NULL;	

	/* Note:
	 * (1) pstBnfa->ulBnfaCaseMode was set to be DETECTION_COMMON_BNFA_PER_PAT_CASE;
	 *  (2) pstBnfa->ulBnfaMethod was set to be 1;
	 *  
	 *   The other codes were save just for backward compatibility. There is only one function to do
	 *    multi-pattern match, Detection_Common_BnfaSearchCsparseNfa.
	 */
	/*This is the only function to do multi-pattern match*/
	ret = Detection_Common_BnfaSearchCsparseNfa( pstBnfa, pucTx, ulN, 
			(DETECTION_SIGINFO_S * (*)(DETECTION_BNFAPATTERN_S*,ULONG i,VOID *pvData))
			plFuncMatch, pvData, ulSindex, pulCurrent_state );

	return ret;
}

ULONG Detection_Common_BnfaPatternCount( DETECTION_BNFA_S * pstBnfa)
{
	return pstBnfa->ulBnfaPatternCnt;
}

/*
 *  Summary Info Data
 */
static DETECTION_BNFA_S g_stAppSummary;
static ULONG g_ulAppSummaryCnt=0;

/*
 *  Info: Print info a particular ulState machine.
 */
VOID Detection_Common_BnfaPrintInfoEx(ULONG ulExecID , DETECTION_BNFA_S * pstBnfa, CHAR * pcText )
{
	ULONG ulMaxMemory=0;

	if( (pstBnfa == NULL)||( pstBnfa->ulBnfaNumStates ==0))
	{
		return;
	}
	ulMaxMemory = pstBnfa->ulBnfaMemory + pstBnfa->ulPatMemory + pstBnfa->ulListMemory + 
		pstBnfa->ulMatchlistMemory + pstBnfa->ulFailstateMemory + pstBnfa->ulNextstateMemory;

	if( pcText && g_ulAppSummaryCnt )
	{
		DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "+-[AC-BNFA Search Info%s]----------------------\n",pcText);
		DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "| Instances        : %lu\n",g_ulAppSummaryCnt);
	}
	else
	{
		DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "+-[AC-BNFA Search Info]------------------------------\n");
	}
	DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "| Patterns         : %lu\n",pstBnfa->ulBnfaPatternCnt);
	DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "| Pattern Chars    : %lu\n",pstBnfa->ulBnfaMaxStates);
	DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "| Num States       : %lu\n",pstBnfa->ulBnfaNumStates);
	DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "| Num plFuncMatch States : %lu\n",pstBnfa->ulBnfaMatchStates);
	if( ulMaxMemory < 1024*1024 )
	{
		DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "| Memory           :   %.lu Kbytes\n", ulMaxMemory/1024 );
		DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "| Patterns       :   %lu K\n",pstBnfa->ulPatMemory/1024 );
		DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "| plFuncMatch Lists    :   %lu K\n",pstBnfa->ulMatchlistMemory/1024 );
		DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "| Transitions    :   %lu K\n",pstBnfa->ulNextstateMemory/1024 );
	}
	else
	{
		DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "| Memory           :   %lu Mbytes\n", ulMaxMemory/(1024*1024) );
		DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "| Patterns       :   %lu M\n",pstBnfa->ulPatMemory/(1024*1024) );
		DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "| plFuncMatch Lists    :   %lu M\n",pstBnfa->ulMatchlistMemory/(1024*1024) );
		DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "| Transitions    :   %lu M\n",pstBnfa->ulNextstateMemory/(1024*1024) );
	}
	DETECTION_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "+-------------------------------------------------\n");
}

VOID Detection_Common_BnfaPrintInfo( DETECTION_BNFA_S * pstBnfa )
{
	Detection_Common_BnfaPrintInfoEx( 0,pstBnfa, 0 );
}

VOID Detection_Common_BnfaPrintSummary( ULONG ulExecID )
{
	Detection_Common_BnfaPrintInfoEx(ulExecID, &g_stAppSummary, " Summary" );
}

VOID Detection_Common_BnfaInitSummary( VOID )
{
	g_ulAppSummaryCnt=0;
	MemSet(&g_stAppSummary,0,sizeof(DETECTION_BNFA_S));
}
VOID Detection_Common_BnfaAccumInfo( DETECTION_BNFA_S * pstBnfa )
{
	DETECTION_BNFA_S * pstPx = &g_stAppSummary;

	g_ulAppSummaryCnt++;

	pstPx->ulBnfaAlphabetSize  = pstBnfa->ulBnfaAlphabetSize;
	pstPx->ulBnfaPatternCnt   += pstBnfa->ulBnfaPatternCnt;
	pstPx->ulBnfaMaxStates    += pstBnfa->ulBnfaMaxStates;
	pstPx->ulBnfaNumStates    += pstBnfa->ulBnfaNumStates;
	pstPx->ulBnfaNumTrans     += pstBnfa->ulBnfaNumTrans;
	pstPx->ulBnfaMatchStates  += pstBnfa->ulBnfaMatchStates;
	pstPx->ulBnfaMemory      += pstBnfa->ulBnfaMemory;
	pstPx->ulPatMemory       += pstBnfa->ulPatMemory;
	pstPx->ulListMemory      += pstBnfa->ulListMemory;
	pstPx->ulMatchlistMemory += pstBnfa->ulMatchlistMemory;
	pstPx->ulNextstateMemory += pstBnfa->ulNextstateMemory;
	pstPx->ulFailstateMemory += pstBnfa->ulFailstateMemory;
}
