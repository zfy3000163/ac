
#include <detection/common/detection_com.h>
#include <detection/common/detection_pub.h>
#include <detection/common/detection_debug.h>
#include <detection/common/detection_common_mem.h>
#include <detection/common/detection_common_ksearch.h>


static VOID Detection_Common_KTrieFree(DETECTION_KTRIENODE_S *pstKtrienNode);

static ULONG g_ulAppMtot = 0;


ULONG Detection_Common_KTrieMemUsed(VOID) 
{ 
	return g_ulAppMtot; 
}

/*
 *  Allocate Memory
 */
static VOID * Detection_Common_KtrieMalloc(ULONG ulN)
{
	VOID *pvP= NULL;

	if (ulN < 1)
		return NULL;

	pvP = (ULONG*)Detection_GlobalMalloc(ulN, DETECTION_MEM_TAG);

	if (pvP)
	{
		g_ulAppMtot += ulN;
	}

	return pvP;
}

/*
 *  Free Memory
 */
static VOID Detection_Common_KtrieFree(VOID *pvP) 
{
	if (pvP == NULL)
		return;

	Detection_GlobalFree(pvP);
}

/*
 *   Local/Tmp ulNocase array
 */
static UCHAR g_ucTnocase[65*1024];

/*
 ** Case Translation Table 
 */
static UCHAR g_ucXlatcase[256];

/*
 *
 */
static VOID Detection_Common_InitXlatcase(VOID)
{
	ULONG i;
	static ULONG ulFirst=1;

	if( ulFirst == 0) return; /* thread safe */

	for(i=0;i<256;i++)
	{
		g_ucXlatcase[ i ] =  (UCHAR)ToLower(i);
	}

	ulFirst=0;
}
/*
 * Check to make sure that p is less than or equal to the ptr range
 * pointers
 *
 * 1 means it's in bounds, 0 means it's not
 */
ULONG Detection_Common_InBounds(const UCHAR *pucStart, const UCHAR *pucEnd, const UCHAR *p)
{
	if(p >= pucStart && p < pucEnd)
	{
		return 1;
	}

	return 0;
}

ULONG Detection_Common_SafeMemcpy(VOID *pvDst, const VOID *pvSrc, ULONG n, const VOID *pvStart, const VOID *pvEnd)
{
	VOID *pvTmp= NULL;

	if(n < 1)
	{
		return 0;
	}

	if ((pvDst == NULL) || (pvSrc == NULL) || (pvStart == NULL)|| (pvEnd == NULL))                                                                         
	{
		return 0;
	}

	pvTmp = ((UCHAR*)pvDst) + (n-1);
	if (pvTmp < pvDst)
	{
		return 0;
	}

	if(!Detection_Common_InBounds(pvStart,pvEnd, pvDst) || !Detection_Common_InBounds(pvStart,pvEnd,pvTmp))
	{
		return 0;
	}

	MemCpy(pvDst, pvSrc, n);

	return 1;
}
static inline VOID Detection_Common_ConvertCaseEx( UCHAR * pucD, UCHAR *pucS, ULONG ulM )
{
	ULONG i;
	for( i=0; i < ulM; i++ )
	{
		pucD[i] = g_ucXlatcase[ pucS[i] ];
	}
}

DETECTION_KTRIE_S * Detection_Common_KTrieNew(ULONG ulMethod, VOID (*pvFuncUserfree)(VOID *pvP))
{
	DETECTION_KTRIE_S * pstKtrie = (DETECTION_KTRIE_S*) Detection_Common_KtrieMalloc( sizeof(DETECTION_KTRIE_S) );

	if( pstKtrie == NULL ) return 0;


	Detection_Common_InitXlatcase();

	pstKtrie->ulMemory = sizeof(DETECTION_KTRIE_S);
	pstKtrie->ulNchars = 0;
	pstKtrie->ulNpats  = 0;
	pstKtrie->ulEndStates = 0;
	pstKtrie->ulMethod = ulMethod; /* - old ulMethod, 1 = queue */
	pstKtrie->pvFuncUserfree = pvFuncUserfree;

	return pstKtrie;
}

ULONG Detection_Common_KTriePatternCount(DETECTION_KTRIE_S *pstKtrie)
{
	return pstKtrie->ulNpats;
}

/*
 * Deletes ulMemory that was used in creating trie
 * and nodes
 */
VOID Detection_Common_KTrieDelete(DETECTION_KTRIE_S *pstKtrie)
{
	DETECTION_KTRIEPATTERN_S *pstKtrieAttern = NULL;
	DETECTION_KTRIEPATTERN_S *pstNext = NULL;
	ULONG i;

	if (pstKtrie == NULL)
		return;

	pstKtrieAttern = pstKtrie->pstPatrn;

	while (pstKtrieAttern != NULL)
	{
		pstNext = pstKtrieAttern->pstNext;

		if (pstKtrie->pvFuncUserfree && pstKtrieAttern->pvId)
			pstKtrie->pvFuncUserfree(pstKtrieAttern->pvId);

		Detection_Common_KtrieFree(pstKtrieAttern->pucP);
		Detection_Common_KtrieFree(pstKtrieAttern->pucPcase);
		Detection_Common_KtrieFree(pstKtrieAttern);

		pstKtrieAttern = pstNext;
	}

	for (i = 0; i < DETECTION_COMMON_KTRIE_ROOT_NODES; i++)
		Detection_Common_KTrieFree(pstKtrie->pstRoot[i]);

	Detection_Common_KtrieFree(pstKtrie);
}

/* 
 * Recursively delete all nodes in trie
 */
static VOID Detection_Common_KTrieFree(DETECTION_KTRIENODE_S *pstKtrienNode)
{
	if (pstKtrienNode == NULL)
		return;

	Detection_Common_KTrieFree(pstKtrienNode->pstChild);
	Detection_Common_KTrieFree(pstKtrienNode->pstSibling);

	Detection_Common_KtrieFree(pstKtrienNode);
}

/*
 *
 */
static DETECTION_KTRIEPATTERN_S * Detection_Common_KTrieNewPattern(UCHAR * pucP, ULONG ulN)
{
	DETECTION_KTRIEPATTERN_S *pstKtrieAttern= NULL;
	ULONG ulRet=0;

	if (ulN < 1)
		return NULL;

	pstKtrieAttern = (DETECTION_KTRIEPATTERN_S*) Detection_Common_KtrieMalloc( sizeof(DETECTION_KTRIEPATTERN_S) );

	if (pstKtrieAttern == NULL)
		return NULL;

	/* Save as a ulNocase string */   
	pstKtrieAttern->pucP = (UCHAR*) Detection_Common_KtrieMalloc( ulN );
	if( pstKtrieAttern->pucP  == NULL) 
	{
		Detection_Common_KtrieFree(pstKtrieAttern); 
		return NULL;
	}

	Detection_Common_ConvertCaseEx( pstKtrieAttern->pucP, pucP, ulN );

	/* Save Case specific version */
	pstKtrieAttern->pucPcase = (UCHAR*) Detection_Common_KtrieMalloc( ulN );
	if( pstKtrieAttern->pucPcase == NULL ) 
	{
		Detection_Common_KtrieFree(pstKtrieAttern->pucP); 
		Detection_Common_KtrieFree(pstKtrieAttern); 
		return NULL;
	}

	ulRet = Detection_Common_SafeMemcpy(pstKtrieAttern->pucPcase, pucP, ulN, pstKtrieAttern->pucPcase, pstKtrieAttern->pucPcase + ulN);
	if (ulRet != 1)
	{
		Detection_Common_KtrieFree(pstKtrieAttern->pucPcase); 
		Detection_Common_KtrieFree(pstKtrieAttern->pucP); 
		Detection_Common_KtrieFree(pstKtrieAttern); 
		return NULL;
	}

	pstKtrieAttern->ulN    = ulN;
	pstKtrieAttern->pstNext = NULL;

	return pstKtrieAttern;
}

/*
 *  Add Pattern info to the list of patterns
 */

ULONG Detection_Common_KTrieAddPattern( DETECTION_KTRIE_S * pstTs, UCHAR * pucP, ULONG ulN, 
		ULONG ulNocase, VOID * pvId )
{
	DETECTION_KTRIEPATTERN_S  *pstPnew= NULL;

	if( pstTs->pstPatrn  == NULL)
	{
		pstPnew = pstTs->pstPatrn = Detection_Common_KTrieNewPattern( pucP, ulN );

		if( pstPnew  == NULL) return 1;
	}
	else
	{
		pstPnew = Detection_Common_KTrieNewPattern(pucP, ulN );

		if( pstPnew  == NULL) return 1;

		pstPnew->pstNext = pstTs->pstPatrn; /* insert at head of list */

		pstTs->pstPatrn = pstPnew;
	}

	pstPnew->ulNocase = ulNocase;
	pstPnew->pvId     = pvId;
	pstPnew->pstMnext  = NULL;

	pstTs->ulNpats++;
	pstTs->ulMemory += sizeof(DETECTION_KTRIEPATTERN_S) + 2 * ulN ; /* Case and ulNocase */

	return 0;
}


/*
 *
 */
static DETECTION_KTRIENODE_S * Detection_Common_KTrieCreateNode(DETECTION_KTRIE_S * pstKtrie)
{
	DETECTION_KTRIENODE_S * pstKtrien=(DETECTION_KTRIENODE_S*)Detection_Common_KtrieMalloc( sizeof(DETECTION_KTRIENODE_S) );

	if(pstKtrien == NULL)
		return 0;


	pstKtrie->ulMemory += sizeof(DETECTION_KTRIENODE_S);

	return pstKtrien;
}



/*
 *  Insert a Pattern in the Trie
 */
static ULONG Detection_Common_KTrieInsert( DETECTION_KTRIE_S *pstKtrie, DETECTION_KTRIEPATTERN_S * pstPx  )
{
	ULONG            ulType = 0;
	ULONG            ulN = pstPx->ulN;
	UCHAR *pucP = pstPx->pucP;
	DETECTION_KTRIENODE_S     *pstRoot= NULL;

	/* Make sure we at least have a pstRoot character for the tree */
	if( pstKtrie->pstRoot[*pucP] == NULL )
	{
		pstKtrie->pstRoot[*pucP] = pstRoot = Detection_Common_KTrieCreateNode(pstKtrie);
		if( pstRoot  == NULL) return 1;
		pstRoot->ulEdge = *pucP;

	}else{

		pstRoot = pstKtrie->pstRoot[*pucP];
	}

	/* Walk existing Patterns */   
	while( ulN )
	{
		if( pstRoot->ulEdge == *pucP )
		{
			pucP++;
			ulN--;

			if( ulN && pstRoot->pstChild )
			{
				pstRoot=pstRoot->pstChild;   
			}
			else /* cannot continue */
			{
				ulType = 0; /* Expand the tree via the pstChild */
				break; 
			}
		}
		else
		{
			if( pstRoot->pstSibling )
			{
				pstRoot=pstRoot->pstSibling;
			}
			else /* cannot continue */
			{
				ulType = 1; /* Expand the tree via the pstSibling */
				break; 
			}
		}
	}

	/* 
	 * Add the pstNext char of the Keyword, if any
	 */
	if( ulN )
	{
		if( ulType == 0 )
		{
			/*
			 *  Start with a new pstChild to finish this Keyword 
			 */
			pstRoot->pstChild= Detection_Common_KTrieCreateNode( pstKtrie );
			if( ! pstRoot->pstChild ) return 1;
			pstRoot=pstRoot->pstChild;
			pstRoot->ulEdge  = *pucP;
			pucP++;
			ulN--;
			pstKtrie->ulNchars++;

		}
		else
		{ 
			/*
			 *  Start a new pstSibling bracnch to finish this Keyword 
			 */
			pstRoot->pstSibling= Detection_Common_KTrieCreateNode( pstKtrie );
			if( ! pstRoot->pstSibling ) return 1;
			pstRoot=pstRoot->pstSibling;
			pstRoot->ulEdge  = *pucP;
			pucP++;
			ulN--;
			pstKtrie->ulNchars++;
		}
	}

	/*
	 *    Finish the keyword as pstChild nodes
	 */
	while( ulN )
	{
		pstRoot->pstChild = Detection_Common_KTrieCreateNode(pstKtrie);
		if( ! pstRoot->pstChild ) return 1;
		pstRoot=pstRoot->pstChild;
		pstRoot->ulEdge  = *pucP;
		pucP++;
		ulN--;
		pstKtrie->ulNchars++;
	}

	if( pstRoot->pstKeyword )
	{
		pstPx->pstMnext = pstRoot->pstKeyword;  /* insert ulDuplicates at front of list */
		pstRoot->pstKeyword = pstPx;
		pstKtrie->ulDuplicates++;
	}
	else
	{
		pstRoot->pstKeyword = pstPx;
		pstKtrie->ulEndStates++;
	}

	return 0;
}


/*
 *
 */
static VOID Detection_Common_BuildBadCharacterShifts( DETECTION_KTRIE_S * pstKt )
{
	ULONG           i,k;
	DETECTION_KTRIEPATTERN_S *pstPlist= NULL; 

	/* Calc the min pattern size */
	pstKt->ulBcSize = 32000;

	for( pstPlist=pstKt->pstPatrn; pstPlist!=NULL; pstPlist=pstPlist->pstNext )
	{ 
		if( pstPlist->ulN < pstKt->ulBcSize )     
		{
			pstKt->ulBcSize = pstPlist->ulN; /* smallest pattern size */
		}
	}

	/*
	 *  Initialze the Bad Character shift table.  
	 */
	for (i = 0; i < DETECTION_COMMON_KTRIE_ROOT_NODES; i++)
	{
		pstKt->usBcShift[i] = (USHORT)pstKt->ulBcSize;  
	}

	/* 
	 *  Finish the Bad character shift table
	 */  
	for( pstPlist=pstKt->pstPatrn; pstPlist!=NULL; pstPlist=pstPlist->pstNext )
	{
		ULONG ulShift, ulCindex;

		for( k=0; k<pstKt->ulBcSize; k++ )
		{
			ulShift = pstKt->ulBcSize - 1 - k;

			ulCindex = pstPlist->pucP[ k ];

			if( ulShift < pstKt->usBcShift[ ulCindex ] )
			{
				pstKt->usBcShift[ ulCindex ] = (USHORT)ulShift;
			}
		}
	}
}


/*
 *  Build the Keyword TRIE
 *  
 */
ULONG Detection_Common_KTrieCompile(DETECTION_KTRIE_S * pstKtrie)
{
	DETECTION_KTRIEPATTERN_S * pstKtrieAttern= NULL;
	/*
	   static ULONG  tmem=0; 
	 */

	/* 
	 *    Build the Keyword TRIE 
	 */
	for( pstKtrieAttern=pstKtrie->pstPatrn; pstKtrieAttern; pstKtrieAttern=pstKtrieAttern->pstNext )
	{
		if( Detection_Common_KTrieInsert( pstKtrie, pstKtrieAttern ) )
			return 1;
	}

	/*
	 *    Build A Setwise Bad Character Shift Table
	 */
	Detection_Common_BuildBadCharacterShifts( pstKtrie );

	/*
	   tmem += pstKtrie->ulMemory;
	   printf(" Compile stats: %d patterns, %d chars, %d duplicate patterns, %d bytes, %d total-bytes\n",pstKtrie->ulNpats,pstKtrie->ulNchars,pstKtrie->ulDuplicates,pstKtrie->ulMemory,tmem);
	 */
	return 0;
}







