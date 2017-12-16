
  
#ifndef __DETECTION_COMMON_LIST_H__
#define __DETECTION_COMMON_LIST_H__

typedef struct stLnode
{
  struct stLnode   *pstNext;
  struct stLnode   *pstPrev;
  VOID                 *pvNodeData;   
}DETECTION_QLNODE_S,DETECTION_SNODE_S,DETECTION_LNODE_S;


typedef struct stSfList
{
  DETECTION_LNODE_S  *pstHead, *pstTail;  
  DETECTION_LNODE_S  *pstCur;  
  ULONG             ulCount;
}DETECTION_SFQUEUE_S,DETECTION_SFSTACK_S,DETECTION_SFLIST_S;

typedef VOID * NODE_DATA;

extern VOID Detection_Common_ListInit ( DETECTION_SFLIST_S * pstList) ;
extern DETECTION_SFLIST_S * Detection_Common_ListNew(VOID); 
extern ULONG  Detection_Common_ListAddTail ( DETECTION_SFLIST_S* pstList, VOID * pvData );
extern VOID * Detection_Common_ListRemoveHead(DETECTION_SFLIST_S * pstList) ;
extern VOID Detection_Common_ListFreeAll( DETECTION_SFLIST_S * pstList, ULONG (*pvfuncNfree)(VOID*) ) ;
extern NODE_DATA Detection_Common_ListFirstpos( DETECTION_SFLIST_S * pstSflist, DETECTION_LNODE_S ** pstLnode );
extern NODE_DATA Detection_Common_ListNextpos( DETECTION_SFLIST_S * pstSflist,  DETECTION_LNODE_S ** pstLnode );
extern NODE_DATA Detection_Common_Listfirst( DETECTION_SFLIST_S * pstSflist );
extern NODE_DATA Detection_Common_Listnext( DETECTION_SFLIST_S * pstSflist );
extern ULONG Detection_Common_ListAddHead ( DETECTION_SFLIST_S * pstList, NODE_DATA pvData );
extern ULONG Detection_Common_ListAddBefore ( DETECTION_SFLIST_S *pstList, DETECTION_LNODE_S *pstListNode, NODE_DATA pvData );
extern ULONG Detection_Common_ListCount ( DETECTION_SFLIST_S *pstList);
extern VOID Detection_Common_ListFree (DETECTION_SFLIST_S * pstList);
extern DETECTION_LNODE_S * Detection_Common_ListFirstNode( DETECTION_SFLIST_S * pstList );
extern DETECTION_LNODE_S * Detection_Common_ListNextNode( DETECTION_SFLIST_S * pstList );




#endif
