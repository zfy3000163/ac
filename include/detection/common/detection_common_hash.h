
  
#ifndef __DETECTION_COMMON_HASH_H__
#define __DETECTION_COMMON_HASH_H__

#include <detection/common/detection_common_list.h>


#define SFGHASH_NOMEM  3//  -2
#define SFGHASH_ERR      2//-1
#define SFGHASH_OK        0
#define SFGHASH_INTABLE   1


/*******HASH�����ṹ***********/
typedef struct stHashfcn 
{
 ULONG      ulSeed;
 ULONG      ulScale;
 ULONG      ulHardener;
 ULONG   (*pulFuncHash)(struct stHashfcn  *pstHash, UCHAR  *pucKey, ULONG ulLen);
 LONG   (*plFunckeycmp)( const VOID *pvS1, const VOID *pvS2, ULONG ulLen);
} DETECTION_HASHFCN_S;

/*******HASH���ṹ***********/
typedef struct stHashNode
{
  struct stHashNode  * pstNext,  * pstPrev;
  VOID                     * pvKey;      			/* ָ��key��ָ�� */
  VOID                     * pvData;     			/* ָ�����ݵ�ָ�� */    
} DETECTION_HASHNODE_S;

/*******HASH��ṹ***********/
typedef struct stHash
{
  DETECTION_HASHFCN_S    * pstHashfcn;
  ULONG                    ulKeysize;    				/* keyֵ���� */
  ULONG                    ulUserkey;   				/* �û�keyֵ*/
  DETECTION_HASHNODE_S ** ppstTable;   	/* ��Ž������portobject ���� */
  ULONG                     ulNrows;  
  ULONG                     ulCount;     				/* HASH���е��ܽ���� */
  ULONG                    (*pvFuncUserFree)( VOID * );  
  ULONG                     ulRow;    
  DETECTION_HASHNODE_S * pstNode;    		/* HASH�ظ���po��㱣��������*/
  ULONG                    ulSplay;
} DETECTION_HASH_S;


/*******XHASH��ض���***********/

/* XHASH   ERROR DEFINES  */

#define DETECTION_XHASH_OK        0
#define DETECTION_XHASH_INTABLE   1
#define DETECTION_XHASH_NOMEM     2
#define DETECTION_XHASH_ERR       3



DETECTION_HASHNODE_S * Detection_Common_GhashFindfirst( DETECTION_HASH_S * pstHash);
DETECTION_HASH_S * Detection_Common_GhashNew( ULONG ulNrows, ULONG ulKeysize, ULONG ulUserkeys, ULONG (*pvFuncUserFree)(VOID*pvP) );
ULONG Detection_Common_GhashAdd( DETECTION_HASH_S * pstHash, VOID * pvKey, VOID * pvData );
DETECTION_HASHNODE_S * Detection_Common_GhashFindnext( DETECTION_HASH_S * pstHash );
DETECTION_HASHNODE_S * Detection_Common_GhashFindfirst( DETECTION_HASH_S * pstHash);
ULONG Detection_Common_GhashSetKeyops( DETECTION_HASH_S *pstHashtable ,
                        ULONG (*pulFuncHash)( DETECTION_HASHFCN_S * p,
                                              UCHAR *d,
                                              ULONG n),
                        LONG (*plFunckeycmp)( const VOID *s1,
                                           const VOID *s2,
                                           ULONG n));
VOID Detection_Common_GhashDelete( DETECTION_HASH_S * pstHashtable );
VOID * Detection_Common_GhashFind( DETECTION_HASH_S * t, VOID * pvKey);
ULONG Detection_Common_hashfcn_hash( DETECTION_HASHFCN_S * pstHashfcn, UCHAR *pucD, ULONG ulNum );

#endif

