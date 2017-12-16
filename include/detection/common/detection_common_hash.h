
  
#ifndef __DETECTION_COMMON_HASH_H__
#define __DETECTION_COMMON_HASH_H__

#include <detection/common/detection_common_list.h>


#define SFGHASH_NOMEM  3//  -2
#define SFGHASH_ERR      2//-1
#define SFGHASH_OK        0
#define SFGHASH_INTABLE   1


/*******HASH函数结构***********/
typedef struct stHashfcn 
{
 ULONG      ulSeed;
 ULONG      ulScale;
 ULONG      ulHardener;
 ULONG   (*pulFuncHash)(struct stHashfcn  *pstHash, UCHAR  *pucKey, ULONG ulLen);
 LONG   (*plFunckeycmp)( const VOID *pvS1, const VOID *pvS2, ULONG ulLen);
} DETECTION_HASHFCN_S;

/*******HASH结点结构***********/
typedef struct stHashNode
{
  struct stHashNode  * pstNext,  * pstPrev;
  VOID                     * pvKey;      			/* 指向key的指针 */
  VOID                     * pvData;     			/* 指向数据的指针 */    
} DETECTION_HASHNODE_S;

/*******HASH表结构***********/
typedef struct stHash
{
  DETECTION_HASHFCN_S    * pstHashfcn;
  ULONG                    ulKeysize;    				/* key值长度 */
  ULONG                    ulUserkey;   				/* 用户key值*/
  DETECTION_HASHNODE_S ** ppstTable;   	/* 存放解析后的portobject 链表 */
  ULONG                     ulNrows;  
  ULONG                     ulCount;     				/* HASH表中的总结点数 */
  ULONG                    (*pvFuncUserFree)( VOID * );  
  ULONG                     ulRow;    
  DETECTION_HASHNODE_S * pstNode;    		/* HASH重复的po结点保存在这里*/
  ULONG                    ulSplay;
} DETECTION_HASH_S;


/*******XHASH相关定义***********/

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

