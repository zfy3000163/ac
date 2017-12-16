
#include <detection/common/detection_com.h>
#include <detection/common/detection_mod.h>
#include <detection/common/detection_pub.h>
//#include <detection/common/detection_config.h>
//#include <detection/detect/detection_detect_pub.h>
#include <detection/common/detection_mod.h>
#include <detection/common/detection_debug.h>
#include <detection/common/detection_common_mem.h>
#include <detection/common/detection_common_mpse.h>
//#include <detection/common/detection_common_bitopfuncs.h>
#include <detection/common/detection_common_bnfasearch.h>
#include <detection/common/detection_common_ksearch.h>
#include <detection/common/detection_common_acsmx2.h>
#include <detection/common/detection_common_acsmx.h>

typedef struct stMpseStruct {

	ULONG    ulMethod;
	VOID * pvObj;
	ULONG    ulVerbose;
	ULLONG ullBcnt;
	CHAR   cIncGlobalCounter;

} DETECTION_MPSE_S;


/* *
 *  @note      创建多模式匹配数据结构
 *                  we do not care about the value of ulMethod, becasue we always set it to be DETECTION_COMMON_MPSE_AC_BNFA
 *  @param   


 *  @retval     
 *  @see 
 *
 ***  
 ***    
 ***
 ***
 */
VOID * Detection_Common_MpseNew( ULONG ulMethod, ULONG ulUseGobalCounterFlag,VOID (*pvFuncUserFree)(VOID *p))
{
	DETECTION_MPSE_S * pstMpse= NULL;

	pstMpse = (DETECTION_MPSE_S*)Detection_GlobalMalloc( sizeof(DETECTION_MPSE_S) ,DETECTION_MEM_TAG);
	if( pstMpse == NULL ) return NULL;

	pstMpse->ulMethod = ulMethod;
	pstMpse->ulVerbose = 0;
	pstMpse->pvObj = NULL;
	pstMpse->ullBcnt = 0;
	pstMpse->cIncGlobalCounter = ulUseGobalCounterFlag;

	pstMpse->pvObj=Detection_Common_BnfaNew(pvFuncUserFree);
	if(pstMpse->pvObj)
		((DETECTION_BNFA_S*)(pstMpse->pvObj))->ulBnfaMethod = 1;

	if( pstMpse->pvObj == NULL )
	{
		Detection_GlobalFree(pstMpse);
		pstMpse = NULL;
	}

	return (VOID *)pstMpse;
}


/* *
 *  @note      设置检测优化使能标志位
 *  @param   pvVoid:模式匹配数据结构
 *                 ulFlag:标志位
 *                   
 *  @retval     
 *  @see 
 *
 ***  
 ***    
 ***
 ***
 */
VOID   Detection_Common_MpseSetOpt( VOID * pvVoid, ULONG ulFlag )
{
	DETECTION_MPSE_S * pstMpse = (DETECTION_MPSE_S*)pvVoid;

	if (pstMpse == NULL)
		return;
	switch( pstMpse->ulMethod )
	{
		case DETECTION_COMMON_MPSE_AC_BNFA_Q:
		case DETECTION_COMMON_MPSE_AC_BNFA:
			if (pstMpse->pvObj)
				Detection_Common_BnfaSetOpt((DETECTION_BNFA_S*)pstMpse->pvObj,ulFlag);
			break;
		default:
			break;
	}
}

VOID   Detection_Common_MpseFree( VOID * pvVoid )
{
	DETECTION_MPSE_S * pstMpse = (DETECTION_MPSE_S*)pvVoid;

	if (pstMpse == NULL)
		return;

	switch( pstMpse->ulMethod )
	{
		case DETECTION_COMMON_MPSE_AC_BNFA:
		case DETECTION_COMMON_MPSE_AC_BNFA_Q:
			if (pstMpse->pvObj)
				Detection_Common_BnfaFree((DETECTION_BNFA_S*)pstMpse->pvObj);
			Detection_GlobalFree(pstMpse);
			return;

		case DETECTION_COMMON_MPSE_AC:
			if (pstMpse->pvObj)
				Detection_Common_AcsmFree((DETECTION_ACSM_S *)pstMpse->pvObj);
			Detection_GlobalFree(pstMpse);
			return;

		case DETECTION_COMMON_MPSE_ACF:
		case DETECTION_COMMON_MPSE_ACF_Q:
		case DETECTION_COMMON_MPSE_ACS:
		case DETECTION_COMMON_MPSE_ACB:
		case DETECTION_COMMON_MPSE_ACSB:
			if (pstMpse->pvObj)
				Detection_Common_AcsmFree2((DETECTION_ACSM2_S *)pstMpse->pvObj);
			Detection_GlobalFree(pstMpse);
			return;

		case DETECTION_COMMON_MPSE_LOWMEM:
		case DETECTION_COMMON_MPSE_LOWMEM_Q:
			if (pstMpse->pvObj)
				Detection_Common_KTrieDelete((DETECTION_KTRIE_S *)pstMpse->pvObj);
			Detection_GlobalFree(pstMpse);
			return;

		default:
			return;
	}
}
/* *
 *  @note      添加模式字符串
 *  @param   pvVoid:模式匹配数据结构
 *                 P:模式字符串所在的buf
 *                 ulM:模式字符串长度
 *                 ulOffset:模式字符串起点
 *                 ulNoCase:大小写不敏感
 *                 ulDepth:模式字符串长度
 *                 pvID:模式匹配数据
 *                 ulIID:规则结点ID
 *  @retval     
 *  @see 
 *
 ***  
 ***    
 ***
 ***
 */
ULONG  Detection_Common_MpseAddPattern ( VOID * pvVoid, VOID * P, ULONG ulM, 
		ULONG ulNoCase,LONG lOffset, LONG lDepth,  VOID* pvID, ULONG ulIID )
{
	DETECTION_MPSE_S * pstMpse = (DETECTION_MPSE_S*)pvVoid;

	switch( pstMpse->ulMethod )
	{
		case DETECTION_COMMON_MPSE_AC_BNFA:
		case DETECTION_COMMON_MPSE_AC_BNFA_Q:
			return Detection_Common_BnfaAddPattern( (DETECTION_BNFA_S*)pstMpse->pvObj, (UCHAR *)P, ulM,
					ulNoCase, pvID );

		case DETECTION_COMMON_MPSE_AC:
			return Detection_Common_AcsmAddPattern( (DETECTION_ACSM_S*)pstMpse->pvObj, (UCHAR *)P, ulM,
					ulNoCase, lOffset, lDepth, pvID, ulIID );

		case DETECTION_COMMON_MPSE_ACF:
		case DETECTION_COMMON_MPSE_ACF_Q:
		case DETECTION_COMMON_MPSE_ACS:
		case DETECTION_COMMON_MPSE_ACB:
		case DETECTION_COMMON_MPSE_ACSB:
			return Detection_Common_AcsmAddPattern2( (DETECTION_ACSM2_S*)pstMpse->pvObj, (UCHAR *)P, ulM,
					ulNoCase, lOffset, lDepth, pvID, ulIID );

		case DETECTION_COMMON_MPSE_LOWMEM:
		case DETECTION_COMMON_MPSE_LOWMEM_Q:
			return Detection_Common_KTrieAddPattern( (DETECTION_KTRIE_S *)pstMpse->pvObj, (UCHAR *)P, ulM,
					ulNoCase, pvID );

		default:
			return 1;
	}
}


/* *
 *  @note      编译模式匹配状态机
 *  @param   pvVoid:模式匹配数据结构


 *  @retval     
 *  @see 
 *
 ***  
 ***    
 ***
 ***
 */
ULONG  Detection_Common_MpsePrepPatterns  ( VOID * pvVoid)
{
	ULONG retv=0;
	DETECTION_MPSE_S * pstMpse = (DETECTION_MPSE_S*)pvVoid;

	switch( pstMpse->ulMethod )
	{
		case DETECTION_COMMON_MPSE_AC_BNFA:
		case DETECTION_COMMON_MPSE_AC_BNFA_Q:
			retv = Detection_Common_BnfaCompile( (DETECTION_BNFA_S*) pstMpse->pvObj);
			break;

		case DETECTION_COMMON_MPSE_AC:
			retv = Detection_Common_AcsmCompile( (DETECTION_ACSM_S*) pstMpse->pvObj);
			break;

		case DETECTION_COMMON_MPSE_ACF:
		case DETECTION_COMMON_MPSE_ACF_Q:
		case DETECTION_COMMON_MPSE_ACS:
		case DETECTION_COMMON_MPSE_ACB:
		case DETECTION_COMMON_MPSE_ACSB:
			retv = Detection_Common_AcsmCompile2( (DETECTION_ACSM2_S*) pstMpse->pvObj);
			break;

		case DETECTION_COMMON_MPSE_LOWMEM:
		case DETECTION_COMMON_MPSE_LOWMEM_Q:
			return Detection_Common_KTrieCompile( (DETECTION_KTRIE_S *)pstMpse->pvObj);

		default:
			retv = 1;
			break; 
	}

	return retv;
}

/* *
 *  @note      打印状态机信息
 *  @param   


 *  @retval     
 *  @see 
 *
 ***  
 ***    
 ***
 ***
 */
ULONG Detection_Common_MpsePrintInfo( VOID *pvVoid )
{
	DETECTION_MPSE_S * pstMpse = (DETECTION_MPSE_S*)pvVoid;

	switch( pstMpse->ulMethod )
	{
		case DETECTION_COMMON_MPSE_AC_BNFA:
		case DETECTION_COMMON_MPSE_AC_BNFA_Q:
			Detection_Common_BnfaPrintInfo( (DETECTION_BNFA_S*) pstMpse->pvObj );
			break;
		case DETECTION_COMMON_MPSE_AC:
			return Detection_Common_AcsmPrintDetailInfo( (DETECTION_ACSM_S*) pstMpse->pvObj );
		case DETECTION_COMMON_MPSE_ACF:
		case DETECTION_COMMON_MPSE_ACF_Q:
		case DETECTION_COMMON_MPSE_ACS:
		case DETECTION_COMMON_MPSE_ACB:
		case DETECTION_COMMON_MPSE_ACSB:
			return Detection_Common_AcsmPrintDetailInfo2( (DETECTION_ACSM2_S*) pstMpse->pvObj );

		default:
			return 1;
	}

	return 0;
}
/* *
 *  @note       打印状态机信息
 *  @param   


 *  @retval     
 *  @see 
 *
 ***  
 ***    
 ***
 ***
 */
ULONG Detection_Common_MpsePrintSummary(ULONG ulExecID )
{

	Detection_Common_AcsmPrintSummaryInfo2(ulExecID);
	Detection_Common_BnfaPrintSummary(ulExecID);

	if( Detection_Common_KTrieMemUsed() )
	{
		ULONG x;
		x = Detection_Common_KTrieMemUsed();
		DETECTION_PARSER_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"[ LowMem Search-Method Memory Used : %lu %s ]\n",
				(x > 1024) ?  x/1024 : x,
				(x > 1024) ? "MBytes" : "KBytes" );

	}
	return 0;
}
/* *
 *  @note      多模式匹配
 *  @param   pvVoid:模式匹配数据结构
 *                 pucKey:待匹配的字符串
 *                 ulLen:待匹配的长度
 *                 plFuncAction:匹配成功后的动作
 *                 pvData:保存匹配结果
 *                 plCurrentState:当前状态
 *  @retval    
 *                    0:  no match
 *                  >0:  AppProtId value of  matched rule    
 *  @see 
 *
 ***  
 ***    
 ***
 ***
 */
DETECTION_SIGINFO_S *  Detection_Common_MpseSearch(VOID *pvVoid, const UCHAR *pucKey, ULONG ulLen, 
		DETECTION_SIGINFO_S * (*plFuncAction )(VOID* pvId, ULONG ulIndex, VOID *pvData), 
		VOID *pvData, LONG *plCurrentState )
{
	DETECTION_MPSE_S * pstMpse = (DETECTION_MPSE_S*)pvVoid;
	DETECTION_SIGINFO_S *ret = NULL;

	pstMpse->ullBcnt += ulLen;

	ret = Detection_Common_BnfaSearch( (DETECTION_BNFA_S*) pstMpse->pvObj, (UCHAR *)pucKey, ulLen, plFuncAction, pvData, 0 /* start-state */, plCurrentState );
	return ret;  
}
/* *
 *  @note     获取模式个数
 *  @param   


 *  @retval     模式个数
 *  @see 
 *
 ***  
 ***    
 ***
 ***
 */
ULONG Detection_Common_MpseGetPatternCount(VOID *pvVoid)
{
	DETECTION_MPSE_S * pstMpse = (DETECTION_MPSE_S*)pvVoid;

	/*pstMpse->ulMethod == DETECTION_COMMON_MPSE_AC_BNFA*/
	return Detection_Common_BnfaPatternCount((DETECTION_BNFA_S *)pstMpse->pvObj);

}
