
#include <detection/common/detection_com.h>
#include <detection/common/detection_mod.h>
#include <detection/common/detection_pub.h>
#include <detection/common/detection_mod.h>
#include <detection/common/detection_debug.h>
#include <detection/common/detection_common_mpse.h>

unsigned long g_ulDetectionParseDbg = 0;
unsigned long g_ulDetectionDbg = 0; 
unsigned long g_PLAYLOAD_DEBUG = 0;


typedef struct stPmx{
	VOID  * pvRuleNode;
	VOID  * pvPatternMatchData;
} DETECTION_PMX_S;

typedef struct stAppPatternMatchData
{
	ULONG   ulExceptionFlag;  /*是否使用了取反符号*/
	LONG    lOffset;              /* 匹配的起点*/
	LONG     lDepth;              /* 匹配的长度*/
	LONG     lDistance;          /*  相对于上一个content选项匹配成功的串尾再加多少字节开始搜索*/
	LONG     lWithin;             /*  与depth类似，只不过是相对于上一个content选项匹配成功的串尾加distance选项指定的字节数而不是相对于数据区净载的开头*/
	ULONG   ulRawbytes;        /*  在原始报文中查找*/
	ULONG   ulNocase;             
	ULONG   ulUseDoe;           /* 查找时使用doe_ptr*/
	ULONG   ulUriBuffer;        /*  URI buffer索引*/
	ULONG   ulPatternSize;    /*匹配字符串长度*/
	ULONG   ulReplaceSize;     
	CHAR   *pcReplaceBuf;      
	CHAR   *pcPatternBuf;     /* 用于匹配的模式字符串*/
	ULONG (*pulFunsearch)(const CHAR *, LONG, struct stAppPatternMatchData *,UCHAR **);  /*指向模式匹配函数的指针，这里采用的时B-M字符串匹配算法*/
	LONG  *lSkipStride;     /* B-M算法的跳转数组*/
	LONG  *lShiftStride;     /*B-M算法的移位数组*/
	ULONG   ulPatternMaxJumpSize;
	struct stAppPatternMatchData *pstNext; /* 指向下一个模式匹配结构*/
	ULONG   ulFlags;               /* flags */
	DETECTION_OPTFPLIST_S *pstFpl;     /*   选项匹配链表指针*/
} DETECTION_PATTERNMATCHDATA_S;




VOID Detection_Detect_DeletePMX(VOID *pvData)
{
	DETECTION_PMX_S *pstPmx = (DETECTION_PMX_S *)pvData;
	DETECTION_RULENODE_S *pstRuleNode = NULL;
	DETECTION_OTNX_S *pstOtnx = NULL;

	pstRuleNode = (DETECTION_RULENODE_S *)pstPmx->pvRuleNode;
	pstOtnx = (DETECTION_OTNX_S *)pstRuleNode->pvRuleData;
	if ( pstRuleNode )
	{
		Detection_GlobalFree(pstRuleNode);
	}
	else
	{
		printf("%s %d NULL\n", __FUNCTION__, __LINE__);
	}
	if ( pstOtnx )
	{
		Detection_GlobalFree(pstOtnx);
	}
	else
	{
		printf("%s %d NULL\n", __FUNCTION__, __LINE__);
	}
	if ( pstPmx )
	{
		Detection_GlobalFree(pstPmx);
	}
	else
	{
		printf("%s %d NULL\n", __FUNCTION__, __LINE__);
	}
}



int main(int argc, char **argv)
{
	DETECTION_PORTGROUP_S * pstPg = NULL;
	DETECTION_PATTERNMATCHDATA_S *pstPmd = NULL;


	if(getenv("TAWL7_DEBUG")){
		g_ulDetectionParseDbg = DETECTION_DEBUGTYPE_ERR | DETECTION_DEBUGTYPE_PROCESS;
		g_ulDetectionDbg = DETECTION_DEBUGTYPE_ERR | DETECTION_DEBUGTYPE_PROCESS ;
	}
	else{
		g_ulDetectionParseDbg = DETECTION_DEBUGTYPE_ERR ;
		g_ulDetectionDbg = DETECTION_DEBUGTYPE_ERR ;
	}
	
	pstPg = (DETECTION_PORTGROUP_S*)Detection_GlobalMalloc (sizeof(DETECTION_PORTGROUP_S), DETECTION_MEM_TAG);
	if(pstPg == NULL)
	{
		DETECTION_PARSER_DEBUG(DETECTION_DEBUGTYPE_ERR,  " Fail to malloc for DETECTION_PORTGROUP_S\n"); 
		return DETECTION_ERR;
	}

	pstPg->pvPgPatData  = Detection_Common_MpseNew(DETECTION_COMMON_MPSE_AC_BNFA, DETECTION_COMMON_MPSE_INCREMENT_GLOBAL_CNT,
			Detection_Detect_DeletePMX );
	if( pstPg->pvPgPatData   == NULL )
	{
		Detection_GlobalFree(pstPg);
		DETECTION_PARSER_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "%s:mpseNew failed\n", __FUNCTION__);
		return DETECTION_ERR;
	}

	Detection_Common_MpseSetOpt(pstPg->pvPgPatData,1);

	
	int i;
	char * pcpattern_data[4] = {"test", "hello", "yes", "what"};

	for(i = 0; i < 4; i++){
		Detection_Common_MpseAddPattern( pstPg->pvPgPatData,
					pcpattern_data[i],
					strlen(pcpattern_data[i]),
					0,
					1, 
					0,
					pcpattern_data[i],
					i);

		if(Detection_Common_MpsePrepPatterns( pstPg->pvPgPatData ))
		{
			/* 编译失败,释放模式匹配数据结构 */
			Detection_Common_MpseFree( pstPg->pvPgPatData );
			pstPg->pvPgPatData = NULL;
			Detection_GlobalFree( pstPg ); 
			DETECTION_PARSER_DEBUG(DETECTION_DEBUGTYPE_PROCESS, "%s: MpsePrepPatterns failed\n", __FUNCTION__);
			return DETECTION_ERR;
		}
	}

	Detection_Common_MpsePrintInfo( pstPg->pvPgPatData );


	Detection_Common_MpseSearch(pstPg->pvPgPatData, argv[1], strlen(argv[1]), NULL, NULL, 0);

	return DETECTION_OK;
	
}



