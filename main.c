
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
	ULONG   ulExceptionFlag;  /*�Ƿ�ʹ����ȡ������*/
	LONG    lOffset;              /* ƥ������*/
	LONG     lDepth;              /* ƥ��ĳ���*/
	LONG     lDistance;          /*  �������һ��contentѡ��ƥ��ɹ��Ĵ�β�ټӶ����ֽڿ�ʼ����*/
	LONG     lWithin;             /*  ��depth���ƣ�ֻ�������������һ��contentѡ��ƥ��ɹ��Ĵ�β��distanceѡ��ָ�����ֽ�����������������������صĿ�ͷ*/
	ULONG   ulRawbytes;        /*  ��ԭʼ�����в���*/
	ULONG   ulNocase;             
	ULONG   ulUseDoe;           /* ����ʱʹ��doe_ptr*/
	ULONG   ulUriBuffer;        /*  URI buffer����*/
	ULONG   ulPatternSize;    /*ƥ���ַ�������*/
	ULONG   ulReplaceSize;     
	CHAR   *pcReplaceBuf;      
	CHAR   *pcPatternBuf;     /* ����ƥ���ģʽ�ַ���*/
	ULONG (*pulFunsearch)(const CHAR *, LONG, struct stAppPatternMatchData *,UCHAR **);  /*ָ��ģʽƥ�亯����ָ�룬������õ�ʱB-M�ַ���ƥ���㷨*/
	LONG  *lSkipStride;     /* B-M�㷨����ת����*/
	LONG  *lShiftStride;     /*B-M�㷨����λ����*/
	ULONG   ulPatternMaxJumpSize;
	struct stAppPatternMatchData *pstNext; /* ָ����һ��ģʽƥ��ṹ*/
	ULONG   ulFlags;               /* flags */
	DETECTION_OPTFPLIST_S *pstFpl;     /*   ѡ��ƥ������ָ��*/
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
			/* ����ʧ��,�ͷ�ģʽƥ�����ݽṹ */
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



