
#ifndef __DETECTION_COMMON_PORTOBJ_H__
#define __DETECTION_COMMON_PORTOBJ_H__

#include  <detection/common/detection_common_list.h>
#include  <detection/common/detection_common_hash.h>
#include  <detection/common/detection_common_bitopfuncs.h>


#define DETECTION_PORT_OBJECT_NOTFLAG 1
#define DETECTION_PORT_OBJECT_PORT  1
#define DETECTION_PORT_OBJECT_RANGE 2
#define DETECTION_PORT_OBJECT_ANY   3

#define DETECTION_SFPO_MAX_LPORTS 500
#define DETECTION_SFPO_MAX_PORTS 65536


#define DETECTION_DETECT_PO_EXTRA_RULE_CNT   25 
#define DETECTION_HASH_INTABLE 2

/*********************PortObjectItem  结构定义******************/
typedef struct stPortObjectItem
 {
    ULONG  ulType; 		/* 端口类型标志，包括任意端口，单个端口和端口范围三种*/
    ULONG  ulFlags;     	/* 端口字符串前有无！号的标志 */
    ULONG  ulHport;   	/* 高位端口*/
    ULONG  ulLport;    	/*低位端口 */
}DETECTION_PORTOBJECTITEM_S;  /*存放基本端口信息的结构类型*/


/*********************portobject  结构定义***********************/
typedef struct { 
    CHAR             * pcName;       			/*端口对象名称*/
    ULONG              ulId;             			/*端口对象的id号*/
    DETECTION_SFLIST_S     * pstItemList; 	/*该端口对象中的端口链表*/
    DETECTION_SFLIST_S     * pstRuleList; 	/*使用该端口对象的规则索引链表*/
    VOID              * pvData;         			/* 存放基于rule-list的端口组（仅限any端口*/
    VOID              (*pvfuncDataFree)(VOID *);/*释放数据函数的指针*/
    ULONG      ulCustomFlag;
}DETECTION_PORTOBJECT_S;


/*********************portobject2 结构定义***********************/
typedef struct  {
    CHAR                *pcName;         			/*优化端口对象名称*/
    ULONG                ulId;               			/*优化端口对象ID */
    DETECTION_SFLIST_S    *pstItemList;  	/*端口及端口范围链表 */
    DETECTION_HASH_S      *pstRuleHash;	 /*以规则在ruleIndexMap中的索引为key值*/
    ULONG                ulPortCnt;      			/*使用该对象的端口总数 */
    DETECTION_BITOP_S     *pstBitop;      	/*使用该对象的端口集合 */
    VOID                 *pvData;           				/*存放基于rule_hash 的端口组 */
    VOID                (*pvfuncDataFree)(VOID *);	/*释放函数*/
}DETECTION_PORTOBJECT2_S;


/*********************porttable 结构定义************************/
typedef struct stPortTable 
{
    DETECTION_SFLIST_S      *pstPoList;    								/* 保存特征中指定源（目标）端口对应的源（目标）端口对象*/
    DETECTION_SFLIST_S      *pstPortLists[DETECTION_SFPO_MAX_PORTS];   	/*端口对象数组，每一个数组元素指向一个端口对象*/
    DETECTION_HASH_S       *pstMpoHash;     							/*存放大优化端口对象和小优化端口对象的哈希表，以端口对象地址为key*/
    DETECTION_HASH_S       *pstMpxoHash;   							/*存放大优化端口对象和小优化端口对象的哈希表，以对象组信息结构为key*/
    DETECTION_SFLIST_S      *pstPlxList;            							/*链表，其结点为存放大（小）端口对象组中端口对象和端口对象个数的结构*/
    DETECTION_PORTOBJECT2_S  *pstPortObject2[DETECTION_SFPO_MAX_PORTS];   /*65536个端口中所有被使用端口对应的优化端口对象数组*/
    ULONG                 ulPgValve;    										/*划分大小端口组的阀值*/
    
}DETECTION_PORTTABLE_S;


/*********************porttables 结构定义************************/
typedef struct stPortTables
{

    DETECTION_PORTTABLE_S * pstTcpSrc, * pstTcpDst;     			/* 存放使用tcp协议并且指定源（目标）端口对应的源（目标）端口对象*/
    DETECTION_PORTTABLE_S * pstUdpSrc, * pstUdpDst;    		/*存放使用udp协议并且指定源（目标）端口对应的源（目标）端口对象*/
    DETECTION_PORTTABLE_S * pstIcmpSrc, * pstIcmpDst;    		/*存放使用icmp协议并且指定源（目标）端口对应的源（目标）端口对象*/	
    DETECTION_PORTTABLE_S * pstIpSrc, * pstIpDst;    			/*存放使用ip协议并且指定源（目标）端口对应的源（目标）端口对象*/ 	
    DETECTION_PORTTABLE_S * pstHttpSrc, * pstHttpDst;    		/*存放使用http协议并且指定源（目标）端口对应的源（目标）端口对象*/ 		
    DETECTION_PORTTABLE_S * pstFtpSrc, * pstFtpDst;    			/*存放使用ftp协议并且指定源（目标）端口对应的源（目标）端口对象*/ 			    
    DETECTION_PORTTABLE_S * pstSmtpSrc, * pstSmtpDst;    		/*存放使用smtp协议并且指定源（目标）端口对应的源（目标）端口对象*/ 		
    DETECTION_PORTTABLE_S * pstTelnetSrc, * pstTelnetDst;    		/*存放使用telnet协议并且指定源（目标）端口对应的源（目标）端口对象*/ 		
//    DETECTION_PORTTABLE_S * pstDnsSrc, * pstDnsDst;    			/*存放使用dns协议并且指定源（目标）端口对应的源（目标）端口对象*/ 			 
    DETECTION_PORTTABLE_S * pstSshSrc, * pstSshDst;    			/*存放使用ssh协议并且指定源（目标）端口对应的源（目标）端口对象*/ 		 	
			
    DETECTION_PORTOBJECT_S * pstTcpAnyany;   				/*使用tcp协议并且源或目标端口是any的特征对应的端口对象*/
    DETECTION_PORTOBJECT_S * pstUdpAnyany;   				/*使用udp协议并且源或目标端口是any的特征对应的端口对象*/
    DETECTION_PORTOBJECT_S * pstIcmpAnyany;   				/*使用Icmp协议并且源或目标端口是any的特征对应的端口对象*/
    DETECTION_PORTOBJECT_S * pstIpAnyany;   					/*使用Ip协议并且源或目标端口是any的特征对应的端口对象*/	
    DETECTION_PORTOBJECT_S * pstHttpAnyany;   				/*使用Http协议并且源或目标端口是any的特征对应的端口对象*/		
    DETECTION_PORTOBJECT_S * pstFtpAnyany;   				/*使用Ftp协议并且源或目标端口是any的特征对应的端口对象*/			
    DETECTION_PORTOBJECT_S * pstSmtpAnyany;   				/*使用Smtp协议并且源或目标端口是any的特征对应的端口对象*/			
    DETECTION_PORTOBJECT_S * pstTelnetAnyany;   				/*使用Telnet协议并且源或目标端口是any的特征对应的端口对象*/			
//    DETECTION_PORTOBJECT_S * pstDnsAnyany;   				/*使用Dns协议并且源或目标端口是any的特征对应的端口对象*/				
    DETECTION_PORTOBJECT_S * pstSshAnyany;   				/*使用Ssh协议并且源或目标端口是any的特征对应的端口对象*/			
	
    DETECTION_PORTOBJECT_S * pstTcpNocontent;   				/*使用tcp协议并且选项中即无content也无uricontent的特征对应的端口对象*/
    DETECTION_PORTOBJECT_S * pstUdpNocontent;   				/*使用udp协议并且选项中即无content也无uricontent的特征对应的端口对象*/
    DETECTION_PORTOBJECT_S * pstIcmpNocontent;   			/*使用Icmp协议并且选项中即无content也无uricontent的特征对应的端口对象*/
    DETECTION_PORTOBJECT_S * pstIpNocontent;   				/*使用Ip协议并且选项中即无content也无uricontent的特征对应的端口对象*/	
    DETECTION_PORTOBJECT_S * pstHttpNocontent;   				/*使用Http协议并且选项中即无content也无uricontent的特征对应的端口对象*/		
    DETECTION_PORTOBJECT_S * pstFtpNocontent;   				/*使用Ftp协议并且选项中即无content也无uricontent的特征对应的端口对象*/			
    DETECTION_PORTOBJECT_S * pstSmtpNocontent;   			/*使用Smtp协议并且选项中即无content也无uricontent的特征对应的端口对象*/			
    DETECTION_PORTOBJECT_S * pstTelnetNocontent;   			/*使用Telnet协议并且选项中即无content也无uricontent的特征对应的端口对象*/				
//    DETECTION_PORTOBJECT_S * pstDnsNocontent;   				/*使用Dns协议并且选项中即无content也无uricontent的特征对应的端口对象*/			
    DETECTION_PORTOBJECT_S * pstSshNocontent;   				/*使用Ssh协议并且选项中即无content也无uricontent的特征对应的端口对象*/				
	
}DETECTION_PORTTABLES_S;


typedef DETECTION_HASH_S  DETECTION_PORTVARTABLE_S;


/**********************存放对象组基本信息的结构********/
typedef struct {
    ULONG  ulCount;
    VOID ** ppvObj;
}DETECTION_PLX_S;


/***********************poparser结构定义****************************/

#define DETECTION_MAX_POPBUFFER_SIZE 256

typedef struct {
    CHAR     *pcStr;      /* 所要解析的字符串 */
    ULONG    ulStrLen;  /* 所解析字符串的长度 */
    ULONG    ulPos;       /* 相当于位置指针 */
    CHAR      cToken[DETECTION_MAX_POPBUFFER_SIZE+4]; 
    ULONG    ulErrFlag;
    DETECTION_PORTVARTABLE_S * pstPvTable;
}DETECTION_POPARSER_S;




extern DETECTION_PORTOBJECTITEM_S * Detection_Common_PortObjectItemNew(VOID);
extern DETECTION_PORTOBJECT_S * Detection_Common_PortObjectNew(VOID);
extern ULONG Detection_Common_PortObjectFree( VOID * pvVoid ) ;
extern DETECTION_PORTOBJECT2_S * Detection_Common_PortObject2New(ULONG ulNrules);
extern VOID Detection_Common_PortObject2Free( VOID * pvVoid ) ;
extern DETECTION_PORTTABLE_S * Detection_Common_PortTableNew(VOID);
extern ULONG Detection_Common_PlxFree(VOID * pvData );
extern VOID Detection_Common_PortTableFree(DETECTION_PORTTABLE_S *pstPortTable);
extern DETECTION_PORTVARTABLE_S * Detection_Common_PortVarTableCreate(VOID);
extern ULONG Detection_Common_PortObjectAddItem( DETECTION_PORTOBJECT_S * pstPo, DETECTION_PORTOBJECTITEM_S * pstPoi, ULONG *pulErrFlag);
extern DETECTION_PORTOBJECT_S * Detection_Common_PortObjectDup( DETECTION_PORTOBJECT_S * pstPo );
extern DETECTION_PORTOBJECT_S * Detection_Common_PortVarTableFind( DETECTION_PORTVARTABLE_S * pstHash, CHAR * pcKeyName );
extern DETECTION_PORTOBJECTITEM_S * Detection_Common_PortObjectItemDup( DETECTION_PORTOBJECTITEM_S * pstPoi);
extern DETECTION_PORTOBJECT2_S * Detection_Common_PortObject2Dup( DETECTION_PORTOBJECT_S * pstPo );
extern VOID Detection_Common_PortObjectPrintPortsRaw(DETECTION_PORTOBJECT_S * pstPo );
extern ULONG Detection_Common_PortObjectHasPort (DETECTION_PORTOBJECT_S * pstPo, ULONG ulPort );
extern ULONG Detection_Common_PortObjectAddPort( DETECTION_PORTOBJECT_S * pstPo, ULONG ulPort, ULONG ulNotFlag );
extern ULONG Detection_Common_PortObjectAddRange( DETECTION_PORTOBJECT_S * pstPo, ULONG ulLport, ULONG ulHport, ULONG ulNotFlag );
extern ULONG Detection_Common_PortObjectAddPortAny( DETECTION_PORTOBJECT_S * pstPo );
extern ULONG Detection_Common_PortObjectHasAny (DETECTION_PORTOBJECT_S * pstPo );
extern ULONG Detection_Common_PortObjectIsPureNot (DETECTION_PORTOBJECT_S * pstPo );
extern CHAR * Detection_Common_PortObjectCharPortArray ( CHAR * pcParray, DETECTION_PORTOBJECT_S * pstPo, ULONG * pulNports );
extern DETECTION_SFLIST_S * Detection_Common_PortObjectItemListFromCharPortArray( CHAR * pcParray, ULONG ulNport );
extern ULONG Detection_Common_PortObjectRemovePorts( DETECTION_PORTOBJECT_S * pstA,  DETECTION_PORTOBJECT_S * pstB );
extern ULONG Detection_Common_PortObjectAddPortObject(DETECTION_PORTOBJECT_S * pstPoDst, DETECTION_PORTOBJECT_S * pstPoSrc, ULONG *pulErrFlag);
extern DETECTION_SFLIST_S * Detection_Common_ListNew(VOID) ;
extern VOID Detection_Common_PortObject2PrintPorts(DETECTION_PORTOBJECT2_S * po );
extern ULONG Detection_Common_PortTableAddObject( DETECTION_PORTTABLE_S *pstPt, DETECTION_PORTOBJECT_S * pstPo );
extern DETECTION_PORTOBJECT_S * Detection_Common_PortObjectDupPorts( DETECTION_PORTOBJECT_S * pstPo );
extern LONG Detection_Common_PortObjectPortCount (DETECTION_PORTOBJECT_S * pstPortObject );
extern ULONG Detection_Common_PortObjectAddRule( DETECTION_PORTOBJECT_S * pstPortObject , ULONG ulRule );
extern DETECTION_PORTOBJECT2_S * Detection_Common_PortObjectAppendEx2(DETECTION_PORTOBJECT2_S * pstPoa, DETECTION_PORTOBJECT_S * pstPob );
extern DETECTION_PORTOBJECT_S * Detection_Common_PortObjectAppend(DETECTION_PORTOBJECT_S * pstPoa, DETECTION_PORTOBJECT_S * pstPob );
extern DETECTION_PORTOBJECT2_S * Detection_Common_PortObject2AppendPortObject(DETECTION_PORTOBJECT2_S * pstPoa, DETECTION_PORTOBJECT_S * pstPob );
extern DETECTION_PORTOBJECT2_S * Detection_Common_PortObject2AppendPortObject2(DETECTION_PORTOBJECT2_S * pstPoa, DETECTION_PORTOBJECT2_S * pstPob );
extern ULONG Detection_Common_PortObjectItemsEqual(DETECTION_PORTOBJECTITEM_S * pstPoia, DETECTION_PORTOBJECTITEM_S * pstPoib );
extern ULONG Detection_Common_PortObjectEqual( DETECTION_PORTOBJECT_S * pstPoa, DETECTION_PORTOBJECT_S *pstPob );
extern ULONG Detection_Common_PortVarTableFree(DETECTION_PORTVARTABLE_S * pstPortVarTbl);



#endif


