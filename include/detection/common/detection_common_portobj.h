
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

/*********************PortObjectItem  �ṹ����******************/
typedef struct stPortObjectItem
 {
    ULONG  ulType; 		/* �˿����ͱ�־����������˿ڣ������˿ںͶ˿ڷ�Χ����*/
    ULONG  ulFlags;     	/* �˿��ַ���ǰ���ޣ��ŵı�־ */
    ULONG  ulHport;   	/* ��λ�˿�*/
    ULONG  ulLport;    	/*��λ�˿� */
}DETECTION_PORTOBJECTITEM_S;  /*��Ż����˿���Ϣ�Ľṹ����*/


/*********************portobject  �ṹ����***********************/
typedef struct { 
    CHAR             * pcName;       			/*�˿ڶ�������*/
    ULONG              ulId;             			/*�˿ڶ����id��*/
    DETECTION_SFLIST_S     * pstItemList; 	/*�ö˿ڶ����еĶ˿�����*/
    DETECTION_SFLIST_S     * pstRuleList; 	/*ʹ�øö˿ڶ���Ĺ�����������*/
    VOID              * pvData;         			/* ��Ż���rule-list�Ķ˿��飨����any�˿�*/
    VOID              (*pvfuncDataFree)(VOID *);/*�ͷ����ݺ�����ָ��*/
    ULONG      ulCustomFlag;
}DETECTION_PORTOBJECT_S;


/*********************portobject2 �ṹ����***********************/
typedef struct  {
    CHAR                *pcName;         			/*�Ż��˿ڶ�������*/
    ULONG                ulId;               			/*�Ż��˿ڶ���ID */
    DETECTION_SFLIST_S    *pstItemList;  	/*�˿ڼ��˿ڷ�Χ���� */
    DETECTION_HASH_S      *pstRuleHash;	 /*�Թ�����ruleIndexMap�е�����Ϊkeyֵ*/
    ULONG                ulPortCnt;      			/*ʹ�øö���Ķ˿����� */
    DETECTION_BITOP_S     *pstBitop;      	/*ʹ�øö���Ķ˿ڼ��� */
    VOID                 *pvData;           				/*��Ż���rule_hash �Ķ˿��� */
    VOID                (*pvfuncDataFree)(VOID *);	/*�ͷź���*/
}DETECTION_PORTOBJECT2_S;


/*********************porttable �ṹ����************************/
typedef struct stPortTable 
{
    DETECTION_SFLIST_S      *pstPoList;    								/* ����������ָ��Դ��Ŀ�꣩�˿ڶ�Ӧ��Դ��Ŀ�꣩�˿ڶ���*/
    DETECTION_SFLIST_S      *pstPortLists[DETECTION_SFPO_MAX_PORTS];   	/*�˿ڶ������飬ÿһ������Ԫ��ָ��һ���˿ڶ���*/
    DETECTION_HASH_S       *pstMpoHash;     							/*��Ŵ��Ż��˿ڶ����С�Ż��˿ڶ���Ĺ�ϣ���Զ˿ڶ����ַΪkey*/
    DETECTION_HASH_S       *pstMpxoHash;   							/*��Ŵ��Ż��˿ڶ����С�Ż��˿ڶ���Ĺ�ϣ���Զ�������Ϣ�ṹΪkey*/
    DETECTION_SFLIST_S      *pstPlxList;            							/*��������Ϊ��Ŵ�С���˿ڶ������ж˿ڶ���Ͷ˿ڶ�������Ľṹ*/
    DETECTION_PORTOBJECT2_S  *pstPortObject2[DETECTION_SFPO_MAX_PORTS];   /*65536���˿������б�ʹ�ö˿ڶ�Ӧ���Ż��˿ڶ�������*/
    ULONG                 ulPgValve;    										/*���ִ�С�˿���ķ�ֵ*/
    
}DETECTION_PORTTABLE_S;


/*********************porttables �ṹ����************************/
typedef struct stPortTables
{

    DETECTION_PORTTABLE_S * pstTcpSrc, * pstTcpDst;     			/* ���ʹ��tcpЭ�鲢��ָ��Դ��Ŀ�꣩�˿ڶ�Ӧ��Դ��Ŀ�꣩�˿ڶ���*/
    DETECTION_PORTTABLE_S * pstUdpSrc, * pstUdpDst;    		/*���ʹ��udpЭ�鲢��ָ��Դ��Ŀ�꣩�˿ڶ�Ӧ��Դ��Ŀ�꣩�˿ڶ���*/
    DETECTION_PORTTABLE_S * pstIcmpSrc, * pstIcmpDst;    		/*���ʹ��icmpЭ�鲢��ָ��Դ��Ŀ�꣩�˿ڶ�Ӧ��Դ��Ŀ�꣩�˿ڶ���*/	
    DETECTION_PORTTABLE_S * pstIpSrc, * pstIpDst;    			/*���ʹ��ipЭ�鲢��ָ��Դ��Ŀ�꣩�˿ڶ�Ӧ��Դ��Ŀ�꣩�˿ڶ���*/ 	
    DETECTION_PORTTABLE_S * pstHttpSrc, * pstHttpDst;    		/*���ʹ��httpЭ�鲢��ָ��Դ��Ŀ�꣩�˿ڶ�Ӧ��Դ��Ŀ�꣩�˿ڶ���*/ 		
    DETECTION_PORTTABLE_S * pstFtpSrc, * pstFtpDst;    			/*���ʹ��ftpЭ�鲢��ָ��Դ��Ŀ�꣩�˿ڶ�Ӧ��Դ��Ŀ�꣩�˿ڶ���*/ 			    
    DETECTION_PORTTABLE_S * pstSmtpSrc, * pstSmtpDst;    		/*���ʹ��smtpЭ�鲢��ָ��Դ��Ŀ�꣩�˿ڶ�Ӧ��Դ��Ŀ�꣩�˿ڶ���*/ 		
    DETECTION_PORTTABLE_S * pstTelnetSrc, * pstTelnetDst;    		/*���ʹ��telnetЭ�鲢��ָ��Դ��Ŀ�꣩�˿ڶ�Ӧ��Դ��Ŀ�꣩�˿ڶ���*/ 		
//    DETECTION_PORTTABLE_S * pstDnsSrc, * pstDnsDst;    			/*���ʹ��dnsЭ�鲢��ָ��Դ��Ŀ�꣩�˿ڶ�Ӧ��Դ��Ŀ�꣩�˿ڶ���*/ 			 
    DETECTION_PORTTABLE_S * pstSshSrc, * pstSshDst;    			/*���ʹ��sshЭ�鲢��ָ��Դ��Ŀ�꣩�˿ڶ�Ӧ��Դ��Ŀ�꣩�˿ڶ���*/ 		 	
			
    DETECTION_PORTOBJECT_S * pstTcpAnyany;   				/*ʹ��tcpЭ�鲢��Դ��Ŀ��˿���any��������Ӧ�Ķ˿ڶ���*/
    DETECTION_PORTOBJECT_S * pstUdpAnyany;   				/*ʹ��udpЭ�鲢��Դ��Ŀ��˿���any��������Ӧ�Ķ˿ڶ���*/
    DETECTION_PORTOBJECT_S * pstIcmpAnyany;   				/*ʹ��IcmpЭ�鲢��Դ��Ŀ��˿���any��������Ӧ�Ķ˿ڶ���*/
    DETECTION_PORTOBJECT_S * pstIpAnyany;   					/*ʹ��IpЭ�鲢��Դ��Ŀ��˿���any��������Ӧ�Ķ˿ڶ���*/	
    DETECTION_PORTOBJECT_S * pstHttpAnyany;   				/*ʹ��HttpЭ�鲢��Դ��Ŀ��˿���any��������Ӧ�Ķ˿ڶ���*/		
    DETECTION_PORTOBJECT_S * pstFtpAnyany;   				/*ʹ��FtpЭ�鲢��Դ��Ŀ��˿���any��������Ӧ�Ķ˿ڶ���*/			
    DETECTION_PORTOBJECT_S * pstSmtpAnyany;   				/*ʹ��SmtpЭ�鲢��Դ��Ŀ��˿���any��������Ӧ�Ķ˿ڶ���*/			
    DETECTION_PORTOBJECT_S * pstTelnetAnyany;   				/*ʹ��TelnetЭ�鲢��Դ��Ŀ��˿���any��������Ӧ�Ķ˿ڶ���*/			
//    DETECTION_PORTOBJECT_S * pstDnsAnyany;   				/*ʹ��DnsЭ�鲢��Դ��Ŀ��˿���any��������Ӧ�Ķ˿ڶ���*/				
    DETECTION_PORTOBJECT_S * pstSshAnyany;   				/*ʹ��SshЭ�鲢��Դ��Ŀ��˿���any��������Ӧ�Ķ˿ڶ���*/			
	
    DETECTION_PORTOBJECT_S * pstTcpNocontent;   				/*ʹ��tcpЭ�鲢��ѡ���м���contentҲ��uricontent��������Ӧ�Ķ˿ڶ���*/
    DETECTION_PORTOBJECT_S * pstUdpNocontent;   				/*ʹ��udpЭ�鲢��ѡ���м���contentҲ��uricontent��������Ӧ�Ķ˿ڶ���*/
    DETECTION_PORTOBJECT_S * pstIcmpNocontent;   			/*ʹ��IcmpЭ�鲢��ѡ���м���contentҲ��uricontent��������Ӧ�Ķ˿ڶ���*/
    DETECTION_PORTOBJECT_S * pstIpNocontent;   				/*ʹ��IpЭ�鲢��ѡ���м���contentҲ��uricontent��������Ӧ�Ķ˿ڶ���*/	
    DETECTION_PORTOBJECT_S * pstHttpNocontent;   				/*ʹ��HttpЭ�鲢��ѡ���м���contentҲ��uricontent��������Ӧ�Ķ˿ڶ���*/		
    DETECTION_PORTOBJECT_S * pstFtpNocontent;   				/*ʹ��FtpЭ�鲢��ѡ���м���contentҲ��uricontent��������Ӧ�Ķ˿ڶ���*/			
    DETECTION_PORTOBJECT_S * pstSmtpNocontent;   			/*ʹ��SmtpЭ�鲢��ѡ���м���contentҲ��uricontent��������Ӧ�Ķ˿ڶ���*/			
    DETECTION_PORTOBJECT_S * pstTelnetNocontent;   			/*ʹ��TelnetЭ�鲢��ѡ���м���contentҲ��uricontent��������Ӧ�Ķ˿ڶ���*/				
//    DETECTION_PORTOBJECT_S * pstDnsNocontent;   				/*ʹ��DnsЭ�鲢��ѡ���м���contentҲ��uricontent��������Ӧ�Ķ˿ڶ���*/			
    DETECTION_PORTOBJECT_S * pstSshNocontent;   				/*ʹ��SshЭ�鲢��ѡ���м���contentҲ��uricontent��������Ӧ�Ķ˿ڶ���*/				
	
}DETECTION_PORTTABLES_S;


typedef DETECTION_HASH_S  DETECTION_PORTVARTABLE_S;


/**********************��Ŷ����������Ϣ�Ľṹ********/
typedef struct {
    ULONG  ulCount;
    VOID ** ppvObj;
}DETECTION_PLX_S;


/***********************poparser�ṹ����****************************/

#define DETECTION_MAX_POPBUFFER_SIZE 256

typedef struct {
    CHAR     *pcStr;      /* ��Ҫ�������ַ��� */
    ULONG    ulStrLen;  /* �������ַ����ĳ��� */
    ULONG    ulPos;       /* �൱��λ��ָ�� */
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


