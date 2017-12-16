  
#ifndef __DETECTION_MOD_H__
#define __DETECTION_MOD_H__

#include <detection/common/detection_com.h>
#include <detection/common/detection_common_portobj.h>
//#include <detection/detect/detection_detect_option_flowbits.h>





#define DETECTION_STATICS_SWITCH    DETECTION_OK

#define  DETECTION_ACCEPT 2
#define  DETECTION_DROP     3



/*****************DETECTION中报文相关的数据结构和接口********************/

/**< packet_flag标志位*/
#define  DETECTION_PKTFLAG_REBUILT_FRAG   0x00000001 	
#define  DETECTION_PKTFLAG_FROM_SERVER    	0x00000040 	
#define  DETECTION_PKTFLAG_FROM_CLIENT     0x00000080 	
#define  DETECTION_PKTFLAG_ALT_DECODE      	0x00000800
#define  DETECTION_PKTFLAG_PREPROC_RPKT   0x00010000 	
#define  DETECTION_PKTFLAG_RPKT         		0x00020000 
#define  DETECTION_PKTFLAG_IP_RULE          	0x00040000 	
#define  DETECTION_PKTFLAG_IP_RULE_2ND     	0x00080000  
#define  DETECTION_PKTFLAG_STATELESS        	0x10000000  
#define  DETECTION_PKTFLAG_LOGGED           	0x80000000  
#define  DETECTION_PKTFLAG_STREAM_EST       0x00000010

#define  DETECTION_PKT_HTTP_DECODE      0x00000100  /* this packet has normalized http */

/*session_flag 的标志 位 */
#define  DETECTION_SSNFLAG_SEEN_CLIENT         0x00000001
#define  DETECTION_SSNFLAG_SEEN_SENDER          DETECTION_SSNFLAG_SEEN_CLIENT
#define  DETECTION_SSNFLAG_SEEN_SERVER         0x00000002
#define  DETECTION_SSNFLAG_SEEN_RESPONDER       DETECTION_SSNFLAG_SEEN_SERVER
#define  DETECTION_SSNFLAG_ESTABLISHED         0x00000004

/**< 解码buff所占的最大长度*/
#define MAX_DECODE_BUF_LEN 65536

/**< URI资源的最大长度*/
#define MAX_URI_BUFF_LEN    256

/**< 报文中能够解析的最大URI的个数*/
#define MAX_URI_BUFF_NUM   5

#define HTTP_BUFFER_METHOD 3

/**< 基于流检测时，保存的流窗口的大小*/
#define MAX_FLOW_BUFF_LEN  128

/**< 最大的IP选项的个数*/
#define MAX_DETECTION_IP_OP_NUM   40

#define  DETECTION_MAX_EVENT_MATCH                8   

#define  DETECTION_RULESIDBYSELF_BEGIN  26000 
/************************************END*******************************************/

/************************常用宏定义******************************/
#define  DETECTION_GET_IPH_PROTO(p) p->protocol
#define  DETECTION_GET_IPH_TOS(p) p->pstIphead->tos
#define  DETECTION_GET_IPH_LEN(p) p->pstIphead->tot_len
#define  DETECTION_GET_IPH_TTL(p) p->pstIphead->ttl
#define  DETECTION_GET_IPH_ID(p) p->pstIphead->id
#define  DETECTION_GET_IPH_OFF(p) p->pstIphead->frag_off  

#define  DETECTION_GET_SRC_IP(P) P->pstIphead->saddr
#define  DETECTION_GET_DST_IP(P) P->pstIphead->daddr

#define  DETECTION_IPH_IS_VALID(p) p->pstIphead


#define  DETECTION_IP_HEADER_LEN           20
#define  DETECTION_TCP_HEADER_LEN          20
#define  DETECTION_UDP_HEADER_LEN          8
#define  DETECTION_ICMP_HEADER_LEN         4


#define  DETECTION_HTTP_BUFFER_URI                 0
#define  DETECTION_HTTP_BUFFER_HEADER          1
#define  DETECTION_HTTP_BUFFER_CLIENT_BODY 2
#define  DETECTION_HTTP_BUFFER_METHOD          3
#define  DETECTION_HTTP_BUFFER_COOKIE           4

#define  DETECTION_HTTPURI_PIPELINE_REQ 0x01
/************************************END*******************************************/

enum 
{
     DETECTION_PLUGIN_CLIENTSERVER,
     DETECTION_PLUGIN_DSIZE_CHECK,
     DETECTION_PLUGIN_FRAG_BITS,
     DETECTION_PLUGIN_FRAG_OFFSET,
     DETECTION_PLUGIN_ICMP_CODE,
     DETECTION_PLUGIN_ICMP_ID_CHECK,
     DETECTION_PLUGIN_ICMP_SEQ_CHECK,
     DETECTION_PLUGIN_ICMP_TYPE,
     DETECTION_PLUGIN_IPOPTION_CHECK,
     DETECTION_PLUGIN_IP_ID_CHECK,
     DETECTION_PLUGIN_IP_PROTO_CHECK,
     DETECTION_PLUGIN_IP_SAME_CHECK,
     DETECTION_PLUGIN_IP_TOS_CHECK,
     DETECTION_PLUGIN_PATTERN_MATCH, /* AND match */
     DETECTION_PLUGIN_PATTERN_MATCH_OR, 
     DETECTION_PLUGIN_PATTERN_MATCH_URI,
     DETECTION_PLUGIN_RESPOND,
     DETECTION_PLUGIN_RPC_CHECK,
     DETECTION_PLUGIN_SESSION,
     DETECTION_PLUGIN_TCP_ACK_CHECK,
     DETECTION_PLUGIN_TCP_FLAG_CHECK,
     DETECTION_PLUGIN_TCP_SEQ_CHECK,
     DETECTION_PLUGIN_TCP_WIN_CHECK,
     DETECTION_PLUGIN_TTL_CHECK,
     DETECTION_PLUGIN_BYTE_TEST,
     DETECTION_PLUGIN_PCRE,
     DETECTION_PLUGIN_URILEN_CHECK,
     DETECTION_PLUGIN_DYNAMIC,
     DETECTION_PLUGIN_FLOWBIT,
     DETECTION_PLUGIN_STREAMDSIZE,
     DETECTION_PLUGIN_IPADDRESS,
     DETECTION_PLUGIN_PORTLIST,
     DETECTION_PLUGIN_ENDTAIL,
     DETECTION_PLUGIN_MAX  /* sentinel value */
};

/***************************公共结构体定义***********************************/

/**< 每个httpuri的结构*/
typedef struct stHttpUri
{
    UCHAR *pcUri;                   /**< uri buff 指针，初始化申请*/
    ULONG ulLength;             /**< uri buff 的有效长度*/
    ULONG ulDecodeFlags; 
}  DETECTION_HTTPURI_S;

typedef struct stIpOptions
{
    UCHAR *pucData;
    USHORT usReserve;
    UCHAR   ucCode;
    UCHAR   ucLen;                   /**< length of the data section */
} DETECTION_IP_OPTION_S;


/**************************存储IP 地址信息的结构***********************/
typedef struct stIpAddrNode
{
    ULONG ulIpAddr;       	 /* IP 地址*/
    ULONG ulNetmask;   	 /* 掩码 */
    ULONG ulAddrFlags;	 /* 是否有效的标志 */

    struct stIpAddrNode *pstNext;
	
}  DETECTION_IPADDRNODE_S;


typedef struct stIpAddrSet
{
     DETECTION_IPADDRNODE_S *pstIpList;        		/*不带!  号的ip 结构链表*/
     DETECTION_IPADDRNODE_S *pstNegIpList;  		/* 带! 号的ip 结构链表*/
}  DETECTION_IPADDRSET_S;


/***********************************TAGDATA 结构定义**************/
typedef struct stTagData
{
    ULONG ulTagType;       
    ULONG ulTagSeconds;    
    ULONG ulTagPackets;    
    ULONG ulTagBytes;      
    ULONG ulTagMetric;   
    ULONG ulTagDirection; 
}  DETECTION_TAGDATA_S;



/****************************SIGINFO 结构定义**********************/
typedef struct stOtnKey
{
   ULONG ulGenerator;
   ULONG ulId;
   
} DETECTION_OTNKEY_S;

typedef struct stSigInfo
{
    ULONG  ulGenerator;       /*特征类id号*/
    ULONG  ulId;	                /*特征id号*/
    ULONG  ulRev;                  /*特征版本号*/
    ULONG  ulClassId;            /*特征分类id*/    
    ULONG  ulPriority;            /*特征优先级*/
    ULONG  warnlevel;	      /*特征规则报警级别*/	 
    CHAR   *pcMessage;         /*特征选项中的msg选项*/
    CHAR    *detail;	
    CHAR 	*group;			/*当前规则所描述的应用协议的组名称*/	 		
    ULONG ulAppProtoId;		/*当前规则所描述的应用协议的ID*/		
    ULONG	ulGroupId;		/*当前规则所描述的应用协议的组ID*/    
    ULONG   ulShared;            	/*动态共享标志*/
    ULONG   ulRuleType;        	/*特征类型*/
    ULONG   ulRuleFlushing; 
    DETECTION_OTNKEY_S  stOtnKey;        
    ULONG ulCheckNum; 		/* 链接上最多检查数据包的个数 */
}  DETECTION_SIGINFO_S;

struct stOptAppTreeNode;       /**< 预先声明 */
struct stAppRuleTreeNode;     /**< 预先声明 */
struct stDetectionPacket;

/**********************特征树结构的内嵌结构***********************************/
 typedef struct stAppRuleFpList
{
    VOID     *pvContext;
    ULONG  (*pulFuncRuleHead)(struct stDetectionPacket *, struct stAppRuleTreeNode *, struct stAppRuleFpList *);
    struct stAppRuleFpList *pstNext;
	
}  DETECTION_RULEFPLIST_S;


 typedef struct stAppOptFpList
{
    VOID     *pvContext;
    ULONG   (*pulFuncOptTest)(struct stDetectionPacket *, struct stOptAppTreeNode *, struct stAppOptFpList *,SESSION_DETECTIONDETECTINFO_S *);
    struct    stAppOptFpList  *pstNext;
    ULONG   ulIsRelative;
    ULONG   ulOptionType;
    
}  DETECTION_OPTFPLIST_S;


typedef struct stAppRspFpList
{
    ULONG   (*pulFuncResponse)(struct stDetectionPacket *, struct stAppRspFpList *);
    VOID     *pvParams; 
    struct    stAppRspFpList *pstNext;
    
}  DETECTION_RSPFPLIST_S;


/*********************特征树第四层链表结构定义************************/
typedef struct stOptAppTreeNode
{
     DETECTION_OPTFPLIST_S    *pstOptFunc;   			/**< 由检测部分实现*/        
     DETECTION_RSPFPLIST_S    *pstRspFunc;   			/**< 由检测部分实现*/  
	
//     DETECTION_OUTPUTFUNCNODE_S *pstOutputFuncs;  /**< 每个特征使能的插件*/     
    
    VOID           *pvDslist[ DETECTION_PLUGIN_MAX];      	/**< 各插件的链表，下标用对应插件名表示*/         
    ULONG          ulChainNodeNumber;              			/**< 特征树第四层链表结点数*/        
    ULONG          ulType;                                    			/**< 规则类型标志 */         
    ULONG          ulEvalIndex;                           			/**< 循环中的计数变量 */        
    ULONG          ulProto;                                  			/**<  特征中使用的协议类型*/        
    struct stAppRuleTreeNode *pstProtoNode;         		/**< 特征树第三层链表结点*/    
    
     DETECTION_SIGINFO_S   stSigInfo;                          	/**< 元数据结构，即可见数据中附带的不可见数据*/    

    CHAR           *pcLogto;
    UCHAR           ucStateless;      
    UCHAR           ucEstablished;     
    UCHAR           ucUnEstablished;    
    UCHAR           ucFailedCheckBits;                			/**< 由检测部分填充*/    
//    UCHAR           ucGenerated;                				

     DETECTION_TAGDATA_S        *pstTag;                     	/**< 特征选项中tag选项相关的结构*/    
    struct stOptAppTreeNode *pstNext;    
    struct stAppRuleTreeNode *pstRtn;                    		/**< 特征树第三层链表结点结构*/    
    struct stOptAppTreeNode *pstNextSoid;                 		/**< 连接指针*/    
    ULONG   ulPcreFlag;                                    			/**< pcre标志*/    
	
}  DETECTION_OPTTREENODE_S;

/*********************特征树第三层链表结构定义************************/

struct stAppProtoList;


typedef struct stAppRuleTreeNode
{
     DETECTION_RULEFPLIST_S   *pstRuleFunc;   			/*特征头检测函数链表指针*/
    ULONG                      ulHeadNodeNumber; 			/*特征链表头的编号*/
    ULONG                      ulType;            					/*特征类型（log,alert等）*/
     DETECTION_IPADDRSET_S    *pstSip;            			/*特征中的源ip地址结构*/
     DETECTION_IPADDRSET_S    *pstDip;        		 	/*特征中的目标ip地址结构*/
    ULONG                      ulProto;						/*特征中的协议类型*/
    char			      *ptrProtocol;	
    DETECTION_PORTOBJECT_S * pstSrcPortObject;		/*特征中的源端口对应的端口对象*/
    DETECTION_PORTOBJECT_S * pstDstPortObject; 		/*特征中的目标端口对应的端口对象*/

    ULONG   ulNotSpFlag;        							/*特征中的源端口带！号的标志*/
    ULONG   ulHsp;            							/*特征中的高位源端口*/
    ULONG   ulLsp;            							/*特征中的低位源端口*/
    ULONG   ulNotDpFlag;        							/*特征中的目标端口带！号的标志*/
    ULONG   ulHdp;           								/*特征中的高位目标端口*/
    ULONG   ulLdp;           								/*特征中的低位目标端口*/
    ULONG   ulFlags;          							/*特征中的解析源端口和目的端口的标志*/
    struct stAppRuleTreeNode *pstRight;  
     DETECTION_OPTTREENODE_S   *pstDown;        		/*指向选项链表*/
    struct stAppProtoList   *pstProtoList;   				/*指向上层链表结构*/
    
}  DETECTION_RULETREENODE_S; /*特征树第三层链表结构*/


/************特征树第二层链表结构定义*******************/
typedef struct stAppProtoList
{        
     DETECTION_RULETREENODE_S    *pstTcpList; 		/*使用tcp协议的特征信息链表*/
     DETECTION_RULETREENODE_S    *pstUdpList;   		/*使用udp协议的特征信息链表*/
     DETECTION_RULETREENODE_S    *pstIcmpList; 		/*使用icmp协议的特征信息链表*/
     DETECTION_RULETREENODE_S    *pstIpList;    		/*使用ip协议的特征信息链表*/	 
     DETECTION_RULETREENODE_S    *pstSshList;    		/*使用ssh协议的特征信息链表*/	
     DETECTION_RULETREENODE_S    *pstDnsList;    		/*使用dns协议的特征信息链表*/			
     DETECTION_RULETREENODE_S    *pstTelnetList;    	/*使用telnet协议的特征信息链表*/		
     DETECTION_RULETREENODE_S    *pstSmtpList;    		/*使用smtp协议的特征信息链表*/	
     DETECTION_RULETREENODE_S    *pstFtpList;    		/*使用ftp协议的特征信息链表*/	
     DETECTION_RULETREENODE_S    *pstHttpList;   		/*使用http协议的特征信息链表*/	 
  //  struct stOutputFuncNode  *pstAlertList;  			/*解析模块只做了初始化*/
    struct stRuleListNode      * pstRuleListNode; 			/*解析模块只做了初始化*/
}  DETECTION_PROTOLIST_S; 



/************特征树首层链表结构定义*******************/
typedef struct stRuleListNode
{
     DETECTION_PROTOLIST_S *pstRuleList;           		/* 特征树下层链表结构指针 */
    ULONG   ulMode;                  						/* 规则模式 */
    ULONG    ulRval;                   						/* 是否有事件发生的标志*/
    ULONG    ulEvalIndex;              						/* 规则索引 */
    CHAR    *pcName;                						/* 该规则链表的名称*/
    struct stRuleListNode *pstNext;  
}  DETECTION_RULELISTNODE_S; 				/*特征树首层链表结构*/

/******************PortGroup  相关结构定义********************/
typedef struct stRuleNode {
  struct  stRuleNode * pstRnNext;
  VOID * pvRuleData;  								/*存放的是OTNX*/
  ULONG ulRuleNodeID;
} DETECTION_RULENODE_S;

/*********************PortGroup  结构定义***********************/
typedef struct 
{
    DETECTION_RULENODE_S *pstPgHead, *pstPgTail, *pstPgCur;  			/*   Content 规则链表*/
    ULONG   ulPgContentCount;              									/*   链表中的规则总数*/
    DETECTION_RULENODE_S *pstPgHeadNC, *pstPgTailNC, *pstPgCurNC;  	/*   No-Content 规则链表*/
    ULONG   ulPgNoContentCount;                   							/*   链表中的规则总数*/
    DETECTION_RULENODE_S *pstPgUriHead, *pstPgUriTail, *pstPgUriCur;     /*    Uri-Content规则链*/
    ULONG  ulPgUriContentCount;                        							/*    链表中的规则总数   */ 
    VOID * pvPgPatData;        											/*    精确模式匹配数据结构*/
    VOID * pvPgPatDataUri;
    ULONG ulAvgLen;  
    ULONG ulMinLen;
    ULONG ulMaxLen;
    ULONG ulC1,ulC2,ulC3,ulC4,ulC5;
    DETECTION_BITOP_S stBoRuleNodeID;
    ULONG ulPgCount;
    ULONG ulPgNQEvents;
    ULONG ulPgQEvents;
} DETECTION_PORTGROUP_S;



/************************OTNX 结构定义*******************/
typedef struct stOtnx{
    DETECTION_OPTTREENODE_S   * pstOtn;
    DETECTION_RULETREENODE_S  * pstRtn; 
   ULONG   ulContentLength;
}  DETECTION_OTNX_S;

/*************************omd 结构定义********************/
typedef struct {
  DETECTION_OTNX_S  *pstMatchArray[ DETECTION_MAX_EVENT_MATCH]; 		
 ULONG  ulMatchCount; 												/*匹配的事件个数*/
 ULONG  ulMatchIndex; 												/*保存最高优先级的事件索引, 代码中没有用到*/
 ULONG  ulMatchMaxLen;											/*保存pstMatchArray数组中的content的最大长度, 代码中没有用到*/
} DETECTION_MATCHINFO_S;


typedef struct stOtnxMatchData
{
    DETECTION_PORTGROUP_S * pstPg;  			/* 被匹配端口组*/
    struct stDetectionPacket * pstPacket;           		/* 被检测报文*/
    ULONG   ulCheckPorts;      												
     DETECTION_MATCHINFO_S  stMatchInfo;		/* 匹配信息*/
}  DETECTION_OTNXMATCHDATA_S;


typedef struct stOmdsession{
   DETECTION_OTNXMATCHDATA_S * pstOmd;  					/* 保存检测结果 */
   SESSION_DETECTIONDETECTINFO_S* pstSessionInfo;
} DETECTION_OMDSESSION_S;  						/*为了避免函数参数变化,将两个结构体封装在一起*/



typedef struct stDetectionPacket
{
     DETECTION_HTTPURI_S       stUriContent[MAX_URI_BUFF_NUM]; 			/**< uri buffer的结构*/
     DETECTION_IP_OPTION_S    stIpOptions[MAX_DETECTION_IP_OP_NUM]; 	/**< IP选项的结构*/
     DETECTION_OTNXMATCHDATA_S  stOmd;  							/* 保存检测结果 */
     SESSION_DETECTIONDETECTINFO_S * session; 	
    struct sk_buff           *pstPkb;                                            /**< 原始的PKB指针*/
    struct iphdr       *pstIphead;                                             /**< IP头的指针*/
    struct ip6_hdr   *pstIp6head; 	
    struct tcphdr    *pstTcphead ;                                          /**< 非本协议时，对应的协议指针为空*/
    struct udphdr    *pstUdphead;
    struct icmphdr  *pstIcmphead;
    const UCHAR   *pucData;                                                /**< 非分片包的负载*/
    UCHAR *pucIpData;                                                       /**< 报文的IP指针的位置，用于匹配IP规则时使用*/
    USHORT usIpVersion;
    ULONG ulDataLen ;                                                         /**< 负载长度*/
    ULONG ulAltDsize ;                                                         /**< decode buff的长度*/
    ULONG ulUriCount;                                                         /**< 报文中包含的uri内容的个数*/
    ULONG ulPacketFlag ;                                                    /**< 报文的标志*/
    ULONG ulIpDataLen ;                                                     /**< IP负载的长度，用于匹配IP规则时使用*/
    UCHAR * pucDoePtr ;                                                    /* 模式匹配的指针偏移 */
    ULONG ulIPOption_num;		                                  /*IP选项的个数*/
    ULONG ulDoDetectContent;                                          /*需要赋值*/
    USHORT usSrcPort;                                                      
    USHORT usDstPort;                                                      	
    USHORT protocol;							/*协议类型*/
    USHORT usDetetionType;	
  
} DETECTION_PACKET_S;


#endif /* __ DETECTION_MOD_H__ */

