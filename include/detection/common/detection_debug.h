#ifndef _DETECTION_DEBUG_H__
#define _DETECTION_DEBUG_H__

/*--------------------------------------detection 调试级别-------------------------------*/
/* 调试信息的类型*/
enum DETECTION_CMD_DEBUGTYPE_en
{
    DETECTION_DEBUGTYPE_ERR = 0x01,                 /*错误*/
    DETECTION_DEBUGTYPE_EVENT = 0x02,             /*事件*/
    DETECTION_DEBUGTYPE_PROCESS = 0x04,         /*关键流程*/
    DETECTION_DEBUGTYPE_ETC = 0x08                  /*其他*/
};


extern unsigned long  g_ulDetectionParseDbg;

extern unsigned long  g_ulDetectionDbg;

extern unsigned long  g_PLAYLOAD_DEBUG;

#define IS_DETECTION_DEBUG_ON  (( g_ulDetectionParseDbg & DETECTION_DEBUGTYPE_PROCESS) ==  DETECTION_DEBUGTYPE_PROCESS)



#define RULE_DETECTION_DEBUG_TOP 0
#if defined(RULE_DETECTION_DEBUG_TOP)
/*解析部分的调试宏*/
#define DETECTION_PARSER_DEBUG(ulType, fmt,args...) \
    if(( g_ulDetectionParseDbg & ulType) == ulType)  \
    { \
    	if(DETECTION_DEBUGTYPE_ERR == ulType){\
	        printf(fmt,  ##args); \
    	}\
	else{\
		printf(fmt,  ##args);  \
	}\
    }

/*检测部分的调试宏*/
#define DETECTION_DETECT_DEBUG(ulType, fmt,args...) \
    if( (g_ulDetectionDbg & ulType) == ulType ) \
    {\
        printf(fmt, ##args); \
    }

/*调试信息打印接口*/
#define DETECTION_DEBUG(ulType, fmt,args...) \
    if( (g_ulDetectionDbg & ulType) == ulType ) \
    {\
        printf(fmt, ##args); \
    }	
    
#else
#define DETECTION_PARSER_DEBUG(ulType, fmt,args...) {}
#define DETECTION_DETECT_DEBUG(ulType, fmt,args...) {}
#define DETECTION_DEBUG(ulType, fmt,args...) {}
#endif


#if defined(RULE_DETECTION_DEBUG_TOP)
extern CHAR *g_pcAppFileName;
extern ULONG g_ulAppFileLine ; 
#endif

#endif /* _DETECTION_DEBUG_H__ */

                                                                                     
