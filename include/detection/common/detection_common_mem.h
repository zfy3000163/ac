  
#ifndef __DETECTION_COMMON_MEM_H__
#define __DETECTION_COMMON_MEM_H__


#define DETECTION_MEM_TAG 0x01

VOID *Detection_Common_GlobalMalloc(ULONG ulSize, ULONG ulMemTag);
ULONG Detection_Common_GlobalFree(VOID *pvObj);

#if defined(RULE_DETECTION_DEBUG_TOP)
VOID Detection_Common_Mem_Show(CHAR *AppMemInfo);
#endif

#define Detection_GlobalMalloc(ulSize, ulMemTag) Detection_Common_GlobalMalloc(ulSize, ulMemTag)
#define Detection_GlobalFree Detection_Common_GlobalFree

#endif /* __DETECTION_COMMON_MEM_H__ */

