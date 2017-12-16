
#ifndef _DETECTION_COM_H__
#define _DETECTION_COM_H__
#include "detection/common/detection_pub.h"

#define DETECTION_OK   0
#define DETECTION_ERR 1

#define INLINE inline

#if (BITS_PER_LONG == 64)
#define ATOM_INC_DETECTION_COUNT(x)  uatomic_inc(&x);
#define ATOM_DEC_DETECTION_COUNT(x)  uatomic_dec(&x); 
#else
pthread_mutex_t _detection_FinishParserRule_lock; 
#define ATOM_INC_DETECTION_COUNT(x) \
pthread_mutex_lock(&_detection_FinishParserRule_lock);\
	x++;\
pthread_mutex_unlock(&_detection_FinishParserRule_lock);\

#define ATOM_DEC_DETECTION_COUNT(x) \
pthread_mutex_lock(&_detection_FinishParserRule_lock);\
x--;\
pthread_mutex_unlock(&_detection_FinishParserRule_lock);\

#endif




extern pthread_mutex_t ids_detection_detec_plugin_lock; 
extern pthread_mutex_t app_detection_detec_plugin_lock; 

#define DETECTION_IDS_DETECT_LOCK  do{\
	pthread_mutex_lock(&ids_detection_detec_plugin_lock);\
}while(0)

#define DETECTION_IDS_DETECT_UNLOCK do{\
	pthread_mutex_unlock(&ids_detection_detec_plugin_lock);\
}while(0)

extern pthread_mutex_t app_detection_detec_plugin_lock; 
#define DETECTION_APP_DETECT_LOCK do{\
	pthread_mutex_lock(&app_detection_detec_plugin_lock);\
}while(0)

#define DETECTION_APP_DETECT_UNLOCK do{\
	pthread_mutex_unlock(&app_detection_detec_plugin_lock);\
}while(0)








/*memory mangement*/
#define MemSet	memset
#define MemCpy	memcpy
#define MemCmp   memcmp
#define MemZero(pAddr, ulSize )   memset(pAddr,0,(__kernel_size_t)(ulSize))

#define FREE_NULL(str)    do { \
    if(str) {free(str); str = NULL;} \
}while(0)

/*string operation*/
#define StrLen strlen
#define StrnCpy strncpy
#define StrCpy strcpy
#define StrCmp strcmp
#define StrnCmp strncmp
#define StrnCat strncat
#define StrCat strcat
#define StrChr strchr
#define StrStr strstr
#define Sprintf sprintf

/*character check and conversion*/
#define IsDigit isdigit
#define IsSpace isspace
#define IsAscii isascii
#define IsAlpha isalpha
#define IsAlnum isalnum
#define IsLower islower
#define IsPrint isprint
#define ToUpper toupper
#define ToLower tolower

/*digital value conversion*/
#define HTONL htonl
#define HTONS htons
#define NTOHL ntohl
#define NTOHS ntohs

/*list operation*/
typedef struct list_head LIST_HEAD_S;
#define ListAdd list_add
#define ListDel list_del
#define ListEntry list_entry
#define LIST_FOR_EACH list_for_each
#define ListHeadInit INIT_LIST_HEAD
#define ListAddTail  list_add_tail
#define LIST_FOR_EACH_ENTRY(pos, head, member, type)				\
	for (pos = list_entry((head)->pstNext, type, member);	\
		     prefetch(pos->member.pstNext), &pos->member != (head); 	\
			 	    pos = list_entry(pos->member.pstNext, type, member))
/*lock operation*/
#define RWLockInit rwlock_init
#define WriteLock write_lock
#define WriteUnlock write_unlock
#define ReadLock read_lock
#define ReadUnlock read_unlock

extern LONG AtoL(const CHAR *pcStr, LONG *plVal);
extern ULONG AtoUl(const CHAR *pcStr, ULONG *pulVal);
extern ULONG Detection_Parser_Flowbits_Getid(char* flowbits);
ULONG Detection_Parser_Flowbits_FreeMap(void);

#endif
