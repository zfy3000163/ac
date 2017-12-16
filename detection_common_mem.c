
#include <detection/common/detection_com.h>
#include <detection/common/detection_pub.h>
//#include <detection/common/detection_config.h>
//#include <detection/detect/detection_detect_pub.h>
#include <detection/common/detection_mod.h>
#include <detection/common/detection_debug.h>
#include <detection/common/detection_common_mem.h>


void *Detection_Common_GlobalMalloc(ULONG ulSize, ULONG ulMemTag)
{
	void *tmp;

	tmp = (void *) calloc(ulSize, sizeof(VOID));

	if(tmp == NULL)
	{
		DETECTION_PARSER_DEBUG(DETECTION_DEBUGTYPE_PROCESS,"Unable to allocate memory!  (%lu requested)\n", ulSize);
	}

	return tmp;
}


ULONG Detection_Common_GlobalFree(VOID *pvObj)
{
	ULONG ulBulkSize = 0;
	if(pvObj == NULL)
		return DETECTION_OK;

	free(pvObj);
	pvObj = NULL;


	return DETECTION_OK;
}


