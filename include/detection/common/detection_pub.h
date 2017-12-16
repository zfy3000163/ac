#ifndef _DETECTION_PUB_H__
#define _DETECTION_PUB_H__

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>


/*
typedef char CHAR;                
typedef unsigned char UCHAR;      
typedef short int SHORT;          
typedef unsigned short int USHORT;
typedef long LONG;                
typedef unsigned long ULONG;      
typedef unsigned long long ULLONG;
*/

typedef int8_t CHAR;                
typedef uint8_t UCHAR;      
typedef int16_t SHORT;          
typedef uint16_t USHORT;
typedef int32_t LONG;                
typedef uint32_t ULONG;      
typedef uint64_t ULLONG;

typedef float FLOAT;              
typedef double DOUBLE;            
typedef void VOID;                
typedef unsigned long BOOL;       



enum DETECTION_DETECT_MOD
{
	DETECTION_DETECT_IDS = 0,
	DETECTION_DETECT_APP = 1
};

#endif   

