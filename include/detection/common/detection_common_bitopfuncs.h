
  
#ifndef __DETECTION_COMMON_BITOPFUNCS_H__
#define __DETECTION_COMMON_BITOPFUNCS_H__


#include <detection/common/detection_com.h>

#include <detection/common/detection_common_mem.h>

typedef struct stBITOP {
    UCHAR *pucBitBuffer;
    ULONG  ulBitBufferSize;
    ULONG  ulMaxBits;
} DETECTION_BITOP_S;



static INLINE ULONG Detection_Common_BoInitStaticBITOP(DETECTION_BITOP_S *pstBitOp,ULONG ulBytes,UCHAR *pucBuf)
{
    if(ulBytes < 1 || !pucBuf || !pstBitOp)
        return 1;

    pstBitOp->pucBitBuffer   = pucBuf;
    pstBitOp->ulBitBufferSize = (ULONG)ulBytes;
    pstBitOp->ulMaxBits       = (ULONG)(ulBytes << 3);

    MemSet(pucBuf, 0x00, ulBytes);

    return 0;
}

static INLINE ULONG Detection_Common_BoInitBITOP(DETECTION_BITOP_S *pstBitOp, ULONG ulSize)
{
    ULONG ulBytes;

    /*
    **  Sanity check for size
    */
    if((ulSize < 1) || (pstBitOp == NULL))
    {
        return 1;
    }

    /*
    **  Check for already initialized buffer, and
    **  if it is already initialized then we return that it
    **  is initialized.
    */
    if(pstBitOp->pucBitBuffer)
    {
        return 0;
    }

    ulBytes = ulSize >> 3;
    if(ulSize & 7) 
    {
        ulBytes++;
    }

    pstBitOp->pucBitBuffer = (UCHAR  *)Detection_GlobalMalloc(ulBytes, DETECTION_MEM_TAG);
    if(pstBitOp->pucBitBuffer == NULL)
    {
        return 1;
    }
    pstBitOp->ulBitBufferSize = (ULONG)ulBytes;
    pstBitOp->ulMaxBits       = (ULONG)ulSize;

    return 0;
}


static INLINE ULONG Detection_Common_BoResetBITOP(DETECTION_BITOP_S *pstBitOp)
{
    if (pstBitOp == NULL)
        return 1;

    MemSet(pstBitOp->pucBitBuffer, 0x00, pstBitOp->ulBitBufferSize);
    return 0;
}



static INLINE ULONG Detection_Common_BoSetBit(DETECTION_BITOP_S *pstBitOp, ULONG ulPos)
{
    UCHAR  ucMask;

    /*
    **  Sanity Check while setting bits
    */
    if((pstBitOp == NULL) || (pstBitOp->ulMaxBits <= ulPos))
        return 1;

    ucMask = (UCHAR)( 0x80 >> (ulPos & 7));

    pstBitOp->pucBitBuffer[ulPos >> 3] |= ucMask;

    return 0;
}

static INLINE ULONG Detection_Common_BoIsBitSet(DETECTION_BITOP_S *pstBitOp, ULONG ulPos)
{
    UCHAR  ucMask;

    /*
    **  Sanity Check while setting bits
    */
    if((pstBitOp == NULL) || (pstBitOp->ulMaxBits <= ulPos))
        return 0;

    ucMask = (UCHAR)(0x80 >> (ulPos & 7));

    return (ucMask & pstBitOp->pucBitBuffer[ulPos >> 3]);
}

static INLINE void Detection_Common_BoClearBit(DETECTION_BITOP_S *pstBitOp, ULONG ulPos)
{
    UCHAR  ucMask;

    /*
    **  Sanity Check while clearing bits
    */
    if((pstBitOp == NULL) || (pstBitOp->ulMaxBits <= ulPos))
        return;

    ucMask = (UCHAR)(0x80 >> (ulPos & 7));

    pstBitOp->pucBitBuffer[ulPos >> 3] &= ~ucMask;
}


static INLINE VOID Detection_Common_BoFreeBITOP(DETECTION_BITOP_S *pstBitOp)
{
    if((pstBitOp == NULL) || (pstBitOp->pucBitBuffer == NULL))
        return;

    Detection_GlobalFree(pstBitOp->pucBitBuffer);
    pstBitOp->pucBitBuffer = NULL;
}

#endif /* _BITOPT_FUNCS_H_ */

