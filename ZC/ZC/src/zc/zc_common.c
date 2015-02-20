/**
******************************************************************************
* @file     zc_common.c
* @authors  cxy
* @version  V1.0.0
* @date     10-Sep-2014
* @brief   
******************************************************************************
*/

#include <zc_common.h>
#include <zc_protocol_controller.h>
#include <zc_sec_engine.h>
 


/*************************************************
* Function: ZC_TraceData
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void ZC_TraceData(u8* pData, u32 Len)
{
    u32 Index;
    if (0 == g_struZcConfigDb.struSwitchInfo.u32TraceSwitch)
    {
        return;
    }
    if (0 == Len)
    {
        return;
    }
    
    ZC_Printf("++++++++++++++++++++++++++++++++++++++++++++++++\n");
    for (Index = 0; Index + 4 < Len; Index = Index + 4)
    {
        ZC_Printf("0x%02x, 0x%02x, 0x%02x, 0x%02x,\n",
            pData[Index],
            pData[Index + 1],
            pData[Index + 2],
            pData[Index + 3]);
    }
    
    for (; Index < Len - 1; Index++)
    {
        ZC_Printf("0x%02x, ", pData[Index]);
    }
    ZC_Printf("0x%02x", pData[Index]);

    ZC_Printf("\n++++++++++++++++++++++++++++++++++++++++++++++++\n");
}

/*************************************************
* Function: ZC_Rand
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void ZC_Rand(u8 *pu8Rand)
{
    u32 u32Rand;
    u32 u32Index; 
    for (u32Index = 0; u32Index < 10; u32Index++)
    {
        u32Rand = rand();
        pu8Rand[u32Index * 4] = ((u8)u32Rand % 26) + 65;
        pu8Rand[u32Index * 4 + 1] = ((u8)(u32Rand >> 8) % 26) + 65;
        pu8Rand[u32Index * 4 + 2] = ((u8)(u32Rand >> 16) % 26) + 65;
        pu8Rand[u32Index * 4 + 3] = ((u8)(u32Rand >> 24) % 26) + 65;        
    }
}


/******************************* FILE END ***********************************/


