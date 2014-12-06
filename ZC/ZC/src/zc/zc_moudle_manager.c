/**
******************************************************************************
* @file     zc_moudle_manager.c
* @authors  cxy
* @version  V1.0.0
* @date     10-Sep-2014
* @brief   
******************************************************************************
*/

#include <zc_common.h>
#include <zc_protocol_controller.h>
#include <zc_module_interface.h>
extern u8 g_u8ClientSendLen;
#ifndef MT7681
extern ZC_UartBuffer g_struUartBuffer;
#endif
/*************************************************
* Function: ZC_DealAppOpt
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
u32 ZC_DealAppOpt(ZC_MessageHead *pstruMsg)
{
    u32 u32Index;
    u32 u32Offset = 0;
    u16 u16RealLen;
    ZC_MessageOptHead *pstruOpt;
    ZC_AppDirectMsg *pstruAppDirect;
    ZC_SendParam struParam;

    u32Offset = sizeof(ZC_MessageHead);
    for (u32Index = 0; u32Index < pstruMsg->OptNum; u32Index++)
    {
        pstruOpt = (ZC_MessageOptHead *)((u8*)pstruMsg + u32Offset);
        if (ZC_OPT_APPDIRECT == ZC_HTONS(pstruOpt->OptCode))
        {
            pstruMsg->OptNum = pstruMsg->OptNum - 1;

            u16RealLen = ZC_HTONS(pstruMsg->Payloadlen)
                            - (sizeof(ZC_MessageOptHead) + ZC_HTONS(pstruOpt->OptLen));

            pstruMsg->Payloadlen = ZC_HTONS(u16RealLen);

            memcpy(g_u8MsgBuildBuffer, (u8*)pstruMsg, u32Offset);

            memcpy(g_u8MsgBuildBuffer + u32Offset, 
                (u8*)pstruMsg + u32Offset + sizeof(ZC_MessageOptHead) + ZC_HTONS(pstruOpt->OptLen),
                (u16RealLen + sizeof(ZC_MessageHead)) - u32Offset);

            pstruAppDirect = (ZC_AppDirectMsg *)(pstruOpt+1);

            g_u8ClientSendLen = u16RealLen + sizeof(ZC_MessageHead);

            struParam.u8NeedPoll = 1;

            g_struProtocolController.pstruMoudleFun->pfunSendToNet(ZC_HTONL(pstruAppDirect->u32AppClientId), g_u8MsgBuildBuffer, g_u8ClientSendLen, &struParam);

            g_u8ClientSendLen = 0;
            return ZC_RET_OK;
        }
        u32Offset += sizeof(ZC_MessageOptHead) + ZC_HTONS(pstruOpt->OptLen);
    }
    
    return ZC_RET_ERROR;

}



/*************************************************
* Function: ZC_RecvDataFromMoudle
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
u32 ZC_RecvDataFromMoudle(u8 *pu8Data, u16 u16DataLen)
{
    ZC_MessageHead *pstrMsg;
    u32 u32RetVal;
    ZC_TraceData(pu8Data, u16DataLen);

    if (0 == u16DataLen)
    {
        return ZC_RET_ERROR;
    }
    
    pstrMsg = (ZC_MessageHead *)pu8Data;

    u32RetVal = ZC_DealAppOpt(pstrMsg);
    if (ZC_RET_OK == u32RetVal)
    {
        return ZC_RET_OK;
    }

    
    switch(pstrMsg->MsgCode)
    {
        case ZC_CODE_DESCRIBE:
        {
            if ((g_struProtocolController.u8MainState >= PCT_STATE_ACCESS_NET) &&
            (g_struProtocolController.u8MainState < PCT_STATE_DISCONNECT_CLOUD)
            )
            {
                PCT_SendNotifyMsg(ZC_CODE_CLOUD_CONNECT);                
                return ZC_RET_OK;
            }
            else if (PCT_STATE_DISCONNECT_CLOUD == g_struProtocolController.u8MainState)
            {
                PCT_SendNotifyMsg(ZC_CODE_CLOUD_DISCONNECT);                
                return ZC_RET_OK;
            }
            
            g_struProtocolController.pstruMoudleFun->pfunStoreInfo((u8*)(pstrMsg + 1), sizeof(ZC_RegisterReq));

            g_struProtocolController.u8MainState = PCT_STATE_ACCESS_NET; 
            
            if (PCT_TIMER_INVAILD != g_struProtocolController.u8RegisterTimer)
            {
                TIMER_StopTimer(g_struProtocolController.u8RegisterTimer);
                g_struProtocolController.u8RegisterTimer = PCT_TIMER_INVAILD;
            }
            break;
        }
        case ZC_CODE_EQ_BEGIN:
        {
            PCT_SendNotifyMsg(ZC_CODE_EQ_DONE);
            if (g_struProtocolController.u8MainState >= PCT_STATE_ACCESS_NET)
            {
                PCT_SendNotifyMsg(ZC_CODE_WIFI_CONNECT);
            }
            break;
        }    
        case ZC_CODE_ZOTA_FILE_BEGIN:
            PCT_ModuleOtaFileBeginMsg(&g_struProtocolController, pstrMsg);
            break;
        case ZC_CODE_ZOTA_FILE_CHUNK:
            PCT_ModuleOtaFileChunkMsg(&g_struProtocolController, pstrMsg);
            break;
        case ZC_CODE_ZOTA_FILE_END:
            PCT_ModuleOtaFileEndMsg(&g_struProtocolController, pstrMsg);
            PCT_SendNotifyMsg(ZC_CODE_ZOTA_END);
            break;
        case ZC_CODE_REST:
            g_struProtocolController.pstruMoudleFun->pfunRest();
            break;
        default:
            PCT_HandleMoudleEvent(pu8Data, u16DataLen);
            break;
    }
    
    return ZC_RET_OK;
}

#ifndef MT7681
/*************************************************
* Function: ZC_AssemblePkt
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
u32 ZC_AssemblePkt(u8 *pu8Data, u32 u32DataLen) 
{
    ZC_MessageHead *pstruMsg;
    u8 u8MagicHead[ZC_MAGIC_LEN] = {0x02,0x03,0x04,0x05};
    u32 u32HeadLen;
    u32 u32MsgLen;
    u32 u32MagicLen = ZC_MAGIC_LEN;

    u32HeadLen = u32MagicLen + sizeof(ZC_MessageHead);
    if (MSG_BUFFER_FULL == g_struUartBuffer.u32Status)
    {
        return ZC_RET_ERROR;
    }
    
    if (MSG_BUFFER_IDLE == g_struUartBuffer.u32Status)
    {

        if (u32DataLen < u32HeadLen)
        {
            memcpy(g_struUartBuffer.u8UartBuffer, pu8Data, u32DataLen);
            g_struUartBuffer.u32Status = MSG_BUFFER_SEGMENT_NOHEAD;
            g_struUartBuffer.u32RecvLen = u32DataLen;
        }
        else
        {
            if (0 != memcmp(pu8Data, u8MagicHead, 4))
            {
                g_struUartBuffer.u32Status = MSG_BUFFER_IDLE;
                g_struUartBuffer.u32RecvLen = 0;
                return ZC_RET_ERROR;
            }
            
            pstruMsg = (ZC_MessageHead *)(pu8Data + u32MagicLen);
            u32MsgLen =  ZC_HTONS(pstruMsg->Payloadlen) + sizeof(ZC_MessageHead) + u32MagicLen;

            if (u32MsgLen > ZC_MAX_UARTBUF_LEN)
            {
                g_struUartBuffer.u32Status = MSG_BUFFER_IDLE;
                g_struUartBuffer.u32RecvLen = 0;
                return ZC_RET_ERROR;
            }

            if (u32MsgLen <= u32DataLen)
            {
                memcpy(g_struUartBuffer.u8UartBuffer, pu8Data, u32MsgLen);
                g_struUartBuffer.u32Status = MSG_BUFFER_FULL;
                g_struUartBuffer.u32RecvLen = u32MsgLen;
            }
            else
            {
                memcpy(g_struUartBuffer.u8UartBuffer, pu8Data, u32DataLen);
                g_struUartBuffer.u32Status = MSG_BUFFER_SEGMENT_HEAD;
                g_struUartBuffer.u32RecvLen = u32DataLen;
            }

        }

        return ZC_RET_OK;

    }

    if (MSG_BUFFER_SEGMENT_HEAD == g_struUartBuffer.u32Status)
    {
        pstruMsg = (ZC_MessageHead *)(g_struUartBuffer.u8UartBuffer + u32MagicLen);
        u32MsgLen = ZC_HTONS(pstruMsg->Payloadlen) + sizeof(ZC_MessageHead) + u32MagicLen;

        if (u32MsgLen <= u32DataLen + g_struUartBuffer.u32RecvLen)
        {
            memcpy((g_struUartBuffer.u8UartBuffer + g_struUartBuffer.u32RecvLen), 
                pu8Data, 
                (u32MsgLen - g_struUartBuffer.u32RecvLen));

            g_struUartBuffer.u32Status = MSG_BUFFER_FULL;
            g_struUartBuffer.u32RecvLen = u32MsgLen;
        }
        else
        {
            memcpy((g_struUartBuffer.u8UartBuffer + g_struUartBuffer.u32RecvLen), 
                pu8Data, 
                u32DataLen);
            g_struUartBuffer.u32RecvLen += u32DataLen;
            g_struUartBuffer.u32Status = MSG_BUFFER_SEGMENT_HEAD;
        }

        return ZC_RET_OK;
    }

    if (MSG_BUFFER_SEGMENT_NOHEAD == g_struUartBuffer.u32Status)
    {
        if ((g_struUartBuffer.u32RecvLen + u32DataLen) < u32HeadLen)
        {
            memcpy((g_struUartBuffer.u8UartBuffer + g_struUartBuffer.u32RecvLen), 
                pu8Data,
                u32DataLen);
            g_struUartBuffer.u32RecvLen += u32DataLen;
            g_struUartBuffer.u32Status = MSG_BUFFER_SEGMENT_NOHEAD;
        }
        else
        {
            memcpy((g_struUartBuffer.u8UartBuffer + g_struUartBuffer.u32RecvLen), 
                pu8Data,
                (u32HeadLen - g_struUartBuffer.u32RecvLen));

            if (0 != memcmp(g_struUartBuffer.u8UartBuffer, u8MagicHead, 4))
            {
                g_struUartBuffer.u32Status = MSG_BUFFER_IDLE;
                g_struUartBuffer.u32RecvLen = 0;
                return ZC_RET_ERROR;
            }

            pstruMsg = (ZC_MessageHead *)(g_struUartBuffer.u8UartBuffer + u32MagicLen);
            u32MsgLen = ZC_HTONS(pstruMsg->Payloadlen) + sizeof(ZC_MessageHead) + u32MagicLen;

            if (u32MsgLen > ZC_MAX_UARTBUF_LEN)
            {
                g_struUartBuffer.u32Status = MSG_BUFFER_IDLE;
                g_struUartBuffer.u32RecvLen = 0;                
                return ZC_RET_ERROR;
            }

            if (u32MsgLen <= u32DataLen + g_struUartBuffer.u32RecvLen)
            {
                memcpy((g_struUartBuffer.u8UartBuffer + g_struUartBuffer.u32RecvLen), 
                    pu8Data,
                    u32MsgLen - g_struUartBuffer.u32RecvLen);
                g_struUartBuffer.u32Status = MSG_BUFFER_FULL;
                g_struUartBuffer.u32RecvLen = u32MsgLen;

            }
            else
            {
                memcpy((g_struUartBuffer.u8UartBuffer + g_struUartBuffer.u32RecvLen), 
                    pu8Data,
                    u32DataLen);
                g_struUartBuffer.u32Status = MSG_BUFFER_SEGMENT_HEAD;
                g_struUartBuffer.u32RecvLen += u32DataLen;
            }

        }

        return ZC_RET_OK;

    }
    return ZC_RET_ERROR;
}


/*************************************************
* Function: HF_Moudlefunc
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void ZC_Moudlefunc(u8 *pu8Data, u32 u32DataLen) 
{
    u32 u32RetVal;
    u32 u32MagicLen = ZC_MAGIC_LEN;

    u32RetVal = ZC_AssemblePkt(pu8Data, u32DataLen);

    if (ZC_RET_ERROR == u32RetVal)
    {
        return;
    }

    if (MSG_BUFFER_FULL == g_struUartBuffer.u32Status)
    {
        ZC_RecvDataFromMoudle(g_struUartBuffer.u8UartBuffer + u32MagicLen, 
            g_struUartBuffer.u32RecvLen - u32MagicLen);
        g_struUartBuffer.u32Status = MSG_BUFFER_IDLE;
        g_struUartBuffer.u32RecvLen = 0;
    }

    return; 
}

#endif
/******************************* FILE END ***********************************/




