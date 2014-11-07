/**
******************************************************************************
* @file     zc_protocol_controller.c
* @authors  cxy
* @version  V1.0.0
* @date     10-Sep-2014
* @brief    protocol controller
******************************************************************************
*/
#include <zc_protocol_controller.h>
#include <zc_sec_engine.h>
#include <zc_module_config.h>
#include <zc_cloud_event.h>
#include <zc_message_queue.h>
#include <zc_protocol_interface.h>
#include <zc_timer.h>


PTC_ProtocolCon  g_struProtocolController;

/*************************************************
* Function: PCT_SendNotifyMsg
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_SendNotifyMsg(u8 u8NotifyCode)
{
    u16 u16Len;
    EVENT_BuildMsg(u8NotifyCode, 0, g_u8MsgBuildBuffer, &u16Len, NULL, 0);
    g_struProtocolController.pstruMoudleFun->pfunSendToMoudle(g_u8MsgBuildBuffer, u16Len);
}

/*************************************************
* Function: PCT_SendHeartMsg
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_SendHeartMsg()
{
    ZC_MessageHead struHeart;
    ZC_SecHead struSecHead;
    u16 u16Len = 0;
    
    EVENT_BuildHeartMsg((u8*)&struHeart, &u16Len);

    /*build sec head*/
    struSecHead.u8SecType = ZC_SEC_ALG_AES;
    struSecHead.u16TotalMsg = ZC_HTONS(u16Len);

    (void)PCT_SendMsgToCloud(&struSecHead, (u8*)&struHeart);

    g_struProtocolController.pstruMoudleFun->pfunSetTimer(PCT_TIMER_SENDHEART, 
        PCT_TIMER_INTERVAL_HEART, &g_struProtocolController.u8HeartTimer);
    
}


/*************************************************
* Function: PCT_Init
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_Init(PTC_ModuleAdapter *pstruAdapter)
{
    g_struProtocolController.pstruMoudleFun = pstruAdapter;
    g_struProtocolController.struCloudConnection.u32Socket = PCT_INVAILD_SOCKET;

    /*config connection type*/
    g_struProtocolController.struCloudConnection.u16Port = ZC_CLOUD_PORT;
    g_struProtocolController.struCloudConnection.u8IpType = ZC_IPTYPE_IPV4;
    g_struProtocolController.struCloudConnection.u8ConnectionType = ZC_CONNECT_TYPE_TCP;

    MSG_Init();
    TIMER_Init();
    
    g_struProtocolController.u8keyRecv = PCT_KEY_UNRECVED;
    g_struProtocolController.u8ReconnectTimer = PCT_TIMER_INVAILD;
    g_struProtocolController.u8SendMoudleTimer = PCT_TIMER_INVAILD;
    g_struProtocolController.u8HeartTimer = PCT_TIMER_INVAILD;
    g_struProtocolController.u8RegisterTimer = PCT_TIMER_INVAILD;

    g_struProtocolController.u8MainState = PCT_STATE_INIT;
    g_struProtocolController.u8EqStart = PCT_EQ_STATUS_OFF;
    
    g_struProtocolController.struOtaInfo.u8NeedReset = PCT_OTA_REST_OFF;    
}
/*************************************************
* Function: PCT_SendEmptyMsg
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_SendEmptyMsg(u8 u8MsgId, u8 u8SecType)
{
    ZC_MessageHead struMsg;
    ZC_SecHead struSecHead;
    u16 u16Len = 0;
    /*build msg*/
    EVENT_BuildEmptyMsg(u8MsgId, (u8*)&struMsg, &u16Len);
    
    /*build sec head*/
    struSecHead.u8SecType = u8SecType;
    struSecHead.u16TotalMsg = ZC_HTONS(u16Len);

    
    (void)PCT_SendMsgToCloud(&struSecHead, (u8*)&struMsg);
}
/*************************************************
* Function: PCT_SendErrorMsg
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_SendErrorMsg(u8 u8MsgId, u8 *pu8Error, u16 u16ErrorLen)
{
    u16 u16Len;
    ZC_SecHead struSecHead;

    EVENT_BuildMsg(ZC_CODE_ERR, u8MsgId, g_u8MsgBuildBuffer, &u16Len, 
        pu8Error, u16ErrorLen);
    
    /*build sec head*/
    struSecHead.u8SecType = ZC_SEC_ALG_AES;
    struSecHead.u16TotalMsg = ZC_HTONS(u16Len);
    
    (void)PCT_SendMsgToCloud(&struSecHead, (u8*)g_u8MsgBuildBuffer);
}

/*************************************************
* Function: PCT_SendCloudAccessMsg1
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_SendCloudAccessMsg1(PTC_ProtocolCon *pstruContoller)
{
    u16 u16Len;
    ZC_SecHead struSechead;
    ZC_HandShakeMsg1 struMsg1;
    u8 *pu8DeviceId;
    u32 u32RetVal;
    
    /*stop reconnection timer*/
    if (PCT_TIMER_INVAILD != pstruContoller->u8ReconnectTimer)
    {
        ZC_Printf("msg1 stop u8ReconnectTimer\n");
        TIMER_StopTimer(pstruContoller->u8ReconnectTimer);
        pstruContoller->u8ReconnectTimer = PCT_TIMER_INVAILD;
    }
    
    pstruContoller->pstruMoudleFun->pfunGetDeviceId(&pu8DeviceId);
    
    memcpy(struMsg1.RandMsg, pstruContoller->RandMsg, ZC_HS_MSG_LEN);
    memcpy(struMsg1.DeviceId, pu8DeviceId, ZC_HS_DEVICE_ID_LEN);
    memcpy(struMsg1.u8Domain, pu8DeviceId + ZC_HS_DEVICE_ID_LEN, ZC_DOMAIN_LEN);

   
    EVENT_BuildMsg(ZC_CODE_HANDSHAKE_1, 1, g_u8MsgBuildBuffer, &u16Len, 
        (u8*)&struMsg1, sizeof(ZC_HandShakeMsg1));
    
    struSechead.u8SecType = ZC_SEC_ALG_RSA;
    struSechead.u16TotalMsg = ZC_HTONS(u16Len);
    
    u32RetVal = PCT_SendMsgToCloud(&struSechead, g_u8MsgBuildBuffer);
    
    if (ZC_RET_ERROR == u32RetVal)
    {
        ZC_Printf("Send Msg1 fail disconnect\n");
        PCT_DisConnectCloud(pstruContoller);
        return;
    }

    ZC_Printf("Send Msg1 \n");
    ZC_TraceData(pstruContoller->RandMsg, ZC_HS_MSG_LEN);

    pstruContoller->u8MainState = PCT_STATE_WAIT_ACCESSRSP;

    
    pstruContoller->pstruMoudleFun->pfunSetTimer(PCT_TIMER_REACCESS, 
        PCT_TIMER_INTERVAL_RECONNECT * 120, &pstruContoller->u8AccessTimer);

}

/*************************************************
* Function: PCT_SendCloudAccessMsg3
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_SendCloudAccessMsg3(PTC_ProtocolCon *pstruContoller)
{
    u16 u16Len;
    ZC_HandShakeMsg3 struMsg3;
    ZC_SecHead struSechead;
    u8 *pu8Vesion;
    
    pstruContoller->pstruMoudleFun->pfunGetVersion(&pu8Vesion);

    memcpy(struMsg3.RandMsg, pstruContoller->RandMsg, ZC_HS_MSG_LEN);
    memcpy(struMsg3.u8EqVersion, pu8Vesion, ZC_EQVERSION_LEN);
    
    /*first set key recv flag*/
    g_struProtocolController.u8keyRecv = PCT_KEY_RECVED;

    EVENT_BuildMsg(ZC_CODE_HANDSHAKE_3, 1, g_u8MsgBuildBuffer, &u16Len, 
        (u8*)&struMsg3, sizeof(ZC_HandShakeMsg3));

    struSechead.u8SecType = ZC_SEC_ALG_AES;
    struSechead.u16TotalMsg = ZC_HTONS(u16Len);

    (void)PCT_SendMsgToCloud(&struSechead, g_u8MsgBuildBuffer);
    
    pstruContoller->u8MainState = PCT_STATE_WAIT_MSG4;
    pstruContoller->pstruMoudleFun->pfunSetTimer(PCT_TIMER_REACCESS, 
        PCT_TIMER_INTERVAL_RECONNECT*10, &pstruContoller->u8AccessTimer);

    return;
}
/*************************************************
* Function: PCT_DisConnectCloud
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_DisConnectCloud(PTC_ProtocolCon *pstruContoller)
{
    pstruContoller->u8MainState = PCT_STATE_DISCONNECT_CLOUD;
    pstruContoller->u8keyRecv = PCT_KEY_UNRECVED;
    MSG_Init();
    PCT_SendNotifyMsg(ZC_CODE_CLOUD_DISCONNECT);
}

/*************************************************
* Function: PCT_ConnectCloud
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_ConnectCloud(PTC_ProtocolCon *pstruContoller)
{
    u32 u32Ret = ZC_RET_OK;
    
    if (PCT_TIMER_INVAILD != pstruContoller->u8ReconnectTimer)
    {
        return;
    }
    
    /*Connect*/
    u32Ret = pstruContoller->pstruMoudleFun->pfunConnectToCloud(&pstruContoller->struCloudConnection);
    if (ZC_RET_OK != u32Ret)
    {
        return;
    }
    /*change state to wait access*/
    pstruContoller->u8MainState = PCT_STATE_WAIT_ACCESS;
    pstruContoller->u8keyRecv = PCT_KEY_UNRECVED;
}
/*************************************************
* Function: PCT_ReconnectCloud
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_ReconnectCloud(PTC_ProtocolCon *pstruContoller)
{
    if (PCT_TIMER_INVAILD != pstruContoller->u8ReconnectTimer)
    {
        ZC_Printf("already reconnected \n");
        return;
    }
    

    MSG_Init();
    g_struProtocolController.u8keyRecv = PCT_KEY_UNRECVED;
    TIMER_Init();
    g_struProtocolController.u8ReconnectTimer = PCT_TIMER_INVAILD;
    g_struProtocolController.u8SendMoudleTimer = PCT_TIMER_INVAILD;
    g_struProtocolController.u8HeartTimer = PCT_TIMER_INVAILD;
    g_struProtocolController.u8MainState = PCT_STATE_INIT;

    pstruContoller->pstruMoudleFun->pfunSetTimer(PCT_TIMER_RECONNECT, 
        PCT_TIMER_INTERVAL_RECONNECT, &pstruContoller->u8ReconnectTimer);
    pstruContoller->struCloudConnection.u32Socket = PCT_INVAILD_SOCKET;
    pstruContoller->u8keyRecv = PCT_KEY_UNRECVED; 
    pstruContoller->u8MainState = PCT_STATE_INIT;
}

/*************************************************
* Function: PCT_SendMoudleTimeout
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_SendMoudleTimeout(PTC_ProtocolCon *pstruProtocolController)
{
    MSG_Buffer *pstruBuffer;
    ZC_MessageHead *pstruMsg;
    ZC_SecHead struHead;
    pstruBuffer = (MSG_Buffer *)pstruProtocolController->pu8SendMoudleBuffer;
    pstruMsg = (ZC_MessageHead*)pstruBuffer->u8MsgBuffer;

    /*Send to Moudle*/
    pstruProtocolController->u8ReSendMoudleNum++;

    ZC_Printf("send moudle timeout, data len = %d\n",pstruBuffer->u32Len);
    if (g_u32LoopFlag == 1)
    {
        struHead.u8SecType = ZC_SEC_ALG_AES;
        struHead.u16TotalMsg = ZC_HTONS(pstruBuffer->u32Len);
        PCT_SendMsgToCloud(&struHead, pstruBuffer->u8MsgBuffer);
        pstruBuffer->u32Len = 0;
        pstruBuffer->u8Status = MSG_BUFFER_IDLE;
        pstruProtocolController->u8SendMoudleTimer = PCT_TIMER_INVAILD;
        pstruProtocolController->u8ReSendMoudleNum = 0;
        return;
    }
    
    if (pstruProtocolController->u8ReSendMoudleNum > PCT_SENDMOUDLE_NUM)
    {
        pstruBuffer = (MSG_Buffer *)pstruProtocolController->pu8SendMoudleBuffer;
        pstruBuffer->u32Len = 0;
        pstruBuffer->u8Status = MSG_BUFFER_IDLE;
        pstruProtocolController->u8SendMoudleTimer = PCT_TIMER_INVAILD;
        pstruProtocolController->u8ReSendMoudleNum = 0;
        
        PCT_SendErrorMsg(pstruMsg->MsgId, NULL, 0);
    }
    else
    {
        pstruProtocolController->pstruMoudleFun->pfunSendToMoudle(pstruBuffer->u8MsgBuffer, 
            pstruBuffer->u32Len);

        pstruProtocolController->pstruMoudleFun->pfunSetTimer(PCT_TIMER_SENDMOUDLE, 
            PCT_TIMER_INTERVAL_SENDMOUDLE, &pstruProtocolController->u8SendMoudleTimer);
    }

}
/*************************************************
* Function: PCT_HandleMoudleEvent
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_HandleMoudleEvent(u8 *pu8Msg, u16 u16DataLen)
{
    MSG_Buffer *pstruBuffer;
    ZC_SecHead struHead;

    if (PCT_TIMER_INVAILD != g_struProtocolController.u8SendMoudleTimer)
    {
        TIMER_StopTimer(g_struProtocolController.u8SendMoudleTimer);
        pstruBuffer = (MSG_Buffer *)g_struProtocolController.pu8SendMoudleBuffer;
        pstruBuffer->u32Len = 0;
        pstruBuffer->u8Status = MSG_BUFFER_IDLE;
        g_struProtocolController.u8SendMoudleTimer = PCT_TIMER_INVAILD;
        g_struProtocolController.u8ReSendMoudleNum = 0;
    }


    struHead.u8SecType = ZC_SEC_ALG_AES;
    struHead.u16TotalMsg = ZC_HTONS(u16DataLen);
    
    (void)PCT_SendMsgToCloud(&struHead, pu8Msg);
    
    return;
}
/*************************************************
* Function: PCT_RecvAccessMsg2
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_RecvAccessMsg2(PTC_ProtocolCon *pstruContoller)
{
    MSG_Buffer *pstruBuffer;
    ZC_MessageHead *pstruMsg;
    ZC_HandShakeMsg2 *pstruMsg2;
 
    pstruBuffer = (MSG_Buffer *)MSG_PopMsg(&g_struRecvQueue);
    if (NULL == pstruBuffer)
    {
        return;
    }

    pstruMsg = (ZC_MessageHead*)pstruBuffer->u8MsgBuffer;
    pstruMsg2 = (ZC_HandShakeMsg2*)(pstruMsg + 1);
    ZC_TraceData((u8*)pstruMsg, ZC_HTONS(pstruMsg->Payloadlen) + sizeof(ZC_MessageHead));

    if (ZC_CODE_HANDSHAKE_2 == pstruMsg->MsgCode)
    {
        TIMER_StopTimer(pstruContoller->u8AccessTimer);
        if (0 == memcmp(pstruMsg2->RandMsg, pstruContoller->RandMsg, ZC_HS_MSG_LEN))
        {
            memcpy(pstruContoller->u8SessionKey, pstruMsg2->SessionKey, ZC_HS_SESSION_KEY_LEN);
            memcpy(pstruContoller->IvRecv, pstruMsg2->SessionKey, ZC_HS_SESSION_KEY_LEN);
            memcpy(pstruContoller->IvSend, pstruMsg2->SessionKey, ZC_HS_SESSION_KEY_LEN);

            PCT_SendCloudAccessMsg3(pstruContoller);
            
            ZC_Printf("Recv Msg2 ok\n");
        }
        else
        {
            PCT_DisConnectCloud(pstruContoller);
            ZC_Printf("Recv Msg2 rand error \n");            
            ZC_TraceData(pstruMsg2->RandMsg, ZC_HS_MSG_LEN);
            ZC_TraceData(pstruContoller->RandMsg, ZC_HS_MSG_LEN);
        }
    }
    
    pstruBuffer->u32Len = 0;
    pstruBuffer->u8Status = MSG_BUFFER_IDLE;
}

/*************************************************
* Function: PCT_RecvAccessMsg4
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_RecvAccessMsg4(PTC_ProtocolCon *pstruContoller)
{
    MSG_Buffer *pstruBuffer;
    ZC_MessageHead *pstruMsg;
    ZC_HandShakeMsg4 *pstruMsg4;
    pstruBuffer = (MSG_Buffer *)MSG_PopMsg(&g_struRecvQueue);
    if (NULL == pstruBuffer)
    {
        return;
    }
    
    pstruMsg = (ZC_MessageHead*)pstruBuffer->u8MsgBuffer;
    pstruMsg4 = (ZC_HandShakeMsg4 *)(pstruMsg + 1);
    ZC_TraceData((u8*)pstruMsg, ZC_HTONS(pstruMsg->Payloadlen) + sizeof(ZC_MessageHead));
    
    if (ZC_CODE_HANDSHAKE_4 == pstruMsg->MsgCode)
    {
        TIMER_StopTimer(pstruContoller->u8AccessTimer);
        if (0 == memcmp(pstruMsg4->RandMsg, pstruContoller->RandMsg, ZC_HS_MSG_LEN))
        {
            pstruContoller->u8MainState = PCT_STATE_CONNECT_CLOUD; 
            ZC_Printf("recv msg4 ok\n");
            PCT_SendNotifyMsg(ZC_CODE_CLOUD_CONNECT);
        }
        else
        {
            PCT_DisConnectCloud(pstruContoller);
            ZC_Printf("Recv msg4 rand error \n");            
            ZC_TraceData(pstruMsg4->RandMsg, ZC_HS_MSG_LEN);
            ZC_TraceData(pstruContoller->RandMsg, ZC_HS_MSG_LEN);
        }

    }
    pstruBuffer->u32Len = 0;
    pstruBuffer->u8Status = MSG_BUFFER_IDLE;

    if (PCT_TIMER_INVAILD != pstruContoller->u8HeartTimer)
    {
        TIMER_StopTimer(pstruContoller->u8HeartTimer);
    }
    pstruContoller->pstruMoudleFun->pfunSetTimer(PCT_TIMER_SENDHEART, 
        PCT_TIMER_INTERVAL_HEART, &pstruContoller->u8HeartTimer);
}
/*************************************************
* Function: PCT_SendAckToCloud
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
void PCT_SendAckToCloud(u8 u8MsgId)
{
    u16 u16Len;
    ZC_SecHead struSechead;

    EVENT_BuildMsg(ZC_CODE_ACK, u8MsgId, g_u8MsgBuildBuffer, &u16Len, NULL, 0);
    struSechead.u8SecType = ZC_SEC_ALG_AES;
    struSechead.u16TotalMsg = ZC_HTONS(u16Len);
    (void)PCT_SendMsgToCloud(&struSechead, g_u8MsgBuildBuffer);
}
/*************************************************
* Function: PCT_HandleOtaBeginMsg
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_HandleOtaBeginMsg(PTC_ProtocolCon *pstruContoller, MSG_Buffer *pstruBuffer)
{
    ZC_MessageHead *pstruMsg;
    ZC_Printf("Ota Begin\n");
    pstruMsg = (ZC_MessageHead*)pstruBuffer->u8MsgBuffer;
    PCT_SendAckToCloud(pstruMsg->MsgId);    
    
    PCT_SendNotifyMsg(ZC_CODE_ZOTA_BEGIN);
    return;
}

/*************************************************
* Function: PCT_HandleOtaFileBeginMsg
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_HandleOtaFileBeginMsg(PTC_ProtocolCon *pstruContoller, MSG_Buffer *pstruBuffer)
{
    ZC_MessageHead *pstruMsg;
    ZC_OtaFileBeginReq *pstruOta;
    ZC_Printf("Ota File Begin\n");
    

    pstruMsg = (ZC_MessageHead*)pstruBuffer->u8MsgBuffer;
    pstruOta = (ZC_OtaFileBeginReq *)(pstruMsg + 1);
    
    pstruContoller->struOtaInfo.u32RecvOffset = 0;
    pstruContoller->struOtaInfo.u32TotalLen = ZC_HTONL(pstruOta->u32FileTotalLen);
    pstruContoller->struOtaInfo.u8Crc[0] = pstruOta->u8TotalFileCrc[0];
    pstruContoller->struOtaInfo.u8Crc[1] = pstruOta->u8TotalFileCrc[1];    
    PCT_SendAckToCloud(pstruMsg->MsgId);


    return;
}
/*************************************************
* Function: PCT_HandleOtaFileChunkMsg
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_HandleOtaFileChunkMsg(PTC_ProtocolCon *pstruContoller, MSG_Buffer *pstruBuffer)
{
    ZC_MessageHead *pstruMsg;
    ZC_OtaFileChunkReq *pstruOta;
    u32 u32FileLen;
    u32 u32RetVal;
    u32 u32RecvOffset;

    ZC_Printf("Ota File Chunk\n");

    
    pstruMsg = (ZC_MessageHead*)pstruBuffer->u8MsgBuffer;
    pstruOta = (ZC_OtaFileChunkReq *)(pstruMsg + 1);
    u32FileLen = ZC_HTONS(pstruMsg->Payloadlen) - sizeof(ZC_OtaFileChunkReq);
    u32RecvOffset = ZC_HTONL(pstruOta->u32Offset);
    
    /*check para*/
    if ((u32RecvOffset != pstruContoller->struOtaInfo.u32RecvOffset)
        || ((u32RecvOffset + u32FileLen) > pstruContoller->struOtaInfo.u32TotalLen)
      || (u32FileLen > ZC_OTA_MAX_CHUNK_LEN))
    {
        ZC_Printf("recv error %d,%d,%d,%d,\n", u32RecvOffset, 
            pstruContoller->struOtaInfo.u32RecvOffset,
            pstruContoller->struOtaInfo.u32TotalLen,
            u32FileLen);
        PCT_SendErrorMsg(pstruMsg->MsgId, NULL, 0);
        return;
    }
    
    u32RetVal = pstruContoller->pstruMoudleFun->pfunUpdate((u8*)(pstruOta + 1), u32RecvOffset, u32FileLen);
    //u32RetVal = ZC_RET_OK;
    ZC_Printf("offset = %d, len = %d\n", u32RecvOffset, u32FileLen);

    if (ZC_RET_ERROR == u32RetVal)
    {
        ZC_Printf("OTA Fail\n");
        PCT_SendErrorMsg(pstruMsg->MsgId, NULL, 0);
        return;
    }

    /*update file offset*/
    pstruContoller->struOtaInfo.u32RecvOffset = pstruContoller->struOtaInfo.u32RecvOffset + u32FileLen;
    PCT_SendAckToCloud(pstruMsg->MsgId);
}
/*************************************************
* Function: PCT_HandleOtaFileEndMsg
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_HandleOtaFileEndMsg(PTC_ProtocolCon *pstruContoller, MSG_Buffer *pstruBuffer)
{
    ZC_MessageHead *pstruMsg;
    ZC_Printf("Ota File End\n");

    pstruMsg = (ZC_MessageHead*)pstruBuffer->u8MsgBuffer;
    PCT_SendAckToCloud(pstruMsg->MsgId);

}
/*************************************************
* Function: PCT_HandleOtaFileEndMsg
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_HandleOtaEndMsg(PTC_ProtocolCon *pstruContoller, MSG_Buffer *pstruBuffer)
{
    ZC_MessageHead *pstruMsg;
    ZC_Printf("Ota End\n");

    pstruMsg = (ZC_MessageHead*)pstruBuffer->u8MsgBuffer;
    PCT_SendAckToCloud(pstruMsg->MsgId);
    pstruContoller->struOtaInfo.u8NeedReset = PCT_OTA_REST_ON;    

    PCT_SendNotifyMsg(ZC_CODE_ZOTA_END);
    pstruContoller->pstruMoudleFun->pfunUpdateFinish(pstruContoller->struOtaInfo.u32TotalLen);
}

/*************************************************
* Function: PCT_HandleMoudleMsg
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_HandleMoudleMsg(PTC_ProtocolCon *pstruContoller, MSG_Buffer *pstruBuffer)
{
    ZC_MessageHead *pstruMsg;
    pstruMsg = (ZC_MessageHead*)pstruBuffer->u8MsgBuffer;

    /*Send to Moudle*/
    if (0 == g_u32LoopFlag)
    {
        pstruContoller->pstruMoudleFun->pfunSendToMoudle((u8*)pstruMsg, pstruBuffer->u32Len);
    }

    /*start send timer*/
    pstruContoller->pstruMoudleFun->pfunSetTimer(PCT_TIMER_SENDMOUDLE, 
        PCT_TIMER_INTERVAL_SENDMOUDLE, &pstruContoller->u8SendMoudleTimer);

    /*copy buffer, prepare for retx*/
    memcpy((u8*)g_struRetxBuffer.u8MsgBuffer, pstruBuffer->u8MsgBuffer, 
        pstruBuffer->u32Len);

    g_struRetxBuffer.u32Len = pstruBuffer->u32Len;
    g_struRetxBuffer.u8Status = MSG_BUFFER_FULL;

    pstruContoller->pu8SendMoudleBuffer = (u8*)&g_struRetxBuffer;
    pstruContoller->u8ReSendMoudleNum = 0;

    /*restart heart timer*/
    if (PCT_TIMER_INVAILD != pstruContoller->u8HeartTimer)
    {
        TIMER_StopTimer(pstruContoller->u8HeartTimer);
    }

    pstruContoller->pstruMoudleFun->pfunSetTimer(PCT_TIMER_SENDHEART, 
        PCT_TIMER_INTERVAL_HEART, &pstruContoller->u8HeartTimer);

}
/*************************************************
* Function: PCT_HandleEvent
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_HandleEvent(PTC_ProtocolCon *pstruContoller)
{
    MSG_Buffer *pstruBuffer;
    ZC_MessageHead *pstruMsg;
    
    if (PCT_TIMER_INVAILD != pstruContoller->u8SendMoudleTimer)
    {
        return;
    }
    
    pstruBuffer = (MSG_Buffer *)MSG_PopMsg(&g_struRecvQueue);
    if (NULL == pstruBuffer)
    {
        return;
    }
    
    pstruMsg = (ZC_MessageHead*)pstruBuffer->u8MsgBuffer;
    ZC_Printf("event %d recv len =%d\n", pstruMsg->MsgId, ZC_HTONS(pstruMsg->Payloadlen) + sizeof(ZC_MessageHead));
    ZC_TraceData((u8*)pstruMsg, ZC_HTONS(pstruMsg->Payloadlen) + sizeof(ZC_MessageHead));

    switch (pstruMsg->MsgCode)
    {
        case ZC_CODE_ZOTA_BEGIN:
            PCT_HandleOtaBeginMsg(pstruContoller, pstruBuffer);
            break;   
        case ZC_CODE_ZOTA_FILE_BEGIN:
            PCT_HandleOtaFileBeginMsg(pstruContoller, pstruBuffer);
            break;
        case ZC_CODE_ZOTA_FILE_CHUNK:
            PCT_HandleOtaFileChunkMsg(pstruContoller, pstruBuffer);
            break;
        case ZC_CODE_ZOTA_FILE_END:
            PCT_HandleOtaFileEndMsg(pstruContoller, pstruBuffer);
            break;  
        case ZC_CODE_ZOTA_END:
            PCT_HandleOtaEndMsg(pstruContoller, pstruBuffer);
            break; 
        default:
            PCT_HandleMoudleMsg(pstruContoller, pstruBuffer);
            break;                                    
    }

    /*send empty msg to cloud*/
    PCT_SendEmptyMsg(pstruMsg->MsgId, ZC_SEC_ALG_AES);

    pstruBuffer->u32Len = 0;
    pstruBuffer->u8Status = MSG_BUFFER_IDLE;

    
    return;
} 

/*************************************************
* Function: PCT_Run
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_Run()
{
    PTC_ProtocolCon *pstruContoller = &g_struProtocolController;
    switch(pstruContoller->u8MainState)
    {
        case PCT_STATE_SLEEP:
            break;
        case PCT_STATE_INIT:
            /*smart connection*/
            break;
        case PCT_STATE_ACCESS_NET:
            PCT_ConnectCloud(pstruContoller);
            break;
        case PCT_STATE_WAIT_ACCESS:
        	PCT_SendCloudAccessMsg1(pstruContoller);        
            break;
        case PCT_STATE_WAIT_ACCESSRSP:
            PCT_RecvAccessMsg2(pstruContoller);
            break;    
        case PCT_STATE_WAIT_MSG4:
            PCT_RecvAccessMsg4(pstruContoller);
            break;
        case PCT_STATE_CONNECT_CLOUD:
            PCT_HandleEvent(pstruContoller);
            break;                       
    }
    
}
/*************************************************
* Function: PCT_WakeUp
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_WakeUp()
{
    if (PCT_STATE_INIT == g_struProtocolController.u8MainState)
    {
        //g_struProtocolController.u8MainState = PCT_STATE_ACCESS_NET;
        g_struProtocolController.pstruMoudleFun->pfunSetTimer(PCT_TIMER_REGISTER, 
            PCT_TIMER_INTERVAL_REGISTER, &g_struProtocolController.u8RegisterTimer);
        /*Intial Bc send Num*/
        g_struProtocolController.u16SendBcNum = 0;

        PCT_SendNotifyMsg(ZC_CODE_WIFI_CONNECT);
    }
    
}

/*************************************************
* Function: PCT_Sleep
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void PCT_Sleep()
{
    MSG_Init();

    g_struProtocolController.u8keyRecv = PCT_KEY_UNRECVED;

    TIMER_Init();
    g_struProtocolController.u8ReconnectTimer = PCT_TIMER_INVAILD;
    g_struProtocolController.u8SendMoudleTimer = PCT_TIMER_INVAILD;
    g_struProtocolController.u8HeartTimer = PCT_TIMER_INVAILD;
    g_struProtocolController.u8MainState = PCT_STATE_INIT;
    g_struProtocolController.u8RegisterTimer = PCT_TIMER_INVAILD;
    PCT_SendNotifyMsg(ZC_CODE_WIFI_DISCONNECT);
}

/*************************************************
* Function: PCT_SendMsgToCloud
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
u32 PCT_SendMsgToCloud(ZC_SecHead *pstruSecHead, u8 *pu8PlainData)
{
    u32 u32Index;
    u16 u16RemainLen;
    u32 u32RetVal;
    u16 u16Len;
    u16 u16PaddingLen;
    
    u32RetVal = SEC_PaddingCheck(pstruSecHead->u8SecType, ZC_HTONS(pstruSecHead->u16TotalMsg), &u16PaddingLen);
    
    if (ZC_RET_ERROR == u32RetVal)
    {
        return ZC_RET_ERROR;
    }

    u16Len = ZC_HTONS(pstruSecHead->u16TotalMsg) + sizeof(ZC_SecHead) + u16PaddingLen;    
    
    if (u16Len > MSG_CIPER_BUFFER_MAXLEN)
    {
        return ZC_RET_ERROR;
    }

    /*Check send buffer is enough*/
    u16RemainLen = 0;
    for (u32Index = 0; u32Index < MSG_BUFFER_SEND_MAX_NUM; u32Index++)
    {
        if (MSG_BUFFER_IDLE == g_struSendBuffer[u32Index].u8Status)
        {
            u16RemainLen += g_u16TcpMss; 
        }
    }
    
    /*if buffer is enough, return*/
    if (u16Len > u16RemainLen)
    {
        return ZC_RET_ERROR;
    }

    u16Len = ZC_HTONS(pstruSecHead->u16TotalMsg) + u16PaddingLen;

    /*first check padding,then Encrypt, final copy sechead*/
    u32RetVal = SEC_Encrypt(pstruSecHead, g_u8CiperBuffer + sizeof(ZC_SecHead), pu8PlainData, &u16Len);
    
    if (ZC_RET_ERROR == u32RetVal)
    {
        return ZC_RET_ERROR;
    }
    pstruSecHead->u16TotalMsg = ZC_HTONS(u16Len);
    /*copy sechead*/
    memcpy(g_u8CiperBuffer, (u8*)pstruSecHead, sizeof(ZC_SecHead));
    
    /*copy to buffer*/
    u16Len = u16Len + sizeof(ZC_SecHead);
    u16RemainLen = u16Len;
    
    for (u32Index = 0; u32Index < MSG_BUFFER_SEND_MAX_NUM; u32Index++)
    {
        if (MSG_BUFFER_IDLE == g_struSendBuffer[u32Index].u8Status)
        {
            if (u16RemainLen > g_u16TcpMss)
            {
                memcpy(g_struSendBuffer[u32Index].u8MsgBuffer, g_u8CiperBuffer + (u16Len - u16RemainLen), g_u16TcpMss);
                g_struSendBuffer[u32Index].u32Len = g_u16TcpMss;
                g_struSendBuffer[u32Index].u8Status = MSG_BUFFER_FULL;
                MSG_PushMsg(&g_struSendQueue, (u8*)&g_struSendBuffer[u32Index]);
                u16RemainLen -= g_u16TcpMss;
            }
            else
            {
                memcpy(g_struSendBuffer[u32Index].u8MsgBuffer, g_u8CiperBuffer + (u16Len - u16RemainLen), u16RemainLen);
                g_struSendBuffer[u32Index].u32Len = u16RemainLen;
                g_struSendBuffer[u32Index].u8Status = MSG_BUFFER_FULL;
                MSG_PushMsg(&g_struSendQueue, (u8*)&g_struSendBuffer[u32Index]);
                break;
            }
            
        }
    }
    return ZC_RET_OK;
}


/******************************* FILE END ***********************************/
