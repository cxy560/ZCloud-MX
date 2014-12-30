/**
******************************************************************************
* @file     zc_cloud_event.c
* @authors  cxy
* @version  V1.0.0
* @date     10-Sep-2014
* @brief    Event
******************************************************************************
*/
#include <zc_cloud_event.h>
#include <zc_protocol_controller.h>

/*************************************************
* Function: EVENT_BuildEmptyMsg
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
u32  EVENT_BuildEmptyMsg(u8 u8MsgId, u8 *pu8Msg, u16 *pu16Len)
{
    ZC_MessageHead *pstruMsg = NULL;
    u16 crc = 0;
    pstruMsg = (ZC_MessageHead *)pu8Msg;
    pstruMsg->MsgCode = ZC_CODE_EMPTY;
    pstruMsg->MsgId = u8MsgId;  
    pstruMsg->OptNum = 0;  
    pstruMsg->Payloadlen = 0;
    pstruMsg->Version = ZC_VERSION;

    crc = crc16_ccitt((u8*)(pstruMsg+1), 0);
    pstruMsg->TotalMsgCrc[0]=(crc&0xff00)>>8;
    pstruMsg->TotalMsgCrc[1]=(crc&0xff);

    *pu16Len = sizeof(ZC_MessageHead);
    return ZC_RET_OK;
}

/*************************************************
* Function: EVENT_BuildHeartMsg
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
u32  EVENT_BuildHeartMsg(u8 *pu8Msg, u16 *pu16Len)
{
    ZC_MessageHead *pstruMsg = NULL;
    u16 crc = 0;
    pstruMsg = (ZC_MessageHead *)pu8Msg;
    pstruMsg->MsgCode = ZC_CODE_HEARTBEAT;
    pstruMsg->MsgId = 0;  
    pstruMsg->Payloadlen = 0;
    pstruMsg->Version = ZC_VERSION;
    pstruMsg->OptNum = 0;      
    crc = crc16_ccitt((u8*)(pstruMsg+1), 0);
    pstruMsg->TotalMsgCrc[0]=(crc&0xff00)>>8;
    pstruMsg->TotalMsgCrc[1]=(crc&0xff);

    *pu16Len = sizeof(ZC_MessageHead);
    return ZC_RET_OK;
}

/*************************************************
* Function: EVENT_BuildMsg
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
u32  EVENT_BuildMsg(u8 u8MsgCode, u8 u8MsgId, u8 *pu8Msg, u16 *pu16Len, u8 *pu8Payload, u16 u16PayloadLen)
{
    ZC_MessageHead *pstruMsg = NULL;
    u16 crc = 0;
    pstruMsg = (ZC_MessageHead *)pu8Msg;
    pstruMsg->MsgCode = u8MsgCode;
    pstruMsg->MsgId = u8MsgId;  
    pstruMsg->Payloadlen = ZC_HTONS(u16PayloadLen);
    pstruMsg->Version = ZC_VERSION;
    pstruMsg->OptNum = 0;  
    crc = crc16_ccitt(pu8Payload,u16PayloadLen);
    pstruMsg->TotalMsgCrc[0]=(crc&0xff00)>>8;
    pstruMsg->TotalMsgCrc[1]=(crc&0xff);
    memcpy((pu8Msg + sizeof(ZC_MessageHead)), pu8Payload, u16PayloadLen);

    *pu16Len = (u16)sizeof(ZC_MessageHead) + u16PayloadLen;
    return ZC_RET_OK;
}

/*************************************************
* Function: EVENT_BuildBcMsg
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
u32  EVENT_BuildBcMsg(u8 *pu8Msg, u16 *pu16Len)
{
    ZC_BroadCastInfo struBc;
    u8 *pu8DeviceId;
    u16 crc = 0;
    ZC_MessageHead *pstruMsg = NULL;
    pstruMsg = (ZC_MessageHead *)pu8Msg;
    pstruMsg->MsgCode = ZC_CODE_BC_INFO;
    pstruMsg->MsgId = 0;
    pstruMsg->Payloadlen = ZC_HTONS(sizeof(ZC_BroadCastInfo));
    pstruMsg->Version = ZC_VERSION;
    pstruMsg->OptNum = 0;      
    g_struProtocolController.pstruMoudleFun->pfunGetStoreInfo(ZC_GET_TYPE_DEVICEID, &pu8DeviceId);

    memcpy(struBc.RandMsg, g_struProtocolController.RandMsg, ZC_HS_MSG_LEN);
    memcpy(struBc.DeviceId, pu8DeviceId, ZC_HS_DEVICE_ID_LEN);
    memcpy((pu8Msg + sizeof(ZC_MessageHead)), &struBc, sizeof(ZC_BroadCastInfo));

    crc = crc16_ccitt((u8*)(pstruMsg + 1), sizeof(ZC_BroadCastInfo));
    pstruMsg->TotalMsgCrc[0]=(crc&0xff00)>>8;
    pstruMsg->TotalMsgCrc[1]=(crc&0xff);

    *pu16Len = (u16)sizeof(ZC_MessageHead)+sizeof(ZC_BroadCastInfo);
    return ZC_RET_OK;

}

/******************************* FILE END ***********************************/
