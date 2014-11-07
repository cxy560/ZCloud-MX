/**
******************************************************************************
* @file     zc_protocol_controller.h
* @authors  cxy
* @version  V1.0.0
* @date     10-Sep-2014
* @brief    protocol controller
******************************************************************************
*/
#ifndef  __ZC_PROTOCOL_CONTROLLER_H__ 
#define  __ZC_PROTOCOL_CONTROLLER_H__

#include <zc_common.h>
#include <zc_module_config.h>
#include <zc_protocol_interface.h>
#include <zc_message_queue.h>
#include <zc_sec_engine.h>
#include <zc_cloud_event.h>

/*PCT Main State Machine*/
#define    PCT_STATE_SLEEP                  (0)
#define    PCT_STATE_INIT                   (1)
#define    PCT_STATE_ACCESS_NET             (2)
#define    PCT_STATE_WAIT_ACCESS            (3)
#define    PCT_STATE_WAIT_ACCESSRSP         (4)
#define    PCT_STATE_WAIT_MSG4              (5)
#define    PCT_STATE_CONNECT_CLOUD          (6)
#define    PCT_STATE_DISCONNECT_CLOUD       (7)

#define    PCT_INVAILD_SOCKET               (0xFFFFFFFF)

#define    PCT_TIMER_RECONNECT              (0)
#define    PCT_TIMER_REACCESS               (1)
#define    PCT_TIMER_SENDMOUDLE             (2)
#define    PCT_TIMER_SENDHEART              (3)
#define    PCT_TIMER_REGISTER               (4)

#define    PCT_TIMER_INTERVAL_RECONNECT     (1000)
#define    PCT_TIMER_INTERVAL_HEART         (1000 * 15)
#define    PCT_TIMER_INTERVAL_SENDMOUDLE    (1000)
#define    PCT_TIMER_INTERVAL_REGISTER      (1000)


#define    PCT_SEND_BC_MAX_NUM              (300)       /*5 minutes*/


#define    PCT_KEY_UNRECVED     (0)
#define    PCT_KEY_RECVED       (1)

#define    PCT_TIMER_INVAILD        (0xFF)
#define    PCT_SENDMOUDLE_NUM       (4)

#define    PCT_OTA_REST_ON       (1)
#define    PCT_OTA_REST_OFF       (0)

#define    PCT_EQ_STATUS_ON        (1)
#define    PCT_EQ_STATUS_OFF       (0)



typedef struct
{
    u32 u32Socket;
    
    u8  u8IpType;             /*IP Type,IPV6,IPV4*/
    u8  u8ConnectionType;
    u16 u16Port;
}PTC_Connection;

typedef void (*pFunSendDataToCloud)(PTC_Connection *pstruConnection);
typedef u32 (*pFunFirmwareUpdate)(u8 *pu8FileData, u32 u32Offset, u32 u32DataLen);
typedef u32 (*pFunFirmwareUpdateFinish)(u32 u32TotalLen);
typedef u32 (*pFunSendDataToMoudle)(u8 *pu8Data, u16 u16DataLen);
typedef u32 (*pFunRecvDataFromMoudle)(u8 *pu8Data, u16 u16DataLen);
typedef u32 (*pFunGetCloudKey)(u8 **pu8Key);
typedef u32 (*pFunGetPrivateKey)(u8 **pu8Key);
typedef u32 (*pFunGetVersion)(u8 **pu8Version);
typedef u32 (*pFunGetDeviceId)(u8 **pu8DeviceId);
typedef u32 (*pFunConnectToCloud)(PTC_Connection *pstruConnection);
typedef u32 (*pFunSetTimer)(u8 u8Type, u32 Interval, u8 *pu8Index);
typedef void (*pFunStopTimer)(u8 u8TimerIndex);


typedef struct
{
    /*action function*/
    pFunConnectToCloud          pfunConnectToCloud;
    //pFunSendDataToCloud         pfunSendToCloud; //
    pFunFirmwareUpdate          pfunUpdate;
    pFunFirmwareUpdateFinish    pfunUpdateFinish;    
    pFunSendDataToMoudle        pfunSendToMoudle;
    //pFunRecvDataFromMoudle      pfunRecvFormMoudle; //
    
    /*config function*/
    pFunGetCloudKey             pfunGetCloudKey;
    pFunGetPrivateKey           pfunGetPrivateKey;
    pFunGetVersion              pfunGetVersion;
    pFunGetDeviceId             pfunGetDeviceId;
    pFunSetTimer                pfunSetTimer;
    pFunStopTimer               pfunStopTimer;
}PTC_ModuleAdapter;

typedef struct
{
    u32 u32TotalLen;
    u32 u32RecvOffset;
    u8 u8Crc[2];
    u8 u8NeedReset;
}PTC_OtaInfo;

typedef struct
{
    u8   u8MainState;                         /*State*/
    u8   u8keyRecv;
    u8   u8ReconnectTimer;
    u8   u8AccessTimer;

    u8   u8HeartTimer;
    u8   u8SendMoudleTimer;
    u8   u8RegisterTimer;

    u8   u8ReSendMoudleNum;

    
    u8   *pu8SendMoudleBuffer;
    
    PTC_Connection struCloudConnection;
    
    u8   u8SessionKey[ZC_HS_SESSION_KEY_LEN];
    u8   IvSend[16];
    u8   IvRecv[16];
    u8   RandMsg[ZC_HS_MSG_LEN];

    u16   u16SendBcNum;
    u8    u8EqStart;
    u8    u8Pad;
    PTC_ModuleAdapter *pstruMoudleFun;      /*Communication With Cloud*/
    PTC_OtaInfo struOtaInfo;
    
}PTC_ProtocolCon;

extern PTC_ProtocolCon  g_struProtocolController;
extern MSG_Buffer g_struRecvBuffer;
extern MSG_Queue  g_struRecvQueue;
extern MSG_Buffer g_struSendBuffer[MSG_BUFFER_SEND_MAX_NUM];
extern MSG_Queue  g_struSendQueue;
extern MSG_Buffer g_struRetxBuffer;

extern u8 g_u8MsgBuildBuffer[MSG_BULID_BUFFER_MAXLEN];
extern u8 g_u8CiperBuffer[MSG_CIPER_BUFFER_MAXLEN];
extern u16 g_u16TcpMss;
extern u32 g_u32LoopFlag;
extern u32 g_u32SecSwitch;

#ifdef __cplusplus
extern "C" {
#endif
void PCT_SendNotifyMsg(u8 u8NotifyCode);
void PCT_SendHeartMsg(void);
void PCT_Init(PTC_ModuleAdapter *pstruAdapter);
void PCT_SendEmptyMsg(u8 u8MsgId, u8 u8SecType);
void PCT_SendErrorMsg(u8 u8MsgId, u8 *pu8Error, u16 u16ErrorLen);
void PCT_SendCloudAccessMsg1(PTC_ProtocolCon *pstruContoller);
void PCT_SendCloudAccessMsg3(PTC_ProtocolCon *pstruContoller);
void PCT_DisConnectCloud(PTC_ProtocolCon *pstruContoller);
void PCT_ConnectCloud(PTC_ProtocolCon *pstruContoller);
void PCT_ReconnectCloud(PTC_ProtocolCon *pstruContoller);
void PCT_SendMoudleTimeout(PTC_ProtocolCon *pstruProtocolController);
void PCT_HandleMoudleEvent(u8 *pu8Msg, u16 u16DataLen);
void PCT_RecvAccessMsg2(PTC_ProtocolCon *pstruContoller);
void PCT_RecvAccessMsg4(PTC_ProtocolCon *pstruContoller);
void PCT_HandleEvent(PTC_ProtocolCon *pstruContoller);
void PCT_Run(void);
void PCT_WakeUp(void);
void PCT_Sleep(void);
u32 PCT_SendMsgToCloud(ZC_SecHead *pstruSecHead, u8 *pu8PlainData);

#ifdef __cplusplus
}
#endif
#endif
/******************************* FILE END ***********************************/

