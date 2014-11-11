#include "stdio.h"
#include "ctype.h"
#include "platform.h"
#include "mxchipWNet.h"
#include "mxchipWNet_HA.h"
#include <zc_common.h>
#include <zc_protocol_controller.h>
#include <zc_module_interface.h>
#include <zc_timer.h>
#include <flash_configurations.h>


static int wifi_disalbed = 0;
static int need_reload = 0;
extern vu32 MS_TIMER;

config_t configParas;

static u8 hugebuf[1000]; // cmd, fwd data are saved in this buffer
mxchipWNet_HA_st  *device_info;



extern PTC_ProtocolCon  g_struProtocolController;
PTC_ModuleAdapter g_struAdapter;

MSG_Buffer g_struRecvBuffer;
MSG_Buffer g_struRetxBuffer;

MSG_Queue  g_struRecvQueue;
MSG_Buffer g_struSendBuffer[MSG_BUFFER_SEND_MAX_NUM];
MSG_Queue  g_struSendQueue;

u8 g_u8MsgBuildBuffer[MSG_BULID_BUFFER_MAXLEN];
u8 g_u8CiperBuffer[MSG_CIPER_BUFFER_MAXLEN];


u16 g_u16TcpMss;
u16 g_u16LocalPort;

#define DEFAULT_IOT_CLOUD_KEY {\
    0xb0, 0x7e, 0xab, 0x09, \
    0x73, 0x4e, 0x78, 0x12, \
    0x7e, 0x8c, 0x54, 0xcd, \
    0xbb, 0x93, 0x3c, 0x16, \
    0x96, 0x23, 0xaf, 0x7a, \
    0xfc, 0xd2, 0x8b, 0xd1, \
    0x43, 0xa2, 0xbb, 0xc8, \
    0x77, 0xa0, 0xca, 0xcd, \
    0x01, 0x00, 0x01\
}

#define DEFAULT_IOT_PRIVATE_KEY {\
    0xb0, 0x7e, 0xab, 0x09, \
    0x73, 0x4e, 0x78, 0x12, \
    0x7e, 0x8c, 0x54, 0xcd, \
    0xbb, 0x93, 0x3c, 0x16, \
    0x96, 0x23, 0xaf, 0x7a, \
    0xfc, 0xd2, 0x8b, 0xd1, \
    0x43, 0xa2, 0xbb, 0xc8, \
    0x77, 0xa0, 0xca, 0xcd, \
    0xef, 0x28, 0x66, 0xbd, \
    0x44, 0xc1, 0x27, 0x58, \
    0x3f, 0x71, 0xe3, 0x03, \
    0xcf, 0x11, 0x69, 0xf1, \
    0xbc, 0xec, 0x8f, 0xcd, \
    0xb5, 0x88, 0xab, 0x50, \
    0x5d, 0xb3, 0xf1, 0xd3, \
    0xbb, 0x9d, 0xf2, 0x9d, \
    0xcd, 0x04, 0xff, 0x7e, \
    0x45, 0x90, 0xa8, 0x1f, \
    0xf8, 0xd3, 0xb2, 0xdf, \
    0x33, 0x06, 0x24, 0xa1, \
    0x93, 0x57, 0x4b, 0xaf, \
    0xfb, 0x6c, 0x63, 0x6f, \
    0x82, 0x24, 0xdc, 0xed, \
    0x6c, 0xdd, 0x7a, 0x61, \
    0x9a, 0xd2, 0x29, 0x32, \
    0xdc, 0x4a, 0x86, 0x20, \
    0x6c, 0x98, 0x16, 0xce, \
    0xfd, 0x31, 0x50, 0xd6\
}

#define DEFAULT_DEVICIID {\
    'z', 'z', 'z', 'z',\
    'z', 'z', 'z', 'z',\
    'z', 'z', 'z', 'z',\
    'z', 'z', 'z', 'z'\
}


typedef struct 
{
    u8 u8CloudKey[36];
    u8 u8PrivateKey[112];
    u8 u8DeviciId[ZC_HS_DEVICE_ID_LEN + ZC_DOMAIN_LEN];
    u8 u8CloudAddr[20];
    u8  u8EqVersion[ZC_EQVERSION_LEN];
}MX_StaInfo;
typedef struct{
  unsigned int start;
  unsigned int interval;
}struMXtimer;

MX_StaInfo g_struMXStaInfo = {
    DEFAULT_IOT_CLOUD_KEY,
    DEFAULT_IOT_PRIVATE_KEY,
    DEFAULT_DEVICIID,
    "www.baidu.com"
};
struMXtimer g_struMtTimer[ZC_TIMER_MAX_NUM];
u32 u32CloudIp;
/*************************************************
* Function: is_wifi_disalbed
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
int is_wifi_disalbed(void)
{
  return wifi_disalbed;
}

/*************************************************
* Function: MX_WakeUp
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void MX_WakeUp()
{
    PCT_WakeUp();
}
/*************************************************
* Function: HF_Sleep
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void MX_Sleep()
{
    PCT_Sleep();
}

/*************************************************
* Function: MX_ConnectToCloud
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
u32 MX_ConnectToCloud(PTC_Connection *pstruConnection)
{
    int fd; 
    int opt = 0;
    struct sockaddr_t addr;

    memset((char*)&addr,0,sizeof(addr));
#if 0    
    retval = gethostbyname((char*)g_struMXStaInfo.u8CloudAddr, u8Ip, 4);
    if(-1 == retval)
    {
        return ZC_RET_ERROR;
    }

    
    ZC_Printf("0x%x.0x%x.0x%x.0x%x\n", u8Ip[0],u8Ip[1],u8Ip[2],u8Ip[3]);
#endif    
    addr.s_ip = inet_addr("192.168.1.111"); 
    addr.s_port = ZC_CLOUD_PORT;
    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    setsockopt(fd,0,SO_BLOCKMODE,&opt,4);

    if(fd<0)
        return ZC_RET_ERROR;
    
    if (connect(fd, &addr, sizeof(addr))< 0)
    {
        close(fd);
        return ZC_RET_ERROR;
    }

    ZC_Printf("connect ok!\n");
    g_struProtocolController.struCloudConnection.u32Socket = fd;
    
    return ZC_RET_OK;
}


/*************************************************
* Function: MX_FirmwareUpdate
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
u32 MX_FirmwareUpdate(u8 *pu8FileData, u32 u32Offset, u32 u32DataLen)
{
	u32 u32UpdataAddr = UPDATE_START_ADDRESS;

    if (0 == u32Offset)
    {
        FLASH_If_Init();
    }
    u32UpdataAddr = u32UpdataAddr + u32Offset;
    FLASH_If_Write(&u32UpdataAddr, (void *)pu8FileData, u32DataLen);
    

    return ZC_RET_OK;
}
/*************************************************
* Function: MX_FirmwareUpdateFinish
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
u32 MX_FirmwareUpdateFinish(u32 u32TotalLen)
{
    memset(&configParas, 0, sizeof(boot_table_t));
    configParas.bootTable.length = u32TotalLen;
    configParas.bootTable.start_address = UPDATE_START_ADDRESS;
    configParas.bootTable.type = 'A';
    configParas.bootTable.upgrade_type = 'U';
    updateConfig(&configParas);

    FLASH_Lock();
    return ZC_RET_OK;
}
/*************************************************
* Function: MX_SendDataToMoudle
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
u32 MX_SendDataToMoudle(u8 *pu8Data, u16 u16DataLen)
{
    u8 u8MagicFlag[4] = {0x02,0x03,0x04,0x05};
    hal_uart_send_data(u8MagicFlag,4); 
    hal_uart_send_data(pu8Data,u16DataLen); 
    return ZC_RET_OK;
}
/*************************************************
* Function: MX_GetCloudKey
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
u32 MX_GetCloudKey(u8 **pu8Key)
{
    *pu8Key = g_struMXStaInfo.u8CloudKey;
    return ZC_RET_OK;
}
/*************************************************
* Function: MX_GetPrivateKey
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
u32 MX_GetPrivateKey(u8 **pu8Key)
{
    *pu8Key = g_struMXStaInfo.u8PrivateKey;
    return ZC_RET_OK;
}
/*************************************************
* Function: MX_GetVersion
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
u32 MX_GetVersion(u8 **pu8Version)
{
    *pu8Version = g_struMXStaInfo.u8EqVersion;
    return ZC_RET_OK;
}
/*************************************************
* Function: MX_GetDeviceId
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
u32 MX_GetDeviceId(u8 **pu8DeviceId)
{
    *pu8DeviceId = g_struMXStaInfo.u8DeviciId;
    return ZC_RET_OK;
}
/*************************************************
* Function: MX_StopTimer
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void MX_StopTimer(u8 u8TimerIndex)
{
}
/*************************************************
* Function: timer_set
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void timer_set(struMXtimer *t, u32 interval)
{
  t->interval = interval;
  t->start = MS_TIMER;
}
/*************************************************
* Function: timer_expired
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
int timer_expired(struMXtimer *t)
{
  return MS_TIMER >= t->start + t->interval;
}


/*************************************************
* Function: MX_SetTimer
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
u32 MX_SetTimer(u8 u8Type, u32 u32Interval, u8 *pu8TimeIndex)
{
    u8 u8TimerIndex;
    u32 u32Retval;
    u32Retval = TIMER_FindIdleTimer(&u8TimerIndex);
    if (ZC_RET_OK == u32Retval)
    {
        TIMER_AllocateTimer(u8Type, u8TimerIndex, (u8*)&g_struMtTimer[u8TimerIndex]);
        timer_set(&g_struMtTimer[u8TimerIndex], u32Interval);
        *pu8TimeIndex = u8TimerIndex;
    }
    return u32Retval;

}
/*************************************************
* Function: MX_TimerExpired
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void MX_TimerExpired()
{
    u8 u8Index;
    u8 u8Status;
    for (u8Index = 0; u8Index < ZC_TIMER_MAX_NUM; u8Index++)
    {   
        TIMER_GetTimerStatus(u8Index, &u8Status);
        if (ZC_TIMER_STATUS_USED == u8Status)
        {
            if (timer_expired(&g_struMtTimer[u8Index]))
            {
                TIMER_StopTimer(u8Index);
                TIMER_TimeoutAction(u8Index);
            }
        }
    }
}

/*************************************************
* Function: MX_RecvDataFromMoudle
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
u32 MX_RecvDataFromMoudle(u8 *pu8Data, u16 u16DataLen)
{
    ZC_MessageHead *pstrMsg;
    ZC_RegisterReq *pstruRegister;
    ZC_MessageOptHead *pstruOpt;

    ZC_TraceData(pu8Data, u16DataLen);

    if (0 == u16DataLen)
    {
        return ZC_RET_ERROR;
    }
    
    pstrMsg = (ZC_MessageHead *)pu8Data;
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
            
            pstruOpt = (ZC_MessageOptHead *)(pstrMsg + 1);
            pstruRegister = (ZC_RegisterReq *)((u8*)(pstruOpt + 1) + ZC_HTONS(pstruOpt->OptLen));
            memcpy(g_struMXStaInfo.u8PrivateKey, pstruRegister->u8ModuleKey, ZC_MODULE_KEY_LEN);
            memcpy(g_struMXStaInfo.u8DeviciId, (u8*)(pstruOpt+1), ZC_HS_DEVICE_ID_LEN);
            memcpy(g_struMXStaInfo.u8DeviciId + ZC_HS_DEVICE_ID_LEN, pstruRegister->u8Domain, ZC_DOMAIN_LEN);
            memcpy(g_struMXStaInfo.u8EqVersion, pstruRegister->u8EqVersion, ZC_EQVERSION_LEN);
            g_struProtocolController.u8MainState = PCT_STATE_ACCESS_NET; 
            if (PCT_TIMER_INVAILD != g_struProtocolController.u8RegisterTimer)
            {
                TIMER_StopTimer(g_struProtocolController.u8RegisterTimer);
                g_struProtocolController.u8RegisterTimer = PCT_TIMER_INVAILD;
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
            break;  
        default:
            PCT_HandleMoudleEvent(pu8Data, u16DataLen);
            break;
    }
    
    return ZC_RET_OK;
}

/*************************************************
* Function: MX_Moudlefunc
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void MX_Moudlefunc(u8 *pu8Data, u32 u32DataLen) 
{
    MX_RecvDataFromMoudle(pu8Data + sizeof(RCTRL_STRU_MSGHEAD), 
        u32DataLen - sizeof(RCTRL_STRU_MSGHEAD));
    return; 
}

/*************************************************
* Function: MX_RecvDataFromCloud
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void MX_RecvDataFromCloud(u8 *pu8Data, u32 u32DataLen)
{
    u32 u32RetVal;
    u16 u16PlainLen;
    u32RetVal = MSG_RecvDataFromCloud(pu8Data, u32DataLen);

    if (ZC_RET_OK == u32RetVal)
    {
        if (MSG_BUFFER_FULL == g_struRecvBuffer.u8Status)
        {
            u32RetVal = SEC_Decrypt((ZC_SecHead*)g_u8CiperBuffer, 
                g_u8CiperBuffer + sizeof(ZC_SecHead), g_struRecvBuffer.u8MsgBuffer, &u16PlainLen);

            g_struRecvBuffer.u32Len = u16PlainLen;
            if (ZC_RET_OK == u32RetVal)
            {
                u32RetVal = MSG_PushMsg(&g_struRecvQueue, (u8*)&g_struRecvBuffer);
            }
        }
    }
    
    return;
}

/*************************************************
* Function: MX_Init
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void MX_Init()
{
    ZC_Printf("MT Init\n");
    g_struAdapter.pfunConnectToCloud = MX_ConnectToCloud;
    g_struAdapter.pfunUpdate = MX_FirmwareUpdate;     
    g_struAdapter.pfunUpdateFinish = MX_FirmwareUpdateFinish;
    g_struAdapter.pfunSendToMoudle = MX_SendDataToMoudle;  
    g_struAdapter.pfunGetCloudKey = MX_GetCloudKey;   
    g_struAdapter.pfunGetPrivateKey = MX_GetPrivateKey; 
    g_struAdapter.pfunGetVersion = MX_GetVersion;    
    g_struAdapter.pfunGetDeviceId = MX_GetDeviceId;   
    g_struAdapter.pfunSetTimer = MX_SetTimer;   
    g_struAdapter.pfunStopTimer = MX_StopTimer;
    
    g_u16TcpMss = 1000;
    PCT_Init(&g_struAdapter);
}
/*************************************************
* Function: MX_SendDataToCloud
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void MX_SendDataToCloud(PTC_Connection *pstruConnection)
{
    MSG_Buffer *pstruBuf = NULL;

    u16 u16DataLen; 
    pstruBuf = (MSG_Buffer *)MSG_PopMsg(&g_struSendQueue); 
    
    if (NULL == pstruBuf)
    {
        return;
    }
    
    u16DataLen = pstruBuf->u32Len; 
    send(pstruConnection->u32Socket, pstruBuf->u8MsgBuffer, u16DataLen, 0);
    ZC_Printf("send data len = %d\n", u16DataLen);
    pstruBuf->u8Status = MSG_BUFFER_IDLE;
    pstruBuf->u32Len = 0;
    return;
}

/*************************************************
* Function: delay_reload
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void delay_reload()
{
    need_reload = 1;
}

/*************************************************
* Function: formatMACAddr
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void formatMACAddr(void *destAddr, void *srcAddr)
{
    sprintf((char *)destAddr, "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",\
    				toupper(*(char *)srcAddr),toupper(*((char *)(srcAddr)+1)),\
    				toupper(*((char *)(srcAddr)+2)),toupper(*((char *)(srcAddr)+3)),\
    				toupper(*((char *)(srcAddr)+4)),toupper(*((char *)(srcAddr)+5)),\
    				toupper(*((char *)(srcAddr)+6)),toupper(*((char *)(srcAddr)+7)),\
    				toupper(*((char *)(srcAddr)+8)),toupper(*((char *)(srcAddr)+9)),\
    				toupper(*((char *)(srcAddr)+10)),toupper(*((char *)(srcAddr)+11)));
}
/*************************************************
* Function: socket_connected
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void socket_connected(int fd)
{
    ZC_Printf("socket connected\n");
    if(fd==g_struProtocolController.struCloudConnection.u32Socket)
    {
        PCT_SendCloudAccessMsg1(&g_struProtocolController);
    }
}
/*************************************************
* Function: RptConfigmodeRslt
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void RptConfigmodeRslt(network_InitTypeDef_st *nwkpara)
{
    if(nwkpara == NULL)
    {
        ZC_Printf("open easy link\n");    
        OpenEasylink(60*5);
    }
    else
    {
        ZC_Printf("recv config\n");    
        memcpy(device_info->conf.sta_ssid, nwkpara->wifi_ssid, sizeof(device_info->conf.sta_ssid));
        memcpy(device_info->conf.sta_key, nwkpara->wifi_key, sizeof(device_info->conf.sta_key));
        /*Clear fastlink record*/
        memset(&(device_info->conf.fastLinkConf), 0x0, sizeof(fast_link_st));
        updateConfiguration(device_info);
        system_reload();
    }
}
/*************************************************
* Function: connected_ap_info
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void connected_ap_info(apinfo_adv_t *ap_info, char *key, int key_len)  //callback, return connected AP info
{
  /*Update fastlink record*/
  int result, result1;
  ZC_Printf("in connected_ap_info\n");
  
  result = memcmp(&(device_info->conf.fastLinkConf.ap_info), ap_info, sizeof(ApList_adv_t));
  result1 = memcmp(&(device_info->conf.fastLinkConf.key), key, key_len);
  if(device_info->conf.fastLinkConf.availableRecord == 0||result||result1){
    device_info->conf.fastLinkConf.availableRecord = 1;
    memcpy(&(device_info->conf.fastLinkConf.ap_info), ap_info, sizeof(ApList_adv_t));
    memcpy(device_info->conf.fastLinkConf.key, key, key_len);
    device_info->conf.fastLinkConf.key_len = key_len;
    updateConfiguration(device_info);
  }
}
/*************************************************
* Function: WifiStatusHandler
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void WifiStatusHandler(int event)
{
    switch (event) 
    {
        case MXCHIP_WIFI_UP:
            break;
        case MXCHIP_WIFI_DOWN:
            MX_Sleep();
        case MXCHIP_WIFI_JOIN_FAILED:
            ZC_Printf("join fail\n");
            break;
        default:
          break;
    }
    return;
}
/*************************************************
* Function: dns_ip_set
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void dns_ip_set(u8 *hostname, u32 ip)
{
	if((int)ip == -1)
	{
	    ZC_Printf("DNS ERROR");
	}
	else
	{
        u32CloudIp = ip;
        ZC_Printf("DNS = 0x%x\n", u32CloudIp);
        MX_WakeUp();
	}
}


/*************************************************
* Function: NetCallback
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void NetCallback(net_para_st *pnet)
{
    int retval;

    ZC_Printf("NetCallback\n");

    strcpy((char *)device_info->status.ip, pnet->ip);
    strcpy((char *)device_info->status.mask, pnet->mask);
    strcpy((char *)device_info->status.gw, pnet->gate);
    strcpy((char *)device_info->status.dns, pnet->dns);
    retval = dns_request((char*)g_struMXStaInfo.u8CloudAddr);
    if (retval > 0)
    {
        u32CloudIp = retval;
        MX_WakeUp();
    }
}

/*************************************************
* Function: mxchipWNet_HA_init
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void mxchipWNet_HA_init(void)
{
    network_InitTypeDef_st wNetConfig;
    network_InitTypeDef_adv_st wNetConfigAdv;
    int err = MXCHIP_FAILED;

    net_para_st para;
    device_info = (mxchipWNet_HA_st *)malloc(sizeof(mxchipWNet_HA_st));
    memset(device_info, 0, sizeof(mxchipWNet_HA_st)); 

    SystemCoreClockUpdate();
    mxchipInit();
    hal_uart_init();
    getNetPara(&para, Station);
    formatMACAddr((void *)device_info->status.mac, &para.mac);
    strcpy((char *)device_info->status.ip, (char *)&para.ip);
    strcpy((char *)device_info->status.mask, (char *)&para.mask);
    strcpy((char *)device_info->status.gw, (char *)&para.gate);
    strcpy((char *)device_info->status.dns, (char *)&para.dns);

    readConfiguration(device_info);


    if(device_info->conf.fastLinkConf.availableRecord){ //Try fast link
        memcpy(&wNetConfigAdv.ap_info, &device_info->conf.fastLinkConf.ap_info, sizeof(ApList_adv_t));
        memcpy(&wNetConfigAdv.key, &device_info->conf.fastLinkConf.key, device_info->conf.fastLinkConf.key_len);
        wNetConfigAdv.key_len = device_info->conf.fastLinkConf.key_len;
        wNetConfigAdv.dhcpMode = DHCP_Client;
        strcpy(wNetConfigAdv.local_ip_addr, (char*)device_info->conf.ip);
        strcpy(wNetConfigAdv.net_mask, (char*)device_info->conf.mask);
        strcpy(wNetConfigAdv.gateway_ip_addr, (char*)device_info->conf.gw);
        strcpy(wNetConfigAdv.dnsServer_ip_addr, (char*)device_info->conf.dns);
        wNetConfigAdv.wifi_retry_interval = 100;
        err = StartAdvNetwork(&wNetConfigAdv);
        ZC_Printf("fast link = %d\n", err);
    }

    if (MXCHIP_FAILED == err)
    {
        wNetConfig.wifi_mode = Station;
        strcpy(wNetConfig.wifi_ssid, device_info->conf.sta_ssid);
        strcpy(wNetConfig.wifi_key, device_info->conf.sta_key);
        wNetConfig.dhcpMode = DHCP_Client;
        strcpy(wNetConfig.local_ip_addr, (char*)device_info->conf.ip);
        strcpy(wNetConfig.net_mask, (char*)device_info->conf.mask);
        strcpy(wNetConfig.gateway_ip_addr, (char*)device_info->conf.gw);
        strcpy(wNetConfig.dnsServer_ip_addr, (char*)device_info->conf.dns);
          wNetConfig.wifi_retry_interval = 500;
        err = StartNetwork(&wNetConfig);
        ZC_Printf("nomarl link = %d\n", err);        
    }
    if (MXCHIP_FAILED == err)
    {
        OpenEasylink(60*5);
    }

    ps_enable();
    MX_Init();
}


/*************************************************
* Function: MX_Recvtick
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void MX_Recvtick(void)
{
    int s32RecvLen;
    fd_set readfds;
    int fd;
    struct timeval_t t;

    fd = g_struProtocolController.struCloudConnection.u32Socket;
    FD_ZERO(&readfds);
    t.tv_sec = 0;
    t.tv_usec = 1000;

    if(PCT_INVAILD_SOCKET != fd)
    {
        FD_SET(fd, &readfds);      
    }


    select(1, &readfds, NULL, NULL, &t);

    if(PCT_INVAILD_SOCKET != fd)
    {
        if (FD_ISSET(fd, &readfds)) 
        {
            s32RecvLen = recv(fd, hugebuf, 1000, 0);
            if(s32RecvLen <= 0)
            {
                PCT_DisConnectCloud(&g_struProtocolController);
            }
            else
            {
                MX_RecvDataFromCloud(hugebuf, s32RecvLen);
            }
        }
    }
}

/*************************************************
* Function: mxchipWNet_HA_tick
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void mxchipWNet_HA_tick(void)
{
    int fd;

    mxchipTick();
    MX_TimerExpired();
    if (!is_wifi_disalbed()) 
    {
        fd = g_struProtocolController.struCloudConnection.u32Socket;
        MX_Recvtick();

        PCT_Run();

        if (PCT_STATE_DISCONNECT_CLOUD == g_struProtocolController.u8MainState)
        {
            close(fd);
            PCT_ReconnectCloud(&g_struProtocolController);
          
        }
        else
        {
            MX_SendDataToCloud(&g_struProtocolController.struCloudConnection);
        }

    }

    if (need_reload == 1) 
    {
        msleep(500);
        NVIC_SystemReset();
    }
}


/******************************* FILE END ***********************************/


