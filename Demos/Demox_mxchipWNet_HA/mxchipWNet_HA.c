#include "stdio.h"
#include "ctype.h"
#include "platform.h"
#include "mxchipWNet.h"
#include "mxchipWNet_HA.h"
#include <zc_common.h>
#include <zc_protocol_controller.h>
#include <zc_module_interface.h>
#include <zc_timer.h>
#include <Flash_if.h>

static int wifi_disalbed = 0;
static int need_reload = 0;
extern vu32 MS_TIMER;


extern u8 hugebuf[1000]; // cmd, fwd data are saved in this buffer
mxchipWNet_HA_st  *device_info;



extern PTC_ProtocolCon  g_struProtocolController;
PTC_ModuleAdapter g_struAdapter;

MSG_Buffer g_struRecvBuffer;
MSG_Buffer g_struRetxBuffer;

MSG_Queue  g_struRecvQueue;
MSG_Buffer g_struSendBuffer[MSG_BUFFER_SEND_MAX_NUM];
MSG_Queue  g_struSendQueue;

u8 g_u8MsgBuildBuffer[MSG_BULID_BUFFER_MAXLEN];


u16 g_u16TcpMss;
u16 g_u16LocalPort;

typedef struct{
  unsigned int start;
  unsigned int interval;
}struMXtimer;

struMXtimer g_struMtTimer[ZC_TIMER_MAX_NUM];
u32 u32CloudIp = 0;
u8 g_u8ClientSendLen = 0;
MSG_Buffer g_struClientBuffer;

struct sockaddr_t struRemoteAddr;

void MX_Rest(void);
void Button_irq_handler(void *arg)
{
    ZC_Printf("easy link\n");
    MX_Rest();
}


void Button_Init(void)
{
    GPIO_InitTypeDef   GPIO_InitStructure;

    Button1_CLK_INIT(Button1_CLK, ENABLE);

    GPIO_InitStructure.GPIO_Pin = Button1_PIN;
    GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
    GPIO_InitStructure.GPIO_Mode = GPIO_Mode_IN;
    GPIO_InitStructure.GPIO_PuPd  = GPIO_PuPd_UP;			
    GPIO_Init(Button1_PORT, &GPIO_InitStructure);

    gpio_irq_enable(Button1_PORT, Button1_IRQ_PIN, IRQ_TRIGGER_FALLING_EDGE, Button_irq_handler, 0);
}


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
    u32 u32Index;
    
    close(g_Bcfd);

    if (PCT_INVAILD_SOCKET != g_struProtocolController.struClientConnection.u32Socket)
    {
        close(g_struProtocolController.struClientConnection.u32Socket);
        g_struProtocolController.struClientConnection.u32Socket = PCT_INVAILD_SOCKET;
    }

    if (PCT_INVAILD_SOCKET != g_struProtocolController.struCloudConnection.u32Socket)
    {
        close(g_struProtocolController.struCloudConnection.u32Socket);
        g_struProtocolController.struCloudConnection.u32Socket = PCT_INVAILD_SOCKET;
    }
    
    for (u32Index = 0; u32Index < ZC_MAX_CLIENT_NUM; u32Index++)
    {
        if (0 == g_struClientInfo.u32ClientVaildFlag[u32Index])
        {
            close(g_struClientInfo.u32ClientFd[u32Index]);
            g_struClientInfo.u32ClientFd[u32Index] = PCT_INVAILD_SOCKET;
        }
    }

    PCT_Sleep();
}
/*************************************************
* Function: HF_WriteDataToFlash
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void MX_WriteDataToFlash(u8 *pu8Data, u16 u16Len)
{
  uint32_t paraStartAddress, paraEndAddress;
  uint32_t next;
  
  paraStartAddress = PARA_START_ADDRESS;
  paraEndAddress = PARA_END_ADDRESS;
  next = paraStartAddress + sizeof(mxchipWNet_HA_config_st);
  FLASH_If_Init();
  FLASH_If_Erase(paraStartAddress , paraEndAddress); 
  FLASH_If_Write(&paraStartAddress, (u32 *)&device_info->conf, sizeof(mxchipWNet_HA_config_st));
  FLASH_If_Byte_Write(&next, pu8Data, u16Len);
  FLASH_Lock();
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

    if (0 == u32CloudIp)
    {
        return ZC_RET_ERROR;
    }
    
    addr.s_ip = u32CloudIp; 
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
    memset(device_info, 0, sizeof(boot_table_t));
    device_info->conf.bootTable.length = u32TotalLen;
    device_info->conf.bootTable.start_address = UPDATE_START_ADDRESS;
    device_info->conf.bootTable.type = 'A';
    device_info->conf.bootTable.upgrade_type = 'U';
    MX_WriteDataToFlash((u8*)&g_struZcConfigDb, sizeof(ZC_ConfigDB));

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
* Function: MX_Rest
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void MX_Rest()
{
    OpenEasylink(60*5);
}
/*************************************************
* Function: MX_SendTcpData
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void MX_SendTcpData(u32 u32Fd, u8 *pu8Data, u16 u16DataLen, ZC_SendParam *pstruParam)
{
    send(u32Fd, pu8Data, u16DataLen, 0);
}

/*************************************************
* Function: MX_SendUdpData
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void MX_SendUdpData(u32 u32Fd, u8 *pu8Data, u16 u16DataLen, ZC_SendParam *pstruParam)
{
    sendto(u32Fd, pu8Data, u16DataLen, 0, 
        (struct sockaddr_t*)pstruParam->pu8AddrPara, sizeof(struct sockaddr_t)); 
}

/*************************************************
* Function: MX_ListenClient
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
u32 MX_ListenClient(PTC_Connection *pstruConnection)
{
    int fd; 
    struct sockaddr_t servaddr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd<0)
        return ZC_RET_ERROR;

    servaddr.s_port = pstruConnection->u16Port;
    if(bind(fd,(struct sockaddr_t *)&servaddr,sizeof(servaddr))<0)
    {
        close(fd);
        return ZC_RET_ERROR;
    }
    
    if (listen(fd, 4)< 0)
    {
        close(fd);
        return ZC_RET_ERROR;
    }

    ZC_Printf("Tcp Listen Port = %d\n", pstruConnection->u16Port);
    g_struProtocolController.struClientConnection.u32Socket = fd;

    return ZC_RET_OK;
}

/*************************************************
* Function: MX_BcInit
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void MX_BcInit()
{
    int tmp=1;
    struct sockaddr_t addr;
    addr.s_port = ZC_MOUDLE_PORT;

    g_Bcfd = socket(AF_INET, SOCK_DGRM, IPPROTO_UDP); 

    tmp=1; 
    setsockopt(g_Bcfd, SOL_SOCKET,SO_BROADCAST,&tmp,sizeof(tmp)); 
    bind(g_Bcfd, &addr, sizeof(addr));
    
    g_struProtocolController.u16SendBcNum = 0;
    memset((char*)&struRemoteAddr,0,sizeof(struRemoteAddr));

    struRemoteAddr.s_port = ZC_MOUDLE_BROADCAST_PORT; 
    struRemoteAddr.s_ip = inet_addr("255.255.255.255"); 
    g_pu8RemoteAddr = (u8*)&struRemoteAddr;
    g_u32BcSleepCount = 2500;
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
    g_struAdapter.pfunSetTimer = MX_SetTimer;   
    g_struAdapter.pfunStopTimer = MX_StopTimer;
    g_struAdapter.pfunListenClient = MX_ListenClient;
    g_struAdapter.pfunSendTcpData = MX_SendTcpData;  
    g_struAdapter.pfunSendUdpData = MX_SendUdpData; 
    g_struAdapter.pfunRest = MX_Rest;
    g_struAdapter.pfunWriteFlash = MX_WriteDataToFlash;
    
    g_u16TcpMss = 1000;
    PCT_Init(&g_struAdapter);
    MX_BcInit();
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
        ZC_Rand(g_struProtocolController.RandMsg);
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
        MX_WriteDataToFlash((u8*)&g_struZcConfigDb, sizeof(ZC_ConfigDB));
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
    MX_WriteDataToFlash((u8*)&g_struZcConfigDb, sizeof(ZC_ConfigDB));
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
            MX_BcInit();
        case MXCHIP_WIFI_JOIN_FAILED:
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
	    ZC_Printf("DNS ERROR\n");
	}
	else
	{
        u32CloudIp = ip;
        ZC_Printf("DNS = 0x%x\n", u32CloudIp);
        //MX_WakeUp();
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

    ZC_Printf("wifi connect\n");

    strcpy((char *)device_info->status.ip, pnet->ip);
    strcpy((char *)device_info->status.mask, pnet->mask);
    strcpy((char *)device_info->status.gw, pnet->gate);
    strcpy((char *)device_info->status.dns, pnet->dns);

    g_u32GloablIp = inet_addr((char *)device_info->status.ip);

    if (1 == g_struZcConfigDb.struSwitchInfo.u32TestAddrConfig)
    {
        retval = dns_request((char *)"test.ablecloud.cn");
    }
    else if (2 == g_struZcConfigDb.struSwitchInfo.u32TestAddrConfig)
    {
        u32CloudIp = g_struZcConfigDb.struSwitchInfo.u32ServerIp;
        retval = 1;
    }
    else
    {
        retval = dns_request((char *)g_struZcConfigDb.struCloudInfo.u8CloudAddr);
    }

    if (retval > 0)
    {
        u32CloudIp = retval;
    }
    
    MX_WakeUp();
}


/*************************************************
* Function: MX_ReadDataFormFlash
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void MX_ReadDataFormFlash(void) 
{
    u32 configInFlash;
    u32 u32MagicFlag = 0xFFFFFFFF;

    configInFlash = PARA_START_ADDRESS;
    memcpy(&u32MagicFlag, (void *)(configInFlash + sizeof(mxchipWNet_HA_config_st)), sizeof(u32));
    if (ZC_MAGIC_FLAG == u32MagicFlag)
    {
        memcpy(&g_struZcConfigDb, (void *)(configInFlash + sizeof(mxchipWNet_HA_config_st)), sizeof(ZC_ConfigDB));
    }
    else
    {
        ZC_Printf("no para, use default\n");
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

    net_para_st para;
    device_info = (mxchipWNet_HA_st *)malloc(sizeof(mxchipWNet_HA_st));
    memset(device_info, 0, sizeof(mxchipWNet_HA_st)); 

    SystemCoreClockUpdate();
    mxchipInit();
    Button_Init();
    hal_uart_init();
    MX_Init();

    
    getNetPara(&para, Station);
    formatMACAddr((void *)device_info->status.mac, &para.mac);
    strcpy((char *)device_info->status.ip, (char *)&para.ip);
    strcpy((char *)device_info->status.mask, (char *)&para.mask);
    strcpy((char *)device_info->status.gw, (char *)&para.gate);
    strcpy((char *)device_info->status.dns, (char *)&para.dns);

    readConfiguration(device_info);
    MX_ReadDataFormFlash();

    wNetConfig.wifi_mode = Station;
    strcpy(wNetConfig.wifi_ssid, device_info->conf.sta_ssid);
    strcpy(wNetConfig.wifi_key, device_info->conf.sta_key);
    wNetConfig.dhcpMode = DHCP_Client;
    strcpy(wNetConfig.local_ip_addr, (char*)device_info->conf.ip);
    strcpy(wNetConfig.net_mask, (char*)device_info->conf.mask);
    strcpy(wNetConfig.gateway_ip_addr, (char*)device_info->conf.gw);
    strcpy(wNetConfig.dnsServer_ip_addr, (char*)device_info->conf.dns);
      wNetConfig.wifi_retry_interval = 500;
    (void)StartNetwork(&wNetConfig);

    ps_enable();
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
    u32 u32Index;
    int fd;
    struct timeval_t t;
    int connfd;
    struct sockaddr_t addr;
    int tmp=1;    

    fd = g_struProtocolController.struCloudConnection.u32Socket;
    FD_ZERO(&readfds);
    t.tv_sec = 0;
    t.tv_usec = 1000;

    FD_SET(g_Bcfd, &readfds);

    if(PCT_INVAILD_SOCKET != fd)
    {
        FD_SET(fd, &readfds);      
    }
    
    if (PCT_INVAILD_SOCKET != g_struProtocolController.struClientConnection.u32Socket)
    {
        FD_SET(g_struProtocolController.struClientConnection.u32Socket, &readfds);
    }

    for (u32Index = 0; u32Index < ZC_MAX_CLIENT_NUM; u32Index++)
    {
        if (0 == g_struClientInfo.u32ClientVaildFlag[u32Index])
        {
            FD_SET(g_struClientInfo.u32ClientFd[u32Index], &readfds);
        }
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
                MSG_RecvDataFromCloud(hugebuf, s32RecvLen);
            }
        }
    }

    for (u32Index = 0; u32Index < ZC_MAX_CLIENT_NUM; u32Index++)
    {
        if (0 == g_struClientInfo.u32ClientVaildFlag[u32Index])
        {
            if (FD_ISSET(g_struClientInfo.u32ClientFd[u32Index], &readfds))
            {
                s32RecvLen = recv(g_struClientInfo.u32ClientFd[u32Index], hugebuf, 1000, 0); 
                if (s32RecvLen > 0)
                {
                    ZC_RecvDataFromClient(g_struClientInfo.u32ClientFd[u32Index], hugebuf, s32RecvLen);
                }
                else
                {   
                    ZC_ClientDisconnect(g_struClientInfo.u32ClientFd[u32Index]);
                    close(g_struClientInfo.u32ClientFd[u32Index]);
                }
                
            }
        }
        
    }
    
    if (PCT_INVAILD_SOCKET != g_struProtocolController.struClientConnection.u32Socket)
    {
        if (FD_ISSET(g_struProtocolController.struClientConnection.u32Socket, &readfds))
        {
            connfd = accept(g_struProtocolController.struClientConnection.u32Socket,(struct sockaddr_t *)&addr,&tmp);
    
            if (ZC_RET_ERROR == ZC_ClientConnect((u32)connfd))
            {
                close(connfd);
            }
            else
            {
                ZC_Printf("accept client = %d", connfd);
            }
        }
    }
    if (FD_ISSET(g_Bcfd, &readfds))
    {
        tmp = sizeof(addr); 
        s32RecvLen = recvfrom(g_Bcfd, g_u8MsgBuildBuffer, 100, 0, (struct sockaddr_t *)&addr, (socklen_t*)&tmp); 
        if(s32RecvLen > 0) 
        {
            ZC_SendClientQueryReq(g_u8MsgBuildBuffer, s32RecvLen);
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
    u32 u32Timer = 0;
    
    mxchipTick();
    MX_TimerExpired();
    if (!is_wifi_disalbed()) 
    {
        ZC_StartClientListen();
        
        fd = g_struProtocolController.struCloudConnection.u32Socket;
        MX_Recvtick();

        PCT_Run();

        if (PCT_STATE_DISCONNECT_CLOUD == g_struProtocolController.u8MainState)
        {
            close(fd);
            u32Timer = rand();
            u32Timer = (PCT_TIMER_INTERVAL_RECONNECT) * (u32Timer % 10 + 1);
            PCT_ReconnectCloud(&g_struProtocolController, u32Timer);
          
        }
        else
        {
            MSG_SendDataToCloud((u8*)&g_struProtocolController.struCloudConnection);
        }

        ZC_SendBc();

    }

    if (need_reload == 1) 
    {
        msleep(500);
        NVIC_SystemReset();
    }
}


/******************************* FILE END ***********************************/


