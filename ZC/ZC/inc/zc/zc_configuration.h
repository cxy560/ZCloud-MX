/**
******************************************************************************
* @file     zc_configuration.h
* @authors  cxy
* @version  V1.0.0
* @date     10-Sep-2014
* @brief    configuration module
******************************************************************************
*/

#ifndef  __ZC_CONFIGURATION_H__ 
#define  __ZC_CONFIGURATION_H__
#include <zc_common.h>
#include <zc_protocol_interface.h>

#define    ZC_GET_TYPE_CLOUDKEY    (0)
#define    ZC_GET_TYPE_DEVICEID    (1)
#define    ZC_GET_TYPE_PRIVATEKEY  (2)
#define    ZC_GET_TYPE_VESION      (3)
#define    ZC_GET_TYPE_TOKENKEY    (4)

#define    ZC_MAGIC_FLAG (0x04083207)



typedef struct 
{
    u32 u32TraceSwitch;     //Trace data switch, 1:open, 0:close,default 0
    u32 u32SecSwitch;       //Sec data switch, 1:open, 0:close, 2:close RSA, default 1
    u32 u32WifiConfig;      //Use Config SSID,password,1:open, 0:close, default 0
    u32 u32TestAddrConfig;  //connect with test url,0:open, 1:"test.ablecloud.cn", 2:use u32IpAddr, default 0

    u8 u8Ssid[ZC_SSID_MAX_LEN];
    u8 u8Password[ZC_PASSWORD_MAX_LEN];

    u32 u32ServerIp;        //use if wifconfig is 1;
}ZC_SwitchInfo;

typedef struct 
{
    u8 u8CloudKey[ZC_CLOUD_KEY_MAX_LEN];
    u8 u8CloudAddr[ZC_CLOUD_ADDR_MAX_LEN];
    u8 u8TokenKey[ZC_HS_SESSION_KEY_LEN];
}ZC_CloudInfo;

typedef struct 
{
    u8 u8PrivateKey[ZC_MODULE_KEY_LEN];
    u8 u8DeviciId[ZC_HS_DEVICE_ID_LEN + ZC_DOMAIN_LEN];
    u8 u8EqVersion[ZC_EQVERSION_LEN];
}ZC_RegisterInfo;

typedef struct
{
    u32 u32MagicFlag;
    u8 u8Ssid[ZC_SSID_MAX_LEN];
    u8 u8Password[ZC_PASSWORD_MAX_LEN];
}ZC_ConnectionInfo;

typedef struct 
{
    u32 u32MagicFlag;
    ZC_ConnectionInfo struConnection;
    ZC_CloudInfo    struCloudInfo;
    ZC_SwitchInfo   struSwitchInfo;
}ZC_ConfigDB;

extern ZC_ConfigDB g_struZcConfigDb;
extern ZC_RegisterInfo g_struRegisterInfo;


#ifdef __cplusplus
extern "C" {
#endif

void ZC_ConfigInitPara(void);
void ZC_ConfigPara(u8 *pu8Data);
void ZC_StoreRegisterInfo(u8 *pu8Data);
void ZC_StoreTokenKey(u8 *pu8Data);
void ZC_StoreConnectionInfo(u8 *pu8Ssid, u8 *pu8Password);
void ZC_GetStoreInfor(u8 u8Type, u8 **pu8Data);

#ifdef __cplusplus
}
#endif

#endif
/******************************* FILE END ***********************************/

