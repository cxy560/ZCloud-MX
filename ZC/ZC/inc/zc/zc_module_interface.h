/**
******************************************************************************
* @file     zc_module_interface.h
* @authors  cxy
* @version  V1.0.0
* @date     10-Sep-2014
* @brief    Security module
******************************************************************************
*/

#ifndef  __ZC_MODULE_INTERFACE_H__ 
#define  __ZC_MODULE_INTERFACE_H__
#include <zc_common.h>

/*big endian*/
#define ZC_MODULE_TRACE_FLAG  (0x01020304)       
#define ZC_MODULE_DATA_FLAG   (0x02030405)       

typedef struct tag_RCTRL_STRU_MSGHEAD
{
    u32 MsgFlag;        /*byte0:0x76, byte1:0x81, byte2:0x43, byte3:0x50*/
}RCTRL_STRU_MSGHEAD;
#ifdef __cplusplus
}
#endif

#endif
/******************************* FILE END ***********************************/

