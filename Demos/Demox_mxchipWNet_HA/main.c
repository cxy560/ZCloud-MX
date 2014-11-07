#include "stdio.h"
#include "ctype.h"

#include "stm32f2xx.h"
#include "platform.h"
#include "mxchipWNet_HA.h"
#include "user_misc.h"

static void uart_tick(void);

static u8 hugebuf[1000]; // cmd, fwd data are saved in this buffer

int uart_cmd_process(u8 *buf, int len)
{
    return 0;
}

static void uart_tick(void)
{
    int recvlen; 

    recvlen = hal_uart_get_one_packet(hugebuf);
    if (recvlen == 0)
        return; 
    MX_Moudlefunc(hugebuf, recvlen);
}

int main(void)
{
    mxchipWNet_HA_init();

    while(1) 
    {
        mxchipWNet_HA_tick();
        uart_tick();
        hal_uart_tx_tick();
    }
}

