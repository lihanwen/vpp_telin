/*******************************************************************************
 Copyright (C) 2016 Hangzhou Telin Technologies Co.,Ltd. All Rights Reserved.
 --------------------------------------------------------------------------------
 文件名称: ac_ctrl.h 
 功能描述: 
*******************************************************************************/
#ifndef __VPP_COMMAND_H__
#define __VPP_COMMAND_H__



#include "vpp.h"

//对应cmd_num_name与cmd_ssid_num_val
enum CMD_NUM{
    CMD_MODULE,
    CMD_OP,
    CMD_IF_INDEX,
    CMD_USER_IP,//u32型的ip
    CMD_NUM_END
};

//对应cmd_ssid_string_name与cmd_ssid_string_val
enum CMD_STRING{
    CMD_IF_IP,
    CMD_PORTAL_URL,
    CMD_NASID,
    CMD_MAC,//用户mac地址
    CMD_STRING_END
};

//用于json数据中的module
enum MODULE_e
{
    MODULE_PORTAL,
	MODULE_USER,
};

//用于读取 在ac上的portal的配置
enum OP_PORTAL_e
{
    OP_PORTAL_ADD,
    OP_PORTAL_DEL,
};

//用于控制扫频的开关
enum AP_SCAN_SWITCH_e
{
    AP_SCAN_SWITCH_OFF, //关闭
    AP_SCAN_SWITCH_TURN //开启
};

//extern u_int16_t cmd_num_val[CMD_NUM_END];

void AC_ctrl_ap_fd(int local_server_sock, void *eloop_ctx, void *sock_ctx);




#endif
