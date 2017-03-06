/*******************************************************************************
 Copyright (C) 2016 Hangzhou Telin Technologies Co.,Ltd. All Rights Reserved.
 --------------------------------------------------------------------------------
 �ļ�����: ac_ctrl.h 
 ��������: 
*******************************************************************************/
#ifndef __VPP_COMMAND_H__
#define __VPP_COMMAND_H__



#include "vpp.h"

//��Ӧcmd_num_name��cmd_ssid_num_val
enum CMD_NUM{
    CMD_MODULE,
    CMD_OP,
    CMD_IF_INDEX,
    CMD_USER_IP,//u32�͵�ip
    CMD_NUM_END
};

//��Ӧcmd_ssid_string_name��cmd_ssid_string_val
enum CMD_STRING{
    CMD_IF_IP,
    CMD_PORTAL_URL,
    CMD_NASID,
    CMD_MAC,//�û�mac��ַ
    CMD_STRING_END
};

//����json�����е�module
enum MODULE_e
{
    MODULE_PORTAL,
	MODULE_USER,
};

//���ڶ�ȡ ��ac�ϵ�portal������
enum OP_PORTAL_e
{
    OP_PORTAL_ADD,
    OP_PORTAL_DEL,
};

//���ڿ���ɨƵ�Ŀ���
enum AP_SCAN_SWITCH_e
{
    AP_SCAN_SWITCH_OFF, //�ر�
    AP_SCAN_SWITCH_TURN //����
};

//extern u_int16_t cmd_num_val[CMD_NUM_END];

void AC_ctrl_ap_fd(int local_server_sock, void *eloop_ctx, void *sock_ctx);




#endif
