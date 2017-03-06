/*******************************************************************************
 Copyright (C) 2016 Hangzhou Telin Technologies Co.,Ltd. All Rights Reserved.
--------------------------------------------------------------------------------
 文件名称: ac_mem.h 
 功能描述: 本文件定义了与ac硬件相关的接口函数
*******************************************************************************/
#ifndef __VPP_MEM_H__
#define __VPP_MEM_H__

#include "vpp.h"


//每次开辟空闲链表的大小
#define MALLOC_SIZE (4*1024)


//判断类型 ap或者wtp
enum LIST_TYPE_e
{
    LIST_TYPE_REDIRECT,
    LIST_TYPE_END
};

//声明mem.c里定义的全局变量
extern struct dl_list idle_list_head[LIST_TYPE_END];
extern struct dl_list http_redirect_msg_head;


enum LIST_USER_TYPE_e
{
    LIST_TYPE_USER,
    LIST_TYPE_USER_END
};

//声明mem.c里定义的全局变量
extern struct dl_list red_user_head[LIST_TYPE_USER_END];
extern struct dl_list red_user_msg_head[1024];


PORTAL_REDIRECT_INFO *AC_memory_redirect(u_int8_t if_index, 
                                            u_int32_t if_ip, char redirect_url[MAX_PORTAL_URL],
                                            char nasid[MAX_NASID_LEN]);
PORTAL_RED_USER_INFO *AC_memory_user_data(u_int32_t user_ip, char mac[ETHER_MAC_LEN]);

extern void free_redirect_info(u_int8_t if_index);
extern void link_head_init(void);
extern void link_user_head_init(void);

extern PORTAL_REDIRECT_INFO *get_redirect_info_by_ifindex(u_int8_t if_index);
extern PORTAL_RED_USER_INFO *get_user_info_by_ip(u_int32_t user_ip);




#endif


