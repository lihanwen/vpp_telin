/*******************************************************************************
 Copyright (C) 2016 Hangzhou Telin Technologies Co.,Ltd. All Rights Reserved.
 --------------------------------------------------------------------------------
 文件名称: ac_mem.c 
 功能描述: 与链表(空闲链表与在线链表)有关的操作
*******************************************************************************/

#include <unistd.h>
#include <stdlib.h> 
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <arpa/inet.h>

#include "vpp.h"
#include "list.h"
#include "cJSON.h"
#include "eloop.h"
#include "vpp_command.h"
#include "vpp_mem.h"
#include "vpp_provider.h"
#include "http_redirect.h"


struct dl_list idle_list_head[LIST_TYPE_END];
struct dl_list http_redirect_msg_head;

struct dl_list red_user_head[LIST_TYPE_USER_END];
struct dl_list red_user_msg_head[1024];


/*******************************************************************************
 函数名称  : link_head_init
 功能描述  : 初始化链表头
 输入参数  : 无
 输出参数  : 无
 返 回 值  : 无
             
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 2016.4.20
*******************************************************************************/
void link_head_init(void)
{
    int i = 0;

    //初始化空闲链表头
    for(i=0; i<LIST_TYPE_END; i++)
    {
        dl_list_init(&idle_list_head[i]);
    }

    //初始化http重定向链表头
    dl_list_init(&http_redirect_msg_head);    

    return ;
}

void link_user_head_init(void)
{
    int i = 0;

    //初始化空闲链表头
    for(i=0; i<1024; i++)
    {
        dl_list_init(&red_user_msg_head[i]);
    }

    for(i=0; i<LIST_TYPE_USER_END; i++)
    {
        dl_list_init(&red_user_head[i]);
    }   

    return ;
}


/*******************************************************************************
 函数名称  : allocate_memory
 功能描述  : 给空闲链表分配4K空间
 输入参数  : type  0位AP链表，1为WTP链表
              size  链表的结构体的大小
 输出参数  : 无
 返 回 值  : 无
             
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 2016.4.20
*******************************************************************************/
static void allocate_memory(int type, int size)
{
    int i = 0;
    char *idle_add;

    //分配4k空间
    idle_add = malloc(MALLOC_SIZE);

    //初始化空闲链表
    for(i = 0; i < (MALLOC_SIZE/size); i++)
    {    
        //初始化要添加的idle_add
        dl_list_init( (struct dl_list *)idle_add );
        
        //把idle_add加入到空闲链表中
        dl_list_add(&(idle_list_head[type]), (struct dl_list *)idle_add);
        //跳到下一个要添加idle_add的位置
        idle_add += size;
    }
    return ;
}


/*******************************************************************************
 函数名称  : allocate_memory
 功能描述  : 给空闲链表分配4K空间
 输入参数  : type  0位AP链表，1为WTP链表
              size  链表的结构体的大小
 输出参数  : 无
 返 回 值  : 无
             
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 2016.4.20
*******************************************************************************/
static void allocate_user_memory(int type, int size)
{
    int i = 0;
    char *idle_add;

    //分配4k空间
    idle_add = malloc(MALLOC_SIZE);

    //初始化空闲链表
    for(i = 0; i < (MALLOC_SIZE/size); i++)
    {    
        //初始化要添加的idle_add
        dl_list_init( (struct dl_list *)idle_add );
        
        //把idle_add加入到空闲链表中
        dl_list_add(&(red_user_head[type]), (struct dl_list *)idle_add);
        //跳到下一个要添加idle_add的位置
        idle_add += size;
    }
    return ;
}


/*******************************************************************************
 函数名称  : get_point
 功能描述  : 获得空闲链表中的一个节点
 输入参数  : type  0位AP链表，1为WTP链表
              size  链表的结构体的大小
 输出参数  : 无
 返 回 值  : 成功返回空闲链表的地址
              失败返回NULL  
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 2016.4.20
*******************************************************************************/
static void *get_point(int type, int size)
{
    struct dl_list *point;
	
    while(1)
    {
        //判断空闲链表是否为空，如果不为空取出到在线链表
        if(idle_list_head[type].next != &(idle_list_head[type]))
        {
            point = idle_list_head[type].next;
            dl_list_del(point);

            break;
        }
        //如果为空分配4k空间
        else
        {    
            allocate_memory(type,size);
        }
    }
    //根据point找到PORTAL_REDIRECT_INFO
    switch(type)
    {
        case LIST_TYPE_REDIRECT:
        {
            return dl_list_entry(point, PORTAL_REDIRECT_INFO, list);
            break;
        }
        default:
            return NULL;
    }

    return NULL;
}

/*******************************************************************************
 函数名称  : get_user_point
 功能描述  : 获得空闲链表中的一个节点
 输入参数  : type  0位AP链表，1为WTP链表
              size  链表的结构体的大小
 输出参数  : 无
 返 回 值  : 成功返回空闲链表的地址
              失败返回NULL  
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 
*******************************************************************************/
static void *get_user_point(int type, int size)
{
    struct dl_list *point;
	
    while(1)
    {
        //判断空闲链表是否为空，如果不为空取出到在线链表
        if(red_user_head[type].next != &(red_user_head[type]))
        {
            point = red_user_head[type].next;
            dl_list_del(point);

            break;
        }
        //如果为空分配4k空间
        else
        {    
            allocate_user_memory(type,size);
        }
    }
    //根据point找到PORTAL_REDIRECT_INFO
    switch(type)
    {
        case LIST_TYPE_USER:
        {
            return dl_list_entry(point, PORTAL_RED_USER_INFO, list);
            break;
        }
        default:
            return NULL;
    }

    return NULL;
}

PORTAL_REDIRECT_INFO * get_redirect_info_by_ifindex(u_int8_t if_index)
{
	PORTAL_REDIRECT_INFO *one_entry = NULL;

	dl_list_for_each(one_entry,&http_redirect_msg_head,PORTAL_REDIRECT_INFO,list)
	{
		if(one_entry->index == if_index)
		{
			return one_entry;
		}
	}
	return NULL;
}

/*******************************************************************************
 函数名称  : get_redirect_info_by_ifindex
 功能描述  : 根据接口索引查找重定向配置
 输入参数  : if_index  接口索引
 输出参数  : 无
 返 回 值  : 
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 2017.2.8
*******************************************************************************/
/*PORTAL_REDIRECT_INFO *get_redirect_info_by_ifindex(u_int8_t if_index)
{
    struct dl_list *p_hash;
    PORTAL_REDIRECT_INFO *redirect_info = NULL;
    VPP_DEBUG("get in   %p\n", (void *)redirect_info);
    p_hash = http_redirect_msg_head.next;
    while( p_hash != &http_redirect_msg_head)
    {    
    
        redirect_info = dl_list_entry(p_hash, PORTAL_REDIRECT_INFO, list);

        if( if_index == redirect_info->index )
        {
            break;
        }
        else
        {    
            p_hash = p_hash->next;
            redirect_info = NULL;
            continue;
        }
    }
	
    return redirect_info;
}
*/
/*******************************************************************************
 函数名称  : AC_memory_redirect
 功能描述  : 添加一个接口的重定向信息
 输入参数  : if_index (接口索引)
             if_ip    (接口ip)
             redirect_url
             nasid
 输出参数  : 无
 返 回 值  : 
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 2017.2.8
*******************************************************************************/
PORTAL_REDIRECT_INFO *AC_memory_redirect(u_int8_t if_index, 
                                            u_int32_t if_ip, char redirect_url[MAX_PORTAL_URL],
                                            char nasid[MAX_NASID_LEN])
{  VPP_DEBUG("AC_memory_redirect \n");
    PORTAL_REDIRECT_INFO *redirect_info;
    //根据接口索引查找重定向配置
    redirect_info = get_redirect_info_by_ifindex(if_index);
    if( redirect_info != NULL )
	{
		free_redirect_info(redirect_info->index);
	}
	
        //如果http_redirect_msg_head中没有这个结构体，在空闲链表中获取一个空结构体
        redirect_info = get_point(LIST_TYPE_REDIRECT, sizeof(PORTAL_REDIRECT_INFO));
        if( redirect_info != NULL )
        {                    
            memset(redirect_info, 0, sizeof(PORTAL_REDIRECT_INFO));
            //初始化重定向信息
            redirect_info->index = if_index;
            redirect_info->nasip = ntohl(if_ip);
            memcpy(redirect_info->url, redirect_url, min(strlen(redirect_url), MAX_PORTAL_URL));
            memcpy(redirect_info->nasid, nasid, min(strlen(nasid), MAX_NASID_LEN));
            redirect_info->unix_socket = -1;
            //初始化链表头
            dl_list_init( &(redirect_info->list) );
            
            //把当前结构体添加到ap_alone_scan_ctrl_hash中
            dl_list_add(&http_redirect_msg_head, &(redirect_info->list));
            //创建监听2050端口的tcpsocket
            redirect_info->unix_socket = vpp_make_listen_tcp_fd(AP_HTTP_REDIRECT_PORT, redirect_info->nasip);
            VPP_DEBUG("1111111111111111111111111  %p\n", (void*)redirect_info);
            if (redirect_info->unix_socket < 0)
            {
                VPP_log_error("xxxxxxxxxxxxxxxxx\n");
                return NULL;
            }
            //接收http报文请求，回重定向http应答并给portal程序发送上线station信息
            VPP_DEBUG("**********接收报文请求**********\n");
            eloop_register_read_sock(redirect_info->unix_socket, AP_read_http, 
                                            NULL, (void*)(long)redirect_info->index);
        }
        else
        {
            return NULL;
        }

    return redirect_info;
}


/*******************************************************************************
 函数名称  : AC_memory_user_data
 功能描述  : 添加一个接口的重定向信息
 输入参数  : if_index (接口索引)
             if_ip    (接口ip)
             redirect_url
             nasid
 输出参数  : 无
 返 回 值  : 
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 2017.2.28
*******************************************************************************/
PORTAL_RED_USER_INFO *AC_memory_user_data(u_int32_t user_ip, char mac[ETHER_MAC_LEN])
{  
    PORTAL_RED_USER_INFO*user_info;

	
    //根据ip查找重定向配置
    user_info = get_user_info_by_ip(user_ip);
    if( user_info == NULL )
	{
		VPP_DEBUG("cant find ip\n");
	
	
        //如果http_redirect_msg_head中没有这个结构体，在空闲链表中获取一个空结构体
        user_info = get_user_point(LIST_TYPE_USER , sizeof(PORTAL_RED_USER_INFO));

	}
    if( user_info != NULL )
    {                    
        memset(user_info, 0, sizeof(PORTAL_RED_USER_INFO));
        //初始化重定向信息
        user_info->user_ip = user_ip;

        memcpy(user_info->user_mac, user_info, min(strlen(mac), ETHER_MAC_LEN));
        //初始化链表头
        dl_list_init( &(user_info->list) );
        
        //把当前结构体添加到ap_alone_scan_ctrl_hash中
        dl_list_add(&red_user_msg_head[user_ip & 1024], &(user_info->list));
      
    }
    else
    {
        return NULL;
    }

    return user_info;
}


/*******************************************************************************
 函数名称  : get_user_info_by_ip
 功能描述  : 根据ip着用户
 输入参数  : user_ip 
 输出参数  : 无
 返 回 值  : 
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 2017.2.8
*******************************************************************************/

PORTAL_RED_USER_INFO *get_user_info_by_ip(u_int32_t user_ip)
{
	struct dl_list *p_hash;
    PORTAL_RED_USER_INFO *user_info = NULL;
    
    //在线链表头赋给p_buf，用于查找
    p_hash = red_user_msg_head[user_ip & 1024].next;
    //判断链表是否查找完
    while( p_hash != &(red_user_msg_head[user_ip & 1024]))
    {    
    
        //根据p_buf找到ap
        user_info = dl_list_entry(p_hash, PORTAL_RED_USER_INFO, list);

        //找到之后跳出循环
        if( user_ip == user_info->user_ip )
        {
            break;
        }
        else
        {    
            p_hash = p_hash->next;
            //用于判断是否找到
            user_info = NULL;
            continue;
        }
    }
	
    return user_info;




}


/*******************************************************************************
 函数名称  : free_alone_ap_scan_ctrl_point
 功能描述  : 从单独ap扫频控制链表中释放放到空闲链表
 输入参数  : if_index (接口索引)
 输出参数  : 无
 返 回 值  : 无 
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 2017.2.8
*******************************************************************************/
void free_redirect_info(u_int8_t if_index)
{    
    PORTAL_REDIRECT_INFO *redirect_info;

    redirect_info = get_redirect_info_by_ifindex(if_index);
    if( NULL == redirect_info )
        return ;

    //停止接收http重定向的报文
    if( -1 != redirect_info->unix_socket )
    {
        eloop_unregister_read_sock(redirect_info->unix_socket);
        shutdown(redirect_info->unix_socket, 2);
        close(redirect_info->unix_socket);
        redirect_info->unix_socket = -1;
    }
        
    //从在线链表中删除point
    dl_list_del(&(redirect_info->list));

    //添加point到空闲链表的尾部
    dl_list_add_tail(&(idle_list_head[LIST_TYPE_REDIRECT]), &(redirect_info->list));

    return ;
}
