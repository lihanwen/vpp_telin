/*******************************************************************************
 Copyright (C) 2016 Hangzhou Telin Technologies Co.,Ltd. All Rights Reserved.
 --------------------------------------------------------------------------------
 �ļ�����: ac_mem.c 
 ��������: ������(������������������)�йصĲ���
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
 ��������  : link_head_init
 ��������  : ��ʼ������ͷ
 �������  : ��
 �������  : ��
 �� �� ֵ  : ��
             
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ : 
 �޸�����  : 
 �޸�Ŀ��  : ���º���
 �޸�����  : 2016.4.20
*******************************************************************************/
void link_head_init(void)
{
    int i = 0;

    //��ʼ����������ͷ
    for(i=0; i<LIST_TYPE_END; i++)
    {
        dl_list_init(&idle_list_head[i]);
    }

    //��ʼ��http�ض�������ͷ
    dl_list_init(&http_redirect_msg_head);    

    return ;
}

void link_user_head_init(void)
{
    int i = 0;

    //��ʼ����������ͷ
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
 ��������  : allocate_memory
 ��������  : �������������4K�ռ�
 �������  : type  0λAP����1ΪWTP����
              size  ����Ľṹ��Ĵ�С
 �������  : ��
 �� �� ֵ  : ��
             
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ : 
 �޸�����  : 
 �޸�Ŀ��  : ���º���
 �޸�����  : 2016.4.20
*******************************************************************************/
static void allocate_memory(int type, int size)
{
    int i = 0;
    char *idle_add;

    //����4k�ռ�
    idle_add = malloc(MALLOC_SIZE);

    //��ʼ����������
    for(i = 0; i < (MALLOC_SIZE/size); i++)
    {    
        //��ʼ��Ҫ��ӵ�idle_add
        dl_list_init( (struct dl_list *)idle_add );
        
        //��idle_add���뵽����������
        dl_list_add(&(idle_list_head[type]), (struct dl_list *)idle_add);
        //������һ��Ҫ���idle_add��λ��
        idle_add += size;
    }
    return ;
}


/*******************************************************************************
 ��������  : allocate_memory
 ��������  : �������������4K�ռ�
 �������  : type  0λAP����1ΪWTP����
              size  ����Ľṹ��Ĵ�С
 �������  : ��
 �� �� ֵ  : ��
             
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ : 
 �޸�����  : 
 �޸�Ŀ��  : ���º���
 �޸�����  : 2016.4.20
*******************************************************************************/
static void allocate_user_memory(int type, int size)
{
    int i = 0;
    char *idle_add;

    //����4k�ռ�
    idle_add = malloc(MALLOC_SIZE);

    //��ʼ����������
    for(i = 0; i < (MALLOC_SIZE/size); i++)
    {    
        //��ʼ��Ҫ��ӵ�idle_add
        dl_list_init( (struct dl_list *)idle_add );
        
        //��idle_add���뵽����������
        dl_list_add(&(red_user_head[type]), (struct dl_list *)idle_add);
        //������һ��Ҫ���idle_add��λ��
        idle_add += size;
    }
    return ;
}


/*******************************************************************************
 ��������  : get_point
 ��������  : ��ÿ��������е�һ���ڵ�
 �������  : type  0λAP����1ΪWTP����
              size  ����Ľṹ��Ĵ�С
 �������  : ��
 �� �� ֵ  : �ɹ����ؿ�������ĵ�ַ
              ʧ�ܷ���NULL  
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ : 
 �޸�����  : 
 �޸�Ŀ��  : ���º���
 �޸�����  : 2016.4.20
*******************************************************************************/
static void *get_point(int type, int size)
{
    struct dl_list *point;
	
    while(1)
    {
        //�жϿ��������Ƿ�Ϊ�գ������Ϊ��ȡ������������
        if(idle_list_head[type].next != &(idle_list_head[type]))
        {
            point = idle_list_head[type].next;
            dl_list_del(point);

            break;
        }
        //���Ϊ�շ���4k�ռ�
        else
        {    
            allocate_memory(type,size);
        }
    }
    //����point�ҵ�PORTAL_REDIRECT_INFO
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
 ��������  : get_user_point
 ��������  : ��ÿ��������е�һ���ڵ�
 �������  : type  0λAP����1ΪWTP����
              size  ����Ľṹ��Ĵ�С
 �������  : ��
 �� �� ֵ  : �ɹ����ؿ�������ĵ�ַ
              ʧ�ܷ���NULL  
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ : 
 �޸�����  : 
 �޸�Ŀ��  : ���º���
 �޸�����  : 
*******************************************************************************/
static void *get_user_point(int type, int size)
{
    struct dl_list *point;
	
    while(1)
    {
        //�жϿ��������Ƿ�Ϊ�գ������Ϊ��ȡ������������
        if(red_user_head[type].next != &(red_user_head[type]))
        {
            point = red_user_head[type].next;
            dl_list_del(point);

            break;
        }
        //���Ϊ�շ���4k�ռ�
        else
        {    
            allocate_user_memory(type,size);
        }
    }
    //����point�ҵ�PORTAL_REDIRECT_INFO
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
 ��������  : get_redirect_info_by_ifindex
 ��������  : ���ݽӿ����������ض�������
 �������  : if_index  �ӿ�����
 �������  : ��
 �� �� ֵ  : 
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ : 
 �޸�����  : 
 �޸�Ŀ��  : ���º���
 �޸�����  : 2017.2.8
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
 ��������  : AC_memory_redirect
 ��������  : ���һ���ӿڵ��ض�����Ϣ
 �������  : if_index (�ӿ�����)
             if_ip    (�ӿ�ip)
             redirect_url
             nasid
 �������  : ��
 �� �� ֵ  : 
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ : 
 �޸�����  : 
 �޸�Ŀ��  : ���º���
 �޸�����  : 2017.2.8
*******************************************************************************/
PORTAL_REDIRECT_INFO *AC_memory_redirect(u_int8_t if_index, 
                                            u_int32_t if_ip, char redirect_url[MAX_PORTAL_URL],
                                            char nasid[MAX_NASID_LEN])
{  VPP_DEBUG("AC_memory_redirect \n");
    PORTAL_REDIRECT_INFO *redirect_info;
    //���ݽӿ����������ض�������
    redirect_info = get_redirect_info_by_ifindex(if_index);
    if( redirect_info != NULL )
	{
		free_redirect_info(redirect_info->index);
	}
	
        //���http_redirect_msg_head��û������ṹ�壬�ڿ��������л�ȡһ���սṹ��
        redirect_info = get_point(LIST_TYPE_REDIRECT, sizeof(PORTAL_REDIRECT_INFO));
        if( redirect_info != NULL )
        {                    
            memset(redirect_info, 0, sizeof(PORTAL_REDIRECT_INFO));
            //��ʼ���ض�����Ϣ
            redirect_info->index = if_index;
            redirect_info->nasip = ntohl(if_ip);
            memcpy(redirect_info->url, redirect_url, min(strlen(redirect_url), MAX_PORTAL_URL));
            memcpy(redirect_info->nasid, nasid, min(strlen(nasid), MAX_NASID_LEN));
            redirect_info->unix_socket = -1;
            //��ʼ������ͷ
            dl_list_init( &(redirect_info->list) );
            
            //�ѵ�ǰ�ṹ����ӵ�ap_alone_scan_ctrl_hash��
            dl_list_add(&http_redirect_msg_head, &(redirect_info->list));
            //��������2050�˿ڵ�tcpsocket
            redirect_info->unix_socket = vpp_make_listen_tcp_fd(AP_HTTP_REDIRECT_PORT, redirect_info->nasip);
            VPP_DEBUG("1111111111111111111111111  %p\n", (void*)redirect_info);
            if (redirect_info->unix_socket < 0)
            {
                VPP_log_error("xxxxxxxxxxxxxxxxx\n");
                return NULL;
            }
            //����http�������󣬻��ض���httpӦ�𲢸�portal����������station��Ϣ
            VPP_DEBUG("**********���ձ�������**********\n");
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
 ��������  : AC_memory_user_data
 ��������  : ���һ���ӿڵ��ض�����Ϣ
 �������  : if_index (�ӿ�����)
             if_ip    (�ӿ�ip)
             redirect_url
             nasid
 �������  : ��
 �� �� ֵ  : 
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ : 
 �޸�����  : 
 �޸�Ŀ��  : ���º���
 �޸�����  : 2017.2.28
*******************************************************************************/
PORTAL_RED_USER_INFO *AC_memory_user_data(u_int32_t user_ip, char mac[ETHER_MAC_LEN])
{  
    PORTAL_RED_USER_INFO*user_info;

	
    //����ip�����ض�������
    user_info = get_user_info_by_ip(user_ip);
    if( user_info == NULL )
	{
		VPP_DEBUG("cant find ip\n");
	
	
        //���http_redirect_msg_head��û������ṹ�壬�ڿ��������л�ȡһ���սṹ��
        user_info = get_user_point(LIST_TYPE_USER , sizeof(PORTAL_RED_USER_INFO));

	}
    if( user_info != NULL )
    {                    
        memset(user_info, 0, sizeof(PORTAL_RED_USER_INFO));
        //��ʼ���ض�����Ϣ
        user_info->user_ip = user_ip;

        memcpy(user_info->user_mac, user_info, min(strlen(mac), ETHER_MAC_LEN));
        //��ʼ������ͷ
        dl_list_init( &(user_info->list) );
        
        //�ѵ�ǰ�ṹ����ӵ�ap_alone_scan_ctrl_hash��
        dl_list_add(&red_user_msg_head[user_ip & 1024], &(user_info->list));
      
    }
    else
    {
        return NULL;
    }

    return user_info;
}


/*******************************************************************************
 ��������  : get_user_info_by_ip
 ��������  : ����ip���û�
 �������  : user_ip 
 �������  : ��
 �� �� ֵ  : 
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ : 
 �޸�����  : 
 �޸�Ŀ��  : ���º���
 �޸�����  : 2017.2.8
*******************************************************************************/

PORTAL_RED_USER_INFO *get_user_info_by_ip(u_int32_t user_ip)
{
	struct dl_list *p_hash;
    PORTAL_RED_USER_INFO *user_info = NULL;
    
    //��������ͷ����p_buf�����ڲ���
    p_hash = red_user_msg_head[user_ip & 1024].next;
    //�ж������Ƿ������
    while( p_hash != &(red_user_msg_head[user_ip & 1024]))
    {    
    
        //����p_buf�ҵ�ap
        user_info = dl_list_entry(p_hash, PORTAL_RED_USER_INFO, list);

        //�ҵ�֮������ѭ��
        if( user_ip == user_info->user_ip )
        {
            break;
        }
        else
        {    
            p_hash = p_hash->next;
            //�����ж��Ƿ��ҵ�
            user_info = NULL;
            continue;
        }
    }
	
    return user_info;




}


/*******************************************************************************
 ��������  : free_alone_ap_scan_ctrl_point
 ��������  : �ӵ���apɨƵ�����������ͷŷŵ���������
 �������  : if_index (�ӿ�����)
 �������  : ��
 �� �� ֵ  : �� 
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ : 
 �޸�����  : 
 �޸�Ŀ��  : ���º���
 �޸�����  : 2017.2.8
*******************************************************************************/
void free_redirect_info(u_int8_t if_index)
{    
    PORTAL_REDIRECT_INFO *redirect_info;

    redirect_info = get_redirect_info_by_ifindex(if_index);
    if( NULL == redirect_info )
        return ;

    //ֹͣ����http�ض���ı���
    if( -1 != redirect_info->unix_socket )
    {
        eloop_unregister_read_sock(redirect_info->unix_socket);
        shutdown(redirect_info->unix_socket, 2);
        close(redirect_info->unix_socket);
        redirect_info->unix_socket = -1;
    }
        
    //������������ɾ��point
    dl_list_del(&(redirect_info->list));

    //���point�����������β��
    dl_list_add_tail(&(idle_list_head[LIST_TYPE_REDIRECT]), &(redirect_info->list));

    return ;
}
