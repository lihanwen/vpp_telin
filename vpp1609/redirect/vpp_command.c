/*******************************************************************************
 Copyright (C) 2016 Hangzhou Telin Technologies Co.,Ltd. All Rights Reserved.
 --------------------------------------------------------------------------------
 文件名称: ac_ctrl.c 
 功能描述: 接收web的命令并控制ap
*******************************************************************************/
#include <unistd.h>
#include <stdlib.h> 
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include "vpp.h"
#include "cJSON.h"
#include "eloop.h"
#include "vpp_command.h"
#include "vpp_mem.h"
#include "vpp_provider.h"
#include "http_redirect.h"



//接收Json文件里的当前节点的num类型的key，与枚举CMD_SSID_NUM相对应，
static char *cmd_num_name[CMD_NUM_END] = 
{
    "module", 
    "op",
    "if_index",
    "user_ip",
};
//存储Json文件里的当前节点的num类型的val，与枚举CMD_SSID_NUM相对应
u_int16_t cmd_num_val[CMD_NUM_END];

//接收的Json文件里的每一个节点的string类型的key，与枚举CMD_SSID_STRING相对应，
static char *cmd_string_name[CMD_STRING_END] = 
{
    "if_ip",
    "porta_url",
    "nasid",
    "user_mac",
};
//存储Json文件里的当前节点的string类型的val，与枚举CMD_SSID_STRING相对应
static char cmd_string_val[CMD_STRING_END][MAX_DATA_LEN];


/*******************************************************************************
 函数名称  : parseJson
 功能描述  : 解析最内层Json节点
 输入参数  : pJson       最内层的Json节点
 输出参数  : 无
 返 回 值  : 无
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 2016.4.1
*******************************************************************************/
int parseJson(cJSON *pJson)
{
    int i;
    if(NULL == pJson)
    {
        return -1;
    }
    switch(pJson->type)
    {
        case cJSON_False :
            VPP_DEBUG("pJson type is cJSON_False, no analyses\n");
            break;
        case cJSON_True :
            VPP_DEBUG("pJson type is cJSON_True, no analyses\n");
            break;
        case cJSON_NULL :
            VPP_DEBUG("pJson type is cJSON_NULL, no analyses\n");
            break;
        case cJSON_Number :
            for(i=0; i<CMD_NUM_END; i++)
            {
                if(0 == strcmp(pJson->string, cmd_num_name[i]))
                {
                    //VPP_DEBUG("%s : %d \n",pJson->string, pJson->valueint);
                    cmd_num_val[i] = (u_int16_t)pJson->valueint;
                }
            }
            break;
        case cJSON_String :
            for(i=0; i<CMD_STRING_END; i++)
            {
                if(0 == strcmp(pJson->string, cmd_string_name[i]))
                {
                    //VPP_DEBUG("%s : %s \n", pJson->string, pJson->valuestring);
                    memset(cmd_string_val[i], '\0', MAX_DATA_LEN);
                    memcpy(cmd_string_val[i], pJson->valuestring, strlen(pJson->valuestring));
                }
            }
            break;
        case cJSON_Array :
            VPP_DEBUG("pJson type is cJSON_Array, no analyses\n");
            break;
        case cJSON_Object :
            //VPP_DEBUG("pJson type is cJSON_Object, no analyses\n");
            break;
        default :
            VPP_DEBUG("pJson type no exit\n");
            break;
    }
    
    return 0;
}

/*******************************************************************************
 函数名称  : write_config
 功能描述  : 读取ssid消息用于配置ap
 输入参数  : read_status   读取状态 0:读取配置文件 1:从页面读取
 输出参数  : 无
 返 回 值  : 无
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 2016.4.1
*******************************************************************************/
void write_config()
{VPP_DEBUG("write_config \n");
    switch (cmd_num_val[CMD_MODULE])
    {
        case MODULE_PORTAL:
        {
            u_int8_t index;

            index = (u_int8_t)cmd_num_val[CMD_IF_INDEX];
            switch(cmd_num_val[CMD_OP])
            {
                case OP_PORTAL_ADD:
                {
                    u_int32_t if_ip;
                    inet_pton(AF_INET, cmd_string_val[CMD_IF_IP], &if_ip);
                    //存储重定向配置
                    AC_memory_redirect(index, 
                                       if_ip,/*网络序*/
                                       cmd_string_val[CMD_PORTAL_URL],
                                       cmd_string_val[CMD_NASID]);
                    break;
                }
                case OP_PORTAL_DEL:
                {
					VPP_DEBUG("gggggggggggggggggg\n");
                    //删除重定向配置
                    free_redirect_info(index);

                    break;
                }
            }
            break;
        }
		case MODULE_USER:
		{
			 switch(cmd_num_val[CMD_OP])
            {
                case OP_PORTAL_ADD:
                { 
					/*
					char user_ip[MAX_IP_LEN]="\0";
					struct in_addr user_addr;	
					u_int32_t ip = cmd_num_val[CMD_USER_IP];
					memcpy(&user_addr,&ip,4);	
					strcpy(user_ip, inet_ntoa(user_addr));
					VPP_DEBUG("--------------------------user_ip %s\n",user_ip);*/
					AC_memory_user_data(cmd_num_val[CMD_USER_IP], cmd_string_val[CMD_MAC]);
                }
			 }
		}
    }
    return ;
}

/*******************************************************************************
 函数名称  : AC_ctrl_ap_fd
 功能描述  : 收到网络报文的回调函数
 输入参数  : sock       监听的socket
             eloop_ctx
             sock_ctx
 输出参数  : 无
 返 回 值  : 无
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 2016.4.1
*******************************************************************************/
void AC_ctrl_ap_fd(int local_server_sock, void *eloop_ctx, void *sock_ctx)
{
    int i;
    struct sockaddr_un addr;
    socklen_t addrlen;
    char buf_ctrl[AC_RECV_BUF_SIZE];
    ssize_t len;

    //定义三层Json结构体
    cJSON *pJson;
    cJSON *pJson_grandpa;
    cJSON *pJson_pa;
    cJSON *pJson_son;
    
    addrlen = sizeof(addr);
    memset(buf_ctrl, '\0', AC_RECV_BUF_SIZE);
	VPP_DEBUG("start	 ====================\n");

    len = recvfrom(local_server_sock, buf_ctrl, sizeof(buf_ctrl), MSG_DONTWAIT,
                    (struct sockaddr*)&addr, &addrlen);
    if( len <= 0)
    {
        VPP_log_error("recvfrom error\n");
        return ;
    }
	VPP_DEBUG("start	 ====================\n");

    VPP_DEBUG("--web_sendto_ac=%s--len=%d\n",buf_ctrl, (int)len);
    //msg转换成Json格式，在函数cJson_Parse中已开辟空间，用完后要用cJSON_Delete释放
    pJson = cJSON_Parse(buf_ctrl);
    if(NULL == pJson)
    {
        /* 发送 */
        VPP_DEBUG("control data not JSON fromat\n");
        
        return ;
    }
    //把已获得的Json文件的孩子节点赋给pJson_grandpa
    pJson_grandpa = pJson->child;
    //遍历与pJson_grandpa同一级的所有节点
    while( pJson_grandpa != NULL)
    {
        for(i=0; i<CMD_NUM_END; i++)
        {
            cmd_num_val[i] = 0;
        }
        //pJson_grandpa的孩子节点赋给pJson_pa
        pJson_pa= pJson_grandpa->child;
        //遍历与pJson_pa同一级的所有节点
        while( pJson_pa != NULL)
        {
            //解析pJson_son里的内容
            parseJson(pJson_pa);
            //pJson_pa的孩子节点赋给pJson_son
            pJson_son = pJson_pa->child;
            //遍历与pJson_son同一级的所有节点
            while( pJson_son != NULL)
            {
                //解析pJson_son里的内容
                parseJson(pJson_son);
                //取下一个pJson_son节点
                pJson_son = pJson_son->next;
            }
            //取下一个pJson_pa节点
            pJson_pa = pJson_pa->next;
        }
        //收到的当前消息存到相应的位置
        write_config();

        //给在线ap下发配置并回复web
        //AC_send_wlan_config_req();
        
        //取下一个pJson_grandpa节点
        pJson_grandpa = pJson_grandpa->next;
    }
    
    //释放用cJSON_Parse开辟的空间
    cJSON_Delete(pJson);
    pJson = NULL;    
}

