/*******************************************************************************
 Copyright (C) 2016 Hangzhou Telin Technologies Co.,Ltd. All Rights Reserved.
 --------------------------------------------------------------------------------
 �ļ�����: ac_ctrl.c 
 ��������: ����web���������ap
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



//����Json�ļ���ĵ�ǰ�ڵ��num���͵�key����ö��CMD_SSID_NUM���Ӧ��
static char *cmd_num_name[CMD_NUM_END] = 
{
    "module", 
    "op",
    "if_index",
    "user_ip",
};
//�洢Json�ļ���ĵ�ǰ�ڵ��num���͵�val����ö��CMD_SSID_NUM���Ӧ
u_int16_t cmd_num_val[CMD_NUM_END];

//���յ�Json�ļ����ÿһ���ڵ��string���͵�key����ö��CMD_SSID_STRING���Ӧ��
static char *cmd_string_name[CMD_STRING_END] = 
{
    "if_ip",
    "porta_url",
    "nasid",
    "user_mac",
};
//�洢Json�ļ���ĵ�ǰ�ڵ��string���͵�val����ö��CMD_SSID_STRING���Ӧ
static char cmd_string_val[CMD_STRING_END][MAX_DATA_LEN];


/*******************************************************************************
 ��������  : parseJson
 ��������  : �������ڲ�Json�ڵ�
 �������  : pJson       ���ڲ��Json�ڵ�
 �������  : ��
 �� �� ֵ  : ��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ : 
 �޸�����  : 
 �޸�Ŀ��  : ���º���
 �޸�����  : 2016.4.1
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
 ��������  : write_config
 ��������  : ��ȡssid��Ϣ��������ap
 �������  : read_status   ��ȡ״̬ 0:��ȡ�����ļ� 1:��ҳ���ȡ
 �������  : ��
 �� �� ֵ  : ��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ : 
 �޸�����  : 
 �޸�Ŀ��  : ���º���
 �޸�����  : 2016.4.1
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
                    //�洢�ض�������
                    AC_memory_redirect(index, 
                                       if_ip,/*������*/
                                       cmd_string_val[CMD_PORTAL_URL],
                                       cmd_string_val[CMD_NASID]);
                    break;
                }
                case OP_PORTAL_DEL:
                {
					VPP_DEBUG("gggggggggggggggggg\n");
                    //ɾ���ض�������
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
 ��������  : AC_ctrl_ap_fd
 ��������  : �յ����籨�ĵĻص�����
 �������  : sock       ������socket
             eloop_ctx
             sock_ctx
 �������  : ��
 �� �� ֵ  : ��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ : 
 �޸�����  : 
 �޸�Ŀ��  : ���º���
 �޸�����  : 2016.4.1
*******************************************************************************/
void AC_ctrl_ap_fd(int local_server_sock, void *eloop_ctx, void *sock_ctx)
{
    int i;
    struct sockaddr_un addr;
    socklen_t addrlen;
    char buf_ctrl[AC_RECV_BUF_SIZE];
    ssize_t len;

    //��������Json�ṹ��
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
    //msgת����Json��ʽ���ں���cJson_Parse���ѿ��ٿռ䣬�����Ҫ��cJSON_Delete�ͷ�
    pJson = cJSON_Parse(buf_ctrl);
    if(NULL == pJson)
    {
        /* ���� */
        VPP_DEBUG("control data not JSON fromat\n");
        
        return ;
    }
    //���ѻ�õ�Json�ļ��ĺ��ӽڵ㸳��pJson_grandpa
    pJson_grandpa = pJson->child;
    //������pJson_grandpaͬһ�������нڵ�
    while( pJson_grandpa != NULL)
    {
        for(i=0; i<CMD_NUM_END; i++)
        {
            cmd_num_val[i] = 0;
        }
        //pJson_grandpa�ĺ��ӽڵ㸳��pJson_pa
        pJson_pa= pJson_grandpa->child;
        //������pJson_paͬһ�������нڵ�
        while( pJson_pa != NULL)
        {
            //����pJson_son�������
            parseJson(pJson_pa);
            //pJson_pa�ĺ��ӽڵ㸳��pJson_son
            pJson_son = pJson_pa->child;
            //������pJson_sonͬһ�������нڵ�
            while( pJson_son != NULL)
            {
                //����pJson_son�������
                parseJson(pJson_son);
                //ȡ��һ��pJson_son�ڵ�
                pJson_son = pJson_son->next;
            }
            //ȡ��һ��pJson_pa�ڵ�
            pJson_pa = pJson_pa->next;
        }
        //�յ��ĵ�ǰ��Ϣ�浽��Ӧ��λ��
        write_config();

        //������ap�·����ò��ظ�web
        //AC_send_wlan_config_req();
        
        //ȡ��һ��pJson_grandpa�ڵ�
        pJson_grandpa = pJson_grandpa->next;
    }
    
    //�ͷ���cJSON_Parse���ٵĿռ�
    cJSON_Delete(pJson);
    pJson = NULL;    
}

