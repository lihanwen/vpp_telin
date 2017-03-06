#ifndef __VPP_H__
#define __VPP_H__

#include "list.h"


#ifndef min
#define min(a,b) ((a)>(b)?(b):(a))
#endif

/* 
  AC�����pid�ļ� 
  ���ļ��е�һ��Ϊ������pid������Ϊdaemon����pid
  ���daemon pid�ж�������ʾdaemon�˳���
 */
#define AC_PID_FILE "/var/run/ac.pid"

#define VPP_DEBUG(str, arg...)  do{\
        if(g_ac_debug)\
        {\
            FILE *debug_fp = fopen("/tmp/vpp_debug.log", "a");\
            if (NULL != debug_fp){\
            fprintf(debug_fp, "%d:L%d in %s, ", g_ac_debug, __LINE__, __FILE__);\
            fprintf(debug_fp, str, ##arg);\
            fflush(debug_fp);\
            fclose(debug_fp);\
            }\
            else g_ac_debug++;\
        }\
}while(0)

#define VPP_log_error(str, arg...)  do{\
                            FILE *debug_fp = fopen("/tmp/vpp_error.log", "a");\
                            if (NULL != debug_fp){\
                            fprintf(debug_fp, "L%d in %s, ", __LINE__, __FILE__);\
                            fprintf(debug_fp, str, ##arg);\
                            fflush(debug_fp);\
                            fclose(debug_fp);\
                            }\
                }while(0)

#define MAC2STRP1(a, b) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (u_int8_t)((a)[5]+b)
#define MACSTRP1 "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX"
                            
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR_LINUX "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX"
#define MACSTR_WIN "%02hhX-%02hhX-%02hhX-%02hhX-%02hhX-%02hhX"
                            
#define MACSTR_A "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX"
#define MAC2STR_A(a) &(a)[0], &(a)[1], &(a)[2], &(a)[3], &(a)[4], &(a)[5]
                
//unix socket �����ļ�·��
#define UNIX_SOCKET_JSON_FILE "/tmp/.json_socket"
//������󳤶�
#define MAX_DATA_LEN 256



#define HTTP_MAX_LEN 10240
#define HTTP_READ_BUF_LEN 4096
#define HTTP_TIME_STRING_LEN 40

//����ʱ��ĳ���
#define TIME_STRING_LEN 40


/* ���ͻ�������С */
#define AC_SEND_BUF_SIZE    2048
/* ���ջ�������С */
#define AC_RECV_BUF_SIZE    2048
/* ����mac��ַ���� */
#define MAC_LENGTH 6
//nas_id�ַ�������󳤶ȣ���һ���ֽ����ڴ��'\0'
#define MAX_NASID_LEN 33
//portal_url�ַ�����󳤶ȣ���һ���ֽ����ڴ��'\0'
#define MAX_PORTAL_URL 129
/* ���ʮ����ip����󳤶�(�Ϊ15����'\0'��һ��λ��) */
#define MAX_IP_LEN 16
//�������ӿ����ĳ���
#define MAX_ETH_NAME_LEN 16
                            
/* ����:��mac��ַ���ȣ�����01:02:03:04:05:06��17���ֽ�*/
#define MAX_MAC_ADDR 17

#define ETHER_MAC_LEN 6                           
                            
/* http�����ض���Ķ˿� */
#define AP_HTTP_REDIRECT_PORT htons(80)


//portal�ض�����Ϣ
typedef struct portal_redirect_info_st
{
    struct dl_list list;
    int  unix_socket;            //�洢������socket
    u_int8_t index;              //����
    u_int32_t nasip;             //���nas_ip ������
    char url[MAX_PORTAL_URL];    //���portal_url��ַ
    char nasid[MAX_NASID_LEN];   //���nas_id
}PORTAL_REDIRECT_INFO;

int g_ac_debug;
//
typedef struct portal_red_user_info_st
{
	struct dl_list list;
	u_int32_t user_ip;
	char user_mac[ETHER_MAC_LEN];
}PORTAL_RED_USER_INFO;



#endif
