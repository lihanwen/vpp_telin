#ifndef __VPP_H__
#define __VPP_H__

#include "list.h"


#ifndef min
#define min(a,b) ((a)>(b)?(b):(a))
#endif

/* 
  AC程序的pid文件 
  该文件中第一个为主程序pid，后面为daemon程序pid
  如果daemon pid有多个，则表示daemon退出过
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
                
//unix socket 本地文件路径
#define UNIX_SOCKET_JSON_FILE "/tmp/.json_socket"
//数据最大长度
#define MAX_DATA_LEN 256



#define HTTP_MAX_LEN 10240
#define HTTP_READ_BUF_LEN 4096
#define HTTP_TIME_STRING_LEN 40

//日期时间的长度
#define TIME_STRING_LEN 40


/* 发送缓冲区大小 */
#define AC_SEND_BUF_SIZE    2048
/* 接收缓冲区大小 */
#define AC_RECV_BUF_SIZE    2048
/* 定义mac地址长度 */
#define MAC_LENGTH 6
//nas_id字符串的最大长度，多一个字节用于存放'\0'
#define MAX_NASID_LEN 33
//portal_url字符串最大长度，多一个字节用于存放'\0'
#define MAX_PORTAL_URL 129
/* 点分十进制ip的最大长度(最长为15，给'\0'留一个位置) */
#define MAX_IP_LEN 16
//网卡、接口名的长度
#define MAX_ETH_NAME_LEN 16
                            
/* 带有:的mac地址长度，例如01:02:03:04:05:06共17个字节*/
#define MAX_MAC_ADDR 17

#define ETHER_MAC_LEN 6                           
                            
/* http报文重定向的端口 */
#define AP_HTTP_REDIRECT_PORT htons(80)


//portal重定向信息
typedef struct portal_redirect_info_st
{
    struct dl_list list;
    int  unix_socket;            //存储监听的socket
    u_int8_t index;              //索引
    u_int32_t nasip;             //存放nas_ip 主机序
    char url[MAX_PORTAL_URL];    //存放portal_url地址
    char nasid[MAX_NASID_LEN];   //存放nas_id
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
