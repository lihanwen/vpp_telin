/*******************************************************************************
 Copyright (C) 2015 Technologies Co.,Ltd. All Rights Reserved.
--------------------------------------------------------------------------------
 文件名称: http_redirect.c 
 功能描述: http网页重定向
*******************************************************************************/
#include <unistd.h>
#include <stdlib.h> 
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <sys/resource.h>
#include <netinet/in.h>
#include <ifaddrs.h>   
#include <sys/socket.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <time.h>

#include "vpp.h"
#include "cJSON.h"
#include "eloop.h"
#include "vpp_command.h"
#include "vpp_mem.h"
#include "vpp_provider.h"
#include "http_redirect.h"

#define HTTP_MAX_LEN 10240
#define HTTP_READ_BUF_LEN 4096

//给要上线的station回的固定的http报文
#define HTTP_VERSION_DATA "HTTP/1.0 200  Output Follows\n"
#define HTTP_SERVER_DATA "Server: ac/1.0.0\n"
#define HTTP_DATE_DATA "Date: %s\n"
#define HTTP_CONNECTION_DATA "Connection: close\n"
#define HTTP_CONTENT_TYPE_DATA "Content-Type: text/html\n\n"
#define HTTP_TEXT_HTTP_DATA "<meta http-equiv=\"refresh\" id=\"portal_href\" content=\"0; "\
                                            "url=%s?&userip=%s&usermac=%s&nasip=%s&nasid=%s\"/>\n"
#define HTTP_ENTER_DATA "\n"


/*******************************************************************************
 函数名称  : httpd_sendHeaders
 功能描述  : 给要上线的station回的固定的http报文
 输入参数  : ac
             clientSock station连接的socket
             wlan_id wlan_id 号
             userip 用户ip
             mac_6  用户mac
 输出参数  : 无
 返 回 值  : socket     成功
             -1         失败
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 2016.11.19
*******************************************************************************/
static int httpd_sendHeaders(int clientSock, u_int8_t index,
                    char *userip)
{
    int ret;
    struct in_addr client_addr;
    char IPdotdec[MAX_IP_LEN];          //存放点分十进制IP地址
    
    char timeBuf[TIME_STRING_LEN];
    char http_buf[HTTP_MAX_LEN];
    char fakemac[ETHER_MAC_LEN] ={ 10,02,03,04,05,06} ;
    char usermac[32]= {0};
    PORTAL_REDIRECT_INFO *redirect_info;
	u_int32_t ip = 0;
//	PORTAL_RED_USER_INFO * user_info;

    memset(timeBuf, 0, TIME_STRING_LEN);
    memset(http_buf, 0, HTTP_MAX_LEN);
    ip = inet_addr(userip);
    
//	user_info = get_user_info_by_ip(ip);
	
	VPP_DEBUG("userip %s\n",userip);
	VPP_DEBUG("inet_addr(userip) %x\n",ip);
    redirect_info = get_redirect_info_by_ifindex(index);
    if( NULL == redirect_info )
    {
        return 0;
    }
 VPP_DEBUG("&&&&&&&&&&&&&&&&&&\n");
    //获取当前时间存入timeBuf
    format_Time_String(timeBuf, 0);

 //   client_addr.s_addr = htonl(redirect_info->nasip);
 	client_addr.s_addr =redirect_info->nasip;//主机序

    memset(IPdotdec, 0, sizeof(IPdotdec));
    inet_ntop(AF_INET, &client_addr, IPdotdec,  sizeof(IPdotdec)); 

   snprintf(usermac, sizeof(usermac), MACSTR_WIN, MAC2STR(fakemac));
 // snprintf(usermac, sizeof(usermac), MACSTR_WIN, MAC2STR(user_info->user_mac));

	VPP_DEBUG("http\n");
	
    //组包要发送的报文
    snprintf(http_buf, HTTP_MAX_LEN, 
                HTTP_VERSION_DATA 
                HTTP_SERVER_DATA
                HTTP_DATE_DATA
                HTTP_CONNECTION_DATA
                HTTP_CONTENT_TYPE_DATA
                HTTP_TEXT_HTTP_DATA,
                timeBuf, redirect_info->url,
                userip,usermac, IPdotdec,
                redirect_info->nasid);
	/*
	snprintf(http_buf, HTTP_MAX_LEN, 
                HTTP_VERSION_DATA 
                HTTP_SERVER_DATA
                HTTP_DATE_DATA
                HTTP_CONNECTION_DATA
                HTTP_CONTENT_TYPE_DATA
                HTTP_TEXT_HTTP_DATA,
                timeBuf, redirect_info->url, 
                userip, IPdotdec, redirect_info->nasid);

	*/

    /* 发送 */
    ret = send(clientSock, http_buf, strlen(http_buf), 0);
    if (ret < 0)
    {
        VPP_log_error("Send fail, errno=%d. Reason:%s\n", errno, strerror(errno));
    }

    return ret;
}

/*******************************************************************************
 函数名称  : AP_redirect_http
 功能描述  : 读取http报文，回固定的http报文
 输入参数  :  sock       监听的socket
             eloop_ctx
             sock_ctx
 输出参数  : 无
 返 回 值  : 无
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 2016.11.19
*******************************************************************************/
static void AP_redirect_http(int sock, void *eloop_ctx, void *sock_ctx)
{
    int ret;
    u_int8_t index;
    struct in_addr client_addr;
    char recvbuf[HTTP_READ_BUF_LEN];
    char userip[MAX_IP_LEN]; //存放点分十进制IP地址
    //char usermac[MAX_MAC_ADDR];
    //char mac_6[MAC_LENGTH];

	VPP_DEBUG("AP_redirect_http \n");

    
    //接收客户端信息
    ret = recv(sock, recvbuf, sizeof(recvbuf), 0);
	VPP_DEBUG("***********recv*************\n");
    if( ret > 0)
    {     
        //获取用户ip及所属的wlan_id
   //     client_addr.s_addr = htonl((u_int32_t)(long)eloop_ctx);
   		client_addr.s_addr = ((u_int32_t)(long)eloop_ctx);
		VPP_DEBUG("client_addr.s_addr : %x \n",client_addr.s_addr);
        index = (u_int8_t)(long)sock_ctx;
        
        memset(userip, 0, sizeof(userip));
		
        inet_ntop(AF_INET, &client_addr, userip,  sizeof(userip)); 
		VPP_DEBUG("@@@@@@@@@@@@@@@@user_ip : %s \n",userip);
        
        //由ip获取mac
        //if( 0 == arp_get_mac(userip, usermac) )
        //{
            //转换以:分隔的mac地址为6个字节数组
            //sscanf( usermac, MACSTR_A, MAC2STR_A(mac_6) );
            httpd_sendHeaders( sock, index, userip );
        //}
        //else
        //{
        //    VPP_DEBUG("in AP_redirect_http, arp_get_mac fail\n");
       // }
    }

    eloop_unregister_read_sock(sock);
    close(sock);

    return ;
}

/*******************************************************************************
 函数名称  : AP_read_http
 功能描述  : 收到http报文的回调函数
 输入参数  : sock       监听的socket
             eloop_ctx
             sock_ctx
 输出参数  : 无
 返 回 值  : 无
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 2016.11.19
*******************************************************************************/
void AP_read_http(int sock, void *eloop_ctx, void *sock_ctx)
{
	VPP_DEBUG("AP_read_http \n");
    u_int8_t index;
    int clientSock;
    socklen_t cliaddr_len;
 //   struct in_addr client_addr;
    struct sockaddr_in client_addr;

    //ac = (AP_SRV *)eloop_ctx;
    index = (u_int8_t)(long)sock_ctx;

    cliaddr_len = sizeof(client_addr);
    bzero(&client_addr, sizeof(client_addr));
        
    //等待创建新连接
    clientSock = accept(sock, (struct sockaddr *)&client_addr, &cliaddr_len);
	VPP_DEBUG("***** accept %x  888 \n",client_addr.sin_addr.s_addr);
    if( clientSock <= 0 )
    {           
        VPP_log_error("AP_read_http accept fail, errno=%d. Reason:%s\n", errno, strerror(errno));
        return ;
    }
    VPP_DEBUG("------------------------\n");
    eloop_register_read_sock(clientSock, AP_redirect_http, 
                    (void*)(long)client_addr.sin_addr.s_addr, (void*)(long)index);
    
    return ;
}
