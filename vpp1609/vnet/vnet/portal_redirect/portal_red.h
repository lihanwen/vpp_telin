
#ifndef PORTAL_RED_H_
#define PORTAL_RED_H_ 

#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <vnet/portal_redirect/cJSON.h>
#include <vnet/portal/portal.h>

//unix socket server ?à?|ì????t??¤??
#define UNIX_SOCKET_JSON_FILE "/tmp/.json_socket"
#define MAX_URL_LENTH 129
#define MAX_NASIP_LENTH 16
#define MAX_NASID_LENTH 20

#define MAX_USERRIP_LENTH 16
/* 带有:的mac地址长度，例如01:02:03:04:05:06共17个字节*/
#define MAX_MAC_ADDR 17

#define NOT_MAC_ADDR "00:00:00:00:00:00"


//¨??¨?¨2json¨oy?Y?D|ì?module
enum MODULE_e
{
    MODULE_PORTAL,
	MODULE_USER,
};

//¨??¨?¨2?¨￠¨¨? ?¨2ac¨|?|ì?portal|ì?????
enum OP_PORTAL_e
{
    OP_PORTAL_ADD,
    OP_PORTAL_DEL,
};

typedef struct portal_redirect_info_st
{
	u_int8_t index;
	char nasip[MAX_NASIP_LENTH];
	char url[MAX_URL_LENTH];
	char nasid[MAX_NASID_LENTH];
}PORTAL_REDIRECT_INFO;
typedef void (*Json_msg_handler)(void *pJson, void *user_data);

int AC_sendto_web(char *json_data);
void json_to_str_sendto_web(cJSON **pJsonRoot);
void Json_add_redirect_data(cJSON *pJson, void *user_data);
void Json_del_redirect_data(cJSON *pJson, void *user_data);
void makeJson_data_thoughput_display(u_int16_t module, u_int16_t op,
            Json_msg_handler fmessage_proc, void *user_data);





typedef struct portal_red_user_info_st
{
	u32 user_ip;
	char user_mac[ETHER_MAC_LEN];
}PORTAL_RED_USER_INFO;
void Json_add_red_user_data(cJSON *pJson, void *user_data);



int portal_vpp_to_kernel_info_init(ip4_header_t * ip4,l7portal_user_info * new_user, u32 portal_bas_ip,u32 sw_if_index,PORTAL_RED_USER_INFO * red_user);
int portal_kernel_to_vpp_info_init(ip4_header_t * ip4,   l7portal_user_info * new_user, u32 portal_bas_ip);



#endif









