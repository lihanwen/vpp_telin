


#ifndef included_portal_h
#define included_portal_h

#include <vlib/vlib.h>
//#include <vppinfra/bihash_8_8.h>
#include <vnet/ip/ip4_packet.h>
//#include <vppinfra/hash.h>
#include <vnet/vnet.h>
//#include "portal_list.h"
#include <vnet/radius/list.h>
//#include <dpdk/dpdk-16.7/lib/librte_eal/common/include/rte_per_lcore.h>

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/dpdk/dpdk.h>

#include <vnet/radius/hashlist.h>
//#include <vnet/radius/interface_radius.h>





#define MD5_DATA_LEN 16
#define MAX_SHARE_KEY_LEN 33
/* 点分十进制ip的最大长度(最长为15，给'\0'留一个位置) */
#define MAX_IP_LEN 16

/*
 * The size of the hash table
 */
#define L7PORTAL_NUM_BUCKETS (64 * 1024)
#define L7PORTAL_MEMORY_SIZE (256<<20)

extern u8 g_portal_debug;
extern u32 gs_bas_ip;
extern u32 portal_server_is_online ;
extern u32 gs_portal_server;

#define Portal_DEBUG(str, arg...)  do{\
        if(g_portal_debug)\
        {\
            FILE *debug_fp = fopen("/tmp/portal_debug.log", "a");\
            if (NULL != debug_fp){\
            fprintf(debug_fp, "%d:L%d in %s, ", g_portal_debug, __LINE__, __FILE__);\
            fprintf(debug_fp, str, ##arg);\
            fflush(debug_fp);\
            fclose(debug_fp);\
            }\
            else g_portal_debug++;\
        }\
}while(0)

//状态机状态
enum PORTAL_STATE_e
{
    PORTAL_STATE_START = 1,    //初始化状态
    PORTAL_STATE_CHALLENGE,    //发起挑战状态
    PORTAL_STATE_AUTH,         //认证状态
    PORTAL_STATE_LOGOUT,       //下线状态
    PORTAL_STATE_Run,          //正在运行
};



/* PKT_REQ_AUTH报文携带的字段(Attr) */

typedef struct req_auth_msg_st
{
    char user_name[256];        //用户名 协议规定最长为32个字节 但是微信认证用户名过长，先设置成256最大值
    u8 password_type;     //标记密码的加密类型 2:不加密 4:chap方式加密
    char password[17];          //用chap方式加密的密码  协议规定最长为16个字节 加一个字节'\0'
}__attribute__ ((packed))REQ_AUTH_MSG;

/* radius报文厂商自定义属性 */
typedef struct rad_vendor_specific_attr_st
{
    u_int32_t  input_rate;    //用户接入到NAS的平均速率(即上传速度)，以bit/s为单位
    u_int32_t  output_rate;    //从NAS到用户的平均速率(即下载速度)，以bit/s为单位
}__attribute__ ((packed))RAD_VENDOR_SPECIFIC_ATTR;

#define PORTAL_SEND_BUF_SIZE 1024
/*
 * MD5 data length
 */

#define MD5_DATA_LEN 16

/* portal协议版本号 */
#define PROTOCAL_VERSION_NUM 2

/* RADUS Message types */
#define RAD_ACCESS_REQUEST        1
#define RAD_ACCESS_ACCEPT        2
#define RAD_ACCESS_REJECT        3


//认证方式
typedef enum
{
    AUTH_MODE_CHAP,
    AUTH_MODE_PAP
}AUTH_MODE_e;

//AttrNum字段的类型
typedef enum
{
    PORTAL_ATTR_USER_NAME = 1,
    PORTAL_ATTR_PASS_WORD = 2,
    PORTAL_ATTR_CHALLENGE = 3,
    PORTAL_ATTR_CHAP_PASSWORD = 4
}PORTAL_ATTR_t;





//ACK_CHALLENGE(2)的err_code类型
typedef enum
{
    ACK_CHALLENGE_ERRCODE_SUCCESS = 0,   //challenge挑战成功
    ACK_CHALLENGE_ERRCODE_REFUSE = 1,    //challenge挑战被拒绝
    ACK_CHALLENGE_ERRCODE_CONNET = 2,    //连接已经建立过
    ACK_CHALLENGE_ERRCODE_AUTH = 3,      //有一个用户正在验证
    ACK_CHALLENGE_ERRCODE_ERR = 4,       //challenge挑战错误
}ACK_CHALLENGE_ERRCODE_t;
//ACK_AUTH(4)的err_code类型
typedef enum
{
    ACK_AUTH_ERRCODE_SUCCESS = 0,   //验证成功
    ACK_AUTH_ERRCODE_REFUSE = 1,    //验证被拒绝
    ACK_AUTH_ERRCODE_CONNET = 2,    //连接已经建立过
    ACK_AUTH_ERRCODE_AUTH = 3,      //有一个用户正在验证
    ACK_AUTH_ERRCODE_ERR = 4,       //验证错误
}ACK_AUTH_ERRCODE_t;
//REQ_LOGOUT(5)的err_code类型
typedef enum
{
    REQ_LOGOUT_ERRCODE_DOWN_LINE = 0,    //下线请求
    REQ_LOGOUT_ERRCODE_TIMEOUT = 1,      //超时请求
}REQ_LOGOUT_ERRCODE_t;

//ACK_LOGOUT(6)的err_code类型
typedef enum
{
    ACK_LOGOUT_ERRCODE_SUCCESS = 0,   //下线成功
    ACK_LOGOUT_ERRCODE_REFUSE = 1,    //下线被拒绝
    ACK_LOGOUT_ERRCODE_ERR = 2,       //下线错误
}ACK_LOGOUT_ERRCODE_t;

//auth_state成员状态
enum AUTH_USER_INFO_STATE_e
{
    AUTH_USER_INFO_STATE_AUTH = 1,      //用户认证通过
    AUTH_USER_INFO_STATE_OFFLINE = 2,   //用户下线
};

//SERVER_MSG结构体的auth_server_flag成员状态
enum AUTH_SERVER_FLAG_e
{
    AUTH_SERVER_FLAG_DOWN = 0,      //不启用备认证服务器
    AUTH_SERVER_FLAG_UP = 1,        //启用备认证服务器
};

typedef enum
{
  PORTAL_NEXT_IP4_LOOKUP,
  PORTAL_NEXT_ERROR_DROP,
  PORTAL_N_NEXT,
} portal_next_t;


typedef struct
{
	
  
}__attribute__((packed)) process_message_t;

typedef struct
{
    u8 version;    /* portal协议版本号 */
    u8 type;       /* 报文类型 */
    u8 auth_mode;  /* 认证方式 */
    u8 srv;        /* 保留字段，值为0 */
    u16 serial_no;  /* 报文的序列号 网络序 */
    u16 req_id;     /* 请求id 有BAS设备随机产生 主机序 */
    u32 user_ip;    /* Portal用户的IP地址 */
    u16 user_port;  /* 目前没有用到，在所有报文中其值为0 */
    u8 err_code;   /* 错误码 */
    u8 attr_num;   /* 可变长度的属性字段个数 */

    unsigned char authenticator_MD5[MD5_DATA_LEN];   /* 用MD5算法实现的验证字 */

} __attribute__((packed)) portal_header_t;

/* portal报文属性字段(Attr) */
typedef struct
{
    u_int8_t type;    //字段类型
    u_int8_t len;     //字段总长度
    char value[0];    //字段的值，协议规定最长为253
}__attribute__ ((packed))PORTAL_ATTR;



typedef enum {
  REQ_CHALLENGE=1,
  ACK_CHALLENGE,
  REQ_AUTH,
  ACK_AUTH ,
  REQ_LOGOUT,
  ACK_LOGOUT,
  AFF_ACK_AUTH,
  NTF_LOGOUT,
  REQ_INFO,
  ACK_INFO=10,
} portal_packet_type_t;

/* 要向服务器发送请求时主、备服务器的信息 */
typedef struct server_msg_st
{
    char master_auth_server_ip[MAX_IP_LEN];
    char standby_auth_server_ip[MAX_IP_LEN];
    int master_auth_port;
    int standby_auth_port;
    char master_auth_share_key[MAX_SHARE_KEY_LEN];
    char standby_auth_share_key[MAX_SHARE_KEY_LEN];
    int auth_msg_timeout;
    int auth_msg_allowed_times;
    char portal_share_key[MAX_SHARE_KEY_LEN];
    u8 auth_server_flag;        //标志是否启用备用服务器  0:不启用 1:启用

}__attribute__ ((packed))SERVER_MSG;

extern SERVER_MSG server_msg;





enum portol_free_rule_em {
	PORTOL_FREE_RULE_ON = 1,
	PORTOL_FREE_RULE_OFF = 0
};

/*
 * The portal user entry results
 */
typedef struct l7portal_user_info_st
{
      struct dl_list list;                    /* list位置不能换，否则free_portal_user_point */
	  //rte_spinlock_t lock;//锁
	  u32 ip;					  /* 客户端地址，主机序 */
	  u8 state;						  /* 状态 */
	  u8 err_code; 				  /* 错误码 */
	  u16 port;						  /* 存下源端口，用于下次发送 */
	  u16 serial_no;				  /* 报文的序列号 网络序 */
	  u16 req_id;					  /* 请求id 有BAS设备随机产生 主机序 */
	  REQ_AUTH_MSG req_auth_msg;			  /* PKT_REQ_AUTH报文携带的字段(Attr) */

      u8 mac[6];       //认证用户mac
	  u8 auth_state;            //验证状态 0:验证通过 1:用户下线
      char sn[19];         //ap序列号
	  char interface[20];

	  unsigned char authenticator_MD5[MD5_DATA_LEN];	  /* 用MD5算法实现的验证字 */
	  unsigned char challenge[MD5_DATA_LEN];		 /* PKT_ACK_CHALLENGE报文发送的challenge字段，在radius认证时会用到 */
	  u32 sw_if_index;
	  u32 online_time;				//上线时间
	  u32 offline_time;         //下线时间 在下线时记录时间，其他时间值为0 用于延时删除验证信息

	  u32 red_dst_ip;/* 需要重定向时记录user的目的ip*/
	  int free_node_yn;//是否为白名单0为否1 为是
	  u32 packet_lenth;//
	  u32 in_flow;
	  u32 out_flow;
	  portal_qos_interface *qos_int;
	 

}__attribute__ ((packed)) l7portal_user_info;


typedef struct
{
	u8 packet_data[32];
	u32 sw_if_index;
} portal_trace_t;


typedef struct
{
  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} l7portal_main_t;

l7portal_main_t l7portal_main;


int portal_build_auth_response_head(l7portal_user_info* result, void* pd, u_int16_t len, u_int8_t type, u_int8_t attr_num);
int portal_build_auth_response(l7portal_user_info* result,portal_header_t *portal_head ,u8 ack_type);
int  portal_build_from_radius_response(u32 ip,unsigned char* buf,int rc);

void suspend_timer_deadline(radius_packet_session *temp, unsigned char *pkgid, char * auth);


#endif
