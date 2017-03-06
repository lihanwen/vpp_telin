


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
/* ���ʮ����ip����󳤶�(�Ϊ15����'\0'��һ��λ��) */
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

//״̬��״̬
enum PORTAL_STATE_e
{
    PORTAL_STATE_START = 1,    //��ʼ��״̬
    PORTAL_STATE_CHALLENGE,    //������ս״̬
    PORTAL_STATE_AUTH,         //��֤״̬
    PORTAL_STATE_LOGOUT,       //����״̬
    PORTAL_STATE_Run,          //��������
};



/* PKT_REQ_AUTH����Я�����ֶ�(Attr) */

typedef struct req_auth_msg_st
{
    char user_name[256];        //�û��� Э��涨�Ϊ32���ֽ� ����΢����֤�û��������������ó�256���ֵ
    u8 password_type;     //�������ļ������� 2:������ 4:chap��ʽ����
    char password[17];          //��chap��ʽ���ܵ�����  Э��涨�Ϊ16���ֽ� ��һ���ֽ�'\0'
}__attribute__ ((packed))REQ_AUTH_MSG;

/* radius���ĳ����Զ������� */
typedef struct rad_vendor_specific_attr_st
{
    u_int32_t  input_rate;    //�û����뵽NAS��ƽ������(���ϴ��ٶ�)����bit/sΪ��λ
    u_int32_t  output_rate;    //��NAS���û���ƽ������(�������ٶ�)����bit/sΪ��λ
}__attribute__ ((packed))RAD_VENDOR_SPECIFIC_ATTR;

#define PORTAL_SEND_BUF_SIZE 1024
/*
 * MD5 data length
 */

#define MD5_DATA_LEN 16

/* portalЭ��汾�� */
#define PROTOCAL_VERSION_NUM 2

/* RADUS Message types */
#define RAD_ACCESS_REQUEST        1
#define RAD_ACCESS_ACCEPT        2
#define RAD_ACCESS_REJECT        3


//��֤��ʽ
typedef enum
{
    AUTH_MODE_CHAP,
    AUTH_MODE_PAP
}AUTH_MODE_e;

//AttrNum�ֶε�����
typedef enum
{
    PORTAL_ATTR_USER_NAME = 1,
    PORTAL_ATTR_PASS_WORD = 2,
    PORTAL_ATTR_CHALLENGE = 3,
    PORTAL_ATTR_CHAP_PASSWORD = 4
}PORTAL_ATTR_t;





//ACK_CHALLENGE(2)��err_code����
typedef enum
{
    ACK_CHALLENGE_ERRCODE_SUCCESS = 0,   //challenge��ս�ɹ�
    ACK_CHALLENGE_ERRCODE_REFUSE = 1,    //challenge��ս���ܾ�
    ACK_CHALLENGE_ERRCODE_CONNET = 2,    //�����Ѿ�������
    ACK_CHALLENGE_ERRCODE_AUTH = 3,      //��һ���û�������֤
    ACK_CHALLENGE_ERRCODE_ERR = 4,       //challenge��ս����
}ACK_CHALLENGE_ERRCODE_t;
//ACK_AUTH(4)��err_code����
typedef enum
{
    ACK_AUTH_ERRCODE_SUCCESS = 0,   //��֤�ɹ�
    ACK_AUTH_ERRCODE_REFUSE = 1,    //��֤���ܾ�
    ACK_AUTH_ERRCODE_CONNET = 2,    //�����Ѿ�������
    ACK_AUTH_ERRCODE_AUTH = 3,      //��һ���û�������֤
    ACK_AUTH_ERRCODE_ERR = 4,       //��֤����
}ACK_AUTH_ERRCODE_t;
//REQ_LOGOUT(5)��err_code����
typedef enum
{
    REQ_LOGOUT_ERRCODE_DOWN_LINE = 0,    //��������
    REQ_LOGOUT_ERRCODE_TIMEOUT = 1,      //��ʱ����
}REQ_LOGOUT_ERRCODE_t;

//ACK_LOGOUT(6)��err_code����
typedef enum
{
    ACK_LOGOUT_ERRCODE_SUCCESS = 0,   //���߳ɹ�
    ACK_LOGOUT_ERRCODE_REFUSE = 1,    //���߱��ܾ�
    ACK_LOGOUT_ERRCODE_ERR = 2,       //���ߴ���
}ACK_LOGOUT_ERRCODE_t;

//auth_state��Ա״̬
enum AUTH_USER_INFO_STATE_e
{
    AUTH_USER_INFO_STATE_AUTH = 1,      //�û���֤ͨ��
    AUTH_USER_INFO_STATE_OFFLINE = 2,   //�û�����
};

//SERVER_MSG�ṹ���auth_server_flag��Ա״̬
enum AUTH_SERVER_FLAG_e
{
    AUTH_SERVER_FLAG_DOWN = 0,      //�����ñ���֤������
    AUTH_SERVER_FLAG_UP = 1,        //���ñ���֤������
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
    u8 version;    /* portalЭ��汾�� */
    u8 type;       /* �������� */
    u8 auth_mode;  /* ��֤��ʽ */
    u8 srv;        /* �����ֶΣ�ֵΪ0 */
    u16 serial_no;  /* ���ĵ����к� ������ */
    u16 req_id;     /* ����id ��BAS�豸������� ������ */
    u32 user_ip;    /* Portal�û���IP��ַ */
    u16 user_port;  /* Ŀǰû���õ��������б�������ֵΪ0 */
    u8 err_code;   /* ������ */
    u8 attr_num;   /* �ɱ䳤�ȵ������ֶθ��� */

    unsigned char authenticator_MD5[MD5_DATA_LEN];   /* ��MD5�㷨ʵ�ֵ���֤�� */

} __attribute__((packed)) portal_header_t;

/* portal���������ֶ�(Attr) */
typedef struct
{
    u_int8_t type;    //�ֶ�����
    u_int8_t len;     //�ֶ��ܳ���
    char value[0];    //�ֶε�ֵ��Э��涨�Ϊ253
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

/* Ҫ���������������ʱ����������������Ϣ */
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
    u8 auth_server_flag;        //��־�Ƿ����ñ��÷�����  0:������ 1:����

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
      struct dl_list list;                    /* listλ�ò��ܻ�������free_portal_user_point */
	  //rte_spinlock_t lock;//��
	  u32 ip;					  /* �ͻ��˵�ַ�������� */
	  u8 state;						  /* ״̬ */
	  u8 err_code; 				  /* ������ */
	  u16 port;						  /* ����Դ�˿ڣ������´η��� */
	  u16 serial_no;				  /* ���ĵ����к� ������ */
	  u16 req_id;					  /* ����id ��BAS�豸������� ������ */
	  REQ_AUTH_MSG req_auth_msg;			  /* PKT_REQ_AUTH����Я�����ֶ�(Attr) */

      u8 mac[6];       //��֤�û�mac
	  u8 auth_state;            //��֤״̬ 0:��֤ͨ�� 1:�û�����
      char sn[19];         //ap���к�
	  char interface[20];

	  unsigned char authenticator_MD5[MD5_DATA_LEN];	  /* ��MD5�㷨ʵ�ֵ���֤�� */
	  unsigned char challenge[MD5_DATA_LEN];		 /* PKT_ACK_CHALLENGE���ķ��͵�challenge�ֶΣ���radius��֤ʱ���õ� */
	  u32 sw_if_index;
	  u32 online_time;				//����ʱ��
	  u32 offline_time;         //����ʱ�� ������ʱ��¼ʱ�䣬����ʱ��ֵΪ0 ������ʱɾ����֤��Ϣ

	  u32 red_dst_ip;/* ��Ҫ�ض���ʱ��¼user��Ŀ��ip*/
	  int free_node_yn;//�Ƿ�Ϊ������0Ϊ��1 Ϊ��
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
