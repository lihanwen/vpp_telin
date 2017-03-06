#ifndef	_HASHLIST_H
#define _HASHLIST_H
#include "list.h"

#include <rte_cycles.h>
#include <rte_config.h>
#include <rte_spinlock.h>
#include <rte_launch.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/unix/plugin.h>

#include <signal.h>
#include <sys/ucontext.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>



//#include </home/administrators/vpp/dpdk/dpdk-16.07/lib/librte_timer/rte_timer.h>//X:\Desktop\vpp\dpdk\dpdk-16.07\lib\librte_timer
#define SUCCESS 1
#define FAILED 0
#define RADIUS_PACKET_SESSION_HASH_SIZE    1024
#define RADIUS_PACKET_SESSION_MAX_NUM    1024 * 50
#define IPV4LEN 10
#define ETH_ALEN_VPP 20
#define FREE_INITLEN 3//表示存储初始链表的长度
#define NODE_NUM 3//表示的是hash表中节点的个数,方便测试
#define MAXNAMELEN 10

#define ETH_LEN 6
#define ETH_DATA_LEN 1500
#define AUTHEN_LEN 17
#define USERNAME_LEN 100
#define PASSWD_LEN 100
#define MD5_DATA_LEN 16


/*定义需要存储的结构体*/
typedef struct record_message_st
{

    u8 passwd_type;
	unsigned char challenge[MD5_DATA_LEN];

    unsigned int client_ip;//ip地址
    char user_name[USERNAME_LEN];
	char passwd[PASSWD_LEN];
	
	unsigned char packet_id;//radius identifier
	char authenticate[AUTHEN_LEN];

	u32 portal_sw_if_index;
//	vlib_node_runtime_t * node;
//	vlib_frame_t * frame;

	unsigned int timeout_sec;
	u64 sustime;

 }RecordMsg;


typedef struct clientsession_st
{
	int flag;
	int resendCount;
	int deleted_by_radius;

       RecordMsg record_msg;

	struct dl_list radius_packet_session_list;//根据packet identifier建立的链
	rte_spinlock_t lock;//锁

	u16 req_id;


}radius_packet_session;

typedef struct radius_ession_hash_head
{
	struct dl_list radius_packet_session_list;//根据packet identifier建立的链
	rte_spinlock_t lock;//锁
}radius_ession_hash_head_t;

extern radius_ession_hash_head_t radius_packet_session_hash[RADIUS_PACKET_SESSION_HASH_SIZE];

int radius_delete_node_bypacketid(unsigned int src_node, u32* ip, char authenticate[AUTHEN_LEN]);
void radius_free_packet_session_init(void);
void radius_packet_session_hash_init(void);
void radius_insert_packet_session(radius_packet_session *node);
radius_packet_session * radius_alloc_packet_session(void);


#endif



