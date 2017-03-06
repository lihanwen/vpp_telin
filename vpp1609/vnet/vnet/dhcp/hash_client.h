
#ifndef HASH_CLIENT_H
#define HASH_CLIENT_H
#include <vnet/radius/list.h>


#include <rte_cycles.h>
#include <rte_config.h>
#include <rte_spinlock.h>
#include <rte_launch.h>
//#include <vnet/ip/udp_packet.h>


#define DHCP_HASH_SIZE 1024*10
#define MSG_TYPE_OPTION 53
#define MAC_SIZE 6
#define MAC_PAD 10
#define SNAME_SIZE 64
#define FILE_SIZE 128

typedef uint8_t u8;
typedef uint16_t  u16;

typedef uint32_t u32;


/* DHCP报文类型 */
typedef enum
{
	DISCOVER_CLIENT = 1,
	OFFER_SERVER = 2,
	REQUEST_CLIENT = 3,
	DECLINE_CLIENT = 4,
	ACK_SERVER = 5,
	RELEASE_CLIENT = 7,
}dhcp_msg_type;

/* 存储报文类型 */
typedef struct{
  u8 op;       		/* 报文类型，1为请求报文；2为响应报文。具体类型在option字段 */
  u8 htype;    		/* DHCP客户端的硬件地址类型 */
  u8 hlen;     		/* DHCP客户端的硬件地址长度 */
  u8 hops;     		/* DHCP报文经过中继的数目 */
  u32 xid;     		/* 客户端发起请求的随机数，标识一次请求过程 */
  u16 secs;   		/* DHCP客户端开始DHCP请求后经过的时间，目前没有使用，固定为0 */
  u16 flags;   		/* 广播标识位，服务器响应单播为0，广播为1 */
  u32 ciaddr;  		/* DHCP客户端地址 */
  u32 yiaddr;  		/* 分配给客户端的IP地址 */
  u32 siaddr; 
  u32 giaddr;
  u8 chaddr[MAC_SIZE];  	/*DHCP客户端MAC地址 */
  u8 chaddr_pad[MAC_PAD];	/*DHCP客户端硬件地址填充 */
  u8 sname[SNAME_SIZE];
  u8 file[FILE_SIZE];
 
}dhcp_header_tl;


/* 客户端信息 */
typedef struct{
  u8 mac[MAC_SIZE];
  u32 ip;
  u32 sw_if_index;
  u32 in_use;
  struct dl_list client_list;
  
  rte_spinlock_t lock;//锁
}dhcp_client_info_t;

dhcp_client_info_t dhcp_client_info[DHCP_HASH_SIZE]; 

void dhcp_init_hash();
void add_dhcp_client(u8 * mac, u32 sw_if_index);
void del_dhcp_client(u8 * mac);
dhcp_client_info_t * search_client_by_mac(u8 * mac);
dhcp_client_info_t * search_client_by_ip(u8 * mac, u32 ip);
void add_client_ip_value(u8 * mac, u32 ip);


u8 search_msg_type_options (void * pd, u16 plen);



#endif
