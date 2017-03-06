
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


/* DHCP�������� */
typedef enum
{
	DISCOVER_CLIENT = 1,
	OFFER_SERVER = 2,
	REQUEST_CLIENT = 3,
	DECLINE_CLIENT = 4,
	ACK_SERVER = 5,
	RELEASE_CLIENT = 7,
}dhcp_msg_type;

/* �洢�������� */
typedef struct{
  u8 op;       		/* �������ͣ�1Ϊ�����ģ�2Ϊ��Ӧ���ġ�����������option�ֶ� */
  u8 htype;    		/* DHCP�ͻ��˵�Ӳ����ַ���� */
  u8 hlen;     		/* DHCP�ͻ��˵�Ӳ����ַ���� */
  u8 hops;     		/* DHCP���ľ����м̵���Ŀ */
  u32 xid;     		/* �ͻ��˷�����������������ʶһ��������� */
  u16 secs;   		/* DHCP�ͻ��˿�ʼDHCP����󾭹���ʱ�䣬Ŀǰû��ʹ�ã��̶�Ϊ0 */
  u16 flags;   		/* �㲥��ʶλ����������Ӧ����Ϊ0���㲥Ϊ1 */
  u32 ciaddr;  		/* DHCP�ͻ��˵�ַ */
  u32 yiaddr;  		/* ������ͻ��˵�IP��ַ */
  u32 siaddr; 
  u32 giaddr;
  u8 chaddr[MAC_SIZE];  	/*DHCP�ͻ���MAC��ַ */
  u8 chaddr_pad[MAC_PAD];	/*DHCP�ͻ���Ӳ����ַ��� */
  u8 sname[SNAME_SIZE];
  u8 file[FILE_SIZE];
 
}dhcp_header_tl;


/* �ͻ�����Ϣ */
typedef struct{
  u8 mac[MAC_SIZE];
  u32 ip;
  u32 sw_if_index;
  u32 in_use;
  struct dl_list client_list;
  
  rte_spinlock_t lock;//��
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
