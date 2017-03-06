#ifndef __QOS_HASH_H__
#define __QOS_HASH_H__

#include <vnet/portal/interface_portal.h>
#include <vnet/radius/list.h>
#include <vnet/portal/portal_hash.h>

#define QOS_HASH_TABLE_SIZE 4096
#define QOS_MALLOC_SIZE (4*1024)


/*限速用户信息*/
typedef struct Qos_user{
	struct dl_list list;	/* list位置不能换，否则free_portal_user_point */
	u32 user_ip;			//用户ip
	u32 sw_if_index;		//接口索引
	u32 avail_token;		//令牌桶剩余令牌数
	u64 last_adjust_time;	//令牌桶上次添加令牌时间
	portal_qos_car *car;	//用户Qos限速信息
	rte_spinlock_t lock;
}Qos_user_info;

struct dl_list qos_idle_list_head[LIST_TYPE_END];//0为portal user的hash头
struct dl_list qos_user_info_hash[QOS_HASH_TABLE_SIZE];
rte_spinlock_t qos_user_info_hash_lock[QOS_HASH_TABLE_SIZE];



void qos_link_head_init(void);
Qos_user_info *get_qos_user_by_ip(u32 *ip);
Qos_user_info *add_qos_user(u32 ip, u32 sw_if_index, portal_qos_car *car);
void free_qos_user_point(Qos_user_info *qos_user);
int qos_show_user_info(void);
void free_all_qos_user(void);
void free_qos_user_by_ip(u32 *ip);


#endif
