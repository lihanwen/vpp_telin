#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<locale.h>
#include"list.h"
#include"hashlist.h"
#include <arpa/inet.h>
#include <vnet/portal/portal.h>
//#include </home/administrators/vpp/build-root/build-vpp-native/dpdk/dpdk-16.07/lib/librte_eal/common/include/rte_lcore.h>
//#include </home/administrators/vpp/build-root/build-vpp-native/dpdk/dpdk-16.07/lib/librte_eal/common/include/generic/rte_cycles.h>


#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/dpdk/dpdk.h>

radius_ession_hash_head_t radius_packet_session_hash[RADIUS_PACKET_SESSION_HASH_SIZE] = {0};
radius_ession_hash_head_t radius_free_packet_session_list[1] = {0};


/******************************************************************************
	函数名称  : radius_init_hash
	功能描述  : 初始化hash表
	输入参数  : 无
	输出参数  : 无
	返 回 值  : 无
 ----------------------------------------------------------------------------
	最近一次修改记录 :
	修改作者  :
	修改目的  : 增新函数
	修改日期  :

*******************************************************************************/

void radius_packet_session_hash_init(void)//初始化hash表
{
	int i;
	for(i = 0; i < RADIUS_PACKET_SESSION_HASH_SIZE; i++)//初始化hash表
	{
		dl_list_init(&(radius_packet_session_hash[i].radius_packet_session_list));
		//free_radius_init_hash(&radius_hash[i]);
		rte_spinlock_init(&radius_packet_session_hash[i].lock);
	}
}

/******************************************************************************
*
	函数名称  : radius_delete_node_bypacketid
	功能描述  : 在hash表中删除节点，并返回需要的参数
	输入参数  : src_node表示key值，ip表示portal服务器的ip，authenticate表示包的认证字段
	输出参数  : 无
	返 回 值  :删除是否成功，返回1成功，0失败
 ----------------------------------------------------------------------------
	最近一次修改记录 :
	修改作者  :
	修改目的  : 增新函数
	修改日期  :

*******************************************************************************
*/

int radius_delete_node_bypacketid(unsigned int src_node, u32* ip, char authenticate[AUTHEN_LEN])
{
	int pos;
	pos = src_node % 1024;//根据hash函数计算关键字在hash表中的位置
 radius_packet_session *tmp;
	int flag = 0;

       rte_spinlock_lock(&radius_packet_session_hash[pos].lock);
	//根据packetid地址删除节点
	dl_list_for_each(tmp, &(radius_packet_session_hash[pos].radius_packet_session_list),  radius_packet_session, radius_packet_session_list)//遍历节点，根据ip删除节点
	{
		if(tmp->record_msg.packet_id == src_node)
		{
			dl_list_del(&(tmp->radius_packet_session_list));
			flag = 1;
			*ip = tmp->record_msg.client_ip;
			memcpy(authenticate, tmp->record_msg.authenticate, AUTHEN_LEN);
			break;	
		}
	}
	rte_spinlock_unlock(&radius_packet_session_hash[pos].lock);
	if(flag && tmp)
	{
		rte_spinlock_lock(&radius_free_packet_session_list[0].lock);
		dl_list_add(&radius_free_packet_session_list[0].radius_packet_session_list, &tmp->radius_packet_session_list);
		rte_spinlock_unlock(&radius_free_packet_session_list[0].lock);
	}
       return flag;
}


/******************************************************************************
	函数名称  : delete_node_bykey
	功能描述  :根据关键字删除hash表中的节点
	输入参数  :kind指的是关键字的类型，del_key指关键字
	输出参数  : 无
	返 回 值  : 删除是否成功，返回1成功，0失败
 ----------------------------------------------------------------------------
	最近一次修改记录 :
	修改作者  :
	修改目的  : 增新函数
	修改日期  :

*******************************************************************************/


/******************************************************************************
	函数名称  : insert_node
	功能描述  :将新增节点插入到hash表中
	输入参数  :msg指的是输入的结构体,istkind指的是关键字的类型
	输出参数  : 无
	返 回 值  : 无
 ----------------------------------------------------------------------------
	最近一次修改记录 :
	修改作者  :
	修改目的  : 增新函数
	修改日期  :

*******************************************************************************/
void radius_insert_packet_session(radius_packet_session *node)
{
	int pacidpos;
	pacidpos = (node->record_msg.packet_id) % 1024;    
	Portal_DEBUG("*******************after the call of timer_reset*******************\n");
 
       node->record_msg.sustime = clib_cpu_time_now ();
	node->record_msg.timeout_sec = 2;
 	rte_spinlock_lock(&radius_packet_session_hash[pacidpos].lock);
	dl_list_add(&(radius_packet_session_hash[pacidpos].radius_packet_session_list), &(node->radius_packet_session_list));
 	rte_spinlock_unlock(&radius_packet_session_hash[pacidpos].lock);

}


void radius_free_packet_session_init(void)
{
 	int i = 0;
	dl_list_init(&radius_free_packet_session_list[0].radius_packet_session_list);
	radius_packet_session * free_session = clib_mem_alloc(RADIUS_PACKET_SESSION_MAX_NUM * sizeof(radius_packet_session));
	if(!free_session)
	return ;
	memset(free_session, 0, RADIUS_PACKET_SESSION_MAX_NUM * sizeof(radius_packet_session));
	for(i = 0; i < RADIUS_PACKET_SESSION_MAX_NUM; i++)
	{
		dl_list_add(&radius_free_packet_session_list[0].radius_packet_session_list,  &free_session[i].radius_packet_session_list);
	}
 	rte_spinlock_init(&radius_free_packet_session_list[0].lock);
 	return;
}

radius_packet_session * radius_alloc_packet_session(void)
{
	int flag = 0;
	radius_packet_session * entry  = NULL;
 	rte_spinlock_lock(&radius_free_packet_session_list[0].lock);
 	dl_list_for_each(entry, &radius_free_packet_session_list[0].radius_packet_session_list, radius_packet_session,  radius_packet_session_list)
 	{
 		flag = 1;
 		dl_list_del(&entry->radius_packet_session_list);
 		break;
 	}
 	rte_spinlock_unlock(&radius_free_packet_session_list[0].lock);
 	if(flag && entry)
 	{
 		memset(entry, 0, sizeof(radius_packet_session));
 		dl_list_init(&entry->radius_packet_session_list);
 		return entry;
 	}
 	return NULL;
}


