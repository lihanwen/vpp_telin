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
	��������  : radius_init_hash
	��������  : ��ʼ��hash��
	�������  : ��
	�������  : ��
	�� �� ֵ  : ��
 ----------------------------------------------------------------------------
	���һ���޸ļ�¼ :
	�޸�����  :
	�޸�Ŀ��  : ���º���
	�޸�����  :

*******************************************************************************/

void radius_packet_session_hash_init(void)//��ʼ��hash��
{
	int i;
	for(i = 0; i < RADIUS_PACKET_SESSION_HASH_SIZE; i++)//��ʼ��hash��
	{
		dl_list_init(&(radius_packet_session_hash[i].radius_packet_session_list));
		//free_radius_init_hash(&radius_hash[i]);
		rte_spinlock_init(&radius_packet_session_hash[i].lock);
	}
}

/******************************************************************************
*
	��������  : radius_delete_node_bypacketid
	��������  : ��hash����ɾ���ڵ㣬��������Ҫ�Ĳ���
	�������  : src_node��ʾkeyֵ��ip��ʾportal��������ip��authenticate��ʾ������֤�ֶ�
	�������  : ��
	�� �� ֵ  :ɾ���Ƿ�ɹ�������1�ɹ���0ʧ��
 ----------------------------------------------------------------------------
	���һ���޸ļ�¼ :
	�޸�����  :
	�޸�Ŀ��  : ���º���
	�޸�����  :

*******************************************************************************
*/

int radius_delete_node_bypacketid(unsigned int src_node, u32* ip, char authenticate[AUTHEN_LEN])
{
	int pos;
	pos = src_node % 1024;//����hash��������ؼ�����hash���е�λ��
 radius_packet_session *tmp;
	int flag = 0;

       rte_spinlock_lock(&radius_packet_session_hash[pos].lock);
	//����packetid��ַɾ���ڵ�
	dl_list_for_each(tmp, &(radius_packet_session_hash[pos].radius_packet_session_list),  radius_packet_session, radius_packet_session_list)//�����ڵ㣬����ipɾ���ڵ�
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
	��������  : delete_node_bykey
	��������  :���ݹؼ���ɾ��hash���еĽڵ�
	�������  :kindָ���ǹؼ��ֵ����ͣ�del_keyָ�ؼ���
	�������  : ��
	�� �� ֵ  : ɾ���Ƿ�ɹ�������1�ɹ���0ʧ��
 ----------------------------------------------------------------------------
	���һ���޸ļ�¼ :
	�޸�����  :
	�޸�Ŀ��  : ���º���
	�޸�����  :

*******************************************************************************/


/******************************************************************************
	��������  : insert_node
	��������  :�������ڵ���뵽hash����
	�������  :msgָ��������Ľṹ��,istkindָ���ǹؼ��ֵ�����
	�������  : ��
	�� �� ֵ  : ��
 ----------------------------------------------------------------------------
	���һ���޸ļ�¼ :
	�޸�����  :
	�޸�Ŀ��  : ���º���
	�޸�����  :

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


