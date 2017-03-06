#include "hash_client.h"

#include <vnet/portal/portal.h>
#include <vnet/ip/udp_packet.h>

/******************************************************************************
	函数名称  : dhcp_init_hash
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
void dhcp_init_hash()
{
	int i = 0;
	for (i = 0; i<DHCP_HASH_SIZE; i++)
	{
		dl_list_init(&(dhcp_client_info[i].client_list));
		rte_spinlock_init(&dhcp_client_info[i].lock);
	}
}

/*******************************************************************************
 函数名称  : dhcp_get_hash_key
 功能描述  : 获得hash表的key值
 输入参数  : 客户端mac地址
 输出参数  : 无
 返 回 值  : hash表的key值
              -1 type 错误

*******************************************************************************/
static int dhcp_make_hash_key(u8 * hash_key)
{
	int sum = (hash_key[0]+hash_key[1]+hash_key[2]+hash_key[3]+hash_key[4]+ hash_key[5]);


	Portal_DEBUG(" sum %d  sum--DHCP_HASH_SIZE = %d \n",sum ,sum % DHCP_HASH_SIZE);
    return sum % DHCP_HASH_SIZE;
}


void add_dhcp_client(u8 * mac, u32 sw_if_index)
{
	Portal_DEBUG(" add client to hash\n");
	int key = dhcp_make_hash_key(mac);
	Portal_DEBUG(" ===========key :%d===========\n", key);
    dhcp_client_info_t * temp = (dhcp_client_info_t *)clib_mem_alloc(sizeof(dhcp_client_info_t));
	if(NULL == temp)
	{
		return NULL;
	}
	memset(temp, 0, sizeof(dhcp_client_info_t));
	memcpy(temp->mac, mac, MAC_SIZE);
	temp->ip = 0;
	temp->sw_if_index = sw_if_index;
	temp->in_use = 0;
	dl_list_init(&(temp->client_list));
	rte_spinlock_init(&(temp->lock));
	rte_spinlock_lock(&dhcp_client_info[key].lock);
	dl_list_add(&(dhcp_client_info[key].client_list), &(temp->client_list));
	rte_spinlock_unlock(&dhcp_client_info[key].lock);
}

void del_dhcp_client(u8 * mac)
{
	Portal_DEBUG(" del client by mac in hash\n");
	int key = dhcp_make_hash_key(mac);
	dhcp_client_info_t * tmp = NULL;
	
	rte_spinlock_lock(&dhcp_client_info[key].lock);
	dl_list_for_each(tmp, &(dhcp_client_info[key].client_list), dhcp_client_info_t, client_list)
	{
		if(((tmp->mac[0]&0xff) == (mac[0]&0xff))&&((tmp->mac[1]&0xff) == (mac[1]&0xff))&&
			((tmp->mac[2]&0xff) == (mac[2]&0xff))&&((tmp->mac[3]&0xff) == (mac[3]&0xff))&&
			((tmp->mac[4]&0xff) == (mac[4]&0xff))&&((tmp->mac[5]&0xff) == (mac[5]&0xff)))

		{
			dl_list_del(&(tmp->client_list));
			clib_mem_free(tmp);
			break;	
		}
	}
	rte_spinlock_unlock(&dhcp_client_info[key].lock);
}

dhcp_client_info_t * search_client_by_mac(u8 * mac)
{
	Portal_DEBUG("search client by mac in hash \n");
	dhcp_client_info_t * tmp = NULL;
	int key = dhcp_make_hash_key(mac);
	Portal_DEBUG(" ===========key :%d===========\n", key);
	rte_spinlock_lock(&dhcp_client_info[key].lock);
	dl_list_for_each(tmp, &(dhcp_client_info[key].client_list), dhcp_client_info_t, client_list)
	{
		Portal_DEBUG("search_client_by_mac dl list mac : %02x %02x %02x %02x %02x %02x \n", 
		tmp->mac[0], tmp->mac[1], tmp->mac[2], tmp->mac[3], tmp->mac[4], tmp->mac[5]);
		if(((tmp->mac[0]&0xff) == (mac[0]&0xff))&&((tmp->mac[1]&0xff) == (mac[1]&0xff))&&
			((tmp->mac[2]&0xff) == (mac[2]&0xff))&&((tmp->mac[3]&0xff) == (mac[3]&0xff))&&
			((tmp->mac[4]&0xff) == (mac[4]&0xff))&&((tmp->mac[5]&0xff) == (mac[5]&0xff)))
		{
			rte_spinlock_unlock(&dhcp_client_info[key].lock);
			return tmp;			
		}
	
	}
	rte_spinlock_unlock(&dhcp_client_info[key].lock);
	return NULL;
}

dhcp_client_info_t * search_client_by_ip(u8 * mac, u32 ip)
{
	Portal_DEBUG("search client by ip in hash \n");
	dhcp_client_info_t * tmp = NULL;
	int key = dhcp_make_hash_key(mac);
	Portal_DEBUG(" ===========key :%d===========\n", key);
	rte_spinlock_lock(&dhcp_client_info[key].lock);
	dl_list_for_each(tmp, &(dhcp_client_info[key].client_list), dhcp_client_info_t, client_list)
	{
		if(tmp->ip == ip)
		{
			rte_spinlock_unlock(&dhcp_client_info[key].lock);
			return tmp;
		}
	}
	rte_spinlock_unlock(&dhcp_client_info[key].lock);
	return NULL;
}

void add_client_ip_value(u8 * mac, u32 ip)
{
	Portal_DEBUG("add client ip value \n");
	dhcp_client_info_t * tmp = NULL;
	int key = dhcp_make_hash_key(mac);

	Portal_DEBUG(" ===========key :%d===========\n", key);
	rte_spinlock_lock(&dhcp_client_info[key].lock);
	dl_list_for_each(tmp, &(dhcp_client_info[key].client_list), dhcp_client_info_t, client_list)
	{	
		Portal_DEBUG("dl list mac add ip : %02x %02x %02x %02x %02x %02x \n", 
		tmp->mac[0], tmp->mac[1], tmp->mac[2], tmp->mac[3], tmp->mac[4], tmp->mac[5]);
		
		if(((tmp->mac[0]&0xff) == (mac[0]&0xff))&&((tmp->mac[1]&0xff) == (mac[1]&0xff))&&
			((tmp->mac[2]&0xff) == (mac[2]&0xff))&&((tmp->mac[3]&0xff) == (mac[3]&0xff))&&
			((tmp->mac[4]&0xff) == (mac[4]&0xff))&&((tmp->mac[5]&0xff) == (mac[5]&0xff)))
		{
			Portal_DEBUG("tmp->ip = ip \n");
			tmp->ip = ip;
				break;
		}

	}
	rte_spinlock_unlock(&dhcp_client_info[key].lock);

}

u8 search_msg_type_options (void * pd, u16 plen)
{
	u8 opt_type, msg_len, msg_type;
	char * pbuf;
	pbuf = (char *)pd;

    while (plen>0)
    {
		/* dhcp option type value*/
		opt_type = *(u8*)pbuf;
		pbuf += sizeof(u8);
		
		/* dhcp option length value*/
		msg_len = *(u8*)pbuf;
		if (opt_type == MSG_TYPE_OPTION)
		{
			pbuf += sizeof(u8);
			msg_type = *(u8*)pbuf;
			return msg_type;
		}
		plen = (u16)(plen - 2*sizeof(u8) - (u16)msg_len);
    }

	return 0;
}

int
dhcp_server_process (vlib_main_t *vm,
		 udp_header_t * udp,
		 dhcp_header_tl *dhcp_head,
		 u32 sw_if_index)
{
	void *pd = ((char *)dhcp_head) + sizeof(dhcp_header_tl);
	/* 整个option的长度 */
	u16 plen = clib_net_to_host_u16(udp->length) - sizeof(udp_header_t) - sizeof(dhcp_header_tl);	
	dhcp_client_info_t * tmp = NULL;
	u8 msg_type = search_msg_type_options(pd, plen);

	Portal_DEBUG("\n\n GET ip :   %08x  %d\n", dhcp_head->yiaddr, clib_net_to_host_u16(udp->dst_port));

	int i=0;
	Portal_DEBUG("get  mac :\n");
	for (i=0;i<6;i++)
		{
		Portal_DEBUG("%02x \n", *((dhcp_head->chaddr)+i));
	}

	switch(msg_type)
	{
		case DISCOVER_CLIENT:
		{
			Portal_DEBUG(" ===========packet DHCP DISCOVER===========\n");
			tmp = search_client_by_mac(dhcp_head->chaddr);
			if (NULL == tmp)
			{
				add_dhcp_client(dhcp_head->chaddr, sw_if_index);
			}			
			break;
		}
		case REQUEST_CLIENT:
		{
			Portal_DEBUG(" ============packet DHCP REQUEST=============\n");
			tmp = search_client_by_mac(dhcp_head->chaddr);
			if (NULL == tmp)
			{
				add_dhcp_client(dhcp_head->chaddr, sw_if_index);
			}	
			break;
		}
		case ACK_SERVER:
		{
			Portal_DEBUG(" =============packet DHCP ACK==============\n");
			add_client_ip_value(dhcp_head->chaddr, dhcp_head->yiaddr);	
			break;
		}
		case RELEASE_CLIENT:
		{
			Portal_DEBUG(" ==============packet DHCP RELEASE===============\n");
			
			del_dhcp_client(dhcp_head->chaddr);
			break;
		}
		case OFFER_SERVER:
		{
			Portal_DEBUG(" ==============packet DHCP OFFER===============\n");
			break;
		}
		case DECLINE_CLIENT:
		{
			Portal_DEBUG(" ===============packet DHCP DECLINE================\n");
					
			del_dhcp_client(dhcp_head->chaddr);
		}
		default: Portal_DEBUG(" ===============default  %d================\n", msg_type);break;
	}



	return 0;
}


