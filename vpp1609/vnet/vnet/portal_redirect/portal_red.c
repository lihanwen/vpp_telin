#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/tcp_packet.h>
#include <vnet/ip/udp_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/feature/feature.h>
#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/ip/ip4.h>
#include <arpa/inet.h>
#include <vnet/portal/portal.h>
#include <vnet/portal/portal_hash.h>
#include <vnet/radius/hashlist.h>
#include "portal_red.h"
#include <vnet/portal/portal_hash.h>
int portal_redirect_process (ip4_header_t * ip4, u32 sw_if_index, PORTAL_RED_USER_INFO *user_red)
{
	 u8 src_not_matched = 1;
	 l7portal_user_info * new_user = NULL;
//	 l7portal_user_info * result_src = NULL;
//	 l7portal_user_info * result_dst = NULL;
	 udp_header_t * udp;
	 l7portal_user_info *user_info = NULL;
	 l7portal_user_info *user_info_prev = NULL;
	 int key = 0;
//	 struct dl_list *p_hash;
	 vnet_main_t * vnm = vnet_get_main();
//	 vnet_hw_interface_t *hi = vnet_get_sup_hw_interface (vnm, sw_if_index);
	 vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
	 u32 portal_bas_ip = si->portal_index_info.portal_info.portal_bas_ip;
//	 u32 portal_server_ip = portal_server_msg[si->portal_index_info.portal_server_index].portal_server_ip;
//	 Portal_DEBUG("************redirect portal_bas_ip %x portal_server_ip %x\n",portal_bas_ip,portal_server_ip);

	 /*如果portal重定向和限速都没有开启，无需做业务处理*/
	 
        if( !si->portal_index_info.portal_info.enable_portal)
        {
        	 	return 0;
        }
<<<<<<< .mine

		 /*放过DNS和DHCP*/
	 if(IP_PROTOCOL_UDP == ip4->protocol)
	 {
	 	 udp = (udp_header_t*) (ip4_next_header(ip4));
	 	 if(clib_host_to_net_u16(UDP_PROTOCOL_DNS) == udp->dst_port || clib_host_to_net_u16(UDP_PROTOCOL_DNS) == udp->src_port)
	 	 {
	 	 	 return 0;
	 	 }
	 	 if(clib_host_to_net_u16(UDP_PROTOCOL_DHCP_SERVER) == udp->dst_port || clib_host_to_net_u16(UDP_PROTOCOL_DHCP_SERVER) == udp->src_port)
	 	 {
	 	 	 return 0;
	 	 }
	 	 if(clib_host_to_net_u16(UDP_PROTOCOL_DHCP_CLIENT) == udp->dst_port || clib_host_to_net_u16(UDP_PROTOCOL_DHCP_CLIENT) == udp->src_port)
	 	 {
	 	 	 return 0;
	 	 }
	 	 
	 }
||||||| .r83
=======


     /*放过DNS和DHCP*/
	 if(IP_PROTOCOL_UDP == ip4->protocol)
	 {
	 	 udp = (udp_header_t*) (ip4_next_header(ip4));
	 	 if(clib_host_to_net_u16(UDP_PROTOCOL_DNS) == udp->dst_port || clib_host_to_net_u16(UDP_PROTOCOL_DNS) == udp->src_port)
	 	 {
	 	 	 return 0;
	 	 }
	 	 if(clib_host_to_net_u16(UDP_PROTOCOL_DHCP_SERVER) == udp->dst_port || clib_host_to_net_u16(UDP_PROTOCOL_DHCP_SERVER) == udp->src_port)
	 	 {
	 	 	 return 0;
	 	 }
	 	 if(clib_host_to_net_u16(UDP_PROTOCOL_DHCP_CLIENT) == udp->dst_port || clib_host_to_net_u16(UDP_PROTOCOL_DHCP_CLIENT) == udp->src_port)
	 	 {
	 	 	 return 0;
	 	 }
	 	 
	 }
>>>>>>> .r109
        
	/*先按照源IP查找用户信息*/
	key = get_portal_hash_key(LIST_TYPE_USER_INFO, &ip4->src_address.data_u32);
	
//	Portal_DEBUG("************key = %d \n",key);
	rte_spinlock_lock(&porta_user_online_hash[key].userlock);
	Portal_DEBUG("************key = %d   ip %08x\n",key, ip4->src_address.data_u32);
	dl_list_for_each_safe(user_info, user_info_prev, &(porta_user_online_hash[key].userlist), l7portal_user_info, list)
	{//	Portal_DEBUG("************user_info ip  = %x\n",user_info->ip);
		if(user_info->ip == ip4->src_address.data_u32)
		{
			src_not_matched = 0;
			new_user = user_info;
			Portal_DEBUG("matched  one user_info ip  = %08x  white list  %d\n",user_info->ip, user_info->free_node_yn);
			if(PORTOL_FREE_RULE_ON == user_info->free_node_yn || AUTH_USER_INFO_STATE_AUTH ==  user_info->auth_state)
			{
				Portal_DEBUG("11111111111111111111111111\n");
				rte_spinlock_unlock(&porta_user_online_hash[key].userlock); 
				return 0;
			}
			break;
		}
	}	
	
	if(src_not_matched)
	{
		new_user = portal_alloc_free_user_entry(LIST_TYPE_USER_INFO, sizeof(l7portal_user_info));
		if(new_user)
		{
			memset(new_user, 0 ,sizeof(l7portal_user_info));
			dl_list_init(&new_user->list);
			//rte_spinlock_init (&(new_user->lock));
			new_user->ip = ip4->src_address.data_u32;
			
			Portal_DEBUG("add  one user_info ip  = %08x\n",new_user->ip);
			dl_list_add(&(porta_user_online_hash[key].userlist), &new_user->list );
		}
	}
<<<<<<< .mine
	//fast mac auth     radius packet  to radius server 
	/*step1: 根据终端mac 对比portal_hash表中状态，认证通过或下线退出*/
	rte_spinlock_unlock(&porta_user_online_hash[key].userlock); 
	key =  get_portal_hash_key(LIST_TYPE_USER_INFO,&user_red.user_ip);
	rte_spinlock_lock(&porta_user_online_hash[key].userlock);//对即将操作的hash表上锁
	dl_list_for_each_safe(user_info, user_info_prev, &(porta_user_online_hash[key].userlist), l7portal_user_info, list)
	{
		if(strcmp(user_info->mac,user_red.user_mac) == 0)
		{
			//免认证条件，设备已下线但是radius服务端用户记录仍处在活跃期的再次登录
			rte_spinlock_unlock(&porta_user_online_hash[key].userlock); 
			goto FAST_AUTH;//跳转至免认证服务，跳过portal重定向页面等处理
		}else
		{
			//此mac地址分配为新ip地址(或此设备为新待认证用户)
		}
	}
	
/**************/	
	
	if(portal_vpp_to_kernel_info_init(ip4, new_user, portal_bas_ip,sw_if_index))
	{
		rte_spinlock_unlock(&porta_user_online_hash[key].userlock); 
		return 0;
	}
||||||| .r83
	if(portal_vpp_to_kernel_info_init(ip4, new_user, portal_bas_ip,sw_if_index))
	{
		rte_spinlock_unlock(&porta_user_online_hash[key].userlock); 
		return 0;
	}
=======

>>>>>>> .r109
	rte_spinlock_unlock(&porta_user_online_hash[key].userlock); 


	  /*先按照目的IP查找用户信息*/
	 key = get_portal_hash_key(LIST_TYPE_USER_INFO, &ip4->dst_address.data_u32);
	 
	 rte_spinlock_lock(&porta_user_online_hash[key].userlock); 
	 dl_list_for_each(user_info, &porta_user_online_hash[key].userlist, l7portal_user_info, list)
	 {
		 if(user_info->ip == ip4->dst_address.data_u32)
		 {
		 	 new_user = user_info;
			 if(PORTOL_FREE_RULE_ON == user_info->free_node_yn || AUTH_USER_INFO_STATE_AUTH ==	user_info->auth_state)
			 {
				 rte_spinlock_unlock(&porta_user_online_hash[key].userlock); 
				 return 0;
			 }
			 if( portal_kernel_to_vpp_info_init(ip4, user_info, portal_bas_ip))
			 {
			 	 rte_spinlock_unlock(&porta_user_online_hash[key].userlock); 
				 return 0;
			 }
			 break;
		 }
<<<<<<< .mine
	 }	 
	//	 
	 rte_spinlock_unlock(&porta_user_online_hash[key].userlock); 
       Portal_DEBUG("3333333333333333333333333333333\n"); 
	
||||||| .r83
	 }	 
	 rte_spinlock_unlock(&porta_user_online_hash[key].userlock); 
       Portal_DEBUG("3333333333333333333333333333333\n"); 
	 /*放过DNS和DHCP*/
	 if(IP_PROTOCOL_UDP == ip4->protocol)
	 {
	 	 udp = (udp_header_t*) (ip4_next_header(ip4));
	 	 if(clib_host_to_net_u16(UDP_PROTOCOL_DNS) == udp->dst_port || clib_host_to_net_u16(UDP_PROTOCOL_DNS) == udp->src_port)
	 	 {
	 	 	 return 0;
	 	 }
	 	 if(clib_host_to_net_u16(UDP_PROTOCOL_DHCP_SERVER) == udp->dst_port || clib_host_to_net_u16(UDP_PROTOCOL_DHCP_SERVER) == udp->src_port)
	 	 {
	 	 	 return 0;
	 	 }
	 	 if(clib_host_to_net_u16(UDP_PROTOCOL_DHCP_CLIENT) == udp->dst_port || clib_host_to_net_u16(UDP_PROTOCOL_DHCP_CLIENT) == udp->src_port)
	 	 {
	 	 	 return 0;
	 	 }
	 	 
	 }
=======
	 }	

	 if(portal_vpp_to_kernel_info_init(ip4, new_user, portal_bas_ip,sw_if_index, user_red))
	 {
		rte_spinlock_unlock(&porta_user_online_hash[key].userlock); 
		return 0;
	 }
>>>>>>> .r109
	//fast mac
FAST_AUTH://免认证处理
	
	

	
	 rte_spinlock_unlock(&porta_user_online_hash[key].userlock); 

	 /*如果源ip或目的ip一个是portal_server 就放过
 	 if(ip4->src_address.as_u32 == portal_server_ip || ip4->dst_address.as_u32 == portal_server_ip)
 	 {
		return 0;
	}
    */

	Portal_DEBUG("redirect drop packet:  src %08x   dst  %08x\n", ip4->src_address.as_u32, ip4->dst_address.data_u32); 
	return 0;
}

#if 0
int portal_user_qos_car_init(l7portal_user_info* new_user, ip4_header_t * ip4, u32 sw_if_index)
{
	u8 i = 0;
	u32 carlarryindex = 0;

	if(sw_if_index < QOS_CAR_INTERFACE_COUNT && qos_interface[sw_if_index] && qos_interface[sw_if_index].qos_car_inbound_count)
	{
		for(i  = 0; i < QOS_CAR_POLICY_COUNT; i++)
		{
			if(qos_interface[sw_if_index].interface_car_inbound)
			{
				carlarryindex = qos_interface[sw_if_index].interface_car_inbound[i].carl_index;
				/*IP匹配*/
				if(qos_carl_msg[carlarryindex].match_flag  && qos_carl_msg[carlarryindex].ip == ip4->src_address.data_u32)
				{
					new_user->inboud_cir = qos_interface[sw_if_index].interface_car_inbound[i].cir;
					new_user->inbount_cbs = qos_interface[sw_if_index].interface_car_inbound[i].cbs;
					break;
				}
				else  if(qos_carl_msg[carlarryindex].ip & qos_carl_msg[carlarryindex].mask == ip4.src_address.data_u32 &  qos_carl_msg[carlarryindex].mask)/*网段匹配*/
				{
					new_user->inboud_cir = qos_interface[sw_if_index].interface_car_inbound[i].cir;
					new_user->inbount_cbs = qos_interface[sw_if_index].interface_car_inbound[i].cbs;
					break;
				}
			}
		}
	}
	if(sw_if_index < QOS_CAR_INTERFACE_COUNT && qos_interface[sw_if_index] && qos_interface[sw_if_index].qos_car_outbound_count)
	{
		for(i  = 0; i < QOS_CAR_POLICY_COUNT; i++)
		{
			if(qos_interface[sw_if_index].qos_car_outbound_count)
			{
				carlarryindex = qos_interface[sw_if_index].qos_car_outbound_count[i].carl_index;
				/*IP匹配*/
				if(qos_carl_msg[carlarryindex].match_flag  && qos_carl_msg[carlarryindex].ip == ip4->src_address.data_u32)
				{
					new_user->outboud_cir = qos_interface[sw_if_index].qos_car_outbound_count[i].cir;
					new_user->outbount_cbs = qos_interface[sw_if_index].qos_car_outbound_count[i].cbs;
					break;
				}
				else  if(qos_carl_msg[carlarryindex].ip & qos_carl_msg[carlarryindex].mask == ip4.src_address.data_u32 &  qos_carl_msg[carlarryindex].mask)/*网段匹配*/
				{
					new_user->outboud_cir = qos_interface[sw_if_index].qos_car_outbound_count[i].cir;
					new_user->outbount_cbs = qos_interface[sw_if_index].qos_car_outbound_count[i].cbs;
					break;
				}
			}
		}
	}
	return 0;
}

#endif
int portal_vpp_to_kernel_info_init(ip4_header_t * ip4,   l7portal_user_info * new_user, u32 portal_bas_ip,u32 sw_if_index, PORTAL_RED_USER_INFO *red_user)
{
//	Portal_DEBUG("-----------vpp to kernal---------\n");
	tcp_header_t * tcp;
	ip_csum_t  sum0;
	u32 old_addr0;
	
	ip4_main_t * ipm = &ip4_main;
	ip4_address_t *if_addr;
//	Portal_DEBUG("--------------1------------\n");
	 if(!new_user)
	 {
//	 Portal_DEBUG("--------no newuser------\n");
	 	return 0;
	 }
//	 Portal_DEBUG("---------ip4_ro %x-----------\n",ip4->protocol);
	 /*判断是tcp协议*/
 	 if (IP_PROTOCOL_TCP == ip4->protocol)
 	 {
 //	 		Portal_DEBUG("---------tcp-----------\n");
 	       tcp = (tcp_header_t*) (ip4_next_header(ip4));
		/*目的端口是80*/
		if(tcp->ports.dst == clib_host_to_net_u16(80))
		{
		       new_user->red_dst_ip = ip4->dst_address.as_u32;
//			   Portal_DEBUG("--------------from 80-------------\n");
//			   Portal_DEBUG("-------------red_dst_ip %d------------\n",new_user->red_dst_ip);
			old_addr0 = ip4->dst_address.as_u32;
			if_addr = ip4_interface_first_address (ipm, sw_if_index, NULL);
			if(if_addr !=NULL)
			{
				ip4->dst_address.as_u32 = if_addr->as_u32;
//				Portal_DEBUG("-----if_adr %x----\n",ip4->dst_address.as_u32);
			}
			else
			{
				ip4->dst_address.as_u32 = portal_bas_ip;
//				Portal_DEBUG("----else %x-----\n",ip4->dst_address.as_u32);
			}
			sum0 = ip4->checksum;
            sum0 = ip_csum_update (sum0, old_addr0, ip4->dst_address.as_u32,  ip4_header_t,  dst_address /* changed member */);
            ip4->checksum = ip_csum_fold (sum0);
            sum0 = tcp->checksum;
            sum0 = ip_csum_update (sum0, old_addr0, ip4->dst_address.as_u32,  ip4_header_t, dst_address /* changed member */);
            tcp->checksum = ip_csum_fold(sum0);
			///////////////////////////////////
/*			makeJson_data_thoughput_display((u_int16_t)MODULE_USER, 0,
            (Json_msg_handler)Json_add_red_user_data, (void *)(red_user));*/
		       return 1;
		}
	 }

//	 Portal_DEBUG("---------------2----------------\n");
	 return 0;
}


int portal_kernel_to_vpp_info_init(ip4_header_t * ip4,   l7portal_user_info * new_user, u32 portal_bas_ip)
{
	tcp_header_t * tcp;
	ip_csum_t  sum0;
	u32 old_addr0;

	 if(!new_user)
	 {
	 	return 0;
	 }
	 /*判断是tcp协议*/
 	 if (IP_PROTOCOL_TCP == ip4->protocol)
 	 {
 	       tcp = (tcp_header_t*) (ip4_next_header(ip4));
		/*源端口是80*/
		if(tcp->ports.src == clib_host_to_net_u16(80))
		{
			 old_addr0 = ip4->src_address.as_u32;
			 ip4->src_address.as_u32 = new_user->red_dst_ip;
	               sum0 = ip4->checksum;
	          	 sum0 = ip_csum_update (sum0, old_addr0, ip4->src_address.as_u32, ip4_header_t, src_address /* changed member */);
	        	 ip4->checksum = ip_csum_fold (sum0);
             		 sum0 = tcp->checksum;
            		 sum0 = ip_csum_update (sum0, old_addr0, ip4->src_address.as_u32,  ip4_header_t,  src_address /* changed member */);
             		 tcp->checksum = ip_csum_fold(sum0);
			 return 1;
		}
	 }
	 return 0;
}




#if 0
int portal_redirect_process (ip4_header_t * ip4, u32 sw_if_index)
{
	 u32 old_addr0;
	 l7portal_user_info * result = NULL;
	 l7portal_user_info * result_pre = NULL;
	 tcp_header_t * tcp;
	 udp_header_t * udp;
	 ip_csum_t  sum0;

	 vnet_main_t * vnm = vnet_get_main();
    vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
	u32 portal_server_ip = portal_server_msg[si->portal_index_info.portal_server_index].portal_server_ip;
	u32 portal_bas_ip = si->portal_index_info.portal_info.portal_bas_ip;
	int key = 0;
//	Portal_DEBUG("portal_bas_ip %d\n",portal_bas_ip);

	 ip4_main_t * ipm = &ip4_main;
	 ip4_address_t *if_addr;



	 /*放过DNS和DHCP*/
	 if(IP_PROTOCOL_UDP == ip4->protocol)
	 {
	 	 udp = (udp_header_t*) (ip4_next_header(ip4));
	 	 if(clib_host_to_net_u16(UDP_PROTOCOL_DNS) == udp->dst_port || clib_host_to_net_u16(UDP_PROTOCOL_DNS) == udp->src_port)
	 	 {
	 	 	 return 0;
	 	 }
	 	 if(clib_host_to_net_u16(UDP_PROTOCOL_DHCP_SERVER) == udp->dst_port || clib_host_to_net_u16(UDP_PROTOCOL_DHCP_SERVER) == udp->src_port)
	 	 {
	 	 	 return 0;
	 	 }
	 	 if(clib_host_to_net_u16(UDP_PROTOCOL_DHCP_CLIENT) == udp->dst_port || clib_host_to_net_u16(UDP_PROTOCOL_DHCP_CLIENT) == udp->src_port)
	 	 {
	 	 	 return 0;
	 	 }

	 }
	 /*如果源ip或目的ip一个是portal_server 就放过*/
 	 if(ip4->src_address.as_u32 == portal_server_ip || ip4->dst_address.as_u32 == portal_server_ip)
 	 {
		goto dispatch1;
	}

	 /*判断是tcp协议*/
 	 if (IP_PROTOCOL_TCP == ip4->protocol)
 	 {
 	    tcp = (tcp_header_t*) (ip4_next_header(ip4));

		/*目的端口是80*/
		if(tcp->ports.dst == clib_host_to_net_u16(80))
		{
		//	result = get_portal_user_by_ip(&ip4->src_address.as_u32);
			key = get_portal_hash_key(LIST_TYPE_USER_INFO, &ip4->src_address.as_u32);
			 rte_spinlock_lock(&porta_user_online_hash[key].userlock);
			 dl_list_for_each_safe(result, result_pre,&(porta_user_online_hash[key].userlist),l7portal_user_info, userlist)
			 {
				 //找到之后跳出循环
				 if( ip4->src_address.as_u32 == result->ip )
					 break;
				 else
				 		continue;
			 }
			if(NULL == result)
			{
				result = red_add_portal_user_to_online(&ip4->src_address.as_u32,sw_if_index);
			}

			if(result != NULL)
			{
				if(AUTH_USER_INFO_STATE_AUTH == result->auth_state)
				{
					goto dispatch1;
				}
				result->red_dst_ip = ip4->dst_address.as_u32;
				old_addr0 = ip4->dst_address.as_u32;
				if_addr = ip4_interface_first_address (ipm, sw_if_index, NULL);
				if(if_addr !=NULL)
				{
					ip4->dst_address.as_u32 = if_addr->as_u32;
				}
				else
				{
					ip4->dst_address.as_u32 = portal_bas_ip;
				}

			Portal_DEBUG("ip4->desip %d\n",ip4->dst_address.as_u32);
				sum0 = ip4->checksum;
                sum0 = ip_csum_update (sum0, old_addr0, ip4->dst_address.as_u32,
                                 ip4_header_t,
                                 dst_address /* changed member */);
                ip4->checksum = ip_csum_fold (sum0);

                sum0 = tcp->checksum;
                sum0 = ip_csum_update (sum0, old_addr0, ip4->dst_address.as_u32,
                                     ip4_header_t,
                                     dst_address /* changed member */);
                tcp->checksum = ip_csum_fold(sum0);
				goto dispatch1;
			}
		}

		/*源端口是80*/
		if(tcp->ports.src == clib_host_to_net_u16(80))
		{
			result = get_portal_user_by_ip(&ip4->dst_address.as_u32);
			if(result != NULL)
			{
				  old_addr0 = ip4->src_address.as_u32;
				  ip4->src_address.as_u32 = result->red_dst_ip;

		          sum0 = ip4->checksum;
		          sum0 = ip_csum_update (sum0, old_addr0, ip4->src_address.as_u32,
		                                 ip4_header_t,
		                                 src_address /* changed member */);
		          ip4->checksum = ip_csum_fold (sum0);

	              sum0 = tcp->checksum;
	              sum0 = ip_csum_update (sum0, old_addr0, ip4->src_address.as_u32,
	                                     ip4_header_t,
	                                     src_address /* changed member */);
	              tcp->checksum = ip_csum_fold(sum0);
				  goto dispatch1;
			}
		}
	 }
	 /* 其他协议 */

	result = get_portal_user_by_ip(&ip4->src_address.as_u32);
	/* result 存在但是未通过 或者 result 不存在 丢包*/
	if((result != NULL && (result->auth_state == AUTH_USER_INFO_STATE_AUTH)))
	{
		goto dispatch1;
	}

	return 1;

dispatch1:
	return 0;

}

#endif
/*******************************************************************************
 函数名称  : AC_sendto_web
 功能描述  : 向web发送数据
 输入参数  : json_data 向web发送的json数据
 输出参数  :
 返 回 值  : 0     成功
             -1    失败
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者  :
 修改目的  : 增新函数
 修改日期  : 2016.4.5
*******************************************************************************/
int AC_sendto_web(char *json_data)
{
    int client_sock;
    int ret;

    if( NULL != json_data)
    {
        //创建套接字
        if (-1 == (client_sock = socket(AF_UNIX, SOCK_DGRAM, 0)) )
        {
            Portal_DEBUG("Create socket fail. Reason:%s\n", strerror(errno));
            return -1;
        }
        struct sockaddr_un client_addr;
        memset (&client_addr, '\0', sizeof(struct sockaddr_un));
        client_addr.sun_family = AF_UNIX;
        memcpy(client_addr.sun_path, UNIX_SOCKET_JSON_FILE, strlen(UNIX_SOCKET_JSON_FILE));

        //打印要发送的数据
        Portal_DEBUG("--ac_sendto_web=%s-- len=%d\n", json_data, (int)strlen(json_data));

        /* 下发给ap */
        ret = (int)sendto(client_sock, json_data, strlen(json_data), 0, \
                                (struct sockaddr *)&client_addr, sizeof(client_addr));
        if (ret < 0)
        {
            Portal_DEBUG("Send fail, errno=%d. Reason:%s\n", errno, strerror(errno));
            Portal_DEBUG("--ac_sendto_web=%s-- \n", json_data);
            close(client_sock);
            return -1;
        }
        close(client_sock);

    }
    else
    {
        Portal_DEBUG("AC_sendto_web parameter is empty\n");
        return -1;
    }

    return 0;
}

/*******************************************************************************
 函数名称  : json_to_str_sendto_web
 功能描述  : json格式转换成字符串发送给web
 输入参数  : pJsonRoot  json数据指针头
 输出参数  : 无
 返 回 值  : 无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者  :
 修改目的  : 增新函数
 修改日期  : 2016.7.28
*******************************************************************************/
void json_to_str_sendto_web(cJSON **pJsonRoot)
{
    if( NULL == *pJsonRoot )
    {
        //AC_DEBUG("wtp online link null\n");
        *pJsonRoot = cJSON_CreateArray();

        if(NULL == *pJsonRoot)
        {
            Portal_DEBUG("cJSON_CreateArray error\n");
            exit(0);
        }
    }
    //用json格式打印(p_Json空间的内容需要释放)
    char *p_Json = cJSON_PrintUnformatted(*pJsonRoot);
    if(NULL == p_Json)
    {
        cJSON_Delete(*pJsonRoot);
        *pJsonRoot = NULL;

        Portal_DEBUG("cJSON_Print error\n");
        return ;
    }

    /* 发送 */
    if( -1 == AC_sendto_web(p_Json) )
    {
        //千万不要忘记释放内存呀，cJSON_Print()函数或者cJSON_PrintUnformatted（）产生的内存，
        //使用free(char *)进行释放
        free(p_Json);
        cJSON_Delete(*pJsonRoot);

        Portal_DEBUG("AC_sendto_web error\n");
        return ;
    }

    free(p_Json);//千万不要忘记释放内存呀，cJSON_Print()函数或者cJSON_PrintUnformatted（）产生的内存，使用free(char *)进行释放
    cJSON_Delete(*pJsonRoot);
    *pJsonRoot = NULL;
    p_Json = NULL;

    return ;
}
void Json_add_redirect_data(cJSON *pJson, void *user_data)
{
	PORTAL_REDIRECT_INFO *portal_info;
	portal_info = (PORTAL_REDIRECT_INFO *)user_data;
    
    cJSON_AddNumberToObject(pJson, "if_index", portal_info->index);
    cJSON_AddStringToObject(pJson, "if_ip", portal_info->nasip);
    cJSON_AddStringToObject(pJson, "porta_url", portal_info->url);
    cJSON_AddStringToObject(pJson, "nasid", "1483697053546");//portal_info->nasid

    return ;
}

void Json_del_redirect_data(cJSON *pJson, void *user_data)
{
	PORTAL_REDIRECT_INFO *portal_info;

	portal_info = (PORTAL_REDIRECT_INFO *)user_data;

    cJSON_AddNumberToObject(pJson, "if_index", portal_info->index);

    return ;
}

/*******************************************************************************
 函数名称  : Json_add_red_user_data
 功能描述  : 
 输入参数  : 
             
 输出参数  : 
 返 回 值  : 
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者  :
 修改目的  : 增新函数
 修改日期  :
*******************************************************************************/

void Json_add_red_user_data(cJSON *pJson, void *user_data)
{
	PORTAL_RED_USER_INFO *portal_red_user;
	portal_red_user = (PORTAL_RED_USER_INFO *)user_data;
       
    cJSON_AddNumberToObject(pJson, "user_ip", portal_red_user->user_ip);
    cJSON_AddStringToObject(pJson, "user_mac", portal_red_user->user_mac);
    return ;
}






/*******************************************************************************
 函数名称  : makeJson_data_thoughput_display
 功能描述  : 组发送流量数据的Json包
 输入参数  : pJsonRoot 根节点 必须定义为cJSON *pJsonRoot = NULL
             op       操作码
 输出参数  : pJsonRoot  根节点  必须定义为cJSON *pJsonRoot = NULL, 使用完必须用cJSON_Delete释放
 返 回 值  : 无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者  :
 修改目的  : 增新函数
 修改日期  : 2017.2.8
*******************************************************************************/
void makeJson_data_thoughput_display(u_int16_t module, u_int16_t op,
            Json_msg_handler fmessage_proc, void *user_data)
{
    cJSON *pJsonRoot = NULL;
    cJSON *pJson_grandpa = NULL;
    cJSON *pJson_pa = NULL;

    //创建一个数组
    pJsonRoot = cJSON_CreateArray();
    if(NULL == pJsonRoot)
    {
        Portal_DEBUG("cJSON_CreateArray error\n");
        exit(0);
    }

    //创建一个对象
    pJson_grandpa = cJSON_CreateObject();
    if(NULL == pJson_grandpa)
    {
        Portal_DEBUG("cJSON_CreateObject error\n");
        return ;
    }
    //把对象添加入数组
    cJSON_AddItemToArray(pJsonRoot, pJson_grandpa);

    //添加number到对象
    cJSON_AddNumberToObject(pJson_grandpa, "module", module);
    cJSON_AddNumberToObject(pJson_grandpa, "op", op);

    //以下为param的内容
    //添加一个item到对象，并给item命名为param
    cJSON_AddItemToObject(pJson_grandpa, "param", pJson_pa=cJSON_CreateObject());

    //填充param数据
    fmessage_proc(pJson_pa, user_data);

    //pJsonRoot转换成字符串，发送给web，释放pJsonRoot的空间，并赋值为NULL
    json_to_str_sendto_web(&pJsonRoot);

    return ;
}



