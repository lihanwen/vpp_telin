/*
 * portal.c
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/ip/udp.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <arpa/inet.h>
#include <vnet/portal/interface_portal.h>


#include <vnet/portal/portal.h>


#include "portal_hash.h"
#include <vnet/radius/md5.h>


#include <vnet/radius/hashlist.h>
#include <vnet/radius/list.h>


#include <vnet/radius/radius_private.h>


#include <rte_cycles.h>
#include <rte_config.h>
#include <rte_spinlock.h>
#include <rte_launch.h>

#include <vnet/radius/interface_radius.h>
#include <vnet/dhcp/hash_client.h>
#include <vnet/portal/token_bucket.h>
#include <vnet/portal/qos_hash.h>



int resendCount = 1;

//#include <ioam/export/ioam_export.h>
u8 g_portal_debug = 0;
/* 当前portal user 数 */
u32 gs_portal_user_num = 0;

/*认证成功并在线的用户数*/
u32 gs_portal_user_online_num =0;

u32 gs_bas_ip;

u32 gs_portal_server;

rte_spinlock_t radius_timer_lock;//锁


static vlib_node_registration_t portal_node;

typedef void (*Portal_msg_handler)(l7portal_user_info* result, u16 msg_type, void *pbuf, u16 len);
SERVER_MSG server_msg;
extern  int radius_response_is_valid(u16 in_len, unsigned char *in,unsigned int *ip);

static u8 *format_portal_trace (u8 * s, va_list * args)
{
	CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
	CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
	portal_trace_t *t = va_arg (*args, portal_trace_t *);
	s = format (s, "portal: %U", t->packet_data);
	return s;
}

/*******************************************************************************
 函数名称  : pack_ack_auth
 功能描述  : 收到radius报文后给portal server发送ACK_AUTH报文
 输入参数  : result portal结构体
 			 buf 报文缓冲
 			 rc radius服务器拒绝或接受用户继续访问
 输出参数  : 
 返 回 值  : 实际要发送报文总长度
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者  :
 修改目的  :
 修改日期  : 2016.12
*******************************************************************************/

int portal_build_from_radius_response(u32 ip,unsigned char* buf,int rc)
{
	 int key = 0;
	 int tlen = 0;
	 int flag = 0;
	 //获取hash值
	 l7portal_user_info * result = NULL;
	 
	 key = get_portal_hash_key(LIST_TYPE_USER_INFO, &(ip));
	 rte_spinlock_lock(&porta_user_online_hash[key].userlock);
	 dl_list_for_each(result, &(porta_user_online_hash[key].userlist),l7portal_user_info, list)
	 {
		 //找到之后跳出循环
		if(result->ip == ip)
		{
			flag = 1;
			break;
		 }
	 }
	 if(!result ||  !flag)
	 {
		rte_spinlock_unlock(&porta_user_online_hash[key].userlock);
	 	return 0;
	 }
	switch(rc)
	{
		case RAD_ACCESS_ACCEPT:
		{

			result->err_code = ACK_AUTH_ERRCODE_SUCCESS;
			//转换状态
			result->state = PORTAL_STATE_AUTH;
			//发送认证成功报文
			tlen = portal_build_auth_response(result,(portal_header_t *)buf,ACK_AUTH);
			break;
		}
		case RAD_ACCESS_REJECT:
		{
			result->err_code = ACK_AUTH_ERRCODE_REFUSE;
			//发送认证失败报文
			tlen = portal_build_auth_response(result,(portal_header_t *) buf,ACK_AUTH);
			break;
		}
	}
	rte_spinlock_unlock(&porta_user_online_hash[key].userlock);
	return tlen;
}
/*******************************************************************************
 函数名称  : pack_rad_access_req
 功能描述  : 发送RAD_ACCESS_REQUEST请求
 输入参数  : result portal结构体
 			 portal_head 报文头
 输出参数  : 无
 返 回 值  : 无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者  :
 修改目的  :
 修改日期  : 2016.12
*******************************************************************************/
unsigned int portal_build_rad_access_request (l7portal_user_info *result,portal_header_t *portal_head ,u16 portal_attr_len, u32 sw_if_index)
{
	u32 rlen = 0;
	unsigned char ps[MSGSIZE];
	radius_packet_session *newnode = NULL;
	unsigned char *name = (unsigned char *)(result->req_auth_msg.user_name);
	unsigned char *passwd = (unsigned char *)(result->req_auth_msg.password);
	u32 plen = portal_attr_len + sizeof(portal_head);

       Portal_DEBUG("***************portal_build_rad_access_request   name lenth**************%s %d\n",name,cal_strlen((char *)name));

	radius_init_request_packet(result->req_auth_msg.password_type, result->challenge, result->req_id, name,passwd,result->ip, ps,&rlen);

	newnode = radius_alloc_packet_session();
	if(!newnode)
	{
		return 0;
	}
	newnode->record_msg.client_ip = result->ip;
	newnode->record_msg.packet_id = ps[POS_IDENT];
	newnode->record_msg.portal_sw_if_index = sw_if_index;
       newnode->record_msg.passwd_type = result->req_auth_msg.password_type;
       clib_memcpy((char *)(newnode->record_msg.challenge), (const char *)result->challenge, cal_strlen((char *)result->challenge));
	clib_memcpy((char *)(newnode->record_msg.user_name), (const char *)name, cal_strlen((char *)name));
	clib_memcpy((char *)(newnode->record_msg.passwd), (const char *)passwd, cal_strlen((char *)passwd));
       clib_memcpy((char *)(newnode->record_msg.authenticate), (const char *)&ps[POS_AUTH], 16);
	newnode->req_id = result->req_id;
	radius_insert_packet_session(newnode);

	if(PREDICT_TRUE(rlen >= plen))
	{
		clib_memcpy(portal_head,ps,rlen);
	}
	else
	{
		clib_memcpy(portal_head,ps,rlen);
	}

	return rlen;
}

/*******************************************************************************
 函数名称  : Portal_proc_rcv_messages
 功能描述  : 处理portal应答消息中的message
 输入参数  : pd            消息缓冲区poratal协议头之后的附加数据
             dlen            poratal协议头之后的数据长度
             fmessage_proc  消息处理函数

 输出参数  : 无
 返 回 值  : 无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者  :
 修改目的  : 增新函数fmessage_proc
 修改日期  : 2016.12.9
*******************************************************************************/
void Portal_proc_rcv_messages(void* portal_attr_head, u16 portal_attr_len, Portal_msg_handler fmessage_proc,
                                                                        l7portal_user_info* result)
{
    #define PORTAL_ATTR_TYPE_HEAD_LEN 2
    u8 msg_type, msg_len;
    char* pbuf;

    pbuf = (char *)portal_attr_head;
    while(portal_attr_len > 0)
    {
        if (portal_attr_len < sizeof(u16))
        {
            break;
        }
        /* 取消息类型 */
        msg_type = *(u8*)pbuf;
        pbuf += sizeof(u8);
        /* 取消息长度 */
        msg_len = (u8)(*(u8*)pbuf-PORTAL_ATTR_TYPE_HEAD_LEN);
		Portal_DEBUG("________msg_type %d msg_len %d_______\n",msg_type,msg_len);
        pbuf += sizeof(u8);

        portal_attr_len = (u16)(portal_attr_len - sizeof(u16));
        fmessage_proc(result, msg_type, pbuf, (u16)clib_min(msg_len, portal_attr_len));
        if (portal_attr_len < msg_len)
        {
            break;
        }
        portal_attr_len = (u16)(portal_attr_len - msg_len);
        pbuf += msg_len;
    }
}

/*******************************************************************************
 函数名称  : Portal_proc_req_auth
 功能描述  : 处理portal的REQ_AUTH报文
 输入参数  : result     portal用户信息
             msg_type   报文类型
             pbuf        报文缓冲区
             len        报文长度
 输出参数  : 无
 返 回 值  : 无
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者  :
 修改目的  :
 修改日期  : 2017.1.5
*******************************************************************************/

void Portal_proc_req_auth(l7portal_user_info* result, u16 msg_type, void *pbuf, u16 len)
{
	Portal_DEBUG("*********msg_type %d len %d***\n",msg_type,len);
    switch(msg_type)
    {
        case PORTAL_ATTR_USER_NAME:
            if( len > 256 )
            {
                Portal_DEBUG("user name len error, len=%d\n", len);
                break;
            }
            //获得用户名
            clib_memcpy(result->req_auth_msg.user_name, (char *)pbuf, len);
            break;
        case PORTAL_ATTR_PASS_WORD:
            if( len > 16 )
            {
                Portal_DEBUG(" password len error, len=%d\n", len);
                break;
            }
            result->req_auth_msg.password_type = PORTAL_ATTR_PASS_WORD;
            //获得明文的密码
            clib_memcpy(result->req_auth_msg.password, (char *)pbuf, len);

            break;
        case PORTAL_ATTR_CHAP_PASSWORD:
            if( 16 != len )
            {
                Portal_DEBUG("chap password len error\n");
                break;
            }
            result->req_auth_msg.password_type = PORTAL_ATTR_CHAP_PASSWORD;
            //获得经过chap加密的密码
            clib_memcpy(result->req_auth_msg.password, (char *)pbuf, len);
            break;
        default:
          //  Portal_DEBUG("in REQ_AUTH message, %d attribute not resolved\n", msg_type);
            break;
    }
}
/*******************************************************************************
 函数名称  : pack_portal_head
 功能描述  : 发送报文
 输入参数  : result portal结构体
             pd        缓冲区
             len        缓冲区长度
             type       报文类型
 输出参数  : 无
 返 回 值  : 同send函数
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者  :
 修改目的  :
 修改日期  : 2016.12
*******************************************************************************/

int portal_build_auth_response_head(l7portal_user_info* result, void* pd, u_int16_t len, u_int8_t type, u_int8_t attr_num)
{
    portal_header_t *phdr;
	unsigned char * phead;
	unsigned int tlen;
    MD5_CTX md5;
	memset(&server_msg, '\0', sizeof(server_msg));

    phdr = (portal_header_t*)((char *)pd- sizeof(portal_header_t));

	phead = (unsigned char *)phdr;

    phdr->version = PROTOCAL_VERSION_NUM;
    phdr->type = type;
    phdr->auth_mode = AUTH_MODE_CHAP;
    phdr->srv = 0;
    phdr->serial_no = result->serial_no;
    phdr->req_id = clib_host_to_net_u16(result->req_id);
    phdr->user_ip = result->ip;
    phdr->user_port = clib_host_to_net_u16(0);
    phdr->err_code = result->err_code;
    phdr->attr_num = attr_num;

/*测试*/
	strcpy(server_msg.portal_share_key, "123456");

    //添加请求报文的验证字
    clib_memcpy(phdr->authenticator_MD5, result->authenticator_MD5, 16);
    //在报文末尾加入加入共享秘钥，用于生成应答报文的验证字
    clib_memcpy(((char *)pd)+len, server_msg.portal_share_key, strlen(server_msg.portal_share_key));
    //生成应答报文的验证字
    MD5_Init(&md5);
	tlen = (unsigned int )(len+sizeof(portal_header_t) + strlen(server_msg.portal_share_key));
/*    MD5_Update(&md5,(unsigned char *)phdr, tlen);*/

	MD5_Update(&md5,phead, 1);
	MD5_Update(&md5,phead+1, 1);
	MD5_Update(&md5,phead+1, 1);
	MD5_Update(&md5,phead+1, 2);
	MD5_Update(&md5,phead+2, 2);
	MD5_Update(&md5,phead+2, 4);
	MD5_Update(&md5,phead+4, 2);
	MD5_Update(&md5,phead+2, 1);
	MD5_Update(&md5,phead+1, 1);
	MD5_Update(&md5,phead+1, 16);
	MD5_Update(&md5,phead+16, len);
	MD5_Update(&md5,phead+len, strlen(server_msg.portal_share_key));



    MD5_Final(phdr->authenticator_MD5, &md5);
    tlen -= strlen(server_msg.portal_share_key);
    /* return total lenth of portal  */
    return tlen;
}

/*******************************************************************************
 函数名称  : pack_portal_ack
 功能描述  : 发送ACK报文
 输入参数  : result portal结构体
             portal_head 报文头
             ack_type    ACK报文类型
 输出参数  : 无
 返 回 值  : 同send函数
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者  :
 修改目的  :
 修改日期  : 2016.12
*******************************************************************************/

int portal_build_auth_response(l7portal_user_info* result,portal_header_t *portal_head ,u8 ack_type)
{
	//void *ph = (char *)portal_head; // record adress of portal_head
	char *portal_attr_head = (char *)(portal_head) + sizeof(portal_header_t);
	char *ps = portal_attr_head;

	if(ack_type == ACK_AUTH|| ack_type == ACK_LOGOUT)
		return  portal_build_auth_response_head(result, ps, (u16)(portal_attr_head - ps), ack_type, 0);
    PORTAL_ATTR *portal_attr;
     int i;


    portal_attr = (PORTAL_ATTR *)portal_attr_head;

    //填充类型
    portal_attr->type = PORTAL_ATTR_CHALLENGE;

    //填充数据长度
    portal_attr->len = MD5_DATA_LEN + sizeof(u_int8_t)*2;

    portal_attr_head += sizeof(PORTAL_ATTR);

    //产生随机数种子
    srand((unsigned int)time(NULL));//设置随机数种子
    for(i = 0; i < MD5_DATA_LEN; i ++)
        portal_attr->value[i] =  (char)(rand()%256);

    //产生challenge 挑战字
    MD5_CTX md5;
    MD5_Init(&md5);
    MD5_Update(&md5, portal_attr->value, MD5_DATA_LEN);
    MD5_Final((unsigned char *)portal_attr_head, &md5);
    //添加challenge 挑战字
    clib_memcpy(result->challenge, (char *)portal_attr_head, MD5_DATA_LEN);
    portal_attr_head+= MD5_DATA_LEN;
    return  portal_build_auth_response_head(result, ps, (u16)(portal_attr_head - ps), ack_type, 1);
}

/*******************************************************************************
 函数名称  : l7portal_process
 功能描述  : 处理portal 2000 报文的功能函数
 输入参数  : next 初始化为error_drop
 			 result为用户信息结构体 初始化为NULL
 			 sw_if_index 数据包来源的接口索引
 输出参数  : 无
 返 回 值  : 
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者  :
 修改目的  :
 修改日期  : 2017.2.23
*******************************************************************************/

static_always_inline int
l7portal_process (vlib_main_t *vm,
		 vlib_node_runtime_t * node,
		 l7portal_main_t * l7pm,
		 u64 * counter_base,
		 vlib_buffer_t * b,
		 ip4_header_t *  ip4,
		 udp_header_t * udp,
		 portal_header_t *portal_head,
		 u32 *next,u32 sw_if_index)
{
	void *portal_attr_head= ((char *)portal_head) + sizeof(portal_header_t);
	u16 portal_attr_len = clib_net_to_host_u16(udp->length) - sizeof(udp_header_t) - sizeof(portal_header_t);
	u32 ip4_src = ip4->src_address.as_u32;
	u32 ip4_dst = ip4->dst_address.as_u32;
	u16 udp_src = udp->dst_port;
	u16 udp_des = udp->src_port;
	u8 type = portal_head->type;//type of message
	u32 msg_len = 0;//total lenth of portal msg or radius msg to be send
	u8 send_to_who = 0;//0 portal_server 1 radius 1812 2 radius 1813
//	u8 is_free_user = 0;// 1 need delete user
	u32 radius_ip = radius_ser_info[0].prim_auth_ip;
	int key= 0;
	l7portal_user_info *result_prev;
	l7portal_user_info *result;
				
	if ( 0 != portal_head->srv || 0 != clib_host_to_net_u16(portal_head->user_port) )
	{
   	 //保留的字段不为0
   		 goto dispatch;
	}

	if (portal_head->version != PROTOCAL_VERSION_NUM)
	{
   	 //协议版本号不对
    	goto dispatch;
	}
	 key = get_portal_hash_key(LIST_TYPE_USER_INFO, &(portal_head->user_ip));
	 rte_spinlock_lock(&porta_user_online_hash[key].userlock);
	 
	 dl_list_for_each_safe(result,result_prev, &(porta_user_online_hash[key].userlist),l7portal_user_info, list)
	 {
		 //找到之后跳出循环
		 if( portal_head->user_ip == result->ip )
			 break;
	 }
	/* Check ip table lookup result */
	if (PREDICT_TRUE (result !=NULL ))//?
    {
    	Portal_DEBUG("The entry was in the table\n");
    	/*
		 *The entry was in the table
		 */
		//如果验证信息已经存在，初始化下线时间为0
        result->offline_time = 0;

    }


	switch(type)
    {
        case REQ_CHALLENGE://上线Challenge请求
        {
			result = add_or_change_portal_user_on_hash(result,portal_head,sw_if_index);
			if( PREDICT_TRUE(NULL == result))
            {
                Portal_DEBUG("allocation portal user  fail\n");
                goto dispatch;
            }
			
			
			//如果state不是PORTAL_STATE_START状态，说明已经有相同ip的用户还在线
			if( PREDICT_TRUE(PORTAL_STATE_START != result->state))
			{
				//还有相同ip的用户在线
				result->err_code = ACK_CHALLENGE_ERRCODE_CONNET;
				Portal_DEBUG("REQ_CHALLENGE state error,state=%u\n", result->state);

			}
			//如果相等发送challenge成功报文
			else
			{
				//challenge成功报文
				result->err_code = ACK_CHALLENGE_ERRCODE_SUCCESS;
				result->state = PORTAL_STATE_CHALLENGE;
			}

			result->serial_no = portal_head->serial_no;//
			result->port = portal_head->user_port;

			msg_len = portal_build_auth_response(result,portal_head,ACK_CHALLENGE);
			Portal_DEBUG("send ack_chanllege\n");

			
			
			*next = PORTAL_NEXT_IP4_LOOKUP;
			goto dispatch;
		}


		case REQ_AUTH://认证请求
		{

			if (PREDICT_TRUE(result == NULL))
 			{
  				/*
		 		*The entry was not in the table
		 		*/
				 Portal_DEBUG("ip no find\n");
				goto dispatch;

  			}
			
			//处理收到的报文
            		Portal_proc_rcv_messages(portal_attr_head, portal_attr_len, Portal_proc_req_auth, result);
			result->port = portal_head->user_port;
			result->serial_no = portal_head->serial_no;
						//添加请求报文的验证字
			clib_memcpy(result->authenticator_MD5, portal_head->authenticator_MD5, MD5_DATA_LEN);


            if( PORTAL_STATE_CHALLENGE != result->state )
            {
				Portal_DEBUG("REQ_AUTH state error state=%u\n",result->state);
            	 //还有相同ip的用户在线
                result->err_code = ACK_AUTH_ERRCODE_CONNET;
                //发送认证失败报文
                *next = PORTAL_NEXT_IP4_LOOKUP;
                msg_len = portal_build_auth_response(result,portal_head,ACK_AUTH);
				Portal_DEBUG("send ack_auth fail\n");
				goto dispatch;
            }
			//如果state不是PORTAL_STATE_CHALLENGE状态，说明已经有相同ip的用户还在线
            else
            {

            	send_to_who = 1;
            	*next = PORTAL_NEXT_IP4_LOOKUP;
				//发给radius
                msg_len = portal_build_rad_access_request( result,portal_head,portal_attr_len, sw_if_index);		
				goto dispatch;
            }

		}

		case REQ_LOGOUT://下线或超时请求
		{

			//如果获取到信息
			if (PREDICT_TRUE(result != NULL))
 			{
  				/*
				 *The entry was  in the table
				 */
				result->auth_state = AUTH_USER_INFO_STATE_OFFLINE;
				//设置下线时间，下次检测到时间差大于10s删除
				result->offline_time = (u32)time(NULL);
				Portal_DEBUG("auth user info  exit,make station offline\n");

  			}
			else
			{
				Portal_DEBUG("auth user info no exit,station already offline\n");
				goto dispatch;
			}
			//收到下线请求
            if( REQ_LOGOUT_ERRCODE_DOWN_LINE == portal_head->err_code )
            {

                    result->err_code = ACK_LOGOUT_ERRCODE_SUCCESS;
                    result->serial_no = portal_head->serial_no;
                    result->port = portal_head->user_port;
                    //添加请求报文的验证字
                    clib_memcpy(result->authenticator_MD5, portal_head->authenticator_MD5, MD5_DATA_LEN);

				*next = PORTAL_NEXT_IP4_LOOKUP;
                msg_len = portal_build_auth_response(result,portal_head,ACK_LOGOUT);
	
				free_portal_user_point(result);
				
				Portal_DEBUG("delete result\n");
				goto dispatch;

            }
			//超时请求
            else if( REQ_LOGOUT_ERRCODE_TIMEOUT == portal_head->err_code )
            {
                Portal_DEBUG("REQ_LOGOUT_ERRCODE_TIMEOUT error\n");

            }	
			goto dispatch;

		}

		case AFF_ACK_AUTH://收到验证成功相应报文的确认报文
		{

			//判断通过序列号是否分配了一个portal结构体
           if (PREDICT_TRUE(result == NULL))
 			{
		 		//The entry was not in the table	
				goto dispatch;
				
  			}
             //如果state不是PORTAL_STATE_AUTH状态，说明已经有相同ip的用户还在线
            if( PORTAL_STATE_AUTH == result->state )
            {
                //用户上线完全成功，
                result->state = PORTAL_STATE_Run;
                result->port = portal_head->user_port;
                result->auth_state = AUTH_USER_INFO_STATE_AUTH;
				gs_portal_user_online_num++;
            }
			break;
		}
	}
	
	dispatch:
		
		rte_spinlock_unlock(&porta_user_online_hash[key].userlock);
		ip4->dst_address.as_u32 = ip4_src;
		udp->dst_port = udp_des;
		if(PREDICT_TRUE(1 == send_to_who))
		{
			ip4->dst_address.as_u32 = radius_ip;
			udp->dst_port = clib_host_to_net_u16(1812);
		}
	     ip4->src_address.as_u32 = ip4_dst;
	     udp->length = clib_host_to_net_u16 (msg_len + sizeof (udp_header_t));
		 udp->src_port = udp_src;

	     ip4_tcp_udp_com_checksum (vm, b);
	     b->current_length =
		 msg_len + sizeof (ip4_header_t) + sizeof (udp);
	     ip4->length = clib_host_to_net_u16 (b->current_length);
	     ip4->checksum = ip4_header_checksum (ip4);
		return 0;

}
 /*******************************************************************************
  函数名称	: l7radius_process
  功能描述	: 处理radius 1812 认证报文的功能函数
  输入参数	: next 初始化为error_drop
			  result为用户信息结构体 初始化为NULL
			  sw_if_index 数据包来源的接口索引
			  rad radius报文
  输出参数	: 无
  返 回 值	: 
 --------------------------------------------------------------------------------
  最近一次修改记录 :
  修改作者	:
  修改目的	:
  修改日期	: 2017.2.23
 *******************************************************************************/

 static_always_inline int
l7radius_process (vlib_main_t *vm,
		 vlib_node_runtime_t * node,
		 l7portal_main_t * l7pm,
		 u64 * counter_base,
		 vlib_buffer_t * b,
		 ip4_header_t *  ip4,
		 udp_header_t * udp,
		 unsigned char *rad,
		 u32 *next,u32 sw_if_index)
{
	u32 user_ip;
	u32 portal_msg_len = 0; 
	vnet_main_t * vnm = vnet_get_main();
       vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
	u32 portal_bas_ip = si->portal_index_info.portal_info.portal_bas_ip;
	u16 rad_len = clib_net_to_host_u16(udp->length) - sizeof(udp_header_t);
	int is_valid = radius_response_is_valid(rad_len,rad,&user_ip);
	u32 portal_server_ip = portal_server_msg[si->portal_index_info.portal_server_index].portal_server_ip;
	 if(is_valid)
	{
		unsigned char portal_pac[2048];
		portal_msg_len = portal_build_from_radius_response(user_ip,portal_pac, rad[POS_CODE]);
		Portal_DEBUG("portal_ack_auth\n");
		clib_memcpy((char *)rad, (const char *)portal_pac, portal_msg_len);
		ip4->dst_address.as_u32 = portal_server_ip;
		ip4->src_address.as_u32 = portal_bas_ip;
		udp->src_port = clib_host_to_net_u16(2000);
		udp->dst_port = clib_host_to_net_u16(portal_server_msg[si->portal_index_info.portal_server_index].portal_server_port);	
		udp->length = clib_host_to_net_u16 (portal_msg_len + sizeof (udp_header_t));
		ip4_tcp_udp_com_checksum (vm, b);
		b->current_length =  portal_msg_len + sizeof (ip4_header_t) + sizeof (udp_header_t);
		ip4->length = clib_host_to_net_u16 (b->current_length);
		ip4->checksum = ip4_header_checksum (ip4);
		*next = PORTAL_NEXT_IP4_LOOKUP;
	}

	 return 0;
}


 void
  suspend_timer_deadline(radius_packet_session *temp, unsigned char *pkgid, char * auth)
  {
	 u32 radlen;
	 u32 * to_output;
	 u32 bi0;
	 vlib_buffer_t *b0;
  	 vlib_frame_t *f;
	 unsigned char *rad0 = NULL;
	 ip4_header_t *ip40;
	 udp_header_t *udp0;

	 vlib_main_t * vm = vlib_get_main();

	vnet_main_t * vnm = vnet_get_main();
    vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, temp->record_msg.portal_sw_if_index);
	u32 portal_bas_ip = si->portal_index_info.portal_info.portal_bas_ip;

//	 u32  *to_next;

//     vlib_node_runtime_t *node =
//      vlib_node_get_runtime (vm, ip4_lookup_node.index);
//	 portal_next_t next_index;
//	 next_index = node->cached_next_index;
//     u32 n_left_to_next;
//	 vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);



	 //u32 next0 = PORTAL_NEXT_ERROR_DROP;

	 /* speculatively enqueue b0 to the current next frame */
	if (vlib_buffer_alloc (vm, &bi0, 1)	== 1)
	{
	      b0 = vlib_get_buffer (vm, bi0);
		  vnet_buffer(b0)->sw_if_index[VLIB_RX] = temp->record_msg.portal_sw_if_index;
		  vnet_buffer(b0)->sw_if_index[VLIB_TX] = ~0;
		  f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);

		  to_output = vlib_frame_vector_args (f);
		  to_output[0] = bi0;
		  f->n_vectors = 1;
		  vlib_buffer_advance(b0, sizeof(ethernet_header_t)*2 );
		  ip40 = vlib_buffer_get_current (b0);
		  vlib_buffer_advance (b0, sizeof (*ip40));
		  udp0 = vlib_buffer_get_current (b0);
		  vlib_buffer_advance (b0, sizeof (*udp0));
		  rad0= vlib_buffer_get_current (b0);

		 ip40->ip_version_and_header_length = 0x45;
		 ip40->flags_and_fragment_offset = 0;
		 ip40->fragment_id = 0;
		 ip40->tos = 0;
		 ip40->ttl = 0xff;
		 ip40->protocol = IP_PROTOCOL_UDP;
		 ip40->dst_address.as_u32 = radius_ser_info[0].prim_auth_ip;
		ip40->src_address.as_u32 = portal_bas_ip;
		Portal_DEBUG("portal_bas_ip %d\n",portal_bas_ip);
		 udp0->src_port = clib_host_to_net_u16(3600);
		 udp0->dst_port = clib_host_to_net_u16(1812);


	     radius_init_request_packet(temp->record_msg.passwd_type, temp->record_msg.challenge, temp->req_id, (unsigned char *)temp->record_msg.user_name,
		 	(unsigned char *)temp->record_msg.passwd, temp->record_msg.client_ip, rad0, &radlen);
		 *pkgid = rad0[POS_IDENT];
		 udp0->checksum = ip4_tcp_udp_com_checksum (vm, b0);
		 udp0->length = clib_net_to_host_u16(radlen + sizeof(udp_header_t));
		 ip40->length = clib_host_to_net_u16 (radlen + sizeof (ip4_header_t) + sizeof (udp0));
		 ip40->checksum = ip4_header_checksum (ip40);
		 vlib_buffer_advance (b0, -sizeof (*udp0));

		 vlib_buffer_advance (b0, -sizeof (*ip40));
		 b0->current_length =
		 radlen + sizeof (ip4_header_t) + sizeof (udp0);

		 vlib_put_frame_to_node(vm, ip4_lookup_node.index, f);

		 //vlib_put_next_frame (vm, node, next_index, n_left_to_next);


 	 }
  }

static uword
portal_node_fn (vlib_main_t * vm,
	       vlib_node_runtime_t * node, vlib_frame_t * frame)
{

	u32 n_left_from, *from, *to_next;
	portal_next_t next_index;

	l7portal_main_t *l7pm = &l7portal_main;
	vlib_error_main_t *em = &vm->error_main;
    vlib_node_t *n = vlib_get_node (vm, portal_node.index);
    u32 node_counter_base_index = n->error_heap_index;
    from = vlib_frame_vector_args (frame);

	n_left_from = frame->n_vectors;	/* number of packets to process */
  	next_index = node->cached_next_index;
	/*
	if (node->flags & VLIB_NODE_FLAG_TRACE)
	{
		vlib_trace_frame_buffers_only (vm, node,
				   from,
				   n_left_from,
				   sizeof (from[0]),
				   sizeof (portal_trace_t));
	}*/
	while (n_left_from > 0)
	{
		u32 n_left_to_next;
		vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
		while (n_left_from >= 4 && n_left_to_next >= 2)
		{
			u32 bi0,bi1;
			vlib_buffer_t *b0,*b1;
			u32 sw_if_index0, sw_if_index1;
			u32 next0 = PORTAL_NEXT_ERROR_DROP;
			u32 next1 = PORTAL_NEXT_ERROR_DROP;
			unsigned char *p0,*p1;
			ip4_header_t *ip40,*ip41;
			udp_header_t *udp0,*udp1;

		/* Prefetch next iteration. */
	     {
			vlib_buffer_t *p2, *p3;

	   		p2 = vlib_get_buffer (vm, from[2]);
	    	p3 = vlib_get_buffer (vm, from[3]);

	    	vlib_prefetch_buffer_header (p2, LOAD);
	    	vlib_prefetch_buffer_header (p3, LOAD);

	    	CLIB_PREFETCH (p2->data, CLIB_CACHE_LINE_BYTES, STORE);
	    	CLIB_PREFETCH (p3->data, CLIB_CACHE_LINE_BYTES, STORE);
	 	 }

	  /* speculatively enqueue b0 and b1 to the current next frame */
	  /* bi is "buffer index", b is pointer to the buffer */
	  		to_next[0] = bi0 = from[0];
	  		to_next[1] = bi1 = from[1];
	  		from += 2;
	  		to_next += 2;
	  		n_left_from -= 2;
	  		n_left_to_next -= 2;

	  		b0 = vlib_get_buffer (vm, bi0);
	  		b1 = vlib_get_buffer (vm, bi1);
	  		p0= vlib_buffer_get_current (b0);
	 		p1= vlib_buffer_get_current (b1);
	 		vlib_buffer_advance (b0, -sizeof (*udp0));
	 		vlib_buffer_advance (b1, -sizeof (*udp1));
	 		udp0 = vlib_buffer_get_current (b0);
	 		udp1 = vlib_buffer_get_current (b1);
	 		vlib_buffer_advance (b0, -sizeof (*ip40));
	 		vlib_buffer_advance (b1, -sizeof (*ip41));
	 		ip40 = vlib_buffer_get_current (b0);
	 		ip41 = vlib_buffer_get_current (b1);

			/* RX interface handles */
	  		sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	 		sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

			/* process 2 pkts */
			/* 收到来自1812 或 1813端口的报文*/
			if(udp0->src_port == clib_host_to_net_u16(1812))
			{
				l7radius_process(vm,node,l7pm,&em->counters[node_counter_base_index],b0,ip40,udp0,p0,&next0,sw_if_index0);
			}

			/* 收到 dest port is 2000*/
			else
			{
				portal_header_t *portal_head0 = (portal_header_t *)p0;	  
				l7portal_process(vm,node,l7pm,&em->counters[node_counter_base_index],b0,ip40,udp0,portal_head0,&next0,sw_if_index0);

			}
			/* 收到来自1812 或 1813端口的报文*/
			if(udp1->src_port == clib_host_to_net_u16(1812))
			{
				/* process 2 pkts */				
				l7radius_process(vm,node,l7pm,&em->counters[node_counter_base_index],b1,ip41,udp1,p1,&next1,sw_if_index1);
			}
			/* 收到 dest port is 2000*/
			else
			{
				portal_header_t *portal_head1 = (portal_header_t *)p1;
				l7portal_process(vm,node,l7pm,&em->counters[node_counter_base_index],b1,ip41,udp1,portal_head1,&next1,sw_if_index1);
			}


	  /* verify speculative enqueues, maybe switch current next frame */
	  /* if next0==next1==next_index then nothing special needs to be done */
	  		vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);

		}
		while (n_left_from >0 && n_left_to_next > 0)
		{
			u32 bi0;
			vlib_buffer_t *b0;
			u32 sw_if_index0;
			u32 next0 = PORTAL_NEXT_ERROR_DROP;
			unsigned char *p = NULL;
			ip4_header_t *ip40;
			udp_header_t *udp0;

	  		/* speculatively enqueue b0 to the current next frame */

	  		bi0 = from[0];
	  		to_next[0] = bi0;
	  		from += 1;
	  		to_next += 1;
	 		n_left_from -= 1;
	 		n_left_to_next -= 1;

	 		b0 = vlib_get_buffer (vm, bi0);
	  		p= vlib_buffer_get_current (b0);
	 		vlib_buffer_advance (b0, -sizeof (*udp0));
	 		udp0 = vlib_buffer_get_current (b0);
	 		vlib_buffer_advance (b0, -sizeof (*ip40));
	 		ip40 = vlib_buffer_get_current (b0);

			/* RX interface handles */
	  		sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

			/* process 1 pkts */
			/* 收到来自1812 或 1813端口的报文*/
			if(udp0->src_port == clib_host_to_net_u16(1812))
			{
				l7radius_process(vm,node,l7pm,&em->counters[node_counter_base_index],b0,ip40,udp0,p,&next0,sw_if_index0);
			}

			/* dest port is 2000*/
			else
			{
				portal_header_t *portal_head0 = (portal_header_t *)p;
				l7portal_process(vm,node,l7pm,&em->counters[node_counter_base_index],b0,ip40,udp0,portal_head0,&next0,sw_if_index0);
			}
			/* verify speculative enqueue, maybe switch current next frame */
	 		 vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);

		}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	}
	return frame->n_vectors;
}

static char *portal_error_strings[] = {
#define portal_error(n,s) s,
//#include "error.def"
#undef portal_error
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (portal_node,static) = {
	.function = portal_node_fn,//portal_node_fn ip6_export_node_fn
	.name = "portal",
	.vector_size = sizeof (u32),
	.format_trace = format_portal_trace,
	.type = VLIB_NODE_TYPE_INTERNAL,
	.n_errors = ARRAY_LEN(portal_error_strings),
	.error_strings = portal_error_strings,
	.n_next_nodes = PORTAL_N_NEXT,
	.next_nodes = {
	[PORTAL_NEXT_IP4_LOOKUP] = "ip4-lookup",
	[PORTAL_NEXT_ERROR_DROP] = "error-drop",
	},
};


/* *INDENT-ON* */

clib_error_t *
l7portal_init (vlib_main_t * vm)
{
  l7portal_main_t *l7pm = &l7portal_main;
  l7pm->vlib_main = vm;
  l7pm->vnet_main = vnet_get_main ();
  rte_spinlock_init(&radius_timer_lock);
 // rte_spinlock_init(&portal_lock);
  
  portal_init_hash();
  portal_alloc_init_free_user_list();
  qos_link_head_init();
  udp_register_dst_port (vm, 2000, portal_node.index, 1);
  radius_free_packet_session_init();
  radius_packet_session_hash_init();
  dhcp_init_hash();
  return 0;
}

VLIB_INIT_FUNCTION (l7portal_init);

