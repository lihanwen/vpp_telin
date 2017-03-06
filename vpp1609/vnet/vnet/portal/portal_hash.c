#include "portal_hash.h"
#include <vnet/radius/list.h>

 portal_user_hash_head_t idle_list_head[LIST_TYPE_END];//0为portal user的hash头

 portal_user_hash_head_t porta_user_online_hash[PORTAL_USER_ONLINE_HASH_SIZE];

/*******************************************************************************
 函数名称  : portal_init_hash
 功能描述  : 初始化链表头
 输入参数  : 无
 输出参数  : 无
 返 回 值  : 无
*******************************************************************************/
void portal_init_hash(void)
{
	int i = 0;
    //初始化portal用户信息空闲链表头
    dl_list_init(&idle_list_head[LIST_TYPE_USER_INFO].userlist);
	rte_spinlock_init (&idle_list_head[LIST_TYPE_USER_INFO].userlock);
    //初始化portal用户信息在线链表头
    for(i=0; i<PORTAL_USER_ONLINE_HASH_SIZE; i++)
    {
        dl_list_init(&porta_user_online_hash[i].userlist);
		rte_spinlock_init (&porta_user_online_hash[i].userlock);
    }
	for(i = 0; i < 256; i++)
	{
		portal_free_rule[i] = 0;
	}
    return ;
}

/*******************************************************************************
 函数名称  : allocate_memory
 功能描述  : 给空闲链表分配4K空间
 输入参数  : type  0为portal用户信息
              size  链表的结构体的大小
 输出参数  : 无
 返 回 值  : 无

*******************************************************************************/
void portal_alloc_init_free_user_list(void)
{
    int i = 0;
    l7portal_user_info *usermem;

    //分配4k空间
    usermem = clib_mem_alloc(PORTAL_MAX_ONLINE_USER_NUM * sizeof(l7portal_user_info));
    if(!usermem)
    {
    	return;
    }
    memset(usermem, 0, PORTAL_MAX_ONLINE_USER_NUM * sizeof(l7portal_user_info));

    //初始化空闲链表
    rte_spinlock_lock(&idle_list_head[LIST_TYPE_USER_INFO].userlock);
    for(i = 0; i < (PORTAL_MAX_ONLINE_USER_NUM); i++)
    {
        //初始化要添加的idle_add
        dl_list_init( &usermem[i].list);
        //把idle_add加入到空闲链表中
        dl_list_add(&(idle_list_head[LIST_TYPE_USER_INFO].userlist), &usermem[i].list);
        //跳到下一个要添加idle_add的位置
    }
    rte_spinlock_unlock(&idle_list_head[LIST_TYPE_USER_INFO].userlock);
    return ;
}

/*******************************************************************************
 函数名称  : get_portal_hash_key
 功能描述  : 获得hash表的key值
 输入参数  : type 0为portal用户信息
             hash_key   哈希值得输入 ip
 输出参数  : 无
 返 回 值  : hash表的key值
              -1 type 错误

*******************************************************************************/
 u32  get_portal_hash_key(int type, void *hash_key)
{
    if( LIST_TYPE_USER_INFO == type)
    {
        u8 *ip = (u8 *)hash_key;

        return (ip[0] + ip[1] +ip[2] +ip[3]) % PORTAL_USER_ONLINE_HASH_SIZE;
    }
    return 0;
}

/*******************************************************************************
 函数名称  : portal_alloc_free_user_entry
 功能描述  : 获得空闲链表中的一个节点
 输入参数  : type  0为portal用户信息
              size  链表的结构体的大小
 输出参数  : 无
 返 回 值  : 成功返回空闲链表的地址
              失败返回NULL
*******************************************************************************/
 void *portal_alloc_free_user_entry(int type, int size)
{
	l7portal_user_info * one_user = NULL;
	l7portal_user_info * next_user = NULL;

	//one_user = malloc(sizeof(l7portal_user_info));
	//return one_user;
	
	rte_spinlock_lock(&idle_list_head[type].userlock);
	dl_list_for_each_safe(one_user,next_user,&idle_list_head[type].userlist,l7portal_user_info,list)
	{	
		dl_list_del(&one_user->list);
		break;
	}
	rte_spinlock_unlock(&idle_list_head[type].userlock);
	
	return one_user;
}

/*******************************************************************************
 函数名称  : get_portal_user_by_ip
 功能描述  : 根据ip查找到指定portal user
 输入参数  : ip  要查找的ip
 输出参数  : 无
 返 回 值  : 查找到的用户
*******************************************************************************/
l7portal_user_info *get_portal_user_by_ip(u32 *ip)
{
	 l7portal_user_info *user_info = NULL;
	 int key = 0;
	 //获取hash值
	 key = get_portal_hash_key(LIST_TYPE_USER_INFO, ip);
	 rte_spinlock_lock(&porta_user_online_hash[key].userlock);
	 dl_list_for_each(user_info, &(porta_user_online_hash[key].userlist),l7portal_user_info, list)
	 {
		 //找到之后跳出循环
		 if( *ip == user_info->ip )
			 break;
	 }
	 rte_spinlock_unlock(&porta_user_online_hash[key].userlock);
    return user_info;
}
#if 0
/*******************************************************************************
 函数名称  : red_add_portal_user_to_online
 功能描述  : 重定向时添加user到在线链表
 输入参数  : 源ip
 输出参数  : 无
 返 回 值  : 新添加的portal user
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者  :
 修改目的  :
 修改日期  :
*******************************************************************************/

l7portal_user_info *red_add_portal_user_to_online(u32 *user_ip,u32 sw_if_index)
{
    l7portal_user_info *result;
	result = get_portal_point(LIST_TYPE_USER_INFO, sizeof(l7portal_user_info));
	if( result == NULL )
		return NULL;
	memset(result, 0, sizeof(l7portal_user_info));

 	//如果大于最大可添加的user数退出
	if(gs_portal_user_num > PORTAL_MAX_USER)
	{
		Portal_DEBUG("link user too much\n");
		return NULL;
	}
	//获取sn的key值
	int key = get_portal_hash_key(LIST_TYPE_USER_INFO,user_ip);

	/* set up result */

	result->sw_if_index = sw_if_index;
    result->ip = *user_ip;
	result->auth_state = 0;
//	result->red_dst_ip = *user_ip;
	//初始化链表头
	dl_list_init( &(result->list) );
	rte_spinlock_init (&(result->lock));
	//把当前ap添加到ap_online_hash中
	dl_list_add(porta_user_online_hash+key, &(result->list));
	//当前在线ap数++
	s_portal_user_num++;
	return result;

}

#endif


/*******************************************************************************
 函数名称  : add_or_change_portal_user_on_hash
 功能描述  : 这个是收到PKT_REQ_CHALLENGE报文时添加user到在线链表或改变原来user的一些状态
 输入参数  : 
 输出参数  : 无
 返 回 值  : 新添加的或已经被改变的portal user
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者  :
 修改目的  :
 修改日期  :
*******************************************************************************/
l7portal_user_info *add_or_change_portal_user_on_hash(l7portal_user_info *result,portal_header_t *portal_head, u32 sw_if_index)
{
   
    static u16 req_id = 0;

	//如果ap_online_hash中没有这个sn，在空闲链表中获取一个空ap
	if(NULL == result)
	{
		result = portal_alloc_free_user_entry(LIST_TYPE_USER_INFO, sizeof(l7portal_user_info));
		if(NULL != result)
		{
			memset(result, 0, sizeof(l7portal_user_info));
		}			  
	}  
	
    //如果大于最大可添加的user数退出
    if(gs_portal_user_num > PORTAL_MAX_USER)
    {
        Portal_DEBUG("link user too much\n");
        return NULL;
    }
	 memset(result->challenge,0,MD5_DATA_LEN);
 	 memset(&(result->req_auth_msg),0,sizeof(result->req_auth_msg));
    //获取sn的key值
    int key = get_portal_hash_key(LIST_TYPE_USER_INFO, &(portal_head->user_ip));

	/* set up result */

	  result->sw_if_index = sw_if_index;
	  result->ip = portal_head->user_ip;
	  result->port = portal_head->user_port;
	  result->serial_no = portal_head->serial_no;
	  result->err_code = portal_head->err_code;
	  clib_memcpy(result->authenticator_MD5, portal_head->authenticator_MD5, MD5_DATA_LEN);
	  result->state = PORTAL_STATE_START;
	  result->auth_state = 0;
      req_id ++;
	  result->req_id = req_id;



    //初始化jiedian
    dl_list_init( &(result->list) );
    //把当前ap添加到ap_online_hash中
    dl_list_add(&(porta_user_online_hash[key].userlist), &(result->list));
    //当前portal数++
    gs_portal_user_num++;
    return result;
}


/*******************************************************************************
 函数名称  : add_white_rule_user_by_ip
 功能描述  : 添加白名单成员(已经存在开启白名单，不存在则添加该白名单)
 输入参数  : 
 输出参数  : 无
 返 回 值  : 新添加的或已经被改变的白名单
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者  :
 修改目的  :
 修改日期  :
*******************************************************************************/

l7portal_user_info *add_white_rule_user_by_ip(u32 *ip_addr)
{
	l7portal_user_info *user_info = NULL;
	 int key = 0;
	 u8 has_same_ip = 0;
	 //获取hash值
	 key = get_portal_hash_key(LIST_TYPE_USER_INFO, ip_addr);
	 rte_spinlock_lock(&porta_user_online_hash[key].userlock);
	 dl_list_for_each(user_info, &(porta_user_online_hash[key].userlist),l7portal_user_info, list)
	 {
		 //找到之后跳出循环
		 if( *ip_addr == user_info->ip )
		 {
		 	 user_info->free_node_yn = PORTOL_FREE_RULE_ON;	
		 	 has_same_ip = 1;
			 break;
		 }
	 }
	 
	if(has_same_ip == 0)
	{
		user_info = portal_alloc_free_user_entry(LIST_TYPE_USER_INFO, sizeof(l7portal_user_info));
		if(NULL == user_info)
		{
			return NULL;
		}
		memset(user_info, 0, sizeof(l7portal_user_info));
		dl_list_init(&user_info->list);
		user_info->ip = *ip_addr;
		user_info->free_node_yn = PORTOL_FREE_RULE_ON;	
		gs_portal_user_num++;
		gs_portal_user_online_num++;
		
		dl_list_add(&porta_user_online_hash[key].userlist, &user_info->list);
		
	}
	rte_spinlock_unlock(&porta_user_online_hash[key].userlock);
	return user_info;
}
/*******************************************************************************
 函数名称  : del_white_rule_user
 功能描述  : 添加白名单成员(已经存在开启白名单，不存在则添加该白名单)
 输入参数  : 
 输出参数  : 无
 返 回 值  : 新添加的或已经被改变的白名单
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者  :
 修改目的  :
 修改日期  :
*******************************************************************************/

l7portal_user_info *del_white_rule_user_by_ip(u32 *ip)
{
	
	l7portal_user_info *user_info= NULL;
	 l7portal_user_info *user_info_prev = NULL;
	  int key = 0;
	  //获取hash值
	  key = get_portal_hash_key(LIST_TYPE_USER_INFO, ip);
	  rte_spinlock_lock(&porta_user_online_hash[key].userlock);
	  dl_list_for_each_safe(user_info,user_info_prev, &(porta_user_online_hash[key].userlist),l7portal_user_info, list)
	  {
		  if( *ip == user_info->ip )
		  	 break;
	  }
	 if(NULL != user_info)
	 {
	 		 dl_list_del(&(user_info->list));
	 }
	 rte_spinlock_unlock(&porta_user_online_hash[key].userlock);
	 
 	if(NULL != user_info)
 	{	
 	
		rte_spinlock_lock(&idle_list_head[LIST_TYPE_USER_INFO].userlock);
		  //添加point到空闲链表的尾部
		 dl_list_add_tail(&(idle_list_head[LIST_TYPE_USER_INFO].userlist), &(user_info->list));
		 rte_spinlock_unlock(&idle_list_head[LIST_TYPE_USER_INFO].userlock);
		 gs_portal_user_num--;
		 gs_portal_user_online_num--;
		 
	}	
	 return user_info;
	
}

/*******************************************************************************
 函数名称  : free_portal_user_point
 功能描述  : 从portal_user链表中释放放到空闲链表
 输入参数  : portal  要删除的节点
 输出参数  : 无
 返 回 值  : 无
 关于自旋锁: 加哈希表的锁	
			 循环查找一遍 给节点上锁
			 删除节点
			 解开节点的锁
			 解开哈希锁
			 加free链表的锁
			 添加用户结点
			 解开free链表的锁	
*******************************************************************************/
void free_portal_user_point(l7portal_user_info *user_info)/////////////////////////////////////////
{	
	
	if(NULL != user_info)
 	{	
 		
	    //从在线链表中删除point
	    dl_list_del(&(user_info->list));
		
		rte_spinlock_lock(&idle_list_head[LIST_TYPE_USER_INFO].userlock);
		  //添加point到空闲链表的尾部
		dl_list_add_tail(&(idle_list_head[LIST_TYPE_USER_INFO].userlist), &(user_info->list));
		rte_spinlock_unlock(&idle_list_head[LIST_TYPE_USER_INFO].userlock);
		 gs_portal_user_num--;
		 gs_portal_user_online_num--;
		 return;
	}	
    return ;
}


/*******************************************************************************
函数名称  : free_all_portal_user_online
功能描述  : 删除所有在线用户
输入参数  :
输出参数  : 无 返 回 值
*******************************************************************************/
void free_all_portal_user_online()
{
	l7portal_user_info *user_info = NULL;
	l7portal_user_info *user_info_prev = NULL;
	int i;
	for(i = 0; i < PORTAL_USER_ONLINE_HASH_SIZE; i++)
	{
		rte_spinlock_lock(&porta_user_online_hash[i].userlock);
		//判断链表是否查找完
		 dl_list_for_each_safe(user_info,user_info_prev, &(porta_user_online_hash[i].userlist),l7portal_user_info, list)
	 	{	
	 		/*如果用户不是在线状态 进行下一次循环*/
			if(PORTAL_STATE_Run != user_info->state )
				  continue;
			else
			{
			
			    //从在线链表中删除point
			    dl_list_del(&(user_info->list));
		
				rte_spinlock_lock(&idle_list_head[LIST_TYPE_USER_INFO].userlock);
				//添加point到空闲链表的尾部
				dl_list_add_tail(&(idle_list_head[LIST_TYPE_USER_INFO].userlist), &(user_info->list));
				rte_spinlock_unlock(&idle_list_head[LIST_TYPE_USER_INFO].userlock);
	
			}	
	 	}
		rte_spinlock_unlock(&porta_user_online_hash[i].userlock);
		
	}
	return ;
}

/*******************************************************************************
函数名称  : free_portal_user_by_ip
功能描述  : 通过ip删除在线用户
输入参数  :
输出参数  : 无 返 回 值
*******************************************************************************/
void free_portal_online_user_by_ip(u32 *ip)
{	
	 
	 l7portal_user_info *user_info= NULL;
	 l7portal_user_info *user_info_prev = NULL;
	  int key = 0;
	  //获取hash值
	  key = get_portal_hash_key(LIST_TYPE_USER_INFO, ip);
	  rte_spinlock_lock(&porta_user_online_hash[key].userlock);
	  dl_list_for_each_safe(user_info,user_info_prev, &(porta_user_online_hash[key].userlist),l7portal_user_info, list)
	  {
		  if( *ip == user_info->ip && PORTAL_STATE_Run == user_info->state)
		  {
				
				 //从在线链表中删除point
				 dl_list_del(&(user_info->list));
				

				 rte_spinlock_lock(&idle_list_head[LIST_TYPE_USER_INFO].userlock);
				  //添加point到空闲链表的尾部
				 dl_list_add_tail(&(idle_list_head[LIST_TYPE_USER_INFO].userlist), &(user_info->list));
				 rte_spinlock_unlock(&idle_list_head[LIST_TYPE_USER_INFO].userlock);
				 gs_portal_user_num--;
				 gs_portal_user_online_num--;
				 break;
 
		  }
		 
	  }
	 rte_spinlock_unlock(&porta_user_online_hash[key].userlock);
	 return ;

}



