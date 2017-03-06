#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/ip/udp.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/portal/qos_hash.h>

/*******************************************************************************
 函数名称  : link_head_init
 功能描述  : 初始化链表头
 输入参数  : 无
 输出参数  : 无
 返 回 值  : 无
*******************************************************************************/
void qos_link_head_init(void)
{
	int i = 0;
    //初始化qos用户信息空闲链表头
    dl_list_init(&qos_idle_list_head[LIST_TYPE_USER_INFO]);
    //初始化qos用户信息在线链表头
    for(i=0; i<QOS_HASH_TABLE_SIZE; i++)
    {
        dl_list_init(&qos_user_info_hash[i]);
        rte_spinlock_init(&(qos_user_info_hash_lock[i]));
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
static void allocate_memory(int type, int size)
{
    int i = 0;
    char *idle_add;

    //分配4k空间
    idle_add = malloc(QOS_MALLOC_SIZE);
    memset(idle_add, 0, QOS_MALLOC_SIZE);

    //初始化空闲链表
    for(i = 0; i < (QOS_MALLOC_SIZE/size); i++)
    {
        //初始化要添加的idle_add
        dl_list_init( (struct dl_list *)idle_add );

        //把idle_add加入到空闲链表中
        dl_list_add(&(qos_idle_list_head[type]), (struct dl_list *)idle_add); //头插
        //跳到下一个要添加idle_add的位置
        idle_add += size;
    }
    return ;
}

/*******************************************************************************
 函数名称  : get_hash_key
 功能描述  : 获得hash表的key值
 输入参数  : type 0为qos用户信息
             hash_key   哈希值得输入 ip
 输出参数  : 无
 返 回 值  : hash表的key值
              -1 type 错误

*******************************************************************************/
static int get_hash_key(int type, void *hash_key)
{
    if(LIST_TYPE_USER_INFO == type)
    {
        u32 ip = *(u32 *)hash_key;

        return ip & QOS_HASH_TABLE_SIZE;
    }
    return -1;
}

/*******************************************************************************
 函数名称  : get_point
 功能描述  : 获得空闲链表中的一个节点
 输入参数  : type  0为qos用户信息
              size  链表的结构体的大小
 输出参数  : 无
 返 回 值  : 成功返回空闲链表的地址
              失败返回NULL
*******************************************************************************/
static void *get_point(int type, int size)
{
    struct dl_list *point;
    while(1)
    {
        //判断空闲链表是否为空，如果不为空取出到在线链表
        if(qos_idle_list_head[type].next != &(qos_idle_list_head[type]))
        {
            point = qos_idle_list_head[type].next;	//取出节点
            dl_list_del(point);	// 从空闲链表删除

            break;
        }
        //如果为空分配4k空间
        else
        {
            allocate_memory(type,size);
        }
    }
    //根据point找到PORTAL_USER_INFO
    if( LIST_TYPE_USER_INFO == type )
    {
        return dl_list_entry(point, Qos_user_info, list);
    }
    else
    {
        return NULL;
    }
}

/*******************************************************************************
 函数名称  : get_portal_user_by_ip
 功能描述  : 根据ip查找到指定portal user
 输入参数  : ip  要查找的ip
 输出参数  : 无
 返 回 值  : 查找到的用户
*******************************************************************************/
Qos_user_info *get_qos_user_by_ip(u32 *ip)
{
 	 struct dl_list *p_hash;
	 Qos_user_info *user_info = NULL;
	 int key = 0;
	 //获取hash值
	 key = get_hash_key(LIST_TYPE_USER_INFO, ip);

	 rte_spinlock_lock(&(qos_user_info_hash_lock[key]));
	 //在线链表头赋给p_hash，用于查找
	 p_hash = qos_user_info_hash[key].next;

	 //判断链表是否查找完
	 while( p_hash != &(qos_user_info_hash[key]))
	 {
		 //根据p_buf找到ap
		 user_info = dl_list_entry(p_hash, Qos_user_info, list);

		 //找到之后跳出循环
		 if( *ip == user_info->user_ip )
		 {
			 break;
		 }
		 else
		 {
			 p_hash = p_hash->next;
			 //用于判断是否找到
			 user_info = NULL;
			 continue;
		 }
	 }
	 rte_spinlock_unlock(&(qos_user_info_hash_lock[key]));
    return user_info;
}

/*******************************************************************************
 函数名称  : add_portal_user_to_online
 功能描述  : 添加user到在线链表
 输入参数  : portal_old 前面保存的portal的内容，要拷贝到返回值的portal中去
 输出参数  : 无
 返 回 值  : 新添加的portal user
--------------------------------------------------------------------------------
 最近一次修改记录 :
 修改作者  :
 修改目的  :
 修改日期  :
*******************************************************************************/
Qos_user_info *add_qos_user(u32 ip, u32 sw_if_index, portal_qos_car *car)
{
    Qos_user_info *result;
    u32 key;

	//如果ap_online_hash中没有这个sn，在空闲链表中获取一个空ap
    result = get_point(LIST_TYPE_USER_INFO, sizeof(Qos_user_info));
    if( result != NULL )
    {
		/*
	        //如果大于最大可添加的user数退出
	        if(gs_portal_user_no > PORTAL_MAX_USER)
	        {
	            Portal_DEBUG("link user too much\n");
	            return NULL;
	        }
		*/
        key = get_hash_key(LIST_TYPE_USER_INFO, &ip);

        memset(result, 0, sizeof(Qos_user_info));

		/* set up result */
		  result->user_ip = ip;
		  result->car = car;
		  result->sw_if_index = sw_if_index;
		  result->avail_token = result->car->cbs;
		  result->last_adjust_time = 0;
		  rte_spinlock_init(&(result->lock));
          
        //初始化链表头
        dl_list_init( &(result->list) );

        //把当前ap添加到ap_online_hash中
        rte_spinlock_lock(&(qos_user_info_hash_lock[key]));
        dl_list_add(qos_user_info_hash+key, &(result->list));
        rte_spinlock_unlock(&(qos_user_info_hash_lock[key]));
        //当前在线ap数++
        //gs_portal_user_no++;

    }
    else
    {
        return NULL;
    }

    return result;
}



/*******************************************************************************
 函数名称  : free_portal_user_point
 功能描述  : 从portal_user链表中释放放到空闲链表
 输入参数  : portal  要删除的节点
 输出参数  : 无
 返 回 值  : 无

*******************************************************************************/
void free_qos_user_point(Qos_user_info *qos_user)
{
    u32 key;
    if(NULL == qos_user)
        return ;

	key = get_hash_key(LIST_TYPE_USER_INFO, &(qos_user->user_ip));

	rte_spinlock_lock(&(qos_user_info_hash_lock[key]));
    //从在线链表中删除point
    dl_list_del(&(qos_user->list));
    rte_spinlock_unlock(&(qos_user_info_hash_lock[key]));

    //添加point到空闲链表的尾部
    dl_list_add_tail(&(qos_idle_list_head[LIST_TYPE_USER_INFO]), &(qos_user->list));
    //gs_portal_user_no--;

    return ;
}


/*******************************************************************************
 函数名称  : portal_show_user_info
 功能描述  : 根据ip查找到指定portal user
 输入参数  : ip  要查找的ip
 输出参数  : 无
 返 回 值  : 查找到的用户
*******************************************************************************/
int qos_show_user_info(void)
{
    struct dl_list *p_hash;
    Qos_user_info *user_info = NULL;
    int key = 0;

	for(key = 0; key < QOS_HASH_TABLE_SIZE; key++)
	{
		p_hash = qos_user_info_hash[key].next;
		//判断链表是否查找完
	    while( p_hash != &(qos_user_info_hash[key]))
	    {
	        //根据p_buf找到ap
	        user_info = dl_list_entry(p_hash, Qos_user_info, list);
	        if(user_info)
	        {
	        	printf("ip %08x \n", user_info->user_ip);
	        }
	        p_hash = p_hash->next;
	    }
	}

    return 0;
}

/*******************************************************************************
函数名称  : free_all_portal_user_online
功能描述  : 删除所有在线用户
输入参数  :
输出参数  : 无 返 回 值
*******************************************************************************/
void free_all_qos_user(void)
{
	struct dl_list *p_hash;
	Qos_user_info *user_info = NULL;
	int i;
	for(i = 0; i < QOS_HASH_TABLE_SIZE; i++)
	{
		//在线链表头赋给p_hash，用于查找
		p_hash = qos_user_info_hash[i].next;
		//判断链表是否查找完
		dl_list_for_each(user_info, p_hash, Qos_user_info, list)
		{
			free_qos_user_point(user_info);
			//portal_user_online_num --;
		}

	}
	return ;
}

/*******************************************************************************
函数名称  : free_portal_user_by_ip
功能描述  : 通过ip删除在线用户
输入参数  :
输出参数  : 无 返 回 值
*******************************************************************************/
void free_qos_user_by_ip(u32 *ip)
{
	Qos_user_info *user_info = get_qos_user_by_ip(ip);
	if(NULL == user_info)
		return;
	free_qos_user_point(user_info);
	return;
}


