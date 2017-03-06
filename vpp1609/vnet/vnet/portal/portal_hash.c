#include "portal_hash.h"
#include <vnet/radius/list.h>

 portal_user_hash_head_t idle_list_head[LIST_TYPE_END];//0Ϊportal user��hashͷ

 portal_user_hash_head_t porta_user_online_hash[PORTAL_USER_ONLINE_HASH_SIZE];

/*******************************************************************************
 ��������  : portal_init_hash
 ��������  : ��ʼ������ͷ
 �������  : ��
 �������  : ��
 �� �� ֵ  : ��
*******************************************************************************/
void portal_init_hash(void)
{
	int i = 0;
    //��ʼ��portal�û���Ϣ��������ͷ
    dl_list_init(&idle_list_head[LIST_TYPE_USER_INFO].userlist);
	rte_spinlock_init (&idle_list_head[LIST_TYPE_USER_INFO].userlock);
    //��ʼ��portal�û���Ϣ��������ͷ
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
 ��������  : allocate_memory
 ��������  : �������������4K�ռ�
 �������  : type  0Ϊportal�û���Ϣ
              size  ����Ľṹ��Ĵ�С
 �������  : ��
 �� �� ֵ  : ��

*******************************************************************************/
void portal_alloc_init_free_user_list(void)
{
    int i = 0;
    l7portal_user_info *usermem;

    //����4k�ռ�
    usermem = clib_mem_alloc(PORTAL_MAX_ONLINE_USER_NUM * sizeof(l7portal_user_info));
    if(!usermem)
    {
    	return;
    }
    memset(usermem, 0, PORTAL_MAX_ONLINE_USER_NUM * sizeof(l7portal_user_info));

    //��ʼ����������
    rte_spinlock_lock(&idle_list_head[LIST_TYPE_USER_INFO].userlock);
    for(i = 0; i < (PORTAL_MAX_ONLINE_USER_NUM); i++)
    {
        //��ʼ��Ҫ��ӵ�idle_add
        dl_list_init( &usermem[i].list);
        //��idle_add���뵽����������
        dl_list_add(&(idle_list_head[LIST_TYPE_USER_INFO].userlist), &usermem[i].list);
        //������һ��Ҫ���idle_add��λ��
    }
    rte_spinlock_unlock(&idle_list_head[LIST_TYPE_USER_INFO].userlock);
    return ;
}

/*******************************************************************************
 ��������  : get_portal_hash_key
 ��������  : ���hash���keyֵ
 �������  : type 0Ϊportal�û���Ϣ
             hash_key   ��ϣֵ������ ip
 �������  : ��
 �� �� ֵ  : hash���keyֵ
              -1 type ����

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
 ��������  : portal_alloc_free_user_entry
 ��������  : ��ÿ��������е�һ���ڵ�
 �������  : type  0Ϊportal�û���Ϣ
              size  ����Ľṹ��Ĵ�С
 �������  : ��
 �� �� ֵ  : �ɹ����ؿ�������ĵ�ַ
              ʧ�ܷ���NULL
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
 ��������  : get_portal_user_by_ip
 ��������  : ����ip���ҵ�ָ��portal user
 �������  : ip  Ҫ���ҵ�ip
 �������  : ��
 �� �� ֵ  : ���ҵ����û�
*******************************************************************************/
l7portal_user_info *get_portal_user_by_ip(u32 *ip)
{
	 l7portal_user_info *user_info = NULL;
	 int key = 0;
	 //��ȡhashֵ
	 key = get_portal_hash_key(LIST_TYPE_USER_INFO, ip);
	 rte_spinlock_lock(&porta_user_online_hash[key].userlock);
	 dl_list_for_each(user_info, &(porta_user_online_hash[key].userlist),l7portal_user_info, list)
	 {
		 //�ҵ�֮������ѭ��
		 if( *ip == user_info->ip )
			 break;
	 }
	 rte_spinlock_unlock(&porta_user_online_hash[key].userlock);
    return user_info;
}
#if 0
/*******************************************************************************
 ��������  : red_add_portal_user_to_online
 ��������  : �ض���ʱ���user����������
 �������  : Դip
 �������  : ��
 �� �� ֵ  : ����ӵ�portal user
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����  :
 �޸�Ŀ��  :
 �޸�����  :
*******************************************************************************/

l7portal_user_info *red_add_portal_user_to_online(u32 *user_ip,u32 sw_if_index)
{
    l7portal_user_info *result;
	result = get_portal_point(LIST_TYPE_USER_INFO, sizeof(l7portal_user_info));
	if( result == NULL )
		return NULL;
	memset(result, 0, sizeof(l7portal_user_info));

 	//�������������ӵ�user���˳�
	if(gs_portal_user_num > PORTAL_MAX_USER)
	{
		Portal_DEBUG("link user too much\n");
		return NULL;
	}
	//��ȡsn��keyֵ
	int key = get_portal_hash_key(LIST_TYPE_USER_INFO,user_ip);

	/* set up result */

	result->sw_if_index = sw_if_index;
    result->ip = *user_ip;
	result->auth_state = 0;
//	result->red_dst_ip = *user_ip;
	//��ʼ������ͷ
	dl_list_init( &(result->list) );
	rte_spinlock_init (&(result->lock));
	//�ѵ�ǰap��ӵ�ap_online_hash��
	dl_list_add(porta_user_online_hash+key, &(result->list));
	//��ǰ����ap��++
	s_portal_user_num++;
	return result;

}

#endif


/*******************************************************************************
 ��������  : add_or_change_portal_user_on_hash
 ��������  : ������յ�PKT_REQ_CHALLENGE����ʱ���user�����������ı�ԭ��user��һЩ״̬
 �������  : 
 �������  : ��
 �� �� ֵ  : ����ӵĻ��Ѿ����ı��portal user
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����  :
 �޸�Ŀ��  :
 �޸�����  :
*******************************************************************************/
l7portal_user_info *add_or_change_portal_user_on_hash(l7portal_user_info *result,portal_header_t *portal_head, u32 sw_if_index)
{
   
    static u16 req_id = 0;

	//���ap_online_hash��û�����sn���ڿ��������л�ȡһ����ap
	if(NULL == result)
	{
		result = portal_alloc_free_user_entry(LIST_TYPE_USER_INFO, sizeof(l7portal_user_info));
		if(NULL != result)
		{
			memset(result, 0, sizeof(l7portal_user_info));
		}			  
	}  
	
    //�������������ӵ�user���˳�
    if(gs_portal_user_num > PORTAL_MAX_USER)
    {
        Portal_DEBUG("link user too much\n");
        return NULL;
    }
	 memset(result->challenge,0,MD5_DATA_LEN);
 	 memset(&(result->req_auth_msg),0,sizeof(result->req_auth_msg));
    //��ȡsn��keyֵ
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



    //��ʼ��jiedian
    dl_list_init( &(result->list) );
    //�ѵ�ǰap��ӵ�ap_online_hash��
    dl_list_add(&(porta_user_online_hash[key].userlist), &(result->list));
    //��ǰportal��++
    gs_portal_user_num++;
    return result;
}


/*******************************************************************************
 ��������  : add_white_rule_user_by_ip
 ��������  : ��Ӱ�������Ա(�Ѿ����ڿ���������������������Ӹð�����)
 �������  : 
 �������  : ��
 �� �� ֵ  : ����ӵĻ��Ѿ����ı�İ�����
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����  :
 �޸�Ŀ��  :
 �޸�����  :
*******************************************************************************/

l7portal_user_info *add_white_rule_user_by_ip(u32 *ip_addr)
{
	l7portal_user_info *user_info = NULL;
	 int key = 0;
	 u8 has_same_ip = 0;
	 //��ȡhashֵ
	 key = get_portal_hash_key(LIST_TYPE_USER_INFO, ip_addr);
	 rte_spinlock_lock(&porta_user_online_hash[key].userlock);
	 dl_list_for_each(user_info, &(porta_user_online_hash[key].userlist),l7portal_user_info, list)
	 {
		 //�ҵ�֮������ѭ��
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
 ��������  : del_white_rule_user
 ��������  : ��Ӱ�������Ա(�Ѿ����ڿ���������������������Ӹð�����)
 �������  : 
 �������  : ��
 �� �� ֵ  : ����ӵĻ��Ѿ����ı�İ�����
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����  :
 �޸�Ŀ��  :
 �޸�����  :
*******************************************************************************/

l7portal_user_info *del_white_rule_user_by_ip(u32 *ip)
{
	
	l7portal_user_info *user_info= NULL;
	 l7portal_user_info *user_info_prev = NULL;
	  int key = 0;
	  //��ȡhashֵ
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
		  //���point�����������β��
		 dl_list_add_tail(&(idle_list_head[LIST_TYPE_USER_INFO].userlist), &(user_info->list));
		 rte_spinlock_unlock(&idle_list_head[LIST_TYPE_USER_INFO].userlock);
		 gs_portal_user_num--;
		 gs_portal_user_online_num--;
		 
	}	
	 return user_info;
	
}

/*******************************************************************************
 ��������  : free_portal_user_point
 ��������  : ��portal_user�������ͷŷŵ���������
 �������  : portal  Ҫɾ���Ľڵ�
 �������  : ��
 �� �� ֵ  : ��
 ����������: �ӹ�ϣ�����	
			 ѭ������һ�� ���ڵ�����
			 ɾ���ڵ�
			 �⿪�ڵ����
			 �⿪��ϣ��
			 ��free�������
			 ����û����
			 �⿪free�������	
*******************************************************************************/
void free_portal_user_point(l7portal_user_info *user_info)/////////////////////////////////////////
{	
	
	if(NULL != user_info)
 	{	
 		
	    //������������ɾ��point
	    dl_list_del(&(user_info->list));
		
		rte_spinlock_lock(&idle_list_head[LIST_TYPE_USER_INFO].userlock);
		  //���point�����������β��
		dl_list_add_tail(&(idle_list_head[LIST_TYPE_USER_INFO].userlist), &(user_info->list));
		rte_spinlock_unlock(&idle_list_head[LIST_TYPE_USER_INFO].userlock);
		 gs_portal_user_num--;
		 gs_portal_user_online_num--;
		 return;
	}	
    return ;
}


/*******************************************************************************
��������  : free_all_portal_user_online
��������  : ɾ�����������û�
�������  :
�������  : �� �� �� ֵ
*******************************************************************************/
void free_all_portal_user_online()
{
	l7portal_user_info *user_info = NULL;
	l7portal_user_info *user_info_prev = NULL;
	int i;
	for(i = 0; i < PORTAL_USER_ONLINE_HASH_SIZE; i++)
	{
		rte_spinlock_lock(&porta_user_online_hash[i].userlock);
		//�ж������Ƿ������
		 dl_list_for_each_safe(user_info,user_info_prev, &(porta_user_online_hash[i].userlist),l7portal_user_info, list)
	 	{	
	 		/*����û���������״̬ ������һ��ѭ��*/
			if(PORTAL_STATE_Run != user_info->state )
				  continue;
			else
			{
			
			    //������������ɾ��point
			    dl_list_del(&(user_info->list));
		
				rte_spinlock_lock(&idle_list_head[LIST_TYPE_USER_INFO].userlock);
				//���point�����������β��
				dl_list_add_tail(&(idle_list_head[LIST_TYPE_USER_INFO].userlist), &(user_info->list));
				rte_spinlock_unlock(&idle_list_head[LIST_TYPE_USER_INFO].userlock);
	
			}	
	 	}
		rte_spinlock_unlock(&porta_user_online_hash[i].userlock);
		
	}
	return ;
}

/*******************************************************************************
��������  : free_portal_user_by_ip
��������  : ͨ��ipɾ�������û�
�������  :
�������  : �� �� �� ֵ
*******************************************************************************/
void free_portal_online_user_by_ip(u32 *ip)
{	
	 
	 l7portal_user_info *user_info= NULL;
	 l7portal_user_info *user_info_prev = NULL;
	  int key = 0;
	  //��ȡhashֵ
	  key = get_portal_hash_key(LIST_TYPE_USER_INFO, ip);
	  rte_spinlock_lock(&porta_user_online_hash[key].userlock);
	  dl_list_for_each_safe(user_info,user_info_prev, &(porta_user_online_hash[key].userlist),l7portal_user_info, list)
	  {
		  if( *ip == user_info->ip && PORTAL_STATE_Run == user_info->state)
		  {
				
				 //������������ɾ��point
				 dl_list_del(&(user_info->list));
				

				 rte_spinlock_lock(&idle_list_head[LIST_TYPE_USER_INFO].userlock);
				  //���point�����������β��
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



