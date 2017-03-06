#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/ip/udp.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/portal/qos_hash.h>

/*******************************************************************************
 ��������  : link_head_init
 ��������  : ��ʼ������ͷ
 �������  : ��
 �������  : ��
 �� �� ֵ  : ��
*******************************************************************************/
void qos_link_head_init(void)
{
	int i = 0;
    //��ʼ��qos�û���Ϣ��������ͷ
    dl_list_init(&qos_idle_list_head[LIST_TYPE_USER_INFO]);
    //��ʼ��qos�û���Ϣ��������ͷ
    for(i=0; i<QOS_HASH_TABLE_SIZE; i++)
    {
        dl_list_init(&qos_user_info_hash[i]);
        rte_spinlock_init(&(qos_user_info_hash_lock[i]));
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
static void allocate_memory(int type, int size)
{
    int i = 0;
    char *idle_add;

    //����4k�ռ�
    idle_add = malloc(QOS_MALLOC_SIZE);
    memset(idle_add, 0, QOS_MALLOC_SIZE);

    //��ʼ����������
    for(i = 0; i < (QOS_MALLOC_SIZE/size); i++)
    {
        //��ʼ��Ҫ��ӵ�idle_add
        dl_list_init( (struct dl_list *)idle_add );

        //��idle_add���뵽����������
        dl_list_add(&(qos_idle_list_head[type]), (struct dl_list *)idle_add); //ͷ��
        //������һ��Ҫ���idle_add��λ��
        idle_add += size;
    }
    return ;
}

/*******************************************************************************
 ��������  : get_hash_key
 ��������  : ���hash���keyֵ
 �������  : type 0Ϊqos�û���Ϣ
             hash_key   ��ϣֵ������ ip
 �������  : ��
 �� �� ֵ  : hash���keyֵ
              -1 type ����

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
 ��������  : get_point
 ��������  : ��ÿ��������е�һ���ڵ�
 �������  : type  0Ϊqos�û���Ϣ
              size  ����Ľṹ��Ĵ�С
 �������  : ��
 �� �� ֵ  : �ɹ����ؿ�������ĵ�ַ
              ʧ�ܷ���NULL
*******************************************************************************/
static void *get_point(int type, int size)
{
    struct dl_list *point;
    while(1)
    {
        //�жϿ��������Ƿ�Ϊ�գ������Ϊ��ȡ������������
        if(qos_idle_list_head[type].next != &(qos_idle_list_head[type]))
        {
            point = qos_idle_list_head[type].next;	//ȡ���ڵ�
            dl_list_del(point);	// �ӿ�������ɾ��

            break;
        }
        //���Ϊ�շ���4k�ռ�
        else
        {
            allocate_memory(type,size);
        }
    }
    //����point�ҵ�PORTAL_USER_INFO
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
 ��������  : get_portal_user_by_ip
 ��������  : ����ip���ҵ�ָ��portal user
 �������  : ip  Ҫ���ҵ�ip
 �������  : ��
 �� �� ֵ  : ���ҵ����û�
*******************************************************************************/
Qos_user_info *get_qos_user_by_ip(u32 *ip)
{
 	 struct dl_list *p_hash;
	 Qos_user_info *user_info = NULL;
	 int key = 0;
	 //��ȡhashֵ
	 key = get_hash_key(LIST_TYPE_USER_INFO, ip);

	 rte_spinlock_lock(&(qos_user_info_hash_lock[key]));
	 //��������ͷ����p_hash�����ڲ���
	 p_hash = qos_user_info_hash[key].next;

	 //�ж������Ƿ������
	 while( p_hash != &(qos_user_info_hash[key]))
	 {
		 //����p_buf�ҵ�ap
		 user_info = dl_list_entry(p_hash, Qos_user_info, list);

		 //�ҵ�֮������ѭ��
		 if( *ip == user_info->user_ip )
		 {
			 break;
		 }
		 else
		 {
			 p_hash = p_hash->next;
			 //�����ж��Ƿ��ҵ�
			 user_info = NULL;
			 continue;
		 }
	 }
	 rte_spinlock_unlock(&(qos_user_info_hash_lock[key]));
    return user_info;
}

/*******************************************************************************
 ��������  : add_portal_user_to_online
 ��������  : ���user����������
 �������  : portal_old ǰ�汣���portal�����ݣ�Ҫ����������ֵ��portal��ȥ
 �������  : ��
 �� �� ֵ  : ����ӵ�portal user
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ :
 �޸�����  :
 �޸�Ŀ��  :
 �޸�����  :
*******************************************************************************/
Qos_user_info *add_qos_user(u32 ip, u32 sw_if_index, portal_qos_car *car)
{
    Qos_user_info *result;
    u32 key;

	//���ap_online_hash��û�����sn���ڿ��������л�ȡһ����ap
    result = get_point(LIST_TYPE_USER_INFO, sizeof(Qos_user_info));
    if( result != NULL )
    {
		/*
	        //�������������ӵ�user���˳�
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
          
        //��ʼ������ͷ
        dl_list_init( &(result->list) );

        //�ѵ�ǰap��ӵ�ap_online_hash��
        rte_spinlock_lock(&(qos_user_info_hash_lock[key]));
        dl_list_add(qos_user_info_hash+key, &(result->list));
        rte_spinlock_unlock(&(qos_user_info_hash_lock[key]));
        //��ǰ����ap��++
        //gs_portal_user_no++;

    }
    else
    {
        return NULL;
    }

    return result;
}



/*******************************************************************************
 ��������  : free_portal_user_point
 ��������  : ��portal_user�������ͷŷŵ���������
 �������  : portal  Ҫɾ���Ľڵ�
 �������  : ��
 �� �� ֵ  : ��

*******************************************************************************/
void free_qos_user_point(Qos_user_info *qos_user)
{
    u32 key;
    if(NULL == qos_user)
        return ;

	key = get_hash_key(LIST_TYPE_USER_INFO, &(qos_user->user_ip));

	rte_spinlock_lock(&(qos_user_info_hash_lock[key]));
    //������������ɾ��point
    dl_list_del(&(qos_user->list));
    rte_spinlock_unlock(&(qos_user_info_hash_lock[key]));

    //���point�����������β��
    dl_list_add_tail(&(qos_idle_list_head[LIST_TYPE_USER_INFO]), &(qos_user->list));
    //gs_portal_user_no--;

    return ;
}


/*******************************************************************************
 ��������  : portal_show_user_info
 ��������  : ����ip���ҵ�ָ��portal user
 �������  : ip  Ҫ���ҵ�ip
 �������  : ��
 �� �� ֵ  : ���ҵ����û�
*******************************************************************************/
int qos_show_user_info(void)
{
    struct dl_list *p_hash;
    Qos_user_info *user_info = NULL;
    int key = 0;

	for(key = 0; key < QOS_HASH_TABLE_SIZE; key++)
	{
		p_hash = qos_user_info_hash[key].next;
		//�ж������Ƿ������
	    while( p_hash != &(qos_user_info_hash[key]))
	    {
	        //����p_buf�ҵ�ap
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
��������  : free_all_portal_user_online
��������  : ɾ�����������û�
�������  :
�������  : �� �� �� ֵ
*******************************************************************************/
void free_all_qos_user(void)
{
	struct dl_list *p_hash;
	Qos_user_info *user_info = NULL;
	int i;
	for(i = 0; i < QOS_HASH_TABLE_SIZE; i++)
	{
		//��������ͷ����p_hash�����ڲ���
		p_hash = qos_user_info_hash[i].next;
		//�ж������Ƿ������
		dl_list_for_each(user_info, p_hash, Qos_user_info, list)
		{
			free_qos_user_point(user_info);
			//portal_user_online_num --;
		}

	}
	return ;
}

/*******************************************************************************
��������  : free_portal_user_by_ip
��������  : ͨ��ipɾ�������û�
�������  :
�������  : �� �� �� ֵ
*******************************************************************************/
void free_qos_user_by_ip(u32 *ip)
{
	Qos_user_info *user_info = get_qos_user_by_ip(ip);
	if(NULL == user_info)
		return;
	free_qos_user_point(user_info);
	return;
}


