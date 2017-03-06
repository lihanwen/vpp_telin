#ifndef __TOKEN_BUCKET_H__
#define __TOKEN_BUCKET_H__
#include <vnet/portal/portal.h>
#include <vnet/portal/interface_portal.h>
#include <vnet/portal/qos_hash.h>

#define BIT_TO_BYTE 8
#define KB_TO_BYTE 1024
#define SECOND_TO_MS 1000
#define MAX_NET_MASK_LEN 32


typedef struct token_bucket {
	//u32 sw_if_index;
	u32 avail_token;		// 桶的当前容量
	u64 last_adjust_time;	//上次添加令牌时间
	portal_qos_car *car;
}token_bucket;  

typedef struct interface_token_bucket{
	token_bucket *inbound_token_bucket;
	token_bucket *outbound_token_bucket;

}interface_token_bucket;

extern interface_token_bucket if_any_token_bucket[QOS_INTERFACE_MAX];

u32 take_token(Qos_user_info *qos_user, u32 count);
void adjust_token_bucket(Qos_user_info *qos_user);
u32 if_bound_take_token(token_bucket *tb, u32 count);
void if_bound_adjust_token_bucket(token_bucket *tb);
void if_bound_any_token_bucket_init(token_bucket **tb, portal_qos_car *car);


#endif
