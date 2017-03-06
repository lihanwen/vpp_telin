#include <vnet/portal/token_bucket.h>
#include <vnet/portal/portal.h>
#include <stdlib.h>

interface_token_bucket if_any_token_bucket[QOS_INTERFACE_MAX] = {0};

i32 get_interval_time(u64 last_adjust_time, u64 now_t)
{
	vlib_main_t * vm = vlib_get_main();
	f64 interval_time = (((i64)now_t - (i64) last_adjust_time)
	   * vm->clib_time.seconds_per_clock)
	  /* subtract off some slop time */  - 50e-6;
	return interval_time * 1e3;
}

u32 take_token(Qos_user_info *qos_user, u32 count)
{
	 if(qos_user->avail_token >= count){
        qos_user->avail_token -= count;
        return 1;
    }
    return 0;
}

void adjust_token_bucket(Qos_user_info *qos_user)
{
	u64 now_t = clib_cpu_time_now ();

	i32 interval_time;

	if(qos_user->last_adjust_time)
	{
		interval_time = get_interval_time(qos_user->last_adjust_time, now_t);
		//printf("qos interval_time %d\n",interval_time);
		if(qos_user->avail_token < qos_user->car->cbs) {
				qos_user->avail_token += (qos_user->car->cir * KB_TO_BYTE / BIT_TO_BYTE / SECOND_TO_MS) * interval_time;
				qos_user->avail_token = qos_user->avail_token > qos_user->car->cbs ? 
					qos_user->car->cbs : qos_user->avail_token;
			}
	}
	qos_user->last_adjust_time = now_t;

}

u32 if_bound_take_token(token_bucket *tb, u32 count)
{
	 if(tb->avail_token >= count){
        tb->avail_token -= count;
        return 1;
    }
    return 0;
}

void if_bound_adjust_token_bucket(token_bucket *tb)
{
	u64 now_t = clib_cpu_time_now ();

	i32 interval_time;

	if(tb->last_adjust_time)
	{
		interval_time = get_interval_time(tb->last_adjust_time, now_t);
		if(tb->avail_token < tb->car->cbs) {
			tb->avail_token += (tb->car->cir * KB_TO_BYTE / BIT_TO_BYTE / SECOND_TO_MS) * interval_time;
			tb->avail_token = tb->avail_token > tb->car->cbs ? 
				tb->car->cbs : tb->avail_token;		
		}
	}
	tb->last_adjust_time = now_t;

}

void if_bound_any_token_bucket_init(token_bucket **tb, portal_qos_car *car)
{
	*tb = (token_bucket *)malloc(sizeof(token_bucket));
	if(*tb)
	{
		(*tb)->car = car;
		(*tb)->avail_token = (*tb)->car->cbs;
		(*tb)->last_adjust_time = 0;
	}
}


