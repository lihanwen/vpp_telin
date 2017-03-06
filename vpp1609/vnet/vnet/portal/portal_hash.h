/*
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
 /*
 * portal_hash.h: types/functions for portal
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 */


#ifndef included_portal_hash_h
#define included_portal_hash_h
#include "portal.h"
#include <vnet/radius/list.h>

/* 当前portal user 数 */
extern u32 gs_portal_user_num ;
extern u32 gs_portal_user_online_num ;


//判断类型
enum LIST_TYPE_e
{
    LIST_TYPE_USER_INFO,
    LIST_TYPE_END
};

/* 支持的portal user数量 */
#define PORTAL_MAX_USER   1024*10

//portal user在线hash大小   最大user在线数除以10
#define PORTAL_USER_ONLINE_HASH_SIZE 128




//每次开辟空闲链表的大小
#define PORTAL_MAX_ONLINE_USER_NUM 10*1024

typedef struct{       
	rte_spinlock_t userlock;	
	struct dl_list userlist;
}portal_user_hash_head_t;

extern portal_user_hash_head_t idle_list_head[LIST_TYPE_END];//0为portal user的hash头

extern portal_user_hash_head_t porta_user_online_hash[PORTAL_USER_ONLINE_HASH_SIZE];



u32  get_portal_hash_key(int type, void *hash_key);
void *portal_alloc_free_user_entry(int type, int size);
void portal_alloc_init_free_user_list(void);


void portal_init_hash(void);
void free_portal_user_point(l7portal_user_info *result);
l7portal_user_info *get_portal_user_by_ip(u32 *ip);
l7portal_user_info *add_or_change_portal_user_on_hash(l7portal_user_info *result,portal_header_t *portal_head,u32 sw_if_index);
l7portal_user_info *add_white_rule_user_by_ip(u32 *ip_addr);
l7portal_user_info *del_white_rule_user_by_ip(u32 *ip);


#endif

