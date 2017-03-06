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
 * interface_portal.h: VNET interfaces/sub-interfaces exported functions
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
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef SERVER_COMMANDS_H
#define SERVER_COMMANDS_H
#include <vnet/radius/list.h>


#define NAME_LEN 35
#define LIST_LEN 8
#define BUFF_SIZE 512

#define DHCP_DEFAULT_TIME 2400
#define DHCP_YEAR_TIME (365 * 24 * 3600)

typedef uint8_t u8;
typedef uint32_t u32;

typedef struct{
  char pool_name[NAME_LEN];  /* 地址池名称,1~35个字符 */
  u32 start_ip;         /* 地址池起始地址 */
  u32 end_ip;           /* 地址池结束地址 */
  u32 net_mask;         /*  子网掩码 */
  u32 dns_list[LIST_LEN];      /* DNS服务器地址,最多可输8个 */
  u32 gateway_list[LIST_LEN];  /* 网关地址，最多可输8个 */

  u32 if_subnet;     /* 接口网络地址 */
  u32 if_mask;       /* 接口子网掩码 */
  u32 default_time;  /* 默认租约时间 */
  u32 max_time;       /* 最大租约时间 */

  struct dl_list list;
}dhcp_server_pool;

extern dhcp_server_pool chain_head;

int write_dhcp_config_file(void);
int write_dhcp_rdconfig_file(void);
int dhcp_restore_conf(void);

int dhcp_check_pool_name (char * name);
dhcp_server_pool * create_dhcp_pool_chain (char * name);
dhcp_server_pool * search_name_node(char *name);
void del_dhcp_pool_chain(char * name);
dhcp_server_pool* check_ip_pool(char * pool_name, u32 start_ip, u32 end_ip);

u32 netmask_len2str(u32 mask_len);



#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

