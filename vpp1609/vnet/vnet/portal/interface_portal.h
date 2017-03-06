
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


#ifndef INTERFACE_PORTAL_H_
#define INTERFACE_PORTAL_H_


#define PORTAL_SERVER_MAX 16
#define PORTAL_WEBS_MAX 16
#define BUFF_SIZE 512

#define ENABLE_PORTAL 1
#define DISABLE_PORTAL 0


#define AUTH_PORT 50100   /* default port portal authentication server */

#define QOS_INTERFACE_MAX 4096
#define QOS_CARL_MAX 200

typedef struct 
{

  u8 portal_server_name[32];  /* portal authentication server name */
  u32 portal_server_ip;       /* portal authentication server ip */
  u16 portal_server_port;     /* portal authentication server port*/
  u8 key_portal[64];           /* simple key */  
}portal_server_t;

extern portal_server_t  portal_server_msg[PORTAL_SERVER_MAX];


typedef struct 
{ 
  u32 carl_index;
  u8 ip_flag[40];
  u8 match_flag;
  u32 ip_address;     
  u32 mask_length;          
}portal_qos_carl;


extern portal_qos_carl qos_carl_msg[QOS_CARL_MAX];

typedef struct 
{ 
  u32 index;
  u8 any_flag;
  //portal_qos_carl qos_carl_msg[QOS_CARL_MAX];
  u32 carl_index;      
  u32 cir;
  u32 cbs;  
}portal_qos_car;

typedef struct 
{
 u32 outbound_index ;
 u32 inbound_index ;
 portal_qos_car* interface_car_inbound[QOS_CARL_MAX];
 portal_qos_car* interface_car_outbound[QOS_CARL_MAX];
}portal_qos_interface;



extern portal_qos_interface qos_interface[QOS_INTERFACE_MAX];



typedef struct 
{
  u8 portal_webs_name[32];    /* portal web server name */
  u8 webs_url[64];             /* Portal Web server url */
}portal_webs_t;
extern portal_webs_t portal_webs_msg[PORTAL_SERVER_MAX];


typedef struct
{
  u32 enable_portal;     /* flag to enable portal */
  u32 portal_bas_ip;     /* Portal bas-ip */
  u8  apply_webs[32];    /* apply Portal Web server (name)*/
  u8  nas_id[20];        /* portal NAS-ID */
  int webs_index;      
}interface_portal;
#define PORTAL_FREE_RUULE_NUM	256
extern u32 portal_free_rule[PORTAL_FREE_RUULE_NUM];



int write_portal_config_file (void);
int portal_check_user_name(u8 *name);
int radius_restore_conf (void);
int portal_restore_conf (void);
int qos_carl_restore(void);
int qos_car_restore(void);

int get_portal_server_index (u8 * name);
int check_nas_id(char *name);
int search_portal_free_rule(int num, u32 dst_ip);


#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

