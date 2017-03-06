


#ifndef INTERFACE_RADIUS_H_
#define INTERFACE_RADIUS_H_

#define BUFF_SIZE 512
#define RADIUS_MAX 16


typedef struct
{
  u8 radius_scheme_name[32]; /*RADIUS 方案视图名字*/
  u32 prim_auth_ip;      /*RADIUS 方案的主认证服务器ip*/
  u32 prim_account_ip;   /*RADIUS 方案的主计费服务器ip*/
  u8 key_auth[64];            /*主认证服务器密钥*/
  u8 key_account[64];         /*主计费服务器密钥*/  

  u32 security_policy_ip;  /*安全策略服务器IP*/
  
}radius_scheme_t;

typedef struct
{
  u8 radius_enable[32]; /*RADIUS enable*/
  u32 radius_user_ip;   
  u32 subnet_mask; 
  u8 account_type[32];
  
}radius_config_t;


extern radius_scheme_t radius_ser_info[RADIUS_MAX];
extern radius_config_t radius_account_info[RADIUS_MAX];

int write_radius_config_file (void);
int radius_check_user_name (u8 *name);
int write_radius_account_config_file(void);
char * radius_get_primary_server(void);

int get_radius_server_index (u8 * name);

#endif
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

