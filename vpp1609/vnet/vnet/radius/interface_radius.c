/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

/**
 * @file
 * @brief Common utility functions for RADIUS.
 *
 */

#include <vppinfra/format.h>
#include "interface_radius.h"
#include <vnet/vnet.h>
#include <vnet/interface.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

radius_scheme_t radius_ser_info[RADIUS_MAX];
radius_config_t radius_account_info[RADIUS_MAX];

int radiusDexa=0;

/*******************************************************************************
 函数名称  : radius_check_user_name
 功能描述  : 检测输入radius相关名字是否合法
 输入参数  : 名字
 输出参数  : 无
 返 回 值  : 1     成功
             0     失败
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/

int radius_check_user_name(u8 *name)
{	  
  int i;    
  u8 *tmp = name;       
  for(i = 0; i < strlen((char *)name); i++)    
  {           
  	if(*tmp == 92 || *tmp == '?' )        
	{            
	  return 0;        
	 }           
	tmp++;   

  }       
	return 1;	
}

/*******************************************************************************
 函数名称  : write_radius_config_file
 功能描述  : 输入write file命令调用此函数写portal模块配置文件
 输入参数  : 无
 输出参数  : 无
 返 回 值  : 0        成功
             其它     失败
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
int
write_radius_config_file (void)
{
   FILE * fp = fopen ("/etc/radius_config.conf", "w+");
    if(fp == NULL)
    {   
        return 1;
    }   
   char buff[BUFF_SIZE];
   memset (buff, 0, BUFF_SIZE);
  int i = 0;
  for (i=0; i<RADIUS_MAX; i++)
  {
  		if (strlen((char *)radius_ser_info[i].radius_scheme_name) <=0)
			continue;
   		snprintf (buff, sizeof(buff), 
                        "radius-scheme-name %s\n",
                        radius_ser_info[i].radius_scheme_name);
		fputs (buff, fp);
   		memset (buff, 0, BUFF_SIZE);
		if (radius_ser_info[i].prim_auth_ip)
		{
        	snprintf(buff, BUFF_SIZE,
				       "auth-ip %d\n", 
				       radius_ser_info[i].prim_auth_ip);	
		}
   		fputs (buff, fp);
   		memset (buff, 0, BUFF_SIZE);		
		if (radius_ser_info[i].prim_account_ip)
		{
			snprintf(buff, BUFF_SIZE,
				       "account-ip %d\n", 
				       radius_ser_info[i].prim_account_ip);	
		}
   		fputs (buff, fp);
   		memset (buff, 0, BUFF_SIZE);		
		if (strlen((char *)radius_ser_info[i].key_auth) >0)
		{
        	snprintf(buff, BUFF_SIZE,
				       "auth-key %s\n", 
				       radius_ser_info[i].key_auth);	
		}
   		fputs (buff, fp);
   		memset (buff, 0, BUFF_SIZE);		
		if (strlen((char *)radius_ser_info[i].key_account) >0)
		{
			snprintf(buff, BUFF_SIZE,
				       "account-key %s\n", 
				       radius_ser_info[i].key_account);
		}
   		fputs (buff, fp);
   		memset (buff, 0, BUFF_SIZE);		
		if (radius_ser_info[i].security_policy_ip)
		{
			snprintf(buff, BUFF_SIZE,
				       "security-ip %d\n", 
				       radius_ser_info[i].security_policy_ip);	
		}

   		fputs (buff, fp);
   		memset (buff, 0, BUFF_SIZE);
  	}
   fclose (fp);
   return 0;
}

/*******************************************************************************
 函数名称  : write_radius_account_config_file
 功能描述  : 输入write file命令调用此函数写portal模块配置文件
 输入参数  : 无
 输出参数  : 无
 返 回 值  : 0        成功
             其它     失败
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
int
write_radius_account_config_file (void)
{
	
   char buff[BUFF_SIZE];
   char buf[BUFF_SIZE];
   
   char enable[10],account_type[10];
   u32 ip,subnetMask;
   memset (buff, 0, BUFF_SIZE);
  int i = 0;
  for (i=0; i<RADIUS_MAX; i++)
  {
		int ret=0;
		
		if (radius_account_info[i].radius_user_ip <=0)
			continue;	
		FILE * fp = fopen ("/etc/radius_account_config.conf", "a+");
  	    FILE * fp1 = fopen ("/etc/radius_account_config.tmp", "a+");
  	  			while(fgets(buf,sizeof(buf),fp)){
				sscanf(buf,"%*s %d %d %s %s",&ip,&subnetMask,enable,account_type);
				if(radius_account_info[i].radius_user_ip==ip){
					snprintf(buff, BUFF_SIZE,
				       "radius-ip-mask %d %d %s %s\n", 
				       radius_account_info[i].radius_user_ip,radius_account_info[i].subnet_mask,radius_account_info[i].radius_enable,radius_account_info[i].account_type);
						 fputs(buff,fp1);
						ret=1;
						
				}else{
   				fputs(buf,fp1);
					}
				
			}
			if(0==ret){
				snprintf(buff, BUFF_SIZE,
				       "radius-ip-mask %d %d %s %s\n", 
				       radius_account_info[i].radius_user_ip,radius_account_info[i].subnet_mask,radius_account_info[i].radius_enable,radius_account_info[i].account_type);
   						fputs(buff,fp1);
			}
   		memset (buff, 0, BUFF_SIZE);
		fclose (fp);
	   fclose (fp1);
	   	remove("/etc/radius_account_config.conf");    
	    rename("/etc/radius_account_config.tmp","/etc/radius_account_config.conf");
  	}
   return 0;
}

static clib_error_t *
create_radius_scheme_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 * name_r = NULL;
  u32 parameter_num = 0;
  int rv = 0;
  
  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
  	return clib_error_return (0, "mandatory argument(s) missing");
  
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  	{
      if (unformat (line_input, " %s", &name_r))
      	{
           if((strlen ((char *)name_r) >= 1) && (strlen ((char *)name_r) <= 32))
		   	  parameter_num++;
		   else
		   	 return clib_error_return (0, "Name is too short or too long");
	  }	  	
  }
  rv = radius_check_user_name (name_r);
  if (!rv)
  	return clib_error_return (0, "The name format error");
  if(parameter_num != 1)
  	return clib_error_return (0, "mandatory argument(s) missing");

  int i = 0, id = 0;
  int index = RADIUS_MAX;
  for (i=0; i< RADIUS_MAX; i++)
  	{
      if (strlen((char *)radius_ser_info[i].radius_scheme_name) <= 0)
	  	index = i;
	  else if (!strcmp((char *)radius_ser_info[i].radius_scheme_name, (char *)name_r))
	  {
	    index = i;
		id = 1;
	  	break;
	  }
  }
  if (index >= RADIUS_MAX)
  	 return clib_error_return (0, "radius server number to the ceiling");
 if (!id)
 {
	 /* RADIUS方案视图名字变化，该试图下的配置清空 */
	  radius_ser_info[0].prim_auth_ip = 0;
	  radius_ser_info[0].prim_account_ip = 0;
	  memset (radius_ser_info[0].radius_scheme_name, 0, 32);
	  memset (radius_ser_info[0].key_auth, 0, 64);
	  memset (radius_ser_info[0].key_account, 0, 64);
	  radius_ser_info[0].security_policy_ip = 0; 
	  
	  /*创建名字为 (name_r) 的 RADIUS 方案 */
	  strcpy ((char *)radius_ser_info[0].radius_scheme_name, (char *)name_r);
	  vlib_cli_output(vm, "New RADIUS scheme .");
 }
  unformat_free (line_input);

  return 0;
}


static clib_error_t *
no_radius_scheme_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	u32 parameter_num = 0;
	u8 * name_r;
	
	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
	  return clib_error_return (0, "mandatory argument(s) missing");
	
	while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	 {
	   if (unformat (line_input, " %s", &name_r))
		  parameter_num++;	 
	 }	
	if (parameter_num != 1)
   	   return clib_error_return (0, "mandatory argument(s) missing");
	int i = 0;
	for (i=0; i<RADIUS_MAX; i++)
	{
	    if (!strcmp ((char *)name_r, (char *)radius_ser_info[i].radius_scheme_name))
		   break;
	}
	if (i >= RADIUS_MAX)
		return clib_error_return (0, "The name does not match");
	 /* 清空该视图配置 */
	else
    {
       memset (radius_ser_info[i].radius_scheme_name, 0, 32);
       radius_ser_info[i].prim_auth_ip = 0;
       radius_ser_info[i].prim_account_ip = 0;
       memset (radius_ser_info[i].key_auth, 0, 64);
       memset (radius_ser_info[i].key_account, 0, 64);
       radius_ser_info[i].security_policy_ip = 0;  
	}
	
	unformat_free (line_input);	
	return 0;
}

int get_radius_server_index (u8 * name)
{
	int i=0;
	for (i=0; i< RADIUS_MAX; i++)
	{
       if(!strcmp((char *)radius_ser_info[i].radius_scheme_name, (char *)name))
	   	   break;
	}
	return i;
}

 char * radius_get_primary_server(void)
 {
 	struct in_addr portalserver = {0};

	 if(radius_ser_info[0].prim_auth_ip)
	 {
	 	portalserver.s_addr = radius_ser_info[0].prim_auth_ip;
	 	return inet_ntoa(portalserver);
	 }
	return NULL;
 }

 static clib_error_t *
radius_primary_authentication_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	char * ip;
	u8 * scheme_name;
    u32 parameter_num = 0;
	
	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
	  return clib_error_return (0, "mandatory argument(s) missing");
	
	while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	  {
		if (unformat (line_input, " %s", &ip))
		   parameter_num++;
		if (unformat (line_input, " %s", &scheme_name))
		   parameter_num++;
	}
	if(parameter_num != 2)
	  return clib_error_return (0, "mandatory argument(s) missing");
	int index_r = get_radius_server_index(scheme_name);
		 /* 配置主认证服务器IP */
	if (0 <= index_r && index_r < RADIUS_MAX)
		radius_ser_info[index_r].prim_auth_ip = inet_addr(ip);
	else
		return clib_error_return (0, "The radius server does not exist");
	
	unformat_free (line_input);
	return 0;	
}


static clib_error_t *
radius_no_primary_authentication_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
    u8 * scheme_name;
	u32 parameter_num = 0;
	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
	   return clib_error_return (0, "mandatory argument(s) missing");
	
	if (unformat (line_input, " %s", &scheme_name))
		parameter_num++;
	if (parameter_num)
	{
	   int index_r = get_radius_server_index(scheme_name);
	   if (0 <= index_r && index_r < RADIUS_MAX)
           radius_ser_info[index_r].prim_auth_ip = 0;
	   else
	   	  return clib_error_return (0, "The radius server does not exist");
	}
	unformat_free (line_input);
	return 0;	
}


static clib_error_t *
radius_primary_accounting_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	char * ip;
	u8 * scheme_name;
    u32 parameter_num = 0;
	
	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
	  return clib_error_return (0, "mandatory argument(s) missing");
	
	while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	  {
		if (unformat (line_input, " %s", &ip))
		     parameter_num++;
		if (unformat (line_input, " %s", &scheme_name))
			parameter_num++;
	}
	if(parameter_num != 2)
	  return clib_error_return (0, "mandatory argument(s) missing");
	int index_r = get_radius_server_index(scheme_name);
    /* 配置主认证服务器IP */
	if (0 <= index_r && index_r < RADIUS_MAX)
	    radius_ser_info[index_r].prim_account_ip = inet_addr(ip);
	else
		return clib_error_return (0, "The radius server does not exist");

	unformat_free (line_input);	
	return 0;	
}


static clib_error_t *
radius_no_primary_accounting_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
    u8 * scheme_name;
	u32 parameter_num = 0;
	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
	   return clib_error_return (0, "mandatory argument(s) missing");
	
	if (unformat (line_input, " %s", &scheme_name))
		parameter_num++;
	if (parameter_num)
	{
	   int index_r = get_radius_server_index(scheme_name);
	   if (0 <= index_r && index_r < RADIUS_MAX)
           radius_ser_info[index_r].prim_account_ip = 0;
	   else
	   	  return clib_error_return (0, "The radius server does not exist");
	}
	unformat_free (line_input);
	return 0;	
}


static clib_error_t *
radius_security_policy_server_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	char * ip;
	u8 * scheme_name;
    u32 parameter_num = 0;
	
	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
	  return clib_error_return (0, "mandatory argument(s) missing");
	
	while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	 {
		if (unformat (line_input, " %s", &ip))
		  parameter_num++;
		if (unformat (line_input, " %s", &scheme_name))
		  parameter_num++;
	}
	if(parameter_num != 2)
	   return clib_error_return (0, "mandatory argument(s) missing");
    int index_r = get_radius_server_index(scheme_name);
	 /* 配置安全策略服务器IP */ 
	if (0 <= index_r && index_r < RADIUS_MAX)
		radius_ser_info[index_r].security_policy_ip = inet_addr(ip);
	else 
		return clib_error_return (0, "The radius server does not exist");
	unformat_free (line_input);	
	return 0;	
}



static clib_error_t *
radius_no_security_policy_server_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
   	unformat_input_t _line_input, *line_input = &_line_input;
    u32 security_ser_ip;
	char * ip;
	u8 * scheme_name;
    u32 parameter_num = 0;
	
	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
	  return clib_error_return (0, "mandatory argument(s) missing");
	
	while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	  {
		if (unformat (line_input, " %s", &ip))
		   parameter_num++;
		if (unformat (line_input, " %s", &scheme_name))
			parameter_num++;
	}
    if(parameter_num != 2)
	   return clib_error_return (0, "mandatory argument(s) missing");
    int index_r = get_radius_server_index(scheme_name);
    /* 清空安全策略服务器IP */ 
	if (0 <= index_r && index_r < RADIUS_MAX)
	{
		security_ser_ip = inet_addr(ip);
		if (security_ser_ip == radius_ser_info[index_r].security_policy_ip)
			radius_ser_info[index_r].security_policy_ip = 0;
		else
			return clib_error_return (0, "IP does not match");
	}
	else
		return clib_error_return (0, "The radius server does not exist");
		  
	unformat_free (line_input);	
	return 0;	
}


static clib_error_t *
radius_key_account_auth_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input; 
  u8 * key;
  u8 is_auth = 0;
  u8 * scheme_name;
  u32 parameter_num = 0;
  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
	 return clib_error_return (0, "mandatory argument(s) missing");
	
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "accounting"))
	  	is_auth = 0;
	  if (unformat (line_input, "authentication"))
	  	is_auth = 1;
	  if (unformat (line_input, "simple %s", &key))
	  	{	  	  
	  	  parameter_num ++;
	  	  if (strlen ((char *)key) < 1 || strlen ((char *)key) > 64)
			 return clib_error_return (0, "The key is too short or too long");		  
	  	}
	  if (unformat (line_input, " %s", &scheme_name))
	  	 parameter_num++;	  	 
   } 
  if (parameter_num != 2)
  	 return clib_error_return (0, "mandatory argument(s) missing");	
  int index_r = get_radius_server_index(scheme_name);
  if (0 <= index_r && index_r <RADIUS_MAX)
  {
     if(is_auth)
         strcpy ((char *)radius_ser_info[index_r].key_auth, (char *)key);
     else
   	     strcpy ((char *)radius_ser_info[index_r].key_account, (char *)key);
  }
  else
  	 return clib_error_return (0, "The radius server does not exist");
  unformat_free (line_input);
  return 0;
}

static clib_error_t *
radius_no_key_account_auth_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input; 
  u8 is_auth = 0;
  u32 parameter_num = 0;
  u8 * scheme_name;
  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
	 return clib_error_return (0, "mandatory argument(s) missing");
	
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "accounting"))
	  	{
	  	 is_auth = 0;
		 parameter_num++;
	  	}
	  if (unformat (line_input, "authentication"))
	  	{
	  	 is_auth = 1;
		 parameter_num++;
	  	}
	  if (unformat (line_input, " %s", &scheme_name))
	  	parameter_num++;
  	}
  if(parameter_num != 2)
   	 return clib_error_return (0, "mandatory argument(s) missing");
  int index_r = get_radius_server_index(scheme_name);
  if (0 <= index_r && index_r <RADIUS_MAX)
  {
	  if(is_auth)
		 memset (radius_ser_info[index_r].key_auth, 0, 64);
	  else
		 memset (radius_ser_info[index_r].key_account, 0, 64);
  }
  else
  	 return clib_error_return (0, "The radius server does not exist");
  unformat_free (line_input);
  return 0;
}
static clib_error_t *
radius_enable_account_auth_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
	 unformat_input_t _line_input, *line_input = &_line_input; 
  char *userIp = NULL;
  char *type = NULL;
  char *subnetMask=NULL;
  char *accountType=NULL;
  u32 networkSegment;
  u32 subnet_mask;
  u32 ip;
  u32 parameter_num = 0;
  int i=0;
  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
	 return clib_error_return (0, "mandatory argument(s) missing");
	
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, " %s",&type)){
	  	if(0!=strcmp(type,"enable") && 0!=strcmp(type,"disable")){
			return clib_error_return (0, "type mandatory argument(s) missing");
		}
	  }
		if (unformat (line_input, " %s",&userIp)){
			if(unformat (line_input, " %s",&subnetMask)){
				if(unformat (line_input, " %s",&accountType)){
					if(NULL!=type && userIp!=NULL && subnetMask!=NULL && accountType!=NULL){
					subnet_mask=inet_addr(subnetMask);	
					ip=inet_addr(userIp);
					networkSegment=subnet_mask & ip;
					for(i=0;i<RADIUS_MAX;i++){
						if(radius_account_info[i].radius_user_ip==networkSegment){
							memset (radius_account_info[i].radius_enable,0, 32);
							memset (radius_account_info[i].account_type,0, 32);
							strcpy ((char *)radius_account_info[i].radius_enable, (char *)type);
							strcpy ((char *)radius_account_info[i].account_type, (char *)accountType);
							radius_account_info[i].subnet_mask=subnet_mask;
							break;
						}
					if(i==(RADIUS_MAX-1)){
					
					strcpy ((char *)radius_account_info[radiusDexa].radius_enable, (char *)type);
					strcpy ((char *)radius_account_info[radiusDexa].account_type, (char *)accountType);
					radius_account_info[radiusDexa].radius_user_ip = networkSegment;
					radius_account_info[radiusDexa].subnet_mask=subnet_mask;
					radiusDexa++;
					}  
						}
					
					 
					}
				 parameter_num++;
				}
			}
		} 	 		  
	  	
	  	  	 
   } 
 
 
  if(parameter_num!=1){
	return clib_error_return (0, "parameter mandatory argument(s) missing");
  }
  if(0 <=radiusDexa && radiusDexa<RADIUS_MAX){
	 memset (type, 0, 20);
  }
  else
  	 return clib_error_return (0, "The radius server does not exist");

  unformat_free (line_input);
  return 0;
}

static clib_error_t *
radius_no_account_auth_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
	 unformat_input_t _line_input, *line_input = &_line_input; 
  char *userIp = NULL;
  char *subnetMask=NULL;
  char *account_type=NULL;
  char buff[BUFF_SIZE];
  u32 networkSegment;
  u32 subnet_mask;
  u32 ip;
  int i=0;
  FILE * fp = fopen ("/etc/radius_account_config.conf", "a+");
  FILE * fp1 = fopen ("/etc/radius_account_config.tmp", "a+");
  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
	 return clib_error_return (0, "mandatory argument(s) missing");
	
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
		if (unformat (line_input, " %s",&userIp)){
			if (unformat (line_input, " %s",&subnetMask)){
				if (unformat (line_input, " %s",&account_type)){
					if(userIp!=NULL && subnetMask!=NULL && account_type!=NULL){
						subnet_mask=inet_addr(subnetMask);	
					    ip=inet_addr(userIp);
					    networkSegment=subnet_mask & ip;
						for(i=0;i<RADIUS_MAX;i++){
							if(radius_account_info[i].radius_user_ip!=networkSegment && radius_account_info[i].radius_user_ip!=0){
								snprintf(buff, BUFF_SIZE,
							       "radius-ip-mask %d %d %s %s\n", 
							       radius_account_info[i].radius_user_ip,radius_account_info[i].subnet_mask,radius_account_info[i].radius_enable,radius_account_info[i].account_type);
									 fputs(buff,fp1);
								
							}else{
								radius_account_info[i].radius_user_ip=0;
								radius_account_info[i].subnet_mask=0;
								memset (radius_account_info[i].radius_enable,0, 32);
								memset (radius_account_info[i].account_type,0, 32);
							}
						}  
					}else if(userIp==NULL && subnetMask==NULL && account_type==NULL){
						for(i=0;i<RADIUS_MAX;i++){

							radius_account_info[i].radius_user_ip=0;
							radius_account_info[i].subnet_mask=0;
							memset (radius_account_info[i].radius_enable,0, 32);
							memset (radius_account_info[i].account_type,0, 32);
						}
					 }
				}
			}	 
		}
	}
	  
	    	  
	fclose (fp);
	fclose (fp1);
	remove("/etc/radius_account_config.conf");    
	rename("/etc/radius_account_config.tmp","/etc/radius_account_config.conf");  	 		  
	  	
  unformat_free (line_input);
  return 0;
}

static clib_error_t *
radius_restore_account_auth_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  u32 ip,subnetMask;
  char enable[10],account_type[10];
  char buf[BUFF_SIZE];
  int i=0,j=0;
  FILE * fp = fopen ("/etc/radius_account_config.conf", "a+");
 // FILE * fp1 = fopen ("/etc/radius_account_config.tmp", "a+");
  /* Get a line of input. */
	
 
				for(i=0;i<RADIUS_MAX;i++){
					radius_account_info[i].radius_user_ip=0;
					radius_account_info[i].subnet_mask=0;
					memset (radius_account_info[i].radius_enable,0, 32);
					memset (radius_account_info[i].account_type,0, 32);
				}
				while(fgets(buf,sizeof(buf),fp)){
					sscanf(buf,"%*s %d %d %s %s",&ip,&subnetMask,enable,account_type);
					if(0!=ip && NULL!=enable && 0!=subnetMask){
						radius_account_info[j].radius_user_ip=ip;
						radius_account_info[j].subnet_mask=subnetMask;
						strcpy ((char *)radius_account_info[j].radius_enable, (char *)enable);
						strcpy ((char *)radius_account_info[j].account_type, (char *)account_type);
						j++;

					}else{
						continue;
					}
							
							
				}
				 
				
		

	
			    	  
	fclose (fp);		  

  return 0;
}

static clib_error_t *
show_radius_account_config_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{

  char buf[BUFF_SIZE];
  FILE * fp = fopen ("/etc/radius_account_config.conf", "a+");
 // FILE * fp1 = fopen ("/etc/radius_account_config.tmp", "a+");
  /* Get a line of input. */
	
 
				while(fgets(buf,sizeof(buf),fp)){
					
					vlib_cli_output(vm, "%s",buf);
				}
		
	
			    	  
	fclose (fp);		  

  return 0;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_radius_scheme_cli, static) = 
{
 .path = "radius scheme",
 .short_help = "radius scheme <radius-scheme-name(string 1~32)>",
 .function = create_radius_scheme_command_fn,
};
/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (no_radius_scheme_cli, static) = 
{
 .path = "no radius scheme",
 .short_help = "no radius scheme <radius-scheme-name(string 1~32)>",
 .function = no_radius_scheme_command_fn,
};
/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (primary_authentication_cli, static) = 
{
 .path = "radius primary authentication",
 .short_help = "radius primary authentication <addr> <scheme_name>",
 .function = radius_primary_authentication_command_fn,
};
/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (no_primary_authentication_cli, static) = 
{
 .path = "radius no primary authentication",
 .short_help = "radius no primary authentication <scheme_name>",
 .function = radius_no_primary_authentication_command_fn,
};
/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (primary_accounting_cli, static) = {
 .path = "radius primary accounting",
 .short_help = "radius primary accounting <addr> <scheme_name>",
 .function = radius_primary_accounting_command_fn,
};
/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (no_primary_accounting_cli, static) = {
 .path = "radius no primary accounting",
 .short_help = "radius no primary accounting <scheme_name>",
 .function = radius_no_primary_accounting_command_fn,
};
/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (security_policy_server_cli, static) = {
 .path = "radius security-policy-server",
 .short_help = "radius security-policy-server <addr> <scheme_name>",
 .function = radius_security_policy_server_command_fn,
};
/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (no_security_policy_server_cli, static) = {
 .path = "radius no security-policy-server",
 .short_help = "radius no security-policy-server <addr> <scheme_name>",
 .function = radius_no_security_policy_server_command_fn,
};
/* *INDENT-ON* */



/* *INDENT-OFF* */
VLIB_CLI_COMMAND (key_account_auth_cli, static) = {
 .path = "radius key",
 .short_help = "radius key <accounting | authentication> simple <key-string> <scheme_name>",
 .function = radius_key_account_auth_command_fn,
};
/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (no_key_account_auth_cli, static) = {
 .path = "radius no key",
 .short_help = "radius no key <accounting | authentication> <scheme_name>",
 .function = radius_no_key_account_auth_command_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (enable_account_auth_cli, static) = {
 .path = "radius-accounting-on",
 .short_help = "radius-accounting-on <enable | disable> <user_ip> <subnet_mask> <time | flow>",
 .function = radius_enable_account_auth_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (no_account_auth_cli, static) = {
 .path = "no radius-accounting",
 .short_help = "no radius-accounting <user_ip> <subnet_mask>",
 .function = radius_no_account_auth_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (radius_no_account_auth_cli, static) = {
 .path = "radius-accounting restore",
 .short_help = "radius-accounting restore",
 .function = radius_restore_account_auth_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_radius_account_config_cli, static) = {
 .path = "show-radius-accounting-config",
 .short_help = "show-radius-accounting-config",
 .function = show_radius_account_config_fn,
};
/* *INDENT-ON* */



/* *INDENT-ON* */
					
/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
