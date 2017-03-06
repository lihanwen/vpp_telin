
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
 * @brief Common utility functions for PORTAL interfaces.
 *
 */

#include <vppinfra/format.h>
#include "interface_portal.h"
#include "portal.h"
#include "portal_hash.h"
#include <arpa/inet.h>
#include <vnet/interface.h>
#include <vnet/vnet.h>
#include <vnet/global_funcs.h>

#include <vnet/radius/interface_radius.h>
#include <vnet/radius/list.h>
#include <vnet/dhcp/server_cmd.h>
#include <vnet/portal_redirect/portal_red.h>


u32 portal_free_rule[PORTAL_FREE_RUULE_NUM];

portal_server_t  portal_server_msg[PORTAL_SERVER_MAX];
portal_webs_t portal_webs_msg[PORTAL_SERVER_MAX];

portal_qos_carl qos_carl_msg[QOS_CARL_MAX];

portal_qos_interface qos_interface[QOS_INTERFACE_MAX];

int qos_carl_restore(void){

FILE* fin;

	char buf[1024];
	int carl_index;
	char ip_flag[20];
	u32 ip_address;
	u32 mask_length;
	fin=fopen("/etc/qos_carl.config","a+");
	while(fgets(buf,sizeof(buf),fin)){
		sscanf(buf,"%d %s %d %d",&carl_index,ip_flag,&ip_address,&mask_length);
		qos_carl_msg[carl_index].carl_index = carl_index;
		strcpy((char*)qos_carl_msg[carl_index].ip_flag,(char*)ip_flag);
		qos_carl_msg[carl_index].ip_address=ip_address;
	  	qos_carl_msg[carl_index].mask_length=mask_length; 
	}

	   fclose(fin);  
       return 0; 
}
int qos_car_restore(void){
	vnet_interface_config *tmp = clib_mem_alloc(sizeof(*tmp));
	memset(tmp,0,sizeof(*tmp));
	tmp=vifm->next;
	while(tmp!=NULL && VNET_INTERFACE_TYPE_VT == tmp->if_type){
	FILE* fin;

	char buf[1024];
	int carl_index;
	u8 ip_flag[40] ;
	u32 cir;
	u32 cbs;
	int sw_if_index = ~0;
	u8 interface_name[40];
	u8 any[20];
	u8 name[50];
	u32 qos_int_index = 0;
	int ret = 0;
	strcpy((char*)name,(char*)tmp->if_name);
	sw_if_index = tmp->if_index;
	fin=fopen("/etc/qos_car.config","a+");
	while(fgets(buf,sizeof(buf),fin)){
	sscanf(buf,"%s %s %d cir %d cbs %d %s",ip_flag,any,&carl_index,&cir,&cbs,interface_name);

	if(strcmp((char*)any,"any")==0)
		ret = 1;
	if(strcmp((char*)any,"carl")==0)
		ret = 0;
	

	if(strcmp((char*)interface_name,(char*)name)==0){
	

	if(strcmp((char*)ip_flag,"inbound")==0){
		for(int i=0;i<qos_interface[sw_if_index].inbound_index;i++)
			{	if(qos_interface[sw_if_index].interface_car_inbound[i]!=NULL){
				if(qos_interface[sw_if_index].interface_car_inbound[i]->carl_index==carl_index){
					qos_int_index=i;
					break;
					}
				else
					qos_int_index=qos_interface[sw_if_index].inbound_index;}
				else
					qos_int_index=qos_interface[sw_if_index].inbound_index;
		}
		if(qos_interface[sw_if_index].interface_car_inbound[qos_int_index]==NULL){
		qos_interface[sw_if_index].interface_car_inbound[qos_int_index] = (portal_qos_car* )(malloc(sizeof(portal_qos_car)));
		qos_interface[sw_if_index].inbound_index++;
			}
		if(ret==1){
			qos_int_index=0;
		qos_interface[sw_if_index].interface_car_inbound[qos_int_index]->carl_index=0;
		qos_interface[sw_if_index].interface_car_inbound[qos_int_index]->any_flag=1;
		qos_interface[sw_if_index].inbound_index = 1;
			}
		else{
		qos_interface[sw_if_index].interface_car_inbound[qos_int_index]->carl_index=carl_index;
		qos_interface[sw_if_index].interface_car_inbound[qos_int_index]->any_flag=0;
		}
		qos_interface[sw_if_index].interface_car_inbound[qos_int_index]->cir=cir;
		qos_interface[sw_if_index].interface_car_inbound[qos_int_index]->cbs=cbs;
		
	}else if(strcmp((char*)ip_flag,"outbound")==0){
	for(int i=0;i<qos_interface[sw_if_index].outbound_index;i++)
			{
			if(qos_interface[sw_if_index].interface_car_outbound[i]!=NULL){
				if(qos_interface[sw_if_index].interface_car_outbound[i]->carl_index==carl_index){
					qos_int_index=i;
					break;
					}
				else
					qos_int_index=qos_interface[sw_if_index].outbound_index;}
				else
					qos_int_index=qos_interface[sw_if_index].outbound_index;
		}
		if(qos_interface[sw_if_index].interface_car_outbound[qos_int_index]==NULL){
		qos_interface[sw_if_index].interface_car_outbound[qos_int_index] = (portal_qos_car* )(malloc(sizeof(portal_qos_car)));
		qos_interface[sw_if_index].outbound_index++;
			}
		if(ret==1){
			qos_int_index=0;
		qos_interface[sw_if_index].interface_car_outbound[qos_int_index]->carl_index=0;
		qos_interface[sw_if_index].interface_car_outbound[qos_int_index]->any_flag=1;
		qos_interface[sw_if_index].outbound_index = 1;
		}
		else{
		qos_interface[sw_if_index].interface_car_outbound[qos_int_index]->carl_index=carl_index;
		qos_interface[sw_if_index].interface_car_outbound[qos_int_index]->any_flag=0;}
		qos_interface[sw_if_index].interface_car_outbound[qos_int_index]->cir=cir;
		qos_interface[sw_if_index].interface_car_outbound[qos_int_index]->cbs=cbs;
		
	}else
	continue;
		}}
	fclose(fin); 
	tmp = tmp->next;
	}
    return 0; 

}
int radius_restore_conf (void)
{
    FILE *fd;
    char buf[BUFF_SIZE];
    char *p, *msg;
    fd = fopen("/etc/radius_config.conf","a+");

    if(fd == NULL)
    {   
        return -1;
    } 
	int i= -1;
    while(fgets(buf , BUFF_SIZE, fd))
    {   
        p = strtok(buf, " ");
        if(p && (msg = strtok(NULL, " ")))
        {   
            if(strcasecmp(p, "radius-scheme-name") == 0)
            {  
            	if (-1 <= i && i < RADIUS_MAX-1)
					i++;
				memset (radius_ser_info[i].radius_scheme_name, 0, 32);
                strncpy((char *)radius_ser_info[i].radius_scheme_name , msg, strlen(msg)-1);
				continue;
            }   
            if(strcasecmp(p, "auth-ip") == 0) 
            {
                radius_ser_info[i].prim_auth_ip = atoi(msg);
				continue;
            }
	        if(strcasecmp(p, "account-ip") == 0)
	        {
                radius_ser_info[i].prim_account_ip = atoi(msg);
				continue;
	        }
            if(strcasecmp(p, "auth-key") == 0)
            {
            	memset(radius_ser_info[i].key_auth, 0, 64);
                strncpy((char *)radius_ser_info[i].key_auth, msg, strlen(msg)-1);
				continue;
            }
	        if(strcasecmp(p, "account-key") == 0)
	        {
                strncpy((char *)radius_ser_info[i].key_account, msg, strlen(msg)-1);
				continue;
	        }
	        if(strcasecmp(p, "security-ip") == 0)
                radius_ser_info[i].security_policy_ip = atoi(msg);
        }
    }
    fclose(fd);
	return 0;
}

int portal_restore_conf (void)
{
    FILE *fd;
    char buf[BUFF_SIZE];
    char *p, *msg;
    fd = fopen("/etc/portal_config.conf","a+");

    if(fd == NULL)
    {   
        return -1;
    }   
	int i = -1, j = -1;
    while(fgets(buf , BUFF_SIZE, fd))
    {   
        p = strtok(buf, " ");
        if(p && (msg = strtok(NULL, " ")))
        {   
        	if(strcasecmp(p, "web-server-name") == 0)
            {
                if (-1 <= j && j < PORTAL_WEBS_MAX-1)
                		j++;
				memset(portal_webs_msg[j].portal_webs_name, 0, 32);
                strncpy((char *)portal_webs_msg[j].portal_webs_name, msg, strlen(msg)-1);
				continue;
            }
	        if(strcasecmp(p, "url") == 0)
            {
            	memset(portal_webs_msg[j].webs_url, 0, 64);
                strncpy((char *)portal_webs_msg[j].webs_url, msg, strlen(msg)-1);
				continue;
            }
            if(strcasecmp(p, "portal-server-name") == 0)
            {   
                if (-1 <= i && i < PORTAL_SERVER_MAX-1)
                     	i++;
				memset(portal_server_msg[i].portal_server_name, 0, 32);
                strncpy((char *)portal_server_msg[i].portal_server_name, msg, strlen(msg)-1);
				continue;
            }   
            if(strcasecmp(p, "ip-address") == 0)
            {   
                portal_server_msg[i].portal_server_ip = atoi(msg);
				continue;
            }
	        if(strcasecmp(p, "port-number") == 0)
            {
                portal_server_msg[i].portal_server_port = atoi(msg);
				continue;
            }
            if(strcasecmp(p, "key") == 0)
            {
            	memset(portal_server_msg[i].key_portal, 0, 64);
                strncpy((char *)portal_server_msg[i].key_portal, msg, strlen(msg)-1);
            }
        }
    }
    fclose(fd);

    fd = fopen ("/etc/portal.free_rule.conf", "a+");
	if(fd == NULL)
    {   
        return -1;
    }   

    while(fgets(buf , BUFF_SIZE, fd))
    {
    	p = strtok(buf, " ");
        if(p && (msg = strtok(NULL, " ")))
        {
        	if(strcasecmp(p, "Rule-Number") == 0)
            {
				i = atoi(msg);
            }
            if(strcasecmp(p, "portal_free_rule_ip") == 0)
            {
				portal_free_rule[i] = atoi(msg);				
				add_white_rule_user_by_ip(&portal_free_rule[i]);
            }
        }
    
    }
    fclose (fd);
   
	return 0;
}
/*******************************************************************************
 ????  : portal_check_user_name
 ????  : ????portal????????
 ????  : ??
 ????  : ?
 ? ? ?  : 1     ??
             0     ??
--------------------------------------------------------------------------------
 ???????? : 
 ????  : 
 ????  : 
 ????  : 
*******************************************************************************/
int portal_check_user_name(u8 *name)
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
 ????  : write_portal_config_file
 ????  : ??write file????????portal??????
 ????  : ?
 ????  : ?
 ? ? ?  : 0        ??
             ??     ??
--------------------------------------------------------------------------------
 ???????? : 
 ????  : 
 ????  : 
 ????  : 
*******************************************************************************/
int
write_portal_config_file (void)
{
   FILE * fp = fopen ("/etc/portal_config.conf", "w+");
   if(fp == NULL)
   {
        return 1;
   }   
   char buff[BUFF_SIZE];
   int i=0;
   for (i=0; i<PORTAL_WEBS_MAX; i++)
   { 
       if (strlen ((char *)portal_webs_msg[i].portal_webs_name) <=0)
	   	   continue;
       snprintf (buff, sizeof(buff),
   	                     "web-server-name %s\n", 	                    
   	                     portal_webs_msg[i].portal_webs_name);
	   fputs (buff, fp);
       memset (buff, 0, BUFF_SIZE);
	   if (strlen ((char *)portal_webs_msg[i].webs_url) >0)
	   {
       		snprintf (buff, BUFF_SIZE,
				        "url %s\n", 
				        portal_webs_msg[i].webs_url);
			fputs (buff, fp);
       		memset (buff, 0, BUFF_SIZE);
	   }
   	}
   for (i=0; i<PORTAL_SERVER_MAX; i++)
   {
       if (strlen((char *)portal_server_msg[i].portal_server_name) <=0)
	   	   continue;
       snprintf (buff, sizeof(buff),
                         "portal-server-name %s\n",
                         portal_server_msg[i].portal_server_name);
	   fputs (buff, fp);
       memset (buff, 0, BUFF_SIZE);
	   if (portal_server_msg[i].portal_server_ip)
	   {
         	snprintf(buff, BUFF_SIZE, 
				       "ip-address %d\n", 
				       portal_server_msg[i].portal_server_ip);
			fputs (buff, fp);
       		memset (buff, 0, BUFF_SIZE); 
	   }
	   snprintf(buff, BUFF_SIZE, 
	   	          "port-number %d\n", 
	   	          portal_server_msg[i].portal_server_port);
	   
   	   fputs (buff, fp);
       memset (buff, 0, BUFF_SIZE); 
	   if (strlen((char *)portal_server_msg[i].key_portal) >0)
	   {
       		snprintf(buff, BUFF_SIZE,
				       "key %s\n", 
				       portal_server_msg[i].key_portal);
			fputs (buff, fp);
       		memset (buff, 0, BUFF_SIZE);
		}
   	}
   fclose (fp);

   fp = fopen ("/etc/portal.free_rule.conf", "w+");
	if(fp == NULL)
    {   
        return 1;
    }   
   for (i = 0; i < PORTAL_FREE_RUULE_NUM; i++)
   {
   		if(portal_free_rule[i])
   		{
	   		memset (buff, 0, BUFF_SIZE);
			snprintf(buff, sizeof(buff),
				"Rule-Number %d\n"
				"portal_free_rule_ip %d\n"
				"\n",
				i,
				portal_free_rule[i]);
			fputs (buff, fp);
   		}
   }
   fclose (fp);
   
   return 0;
}

/*******************************************************************************
 ????  : portal_server_name_command_fn
 ????  : ??????portal???????
             portal server <server-name(string 1~32)>
 ????  : vm 
             input  
             cmd
 ????  : ?
 ? ? ?  : 0        ??
             ??     ??
--------------------------------------------------------------------------------
 ???????? : 
 ????  : 
 ????  : 
 ????  : 
*******************************************************************************/
static clib_error_t *
portal_server_name_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 * name_p = NULL;
  u32 parameter_num = 0;
  int rv = 0;
  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
  	return clib_error_return (0, "mandatory argument(s) missing");
  
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  	{
      if (unformat (line_input, " %s", &name_p))
      	{
           if ((strlen ((char *)name_p) >= 1) && (strlen ((char *)name_p) <= 32))
		   	  parameter_num++;
		   else
		   	 return clib_error_return (0, "Name is too short or too long");
	  }	  	
  }
  rv = portal_check_user_name (name_p);
  if (!rv)
  	return clib_error_return (0, "The name format error");
  if (parameter_num != 1)
  	return clib_error_return (0, "mandatory argument(s) missing");
  int i=0, id = 0;
  int index = PORTAL_SERVER_MAX;
  for (i=0; i<PORTAL_SERVER_MAX; i++)
  {  
	 if (strlen((char *)portal_server_msg[i].portal_server_name) <= 0)
	 	 index = i;
	 else if (!strcmp((char *)portal_server_msg[i].portal_server_name, (char *)name_p))
	 {
	 	 index = i;	
		 id = 1;
		 break;
	 }
  }
  if (index >= PORTAL_SERVER_MAX)
  	 return clib_error_return (0, "portal server number to the ceiling");
  if (!id)
  {
  	/*Portal ?????????,??????*/
	  portal_server_msg[index].portal_server_ip = 0;
	  memset (portal_server_msg[index].key_portal, 0, 64);
	  portal_server_msg[index].portal_server_port =  AUTH_PORT;
	  memset (portal_server_msg[index].portal_server_name, 0, 32);
	  /* ??Portal ??????? */
	  strcpy ((char *)(portal_server_msg[index].portal_server_name), (char *)(name_p));
	  vlib_cli_output(vm, "New portal server added .");
  }
  unformat_free (line_input);
  return 0;
}

/*******************************************************************************
 ????  : no_portal_server_name_command_fn
 ????  : ????????????portal?????????
             no portal server <server-name(string 1~32)>
 ????  : vm 
             input  
             cmd
 ????  : ?
 ? ? ?  : 0            ??
             ????     ??
--------------------------------------------------------------------------------
 ???????? : 
 ????  : 
 ????  : 
 ????  : 
*******************************************************************************/
static clib_error_t *
no_portal_server_name_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
   unformat_input_t _line_input, *line_input = &_line_input;
   u32 parameter_num = 0;
   u8 * name_p = NULL;
   
   /* Get a line of input. */
   if (!unformat_user (input, unformat_line_input, line_input))
  	 return clib_error_return (0, "mandatory argument(s) missing");
  
   while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  	{
      if (unformat (line_input, " %s", &name_p))
		   parameter_num++; 	
    }
   if (parameter_num != 1)
   	  return clib_error_return (0, "mandatory argument(s) missing");

   int i = 0;
   for (i=0; i<PORTAL_SERVER_MAX; i++)
   {  	 
      if (!strcmp ((char *)name_p, (char *)portal_server_msg[i].portal_server_name))
            break;
   	}
   if (i >= PORTAL_SERVER_MAX)
		return clib_error_return (0, "The name does not match");

    /* ??Portal ????????? */
   else
   	{
	   memset (portal_server_msg[i].portal_server_name, 0, 32);  
	   portal_server_msg[i].portal_server_ip = 0;
	   memset (portal_server_msg[i].key_portal, 0, 64);
   }
   
   unformat_free (line_input);   
   return 0;
}


int get_portal_server_index (u8 * name)
{
	int i=0;
	for (i=0; i< PORTAL_SERVER_MAX; i++)
	{
       if(!strcmp((char *)portal_server_msg[i].portal_server_name, (char *)name))
	   	   break;
	}
	return i;
}

/*******************************************************************************
 ????  : portal_server_ip_key_fn
 ????  : ??????portal??????IP???
             portal ip <ip-address> key simple <key-string(string 1~64)>
 ????  : vm 
             input  
             cmd
 ????  : ?
 ? ? ?  : 0        ??
             ??     ??
--------------------------------------------------------------------------------
 ???????? : 
 ????  : 
 ????  : 
 ????  : 
*******************************************************************************/

static clib_error_t *
portal_server_ip_key_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input; 
  char * ip;
  u8 * key;
  u8 * server_name;
  u8 ip_is_set = 0;
  u8 key_is_set = 0;
  u8 parameter_num = 0;
  
  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
	return clib_error_return (0, "mandatory argument(s) missing");	
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
       if (unformat (line_input, " %s", &ip))
	   	   ip_is_set++;
	   if (unformat (line_input, "key simple %s", &key))
	   	{
           if (strlen ((char *)key) < 1 || strlen ((char *)key) > 64)
		   	 return clib_error_return (0, "The key is too short or too long");
		   else	   
		      key_is_set++;
	   }
	   if (unformat (line_input, " %s", &server_name))
	   	  parameter_num++;
  	}
  if (!(ip_is_set && key_is_set && parameter_num))
  	 return clib_error_return (0, "mandatory argument(s) missing");

  int index_p = get_portal_server_index(server_name);
  if (0 <= index_p && index_p < PORTAL_SERVER_MAX)
   {
	/* ?? Portal ?????IP??? */
    portal_server_msg[index_p].portal_server_ip = inet_addr(ip);
    strcpy ((char *)portal_server_msg[index_p].key_portal, (char *)key);
  	}
  else
  	 return clib_error_return (0, "The portal server does not exist");
  unformat_free (line_input);
  return 0;
}

/*******************************************************************************
 ????  : no_portal_server_ip_key_fn
 ????  : ??????portal??????IP???
             portal no ip
 ????  : vm 
             input  
             cmd
 ????  : ?
 ? ? ?  : 0            ??
             ????     ??
--------------------------------------------------------------------------------
 ???????? : 
 ????  : 
 ????  : 
 ????  : 
*******************************************************************************/
static clib_error_t *
no_portal_server_ip_key_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	u8 * server_name;
    u32 parameter_num = 0;
		/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
	   return clib_error_return (0, "mandatory argument(s) missing");
	
	if (unformat (line_input, " %s", &server_name))
		parameter_num++;
	
	if (parameter_num)
	{  
	   int index_p = get_portal_server_index (server_name);
	   if (0 <= index_p && index_p < PORTAL_SERVER_MAX)
	   {
	       portal_server_msg[index_p].portal_server_ip = 0;
           memset (portal_server_msg[index_p].key_portal, 0, 64);
	   	}
	   else
		  return clib_error_return (0, "The portal server does not exist");
	}
	else 
	  return clib_error_return (0, "mandatory argument(s) missing");  
	
	unformat_free (line_input); 
	return 0;
}

/*******************************************************************************
 ????  : portal_server_port_command_fn
 ????  : ??????portal?????????
             portal port <port-number>
 ????  : vm 
             input  
             cmd
 ????  : ?
 ? ? ?  : 0        ??
             ??     ??
--------------------------------------------------------------------------------
 ???????? : 
 ????  : 
 ????  : 
 ????  : 
*******************************************************************************/
static clib_error_t *
portal_server_port_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input; 
	char * portal_port;
	u8 * server_name;
    u32 parameter_num = 0;
	/* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
	return clib_error_return (0, "mandatory argument(s) missing");	
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  	{
       if (unformat (line_input, " %s", &portal_port))
	      parameter_num++;  
	   if (unformat (line_input, " %s", &server_name))
	   	  parameter_num++;
  }
  if(parameter_num != 2)
	return clib_error_return (0, "mandatory argument(s) missing");
  int index_p = get_portal_server_index (server_name);
  	  /* ?? Portal ??????? Portal????? */
  if (0 <= index_p && index_p < PORTAL_SERVER_MAX)
     portal_server_msg[index_p].portal_server_port = atoi(portal_port);
  else
	 return clib_error_return (0, "The portal server does not exist");
  
  unformat_free (line_input);  
  return 0;
}

/*******************************************************************************
 ????  : no_portal_server_port_command_fn
 ????  : ??????portal??????,?????50100
             portal no port
 ????  : vm 
             input  
             cmd
 ????  : ?
 ? ? ?  : 0        ??
             ??     ??
--------------------------------------------------------------------------------
 ???????? : 
 ????  : 
 ????  : 
 ????  : 
*******************************************************************************/
static clib_error_t *
no_portal_server_port_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	u8 * server_name;
    u32 parameter_num = 0;
		/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
	   return clib_error_return (0, "mandatory argument(s) missing");
	
	if (unformat (line_input, " %s", &server_name))
		parameter_num++;
	
	if (parameter_num)
	{    /* ??????50100 */
	   int index_p = get_portal_server_index (server_name);
	   if (0 <= index_p && index_p < PORTAL_SERVER_MAX)
	   	  portal_server_msg[index_p].portal_server_port = AUTH_PORT;
	   else
	   	  return clib_error_return (0, "The portal server does not exist");
	}
    else
	   return clib_error_return (0, "mandatory argument(s) missing");

  unformat_free (line_input);  
  return 0;
}

/*******************************************************************************
 ????  : portal_web_server_name_command_fn
 ????  : ??????portal web?????
             portal web-server <server-name(string 1~32)>
 ????  : vm 
             input  
             cmd
 ????  : ?
 ? ? ?  : 0        ??
             ??     ??
--------------------------------------------------------------------------------
 ???????? : 
 ????  : 
 ????  : 
 ????  : 
*******************************************************************************/
static clib_error_t *
portal_web_server_name_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 * name_p = NULL;
  u32 parameter_num = 0;
  int rv = 0;
  
  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
  	return clib_error_return (0, "mandatory argument(s) missing");
  
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  	{
      if (unformat (line_input, " %s", &name_p))
      	{
           if((strlen ((char *)name_p) >= 1) && (strlen ((char *)name_p) <= 32))
		   	  parameter_num++;
		   else
		   	  return clib_error_return (0, "Name is too short or too long");
	  }	  	
  }  
  rv = portal_check_user_name (name_p);
  if (!rv)
  {
	unformat_free (line_input);
  	return clib_error_return (0, "The name format error");
  }
  if(parameter_num != 1)
  {	
	unformat_free (line_input);
  	return clib_error_return (0, "mandatory argument(s) missing");
  }  
  
  int i=0, id = 0;
  int index = PORTAL_WEBS_MAX; 
  for (i=0; i<PORTAL_WEBS_MAX; i++)
  {  
	 if (strlen((char *)portal_webs_msg[i].portal_webs_name)<=0)
	 	 index = i;
	 else if (!strcmp((char *)portal_webs_msg[i].portal_webs_name, (char *)name_p))
	 {
	 	 index = i;
		 id = 1;
		 break;
	 }
  }
  if (index>=PORTAL_WEBS_MAX)
  	 return clib_error_return (0, "portal web-server number to the ceiling");
  if (!id)
  {
	    /*Portal web???????,??????*/
	  memset (portal_webs_msg[index].webs_url, 0, 64);
	  memset (portal_webs_msg[index].portal_webs_name, 0, 32);

	   /*?? Portal Web ?????*/
	  strcpy ((char *)portal_webs_msg[index].portal_webs_name, (char *)name_p);
	  vlib_cli_output(vm, "New portal web-server added .");
  }
  unformat_free (line_input);
  return 0;
}

/*******************************************************************************
 ????  : no_portal_webs_name_command_fn
 ????  : ????????????portal web???????
             no portal web-server <server-name(string 1~32)>
 ????  : vm 
             input  
             cmd
 ????  : ?
 ? ? ?  : 0        ??
             ??     ??
--------------------------------------------------------------------------------
 ???????? : 
 ????  : 
 ????  : 
 ????  : 
*******************************************************************************/
static clib_error_t *
no_portal_webs_name_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
   unformat_input_t _line_input, *line_input = &_line_input; 
   u32 parameter_num = 0;
   u8 * name_p;
   
   /* Get a line of input. */
   if (!unformat_user (input, unformat_line_input, line_input))
  	 return clib_error_return (0, "mandatory argument(s) missing");
   
   while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
   {  
      if (unformat (line_input, " %s", &name_p))
		   parameter_num++;	
    }
   
   if (parameter_num != 1)
   	  return clib_error_return (0, "mandatory argument(s) missing"); 
   int i = 0;
   for (i=0; i<PORTAL_WEBS_MAX; i++)
   {
      if (!strcmp ((char *)name_p, (char *)portal_webs_msg[i].portal_webs_name))
            break;      
   }
   
   if (i >= PORTAL_WEBS_MAX)
		return clib_error_return (0, "The name does not match");
   /* ??Portal Web ???? ???URL?? */
   else 
   	{
   	   memset (portal_webs_msg[i].portal_webs_name, 0, 32);  
       memset (portal_webs_msg[i].webs_url, 0, 64);
   	}
   
   unformat_free (line_input);   
   return 0;
}

int get_portal_webs_index (u8 * name)
{
	int i=0;
	for (i=0; i< PORTAL_WEBS_MAX; i++)
	{
       if(!strcmp((char *)portal_webs_msg[i].portal_webs_name, (char *)name))
	   	   break;
	}
	return i;
}

/*******************************************************************************
 ????  : portal_web_server_url_command_fn
 ????  : ??????portal web????URL
             portal url <url-string>
 ????  : vm 
             input  
             cmd
 ????  : ?
 ? ? ?  : 0        ??
             ??     ??
--------------------------------------------------------------------------------
 ???????? : 
 ????  : 
 ????  : 
 ????  : 
*******************************************************************************/

static clib_error_t *
portal_web_server_url_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 * url;
  u8 * webs_name;
  u32 parameter_num = 0;
  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
      return clib_error_return (0, "mandatory argument(s) missing");
  
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  	{
      if (unformat (line_input, " %s", &url))
	  	 parameter_num++;
	  if (unformat (line_input, "%s", &webs_name))
	  	 parameter_num++;
  }
  if(parameter_num != 2)
    return clib_error_return (0, "mandatory argument(s) missing"); 

  int index_p = get_portal_webs_index(webs_name);
  if (0 <= index_p && index_p < PORTAL_WEBS_MAX)
      strcpy ((char *)portal_webs_msg[index_p].webs_url, (char *)url);
  else
  	 return clib_error_return (0, "The portal server does not exist");
  /* ??Portal Web ????URL */
  unformat_free (line_input); 
  return 0;
  
}

/*******************************************************************************
 ????  : no_portal_webs_url_command_fn
 ????  : ??????portal web???URL
             no portal web-server <server-name(string 1~32)>
 ????  : vm 
             input  
             cmd
 ????  : ?
 ? ? ?  : 0        ??
             ??     ??
--------------------------------------------------------------------------------
 ???????? : 
 ????  : 
 ????  : 
 ????  : 
*******************************************************************************/
static clib_error_t *
no_portal_webs_url_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input; 
	u32 parameter_num = 0;
	u8 * webs_name;
	
	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
	  return clib_error_return (0, "mandatory argument(s) missing");
	
	while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{  
	   if (unformat (line_input, " %s", &webs_name))
			parameter_num++; 
	 }	
	if (parameter_num != 1)
	   return clib_error_return (0, "mandatory argument(s) missing"); 
    int index_p = get_portal_webs_index(webs_name);
    if (0 <= index_p && index_p < PORTAL_WEBS_MAX)
		memset (portal_webs_msg[index_p].webs_url, 0, 64);
	else
		return clib_error_return (0, "The portal server does not exist");
   unformat_free (line_input); 
   return 0;
}

static clib_error_t *
portal_enable_method_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    u32 parameter_num = 0;
	int if_sw_index = ~0;
	vnet_main_t * vnm = vnet_get_main();
	 /*  Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
  	    return clib_error_return (0, "mandatory argument(s) missing");
	while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
		if (unformat (line_input, "direct"))
  	       parameter_num++;
	   else if (unformat (line_input, "layer3"))
		   return clib_error_return (0, "Don't have the enabling type");
	   else if (unformat (line_input, "redhcp"))
		   return clib_error_return (0, "Don't have the enabling type");

	  if (! unformat_user (line_input, unformat_vnet_sw_interface, vnm, &if_sw_index))
 			return clib_error_return (0, "index error");
	}
	if(!parameter_num)
	   return clib_error_return (0, "mandatory argument(s) missing");

  vnet_interface_config * node = get_interface_message_by_sw_index (if_sw_index);
  if (node == NULL)
  	 return clib_error_return (0, "interface error");
  node->if_portal.enable_portal= ENABLE_PORTAL;

  vnet_sw_interface_t *hi = vnet_get_sw_interface (vnm, if_sw_index);
  hi->portal_index_info.portal_info.enable_portal = ENABLE_PORTAL;
  unformat_free (line_input);
  return 0;
}


static clib_error_t *
no_portal_enable_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	int if_sw_index = ~0;
	vnet_main_t * vnm = vnet_get_main();
	   /* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
	  return clib_error_return (0, "mandatory argument(s) missing");

	if (! unformat_user (line_input, unformat_vnet_sw_interface, vnm, &if_sw_index))
		 return clib_error_return (0, "index error");
	/* ?????,????????,??????? */
	vnet_interface_config * node = get_interface_message_by_sw_index(if_sw_index);
	 if (node == NULL)
		  return clib_error_return (0, "interface error");
	  node->if_portal.enable_portal = DISABLE_PORTAL;

  	 vnet_sw_interface_t *hi = vnet_get_sw_interface (vnm, if_sw_index);
	 hi->portal_index_info.portal_info.enable_portal = DISABLE_PORTAL;

	unformat_free (line_input);
	return 0;

}


static clib_error_t *
portal_apply_web_server_command_fn(vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 * name_p;
  u32 parameter_num = 0;
  int sw_if_index = ~0;
  vnet_main_t * vnm = vnet_get_main();
  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
  	return clib_error_return (0, "mandatory argument(s) missing");
  
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  	{
      if (unformat (line_input, " %s", &name_p))
      	{
           if((strlen ((char *)name_p) >= 1) && (strlen ((char *)name_p) <= 32))
		   	 parameter_num++;
		   else
		   	return clib_error_return (0, "Name is too short or too long");
	  }
	  if (! unformat_user (line_input, unformat_vnet_sw_interface, vnm, &sw_if_index))
 			return clib_error_return (0, "index error");
  }
  if(!parameter_num)
 	 return clib_error_return (0, "mandatory argument(s) missing");

  int i = 0;
  for (i=0; i<PORTAL_WEBS_MAX; i++)
  {
 	 /* ??Portal Web ??? */
     if(!strcmp ((char *)name_p, (char *)portal_webs_msg[i].portal_webs_name))
	 	break;       
  }
  if (i >= PORTAL_WEBS_MAX)
  	  return clib_error_return (0, "Reference to failure");//????
  /* Access interface node */
  vnet_interface_config * node = get_interface_message_by_sw_index(sw_if_index);
  if (node == NULL)
  	  return clib_error_return (0, "interfacesss error");
  
  int j = 0;
  for (j=0; j<PORTAL_SERVER_MAX; j++)
  {
     if(!strcmp ((char *)name_p, (char *)portal_server_msg[j].portal_server_name))
	 	break;
  }
  if (j >= PORTAL_SERVER_MAX)
  	 return clib_error_return (0, "Failure associated with portal server");//????
  memset(node->if_portal.apply_webs, 0, 32);	 
  strcpy((char *)node->if_portal.apply_webs, (char *)name_p);
  node->if_portal.webs_index = i;
  
  //The subscript into interface structure
  gs_portal_server = portal_server_msg[j].portal_server_ip;
  vnet_sw_interface_t *hi = vnet_get_sw_interface (vnm, sw_if_index);
  hi->portal_index_info.portal_webs_index = i;
  hi->portal_index_info.portal_server_index = j;

  memset(hi->portal_index_info.portal_info.apply_webs, 0, 32);	
  strcpy((char*)hi->portal_index_info.portal_info.apply_webs, (char *)node->if_portal.apply_webs);

  PORTAL_REDIRECT_INFO portal_info;
  memset(&portal_info, 0, sizeof(PORTAL_REDIRECT_INFO));

  portal_info.index = sw_if_index;
    struct in_addr client_addr;
    char IPdotdec[MAX_IP_LEN];          //存放点分十进制IP地址  
    client_addr.s_addr = htonl(node->ip_address);

    memset(IPdotdec, 0, sizeof(IPdotdec));
    inet_ntop(AF_INET, &client_addr, IPdotdec,  sizeof(IPdotdec)); 

  
  memcpy(portal_info.nasip, IPdotdec,
  		clib_min(sizeof(portal_info.nasip), strlen(IPdotdec)));
  memcpy(portal_info.url, portal_webs_msg[i].webs_url,
  		clib_min(sizeof(portal_info.url), strlen((const char*)portal_webs_msg[i].webs_url)));

  memcpy(portal_info.nasid, hi->portal_index_info.portal_info.nas_id,
		clib_min(sizeof(portal_info.nasid), strlen((const char*)(hi->portal_index_info.portal_info.nas_id))));

  makeJson_data_thoughput_display((u_int16_t)MODULE_PORTAL, (u_int16_t)OP_PORTAL_ADD,
            (Json_msg_handler)Json_add_redirect_data, (void *)(&portal_info));

  ///////////////sw_if_index	node->ip_address   portal_webs_msg[i].webs_url
  			/////////////////hi->portal_index_info.portal_info.nas_id

  unformat_free (line_input);
  return 0;  
}


static clib_error_t *
no_portal_apply_webs_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
   unformat_input_t _line_input, *line_input = &_line_input;
   int sw_if_index = ~0;
   vnet_main_t * vnm = vnet_get_main();
     /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
  	return clib_error_return (0, "mandatory argument(s) missing");

  if (! unformat_user (line_input, unformat_vnet_sw_interface, vnm, &sw_if_index))
	  return clib_error_return (0, "index error");

  /* ?????,????????,??????? */
  vnet_interface_config * node = get_interface_message_by_sw_index(sw_if_index);
  if (node == NULL)
  	    return clib_error_return (0, "interface error");
  memset(node->if_portal.apply_webs, 0 , 32);
  node->if_portal.webs_index = PORTAL_WEBS_MAX;
  gs_portal_server = 0;
  vnet_sw_interface_t *hi = vnet_get_sw_interface (vnm, sw_if_index);
  hi->portal_index_info.portal_webs_index = PORTAL_WEBS_MAX;
  hi->portal_index_info.portal_server_index = PORTAL_SERVER_MAX;

  PORTAL_REDIRECT_INFO portal_info;
  memset(&portal_info, 0, sizeof(PORTAL_REDIRECT_INFO));

  portal_info.index = sw_if_index;

  makeJson_data_thoughput_display((u_int16_t)MODULE_PORTAL, (u_int16_t)OP_PORTAL_DEL,
            (Json_msg_handler)Json_del_redirect_data, &portal_info);


  ////////////////  sw_if_index



  unformat_free (line_input);
  return 0;
}


static clib_error_t *
portal_bas_ip_command_fn(vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  char * ip;
  int sw_if_index = ~0;
  u32 parameter_num = 0;
  vnet_main_t * vnm = vnet_get_main();
  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
  	return clib_error_return (0, "mandatory argument(s) missing");
  
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  	{
      if (unformat (line_input, " %s", &ip))
      	 parameter_num++;
	  if (! unformat_user (line_input, unformat_vnet_sw_interface, vnm, &sw_if_index))
		  return clib_error_return (0, "index error");
	  
  }
  if(!parameter_num )
     return clib_error_return (0, "mandatory argument(s) missing");

   /* ?????,????????,??Bas-ip */
  vnet_interface_config * node = get_interface_message_by_sw_index(sw_if_index);
  if (node == NULL)
  	 return clib_error_return (0, "interface error");
  node->if_portal.portal_bas_ip = inet_addr(ip);
  vnet_sw_interface_t *hi = vnet_get_sw_interface (vnm, sw_if_index);
  hi->portal_index_info.portal_info.portal_bas_ip = node->if_portal.portal_bas_ip;
  gs_bas_ip = inet_addr(ip);
  unformat_free (line_input); 
  return 0;

}

static clib_error_t *
no_portal_bas_ip_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
	int sw_if_index = ~0;
	vnet_main_t * vnm = vnet_get_main();
	  /* Get a line of input. */
  	if (!unformat_user (input, unformat_line_input, line_input))
  		return clib_error_return (0, "mandatory argument(s) missing");


 	if (! unformat_user (line_input, unformat_vnet_sw_interface, vnm, &sw_if_index))
	 	return clib_error_return (0, "index error");

    /* ?????,????????,??Bas-ip */
  	vnet_interface_config * node = get_interface_message_by_sw_index(sw_if_index);
  	if (node == NULL)
	    return clib_error_return (0, "interface error");

	 node->if_portal.portal_bas_ip = 0;
	 gs_bas_ip = 0;
    vnet_sw_interface_t *hi = vnet_get_sw_interface (vnm, sw_if_index);
  	hi->portal_index_info.portal_info.portal_bas_ip = 0;	
  	unformat_free (line_input); 
 	return 0;
}

int check_nas_id(char *name)
{
    int i;
    char *tmp = name;
    //printf("%s\n" , tmp);
    for(i = 0; i < strlen(name); i++)
    {   
        if(*tmp == 92 || *tmp == '|' || *tmp+i == '/' || *tmp == ';' 
			|| *tmp == '*' || *tmp == '?' || *tmp == '<' || *tmp == '>' )
        {
            return 0;
        }   
        tmp++;
    }   
    return 1;
	
}

static clib_error_t *
portal_nas_id_command_fn(vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  	unformat_input_t _line_input, *line_input = &_line_input;
  	char * nas_id;
  	int sw_if_index = ~0;
  	u32 parameter_num = 0;
  	vnet_main_t * vnm = vnet_get_main();
  	/* Get a line of input. */
  	if (!unformat_user (input, unformat_line_input, line_input))
  		return clib_error_return (0, "mandatory argument(s) missing");
  
  	while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  	{
      	if (unformat (line_input, " %s", &nas_id))
      	 	parameter_num++;
	  	if (! unformat_user (line_input, unformat_vnet_sw_interface, vnm, &sw_if_index))
		  	return clib_error_return (0, "index error");
	  
  	}
  	if(!parameter_num )
     	return clib_error_return (0, "mandatory argument(s) missing");

  	int ret = check_nas_id(nas_id);
	if(ret == 0)
		return clib_error_return (0, "nas id input error");
   	/* ?????,????????,??nas-id */
  	vnet_interface_config * node = get_interface_message_by_sw_index(sw_if_index);
  	if (node == NULL)
  	 	return clib_error_return (0, "interface error");

    memset(node->if_portal.nas_id, 0, 20);
  	strcpy((char *)node->if_portal.nas_id, (char *)nas_id);
  	vnet_sw_interface_t *hi = vnet_get_sw_interface (vnm, sw_if_index);
	memset(hi->portal_index_info.portal_info.nas_id, 0, 20);
  	strcpy((char *)hi->portal_index_info.portal_info.nas_id, (char *)nas_id);

  	unformat_free (line_input); 
  	return 0;

}


static clib_error_t *
no_portal_nas_id_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
	int sw_if_index = ~0;
	vnet_main_t * vnm = vnet_get_main();
	  /* Get a line of input. */
  	if (!unformat_user (input, unformat_line_input, line_input))
  		return clib_error_return (0, "mandatory argument(s) missing");


 	if (! unformat_user (line_input, unformat_vnet_sw_interface, vnm, &sw_if_index))
	 	return clib_error_return (0, "index error");

    /* ?????,????????,??nas-id */
  	vnet_interface_config * node = get_interface_message_by_sw_index(sw_if_index);
  	if (node == NULL)
	    return clib_error_return (0, "interface error");

  	memset(&(node->if_portal.nas_id), 0, 20);
  	vnet_sw_interface_t *hi = vnet_get_sw_interface (vnm, sw_if_index);
  	memset(hi->portal_index_info.portal_info.nas_id , 0, 20);

  	unformat_free (line_input);
  	return 0;
}

/*******************************************************************************
 函数名称  : search_portal_free_rule
 功能描述  : 查找白名单数组
 输入参数  :	num  	数组下标
 			dst_ip	IP地址
 输出参数  : 无
 返 回 值  : -1	此数组中已经存有IP地址
 		    -2	数组中存有相同的IP地址
 		    i	大于0的数
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 
*******************************************************************************/
int search_portal_free_rule(int num, u32 dst_ip)
{
	int i = 0;
	if(portal_free_rule[num] != 0)
		return -1;
	for(i = 0; i < PORTAL_FREE_RUULE_NUM; i++)
	{
		if(portal_free_rule[i] == dst_ip)
			return -2;
	}
	return i;
}

static clib_error_t *
portal_free_rule_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;

	int free_rule_num, num_m_args = 0;
	char * dst_ip;
	u32 ip_addr;
	
	if (!unformat_user (input, unformat_line_input, line_input))
	return 0;

	while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
		if (unformat (line_input, "%d", &free_rule_num))
			num_m_args++;
		if (unformat (line_input, "destination ip %s", &dst_ip))
			num_m_args++;
		else
			return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
	}
	unformat_free (line_input);

	if (num_m_args < 2)
		return clib_error_return (0, "mandatory argument(s) missing");

	if(free_rule_num < 0 || free_rule_num > 255)
	{
  		vlib_cli_output(vm, "free_rule_num %d should 0~256 !\n", free_rule_num);
		return 0;
  	}

	ip_addr = inet_addr(dst_ip);
	int ret_num = search_portal_free_rule(free_rule_num, ip_addr);
	if(ret_num < 0)/* 此白名单数组中有IP地址或数组中有相同IP地址 */
		return clib_error_return (0, "this num or ip_address has used");
	add_white_rule_user_by_ip(&ip_addr);
	portal_free_rule[free_rule_num] = ip_addr;

	unformat_free (line_input);
	return 0;
}


static clib_error_t *
no_portal_free_rule_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;

	int num_m_args = 0;
	int if_all = 0;
	int free_rule_num = -1;
	if (!unformat_user (input, unformat_line_input, line_input))
	return 0;

	while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
		if (unformat (line_input, " all"))
		{
		 	if_all = 1;
			num_m_args++;
		}
		else if (unformat (line_input, "%d", &free_rule_num))
		  num_m_args++; 
		else
			return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
	}
	unformat_free (line_input);

	if (num_m_args < 1)
		return clib_error_return (0, "mandatory argument(s) missing");

	
	int ret_num;
	if(if_all)
	{
		int i;
		for(i = 0; i < PORTAL_FREE_RUULE_NUM; i++)
		{
			ret_num	= search_portal_free_rule(i, -1);
			if(ret_num == -1)/* 白名单数组中有IP地址 */
			{
				del_white_rule_user_by_ip(&portal_free_rule[i]);
				portal_free_rule[i] = 0;
			}
		}
	}
	
	else if(free_rule_num < 0 || free_rule_num > 255)
	{
  		clib_error_return(0, "free_rule_num %d should 0~256 !\n", free_rule_num);
  	}
	else
	{
		int i = free_rule_num;
		ret_num = search_portal_free_rule(i, -1);
		if(ret_num == -1)
		{
			del_white_rule_user_by_ip(&portal_free_rule[i]);
			portal_free_rule[i] = 0;
		}
	}
	
	
	unformat_free (line_input);
	return 0;
}


static clib_error_t *
display_portal_free_rule_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;

	int num_m_args = 0;
	int if_all = 0;
	int free_rule_num = 0;
	
	if (!unformat_user (input, unformat_line_input, line_input))
		return 0;

	while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
		if (unformat (line_input, " all"))
		{
		 	if_all = 1;
			num_m_args++;
		}
		else if (unformat (line_input, "%d", &free_rule_num))
		  num_m_args++; 
		else
			return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
	}
	unformat_free (line_input);

	if (num_m_args < 1)
		return clib_error_return (0, "mandatory argument(s) missing");

	
	int ret_num;
	struct in_addr ip;
	if(if_all)
	{
		int i = 0;
		for(i = 0; i < PORTAL_FREE_RUULE_NUM; i++)
		{
			ret_num	= search_portal_free_rule(i, -1);
			if(ret_num == -1)/* 白名单数组中有IP地址 */
			{
				memcpy(&ip, &(portal_free_rule[i]), 4);
				vlib_cli_output(vm, "Rule-Number: %d\n"
									"Destination:\n"
									" IP     : %s\n",
									i,inet_ntoa(ip));
			}
		}
		return 0;
	}
	
	if(free_rule_num < 0 || free_rule_num > 255)
	{
  		vlib_cli_output(vm, "free_rule_num %d should 0~256 !\n", free_rule_num);
		return 0;
  	}
	else
	{
		ret_num = search_portal_free_rule(free_rule_num, -1);
		if(ret_num == -1)/* 白名单数组中有IP地址 */
		{
			memcpy(&ip, &(portal_free_rule[free_rule_num]), 4);
			vlib_cli_output(vm, "Rule-Number: %d\n"
								"Destination:\n"
								" IP     : %s\n",
								free_rule_num, inet_ntoa(ip));
		}
		
	}
	
	
	unformat_free (line_input);
	return 0;
}
void
display_online_user(l7portal_user_info * user_info, int index)
{
    vlib_main_t *vm = vlib_get_main ();
	char buff[1024];
	struct in_addr addr;
	memcpy (&addr, &(user_info->ip), 4);
	if (gs_portal_user_online_num == 0)
		vlib_cli_output (vm, "Total portal users：0\n");
	else
	{
	snprintf (buff, sizeof(buff),
		  "Total portal users：%d\n"
		  "Username: %s\n"
		  "  Portal server: %s\n"
		  "  State: Online\n"
		  "  VPN instance: --\n"
		  "  MAC				  IP			  VLAN	  Interface\n"
		  "  %s 				  %s			  --	  %s\n",
		  gs_portal_user_online_num,
		  user_info->req_auth_msg.user_name,
		  portal_server_msg[index].portal_server_name,
		  user_info->mac,
		  inet_ntoa(addr),
		  user_info->interface);  
	vlib_cli_output (vm, "%s", buff);
	}
}

static clib_error_t *
display_portal_user_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
   unformat_input_t _line_input, *line_input = &_line_input;   
   vnet_main_t *vnm = vnet_get_main ();
   u8 * if_id;
   u8 * if_type;
   u8 * if_name = NULL;
   int num_all =0, num_if =0;
   int sw_if_index = ~0;
   vnet_sw_interface_t * hi = NULL;
   int server_index;
   
   if (!unformat_user (input, unformat_line_input, line_input))
  	 return clib_error_return (0, "mandatory argument(s) missing");
   
   while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	   if (unformat (line_input, " all"))
		  num_all = 1;
	   else if (unformat (line_input, " interface %s %s", &if_type, &if_id))
		  num_if = 1;  
   }
   if (num_all)
   {
	  l7portal_user_info *user_info = NULL;		
	  int i;	
	  for(i = 0; i < PORTAL_USER_ONLINE_HASH_SIZE; i++)		  	
	  {		
			//判断链表是否查找完
			rte_spinlock_lock(&porta_user_online_hash[i].userlock);
			dl_list_for_each(user_info, &(porta_user_online_hash[i].userlist), l7portal_user_info, list)//遍历节点		
			{  
				 hi = vnet_get_sw_interface (vnm, user_info->sw_if_index);
				 int server_index = hi->portal_index_info.portal_server_index;
				 display_online_user(user_info, server_index);
				
			}
			rte_spinlock_unlock(&porta_user_online_hash[i].userlock);
		}   
   }
 		
   else if (num_if)
   {
	  unformat_input_t * if_input = NULL;
	  sprintf ((char *)if_name, "%s%s", (char *)if_type, (char *)if_id);
	  
	  unformat_init_vector(if_input, if_name);
	  unformat_user (if_input, unformat_vnet_sw_interface, vnm, &sw_if_index);
	
	  l7portal_user_info *user_info = NULL;		
	  int i;	
	  for(i = 0; i < PORTAL_USER_ONLINE_HASH_SIZE; i++)	
	  	
	  {			
			//判断链表是否查找完	
			rte_spinlock_lock(&porta_user_online_hash[i].userlock);
			dl_list_for_each(user_info, &(porta_user_online_hash[i].userlist), l7portal_user_info, list)//遍历节点		
			{  
				if(user_info->sw_if_index == sw_if_index)
				{
				  hi = vnet_get_sw_interface (vnm, sw_if_index);
	              server_index = hi->portal_index_info.portal_server_index;
				  display_online_user(user_info, server_index);
				}
			}	
			rte_spinlock_unlock(&porta_user_online_hash[i].userlock);
		}   
   }
	else
		return clib_error_return (0, "mandatory argument(s) missing");
  
    unformat_free (line_input);
    return 0;
}


static clib_error_t *
show_qos_carl_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
    int carl_index;
	struct in_addr addr;
	if (!unformat_user (input, unformat_line_input, line_input))
  		return clib_error_return (0, "mandatory argument(s) missing1");
	if(unformat_check_input (line_input) == UNFORMAT_END_OF_INPUT){
		for(int i=1;i<200;i++){
			if(qos_carl_msg[i].carl_index==0)
				continue;
			memcpy(&addr,&qos_carl_msg[i].ip_address,4);
			vlib_cli_output(vm,"qos carl %d %s subnet %s %d\n",
			qos_carl_msg[i].carl_index,
			qos_carl_msg[i].ip_flag,
			inet_ntoa(addr),
			qos_carl_msg[i].mask_length);

		}
		return 0;
	}
	if (!unformat (line_input, " %u", &carl_index))
		return clib_error_return (0, "mandatory argument(s) missing2");
	if(carl_index<=0||carl_index>199)
		return clib_error_return (0, "carl-index range 1-199");
	if(qos_carl_msg[carl_index].carl_index==0)
		return clib_error_return (0, "no carl-index");
	memcpy(&addr,&qos_carl_msg[carl_index].ip_address,4);
	vlib_cli_output(vm,"qos carl %d %s subnet %s %d\n",
		qos_carl_msg[carl_index].carl_index,
		qos_carl_msg[carl_index].ip_flag,
		inet_ntoa(addr),
		qos_carl_msg[carl_index].mask_length);
	unformat_free (line_input); 
	return 0;
}
static clib_error_t *
show_qos_car_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;

	int sw_if_index = ~0;
	u8* name;
	vnet_main_t * vnm = vnet_get_main();
	if (!unformat_user (input, unformat_line_input, line_input))
  		return clib_error_return (0, "mandatory argument(s) missing1");
	name = line_input->buffer;
	if (! unformat_user (line_input, unformat_vnet_sw_interface, vnm, &sw_if_index))
		  return clib_error_return (0, "index error");

	for(int i=0;i<qos_interface[sw_if_index].inbound_index;i++){
	if(qos_interface[sw_if_index].interface_car_inbound[i]==NULL)
		continue;
	if(qos_interface[sw_if_index].interface_car_inbound[i]->any_flag==0)
	vlib_cli_output(vm,"Interface: %s\n Direction: Inbound\nRule(s):\
		If-match %d\nCIR %d (kbps),  CBS %d (byte)\n",name,
		qos_interface[sw_if_index].interface_car_inbound[i]->carl_index,
		qos_interface[sw_if_index].interface_car_inbound[i]->cir,
		qos_interface[sw_if_index].interface_car_inbound[i]->cbs);
	if(qos_interface[sw_if_index].interface_car_inbound[i]->any_flag==1)
	vlib_cli_output(vm,"Interface: %s\n Direction: Inbound\nRule(s):\
		If-match ANY\nCIR %u (kbps),  CBS %d (byte)\n",name,
		qos_interface[sw_if_index].interface_car_inbound[i]->cir,
		qos_interface[sw_if_index].interface_car_inbound[i]->cbs);
		}
	for(int i=0;i<qos_interface[sw_if_index].outbound_index;i++){
	if(qos_interface[sw_if_index].interface_car_outbound[i]==NULL)
		continue;
	if(qos_interface[sw_if_index].interface_car_outbound[i]->any_flag==0)
	vlib_cli_output(vm,"Interface: %s\n Direction: Outbound\nRule(s):\
		If-match %d\nCIR %d (kbps),  CBS %d (byte)\n",name,
		qos_interface[sw_if_index].interface_car_outbound[i]->carl_index,
		qos_interface[sw_if_index].interface_car_outbound[i]->cir,
		qos_interface[sw_if_index].interface_car_outbound[i]->cbs);
	if(qos_interface[sw_if_index].interface_car_outbound[i]->any_flag==1)
	vlib_cli_output(vm,"Interface: %s\n Direction: Outbound\nRule(s):\
		If-match ANY\nCIR %u (kbps),  CBS %d (byte)\n",name,
		qos_interface[sw_if_index].interface_car_outbound[i]->cir,
		qos_interface[sw_if_index].interface_car_outbound[i]->cbs);
		}
	unformat_free (line_input); 	
	return 0;
}
static clib_error_t *
no_qos_carl_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
   unformat_input_t _line_input, *line_input = &_line_input;
   int carl_index;
	if (!unformat_user (input, unformat_line_input, line_input))
  		return clib_error_return (0, "mandatory argument(s) missing1");
		
	if (!unformat (line_input, " %d", &carl_index))
		return clib_error_return (0, "mandatory argument(s) missing2");
	if(carl_index==0||carl_index>199)
		return clib_error_return (0, "carl-index range 1-199");
	if(qos_carl_msg[carl_index].carl_index == 0)
		return clib_error_return (0, "no carl-index");

		qos_carl_msg[carl_index].carl_index= 0;
		memset(qos_carl_msg[carl_index].ip_flag,0,sizeof(qos_carl_msg[carl_index].ip_flag));
		qos_carl_msg[carl_index].ip_address= 0;
		qos_carl_msg[carl_index].mask_length= 0;
		FILE* fin;
		FILE* fout;
		int index;
		index = 0;
		
		char buf[60];
		fin=fopen("/etc/qos_carl.config","a+");
		fout=fopen("/etc/qos_carl.tmp","a+");
		while(fgets(buf,sizeof(buf),fin)){
			sscanf(buf,"%u %*s %*s %*s",&index);
			if(index==carl_index)
				continue;
			else
				fprintf(fout,"%s",buf);
		}
		fclose(fin);  
        fclose(fout);  
  
        remove("/etc/qos_carl.config");  
        rename("/etc/qos_carl.tmp","/etc/qos_carl.config");
		


unformat_free (line_input); 
return 0;
}
static clib_error_t *
no_qos_car_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
   unformat_input_t _line_input, *line_input = &_line_input;
   int carl_index=0;
   char* flag;
   char* tmp;
   int ret = 0;
   int sw_if_index = ~0;
   int qos_int_index;
   u8* interface_name;
	vnet_main_t * vnm = vnet_get_main();
	if (!unformat_user (input, unformat_line_input, line_input))
  		return clib_error_return (0, "mandatory argument(s) missing1");
	
		
	if (!unformat (line_input, " %s", &flag))
		return clib_error_return (0, "mandatory argument(s) missing2");
	
	if (!unformat (line_input, " %s", &tmp))
		return clib_error_return (0, "mandatory argument(s) missing2");
	
	if(strcmp(tmp,"any")==0)
	ret = 1;
	else{
		if (!unformat (line_input, " %d", &carl_index))
		return clib_error_return (0, "mandatory argument(s) missing3");
		if(carl_index<=0||carl_index>199)
		return clib_error_return (0, "carl-index range 1-199");
		}
	interface_name = line_input->buffer;
	if (! unformat_user (line_input, unformat_vnet_sw_interface, vnm, &sw_if_index))
		  return clib_error_return (0, "index error");
	if(strcmp(flag,"inbound")==0){
		qos_int_index = qos_interface[sw_if_index].inbound_index;
		if(ret==1){
			for(int i=0;i<qos_int_index;i++){
				if(qos_interface[sw_if_index].interface_car_inbound[i]==NULL)
					continue;
			if(qos_interface[sw_if_index].interface_car_inbound[i]->any_flag==1){
				qos_interface[sw_if_index].interface_car_inbound[i]=NULL;
				int j=i;
				while(qos_interface[sw_if_index].interface_car_inbound[j+1]!=NULL){
					qos_interface[sw_if_index].interface_car_inbound[j]=qos_interface[sw_if_index].interface_car_inbound[j+1];
					j++;
				}
				qos_interface[sw_if_index].inbound_index--;}
		}}else{
		for(int i=0;i<qos_int_index;i++){
			if(qos_interface[sw_if_index].interface_car_inbound[i]==NULL)
					continue;
			if(qos_interface[sw_if_index].interface_car_inbound[i]->carl_index==carl_index){
				qos_interface[sw_if_index].interface_car_inbound[i]=NULL;
				int j=i;
				while(qos_interface[sw_if_index].interface_car_inbound[j+1]!=NULL){
					qos_interface[sw_if_index].interface_car_inbound[j]=qos_interface[sw_if_index].interface_car_inbound[j+1];
					j++;
				}
			qos_interface[sw_if_index].inbound_index--;}
		}}
		
		}
	else if(strcmp(flag,"outbound")==0){
		qos_int_index = qos_interface[sw_if_index].outbound_index;
		if(ret==1){
			for(int i=0;i<qos_int_index;i++){
				if(qos_interface[sw_if_index].interface_car_outbound[i]==NULL)
					continue;
			if(qos_interface[sw_if_index].interface_car_outbound[i]->any_flag==1){
				qos_interface[sw_if_index].interface_car_outbound[i]=NULL;
				int j=i;
				while(qos_interface[sw_if_index].interface_car_outbound[j+1]!=NULL){
					qos_interface[sw_if_index].interface_car_outbound[j]=qos_interface[sw_if_index].interface_car_outbound[j+1];
					j++;
				}
				qos_interface[sw_if_index].outbound_index--;}
		}}else{
		for(int i=0;i<qos_int_index;i++){
			if(qos_interface[sw_if_index].interface_car_outbound[i]==NULL)
					continue;
			if(qos_interface[sw_if_index].interface_car_outbound[i]->carl_index==carl_index){
				qos_interface[sw_if_index].interface_car_outbound[i]=NULL;
			    int j=i;
				while(qos_interface[sw_if_index].interface_car_outbound[j+1]!=NULL){
					qos_interface[sw_if_index].interface_car_outbound[j]=qos_interface[sw_if_index].interface_car_outbound[j+1];
					j++;
				}
				qos_interface[sw_if_index].outbound_index--;}
		}}
		
		}
	else
		return clib_error_return (0, "mandatory argument(s) error");
		//qos_interface[1].interface_car_inbound[carl_index]->carl_index= 0;
		
		FILE* fin;
		FILE* fout;
		int index;
		char boundChar[40];
		char buf[200];
		char name[40];
		//vlib_cli_output(vm, "~~~~~~~~~~~~~~~~\n");
		fin=fopen("/etc/qos_car.config","a+");
		fout=fopen("/etc/qos_car.tmp","a+");
		//vlib_cli_output(vm, "------------------\n");
		while(fgets(buf,sizeof(buf),fin)){
			sscanf(buf,"%s %*s %d cir %*s cbs %*s %s\n",boundChar,&index,name);
		if(strcmp((char*)name,(char*)interface_name)==0){
			if(strcmp(boundChar,flag)==0){
			    if(index == 0){
				if(ret==1)
				continue;
				if(ret==0)
				fprintf(fout,"%s",buf);
				}else{
				if(index==carl_index)
				continue;
				if(index!=carl_index)
				fprintf(fout,"%s",buf);
				}
				}
			else
			{fprintf(fout,"%s",buf);}
			}
			else
			{fprintf(fout,"%s",buf);}	
		}
        fclose(fout);  
  		fclose(fin);
        remove("/etc/qos_car.config");  
        rename("/etc/qos_car.tmp","/etc/qos_car.config");


unformat_free (line_input); 
return 0;
}
static clib_error_t *
qos_carl_restore_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{   
	qos_carl_restore();
	return 0;
}
static clib_error_t *
qos_car_restore_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{   
	qos_carl_restore();
	return 0;
}


static clib_error_t *
qos_carl_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
	u32 carl_index;
	u8* ip_flag;
	char* ip_address;
	int mask_length;
	int match_flag = 0;
  	if (!unformat_user (input, unformat_line_input, line_input))
  		return clib_error_return (0, "mandatory argument(s) missing1");
		
	if (!unformat (line_input, " %d", &carl_index))
		return clib_error_return (0, "mandatory argument(s) missing2");
	if(carl_index<=0||carl_index>199)
		return clib_error_return (0, "carl-index range 1-199");
	if (!unformat (line_input, " %s", &ip_flag))
		return clib_error_return (0, "mandatory argument(s) missing3");
	if(strcmp((char*)ip_flag,"source-ip-address")==0)
		match_flag = 0;
	else if(strcmp((char*)ip_flag,"destination-ip-address")==0)
		match_flag = 1;
	else
		return clib_error_return (0, "wrong input");
	if (!unformat (line_input, " subnet %s", &ip_address))
		return clib_error_return (0, "mandatory argument(s) missing4");
	if (!unformat (line_input, " %d", &mask_length))
		return clib_error_return (0, "mandatory argument(s) missing5");
	if(mask_length<17||mask_length>31)
		return clib_error_return (0, "mask_length too long or too short(17-31)");
      for(int i=0;i<200;i++){
		if(qos_carl_msg[i].carl_index == 0)
			continue;
		if(strcmp((char*)qos_carl_msg[i].ip_flag,(char*)ip_flag)==0){
		  if(qos_carl_msg[i].ip_address==inet_addr(ip_address)){
			if(qos_carl_msg[i].mask_length==mask_length)
				return clib_error_return (0, "Object repeats") ;
		  }
		}
      	}
		qos_carl_msg[carl_index].carl_index = carl_index;
        strcpy((char*)qos_carl_msg[carl_index].ip_flag,(char*)ip_flag);
		qos_carl_msg[carl_index].match_flag = match_flag;
		qos_carl_msg[carl_index].ip_address=inet_addr(ip_address);
	  	qos_carl_msg[carl_index].mask_length=mask_length; 
  		char carl_in[60];
        sprintf(carl_in,"%d %s %d %d",carl_index,ip_flag,inet_addr(ip_address),mask_length);
		FILE* fin;
		FILE* fout;
		int ret,index;
		index = 0;
		ret=0;
		char buf[1024];
		fin=fopen("/etc/qos_carl.config","a+");
		fout=fopen("/etc/qos_carl.tmp","a+");
		while(fgets(buf,sizeof(buf),fin)){
			sscanf(buf,"%d %*s %*s %*s",&index);
			if(index==carl_index)
				{
				fprintf(fout,"%s\n",carl_in);
				ret = 1;
				}
			else
				fprintf(fout,"%s",buf);
		}
		if(0==ret){
		 fprintf(fout,"%s\n",carl_in);
		}
		fclose(fin);  
        fclose(fout);  
  
        remove("/etc/qos_carl.config");  
        rename("/etc/qos_carl.tmp","/etc/qos_carl.config");
unformat_free (line_input); 
return 0;		
}

static clib_error_t *
qos_car_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
	
	u8* flag;
	char* tmp;
	u32 cir;
	u32 cbs;
	u8* interface_name;
    int qos_carl_index = 0;
	u32 carl_index =0;
	int ret = 0;
	int sw_if_index = ~0;
	vnet_main_t * vnm = vnet_get_main();
	if (!unformat_user (input, unformat_line_input, line_input))
  		return clib_error_return (0, "mandatory argument(s) missing1");
	
	
	if (!unformat (line_input, " %s", &flag))
		return clib_error_return (0, "mandatory argument(s) missing2");
		
	  //vlib_cli_output(vm, "%d\n",carl_index);
	if (!unformat (line_input, " %s", &tmp))
		return clib_error_return (0, "mandatory argument(s) missing3");
	else {
		if(strcmp(tmp,"any")==0)
			ret = 1;
		else if(strcmp(tmp,"carl")==0){
			if (!unformat (line_input, " %d", &carl_index))
			return clib_error_return (0, "mandatory argument(s) missing3");
			if(carl_index<=0||carl_index>199)
			return clib_error_return (0, "carl-index range 1-199");
			if(qos_carl_msg[carl_index].carl_index==0)
			return clib_error_return (0, "no carl-index");
			}
		else
			return clib_error_return (0, "wrong input");
		}
	if (!unformat (line_input, " cir %d", &cir))
		return clib_error_return (0, "mandatory argument(s) missing4");
	if(cir<3||cir>10000)
		return clib_error_return (0, "cir range 3-10000");
	
	if (!unformat (line_input, " cbs %d", &cbs))
		return clib_error_return (0, "mandatory argument(s) missing5");
	if(cbs<1000||cbs>4294967294)
		return clib_error_return (0, "cbs range 1000-4294967294");
	interface_name = line_input->buffer;
	if (! unformat_user (line_input, unformat_vnet_sw_interface, vnm, &sw_if_index))
		  return clib_error_return (0, "interface index error");
	
    if(strcmp((char*)flag,"inbound")==0){
		for(int i=0;i<qos_interface[sw_if_index].inbound_index;i++)
			{
				if(qos_interface[sw_if_index].interface_car_inbound[i]->carl_index==carl_index){
					qos_carl_index=i;
					break;
					}
				else
					qos_carl_index=qos_interface[sw_if_index].inbound_index;
		}
		if(qos_interface[sw_if_index].interface_car_inbound[qos_carl_index]==NULL){
		qos_interface[sw_if_index].interface_car_inbound[qos_carl_index] = (portal_qos_car* )(malloc(sizeof(portal_qos_car)));
		qos_interface[sw_if_index].inbound_index++;
			}
		if(ret==1){
		qos_carl_index = 0;
		for(int i=1;i<qos_interface[sw_if_index].inbound_index;i++){
			if(qos_interface[sw_if_index].interface_car_inbound[i]!=NULL)
				qos_interface[sw_if_index].interface_car_inbound[i]= NULL;
				}
		qos_interface[sw_if_index].interface_car_inbound[qos_carl_index]->carl_index=0;
		qos_interface[sw_if_index].interface_car_inbound[qos_carl_index]->any_flag=1;
		qos_interface[sw_if_index].inbound_index = 1;
			}
		else{
			if(qos_interface[sw_if_index].interface_car_inbound[0]->any_flag==1)
				qos_carl_index = 0;
		qos_interface[sw_if_index].interface_car_inbound[qos_carl_index]->carl_index=carl_index;
		qos_interface[sw_if_index].interface_car_inbound[qos_carl_index]->any_flag=0;
		}
		qos_interface[sw_if_index].interface_car_inbound[qos_carl_index]->cir=cir;
		qos_interface[sw_if_index].interface_car_inbound[qos_carl_index]->cbs=cbs;
		
	}else if(strcmp((char*)flag,"outbound")==0){
	for(int i=0;i<qos_interface[sw_if_index].outbound_index;i++)
			{
			
				if(qos_interface[sw_if_index].interface_car_outbound[i]->carl_index==carl_index){
					qos_carl_index=i;
					break;
					}
				else
					qos_carl_index=qos_interface[sw_if_index].outbound_index;
		}
		if(qos_interface[sw_if_index].interface_car_outbound[qos_carl_index]==NULL){
		qos_interface[sw_if_index].interface_car_outbound[qos_carl_index] = (portal_qos_car* )(malloc(sizeof(portal_qos_car)));
		qos_interface[sw_if_index].outbound_index++;
			}
		if(ret==1){
		qos_carl_index = 0;
		for(int i=1;i<qos_interface[sw_if_index].outbound_index;i++){
			if(qos_interface[sw_if_index].interface_car_outbound[i]!=NULL)
				qos_interface[sw_if_index].interface_car_outbound[i] = NULL;
				}
		qos_interface[sw_if_index].interface_car_outbound[qos_carl_index]->carl_index=0;
		qos_interface[sw_if_index].interface_car_outbound[qos_carl_index]->any_flag=1;
		qos_interface[sw_if_index].outbound_index = 1;
		}
		else{
			if(qos_interface[sw_if_index].interface_car_outbound[0]->any_flag==1)
				qos_carl_index = 0;
		qos_interface[sw_if_index].interface_car_outbound[qos_carl_index]->carl_index=carl_index;
		qos_interface[sw_if_index].interface_car_outbound[qos_carl_index]->any_flag=0;
		}
		qos_interface[sw_if_index].interface_car_outbound[qos_carl_index]->cir=cir;
		qos_interface[sw_if_index].interface_car_outbound[qos_carl_index]->cbs=cbs;
		
	}else
	return clib_error_return (0, "mandatory argument(s) error");
	char carl_in[60];
	   
    sprintf(carl_in,"%s %s %d cir %d cbs %d %s",flag ,tmp,carl_index,cir,cbs,interface_name);
	FILE* fin;
	FILE* fout;
	int index = 0;

	char buf[1024];
	int a = 0;
	int b = 0;
	char ip_flag[20];
	char name[40];
	fin=fopen("/etc/qos_car.config","a+");
	fout=fopen("/etc/qos_car.tmp","a+");
	while(fgets(buf,sizeof(buf),fin)){
		sscanf(buf,"%s %*s %d cir %*s cbs %*s %s",ip_flag,&index,name);
		if(strcmp((char*)name,(char*)interface_name)==0){

		if(strcmp((char*)ip_flag,(char*)flag)==0){
		    if(index == 0){
			
			fprintf(fout,"%s\n",carl_in);
			a = 1;
			}
			else{
				if(ret==1){
					if(b==0){
				fprintf(fout,"%s\n",carl_in);
				a = 1;
				b = 1;
						}
				}else{
					if(index==carl_index)
					{
					fprintf(fout,"%s\n",carl_in);
					a = 1;
					}else
					fprintf(fout,"%s",buf);
				}}
		}
		else{
		fprintf(fout,"%s",buf);

		}}
		else{
		fprintf(fout,"%s",buf);
		}
	}
	if(0==a){
	 fprintf(fout,"%s\n",carl_in);
	}
	fclose(fin);  
    fclose(fout);  
  
    remove("/etc/qos_car.config");  
    rename("/etc/qos_car.tmp","/etc/qos_car.config");
unformat_free (line_input); 
return 0;				
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (portal_server_name_cli, static) = {
 .path = "portal server",
 .short_help = "portal server <server-name(string 1~32)>",
 .function = portal_server_name_command_fn,
};

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (no_portal_server_name_cli, static) = {
 .path = "no portal server",
 .short_help = "no portal server <server-name(string 1~32)>",
 .function = no_portal_server_name_command_fn,
};

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (portal_server_ip_key_cli, static) = {
 .path = "portal ip",
 .short_help = "portal ip <addr> key simple <key-string(string 1~64)> <server-name>",
 .function = portal_server_ip_key_fn,
};
/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (no_portal_server_ip_key_cli, static) = {
 .path = "portal no ip",
 .short_help = "portal no ip <server-name>",
 .function = no_portal_server_ip_key_fn,
};
/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (portal_server_port_cli, static) = {
 .path = "portal port",
 .short_help = "portal port <port-number> <server-name>",
 .function = portal_server_port_command_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (no_portal_server_port_cli, static) = {
 .path = "portal no port",
 .short_help = "portal no port <server-name>",
 .function = no_portal_server_port_command_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (portal_web_server_name_cli, static) = {
 .path = "portal web-server",
 .short_help = "portal web-server <server-name(string 1~32)>",
 .function = portal_web_server_name_command_fn,
};
/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (no_web_server_name_cli, static) = {
 .path = "no portal web-server",
 .short_help = "no portal web-server <server-name(string 1~32)>",
 .function = no_portal_webs_name_command_fn,
};
/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (portal_web_server_url_cli, static) = {
 .path = "portal url",
 .short_help = "portal url <url-string> <webs-name>",
 .function = portal_web_server_url_command_fn,
};
/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (no_web_server_url_cli, static) = {
 .path = "portal no url",
 .short_help = "portal no url <webs-name>",
 .function = no_portal_webs_url_command_fn,
};
/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (portal_enable_method_cli, static) = {
 .path = "portal enable method",
 .short_help = "portal enable method <direct | layer3 | redhcp> <interface-name>",
 .function = portal_enable_method_command_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (no_portal_enable_cli, static) = {
 .path = "no portal enable",
 .short_help = "no portal enable <interface-name>",
 .function = no_portal_enable_command_fn,
};
/* *INDENT-ON* */


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (portal_apply_web_server_cli, static) = {
 .path = "portal apply web-server",
 .short_help = "portal apply web-server <server-name(string 1~32)> <interface-name>",
 .function = portal_apply_web_server_command_fn,
};
/* *INDENT-ON* */


/* *INDENT-OFF*/
VLIB_CLI_COMMAND (no_portal_apply_webs_cli, static) = {
 .path = "no portal apply web-server",
 .short_help = "no portal apply web-server <interface_name>",
 .function = no_portal_apply_webs_command_fn,
};
 /*INDENT-ON* */


/* *INDENT-OFF* */ 
VLIB_CLI_COMMAND (portal_bas_ip_cli, static) = {
 .path = "portal bas-ip",
 .short_help = "portal bas-ip <addr> <interface-name>",
 .function = portal_bas_ip_command_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (no_portal_bas_ip_cli, static) = {
 .path = "no portal bas-ip",
 .short_help = "no portal bas-ip <interface-name>",
 .function = no_portal_bas_ip_command_fn,
};
 /*INDENT-ON* */
 
 /* *INDENT-OFF* */ 
VLIB_CLI_COMMAND (portal_nas_id_cli, static) = {
  .path = "portal nas-id",
  .short_help = "portal nas-id <nas_id> <interface-name>",
  .function = portal_nas_id_command_fn,
 };
 /* *INDENT-ON* */
 
 /* *INDENT-OFF* */
 VLIB_CLI_COMMAND (no_portal_nas_id_cli, static) = {
  .path = "no portal nas-id",
  .short_help = "no portal nas-id <interface-name>",
  .function = no_portal_nas_id_command_fn,
 };
  /*INDENT-ON* */
 /* *INDENT-OFF* */
VLIB_CLI_COMMAND (portal_free_rule_cli, static) = {
 .path = "portal free-rule",
 .short_help = "portal free-rule <rule-number> destination ip <ip-address>",
 .function = portal_free_rule_command_fn,
};
 /*INDENT-ON* */

 /* *INDENT-OFF* */
VLIB_CLI_COMMAND (no_portal_free_rule_cli, static) = {
 .path = "no portal free-rule",
 .short_help = "no portal free-rule (all | <rule-name>)",
 .function = no_portal_free_rule_command_fn,
};
 /*INDENT-ON* */

 /* *INDENT-OFF* */
VLIB_CLI_COMMAND (display_portal_free_rule_cli, static) = {
 .path = "display portal free-rule",
 .short_help = "display portal free-rule (all | <rule-name>)",
 .function = display_portal_free_rule_command_fn,
};
 /*INDENT-ON* */
 /* *INDENT-OFF* */
VLIB_CLI_COMMAND (display_portal_user_cli, static) = {
 .path = "display portal user",
 .short_help = "display portal user (all | interface <if-type> <if-num>)",
 .function = display_portal_user_command_fn,
};
/* *INDENT-ON* */
			

VLIB_CLI_COMMAND (qos_carl_cli, static) = {
 .path = "qos carl",
 .short_help = "qos carl <carl-index(1-199)> <destination-ip-address | source-ip-address> <subnet> <ip-address> <mask-length(17-31)>",
 .function = qos_carl_command_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_qos_carl_cli, static) = {
 .path = "show qos carl",
 .short_help = "show qos carl {carl-index(1-199)} ",
 .function = show_qos_carl_command_fn,
};
VLIB_CLI_COMMAND (show_qos_car_cli, static) = {
 .path = "show qos car",
 .short_help = "show qos car <interface-name> ",
 .function = show_qos_car_command_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (qos_carl_restore_cli, static) = {
 .path = "qos carl restore",
 .short_help = "qos carl restore ",
 .function = qos_carl_restore_command_fn,
};
VLIB_CLI_COMMAND (qos_car_restore_cli, static) = {
 .path = "qos car restore",
 .short_help = "qos car restore <interface-name>",
 .function = qos_car_restore_command_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (qos_car_cli, static) = {
 .path = "qos car",
 .short_help = "qos car <inbound | outbound > <carl carl-index> <cir committed-information-rate(kbps)> <cbs committed-burst-size(kbps)>",
 .function = qos_car_command_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (no_qos_carl_cli, static) = {
 .path = "no qos carl",
 .short_help = "no qos carl <carl-index>",
 .function = no_qos_carl_command_fn,
};

VLIB_CLI_COMMAND (no_qos_car_cli, static) = {
 .path = "no qos car",
 .short_help = "no qos car <inbound|outbound> <carl carl-index(1-199)> <interface-name>",
 .function = no_qos_car_command_fn,
};
/* *INDENT-ON* */

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/



