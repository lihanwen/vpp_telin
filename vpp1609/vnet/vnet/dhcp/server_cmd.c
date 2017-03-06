#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include "server_cmd.h"
#include <vnet/global_funcs.h>

#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/types.h>    
#include <sys/stat.h>    
#include <fcntl.h>

#include "hash_client.h"

//#include <rte_cycles.h>
//#include <rte_config.h>
//#include <rte_spinlock.h>
//#include <rte_launch.h>


dhcp_server_pool chain_head;

/*******************************************************************************
 函数名称  : create_ip_pool_chain
 功能描述  : 创建地址池链表节点函数
 输入参数  : 地址池名字
 输出参数  : 无
 返 回 值  : 0     成功
             无    失败
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
dhcp_server_pool * create_dhcp_pool_chain (char * name)
{
   dhcp_server_pool * ret = search_name_node(name);
   int i = 0;
   if (NULL == ret)
   	{
		ret = (dhcp_server_pool *)malloc(sizeof(dhcp_server_pool));
		memset(ret->pool_name, 0, NAME_LEN);
		strcpy(ret->pool_name, name);
		ret->default_time = DHCP_DEFAULT_TIME;
		ret->max_time = 0;
		ret->start_ip = 0;
		ret->end_ip = 0;
		ret->net_mask = 0;
		ret->if_mask = 0;
		ret->if_subnet = 0;
		for (i=0; i<LIST_LEN; i++)
		{
			ret->dns_list[i] = 0;
			ret->gateway_list[i] = 0;
		}

		dl_list_init(&(ret->list));
		dl_list_add_tail(&(chain_head.list), &(ret->list));
   }
   /*
   else
   {
		ret->start_ip = 0;
		ret->end_ip = 0;
		i = 0;
		for (i=0;i<LIST_LEN;i++)
		{
			ret->dns_list[i] = 0;
			ret->gateway_list[i] = 0;
		}
		ret->max_time = 0;
		ret->net_mask = 0;
   }
   */
   return ret;
}

/*******************************************************************************
 函数名称  : write_dhcp_config_file
 功能描述  : 写启动DHCP配置文件
 输入参数  : 无
 输出参数  : 无
 返 回 值  : 1     成功
             0     失败
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
int write_dhcp_config_file(void)
{	
	char buff[BUFF_SIZE];
	dhcp_server_pool * tmp =NULL;
	struct in_addr addr0;
	int fp_t = open ("/var/lib/dhcp/dhcpd.leases",O_RDWR|O_CREAT,00007);
	FILE *fp = fopen("/etc/dhcp/dhcpd.conf","w+");
	fputs("ddns-update-style none;\n",fp);
	dl_list_for_each(tmp, &(chain_head.list), dhcp_server_pool, list)
	{
		int i = 0, dns_num = 0, gateway_num = 0;
		if(tmp->if_subnet)
		{
			memcpy(&addr0, &(tmp->if_subnet), 4);
			snprintf(buff, sizeof(buff), "subnet %s ", inet_ntoa(addr0));
			fputs(buff,fp);
			memset(buff,0,BUFF_SIZE);			
		}
		else
			continue;
		if(tmp->if_mask)
		{
			memcpy(&addr0, &(tmp->if_mask), 4);	
			snprintf(buff,sizeof(buff), "netmask %s {\n", inet_ntoa(addr0));
			fputs(buff,fp);
			memset(buff,0,BUFF_SIZE);			
		}

		if(tmp->start_ip)
		{
		   memcpy(&addr0, (&tmp->start_ip), 4);
		   snprintf(buff,sizeof(buff), " range %s ", inet_ntoa(addr0));
		   fputs (buff,fp);
		   memset(buff,0,BUFF_SIZE);
		}
		if(tmp->end_ip)
		{
		   memcpy(&addr0, &(tmp->end_ip), 4);	
		   snprintf(buff,sizeof(buff), "%s;\n", inet_ntoa(addr0));
		   fputs (buff,fp);
		   memset(buff,0,BUFF_SIZE);
		}		
		
		for(i=0;i<LIST_LEN;i++)
		{
		   if(tmp->gateway_list[i])
		   {
		   		gateway_num ++;
			  	memcpy(&addr0, &(tmp->gateway_list[i]), 4);
				if (gateway_num == 1)
				{
					snprintf(buff,sizeof(buff)," option routers %s", inet_ntoa(addr0));
					fputs(buff,fp);
					memset(buff,0,BUFF_SIZE);
				}
				else
				{
			  		snprintf(buff, sizeof(buff), ", %s", inet_ntoa(addr0));
					fputs(buff,fp);
	            	memset(buff,0,BUFF_SIZE);
				}
		   }
		}
		if (gateway_num)
			fputs(";\n",fp);
	
		if(tmp->net_mask)
		{
			memcpy(&addr0, &(tmp->net_mask), 4);	
			snprintf(buff,sizeof(buff), " option subnet-mask %s;\n", inet_ntoa(addr0));
		   	fputs(buff,fp);
            memset(buff,0,BUFF_SIZE);
		}	
		
		snprintf(buff,sizeof(buff), " default-lease-time %d;\n",tmp->default_time);
		fputs(buff,fp);
		memset(buff,0,BUFF_SIZE);

		if(tmp->max_time)
		{
			snprintf(buff,sizeof(buff), " max-lease-time %d;\n",tmp->max_time);
			fputs(buff,fp);
			memset(buff,0,BUFF_SIZE);
		}

		for(i=0;i<LIST_LEN;i++)
		{
		   if(tmp->dns_list[i])
		   {
		   		dns_num ++;
			  	memcpy(&addr0, &(tmp->dns_list[i]), 4);
				if (dns_num == 1)
				{
					snprintf(buff,sizeof(buff), " option domain-name-servers %s", inet_ntoa(addr0));
					fputs(buff,fp);
					memset(buff,0,BUFF_SIZE);
				}
				else
				{
			 		snprintf(buff, sizeof(buff), ", %s", inet_ntoa(addr0));
			 		fputs(buff,fp);
            		memset(buff,0,BUFF_SIZE);
				}
		   }
		}	
		if (dns_num)
			fputs(";\n}\n", fp);
		else
			fputs("}\n",fp);
	}
	close(fp_t);
	fclose (fp);
	return 0;
}

/*******************************************************************************
 函数名称  : write_dhcp_rdconfig_file
 功能描述  : 写DHCP配置恢复文件
 输入参数  : 无
 输出参数  : 无
 返 回 值  : 1     成功
             0     失败
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
int write_dhcp_rdconfig_file(void)
{
	
	FILE *fp = fopen("/etc/dhcp_config.conf","w+");
	char buff[BUFF_SIZE];
	dhcp_server_pool * tmp = NULL;
	dl_list_for_each(tmp, &(chain_head.list), dhcp_server_pool, list)
	{
		snprintf(buff,sizeof(buff),"pool-name %s\n",
					tmp->pool_name);
		fputs (buff,fp);
		memset(buff,0,BUFF_SIZE);

		snprintf(buff,sizeof(buff),"if-subnet %d\n",
					tmp->if_subnet);
		fputs (buff,fp);
		memset(buff,0,BUFF_SIZE);

		snprintf(buff,sizeof(buff),"if-mask %d\n",
					tmp->if_mask);
		fputs (buff,fp);
		memset(buff,0,BUFF_SIZE);

		snprintf(buff,sizeof(buff),"range %d %d\n",
					tmp->start_ip,tmp->end_ip);
		fputs (buff,fp);
		memset(buff,0,BUFF_SIZE);


		snprintf(buff,sizeof(buff),"netmask %d\n",
					tmp->net_mask);
		fputs (buff,fp);
		memset(buff,0,BUFF_SIZE);
			
		snprintf(buff,sizeof(buff),"max-time %d\n",
					tmp->max_time);
		fputs (buff,fp);
		memset(buff,0,BUFF_SIZE);
	
		fputs("dns-list",fp);
		for(int i=0;i<LIST_LEN;i++)
		{
	   		snprintf(buff,sizeof(buff)," %d",
					  tmp->dns_list[i]);
	   		fputs (buff,fp);
	   		memset(buff,0,BUFF_SIZE);
		}
		fputs(" \n",fp);
		fputs("gateway-list",fp);
		for(int i=0;i<LIST_LEN;i++)
		{
    		snprintf(buff,sizeof(buff), " %d",
                  tmp->gateway_list[i]);
     		fputs (buff,fp);
     		memset(buff,0,BUFF_SIZE);
		}
		fputs(" \n",fp);
	}
	fclose(fp);
	return 0;
}

/*******************************************************************************
 函数名称  : dhcp_restore_conf
 功能描述  : 写DHCP配置恢复，读配置文件文件
 输入参数  : 无
 输出参数  : 无
 返 回 值  : 1     成功
             0     失败
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
int dhcp_restore_conf(void)
{
	  char *p = NULL, *msg = NULL;
	  char name[NAME_LEN] ;
	  char data[BUFF_SIZE];
	  dhcp_server_pool * tmp = NULL;
	  int i=0;
	  FILE *fd = fopen("/etc/dhcp_config.conf","a+");	  
	  if(fd == NULL)
		 return -1;
	  
	  while(fgets(data,BUFF_SIZE,fd))
	  {
		 p=strtok(data," ");
		 if(p && (msg=strtok(NULL," ")))
		 {
			 if(strcasecmp(p,"pool-name")==0)
			 {
			 	memset(name, 0, NAME_LEN);
				strncpy(name, msg, strlen(msg)-1);
				tmp = create_dhcp_pool_chain (name);
			 }
			 if(strcasecmp(p,"if-subnet")==0)
			 {
				tmp->if_subnet =atoi(msg);
			 }
			 if(strcasecmp(p,"if-mask")==0)
			 {
				tmp->if_mask =atoi(msg);
			 }
			 if(strcasecmp(p,"netmask")==0)
			 {
				tmp->net_mask =atoi(msg);
			 }
			 if(strcasecmp(p,"max-time")==0)
			 {
				tmp->max_time=atoi(msg);
			 }
			 if(strcasecmp(p,"range")==0)
			 {
				tmp->start_ip =atoi(msg);
				msg=strtok(NULL," ");
				if(msg)
				{
				   tmp->end_ip =atoi(msg);
				}
			 }
			 if(strcasecmp(p,"dns-list")==0)
			 {
			 	for(i=0;i<LIST_LEN;i++)
				{
					if(msg)
					 {
						 tmp->dns_list[i]=atoi(msg);
					 }
					else
						break;
					 msg=strtok(NULL," ");
				}
			 }
				
			if(strcasecmp(p,"gateway-list")==0)
			{
				for(i=0;i<LIST_LEN;i++)
				{
					if(msg)
					{
						tmp->gateway_list[i]=atoi(msg);
					}
					else
						break;
					msg = strtok(NULL," ");
				}
			}	 
		}		 
	} 
	fclose(fd);
	return 0;
}

/*******************************************************************************
 函数名称  : dhcp_check_user_name
 功能描述  : 检测输入dhcp ip-pool名字是否合法
 输入参数  : 地址池名字
 输出参数  : 无
 返 回 值  : 1     成功
             0     失败
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
int dhcp_check_pool_name (char * name)
{
	int i;    
    char *tmp = name;    
    for(i = 0; i < strlen(name); i++)    
    {           
  		if(*tmp == 92 ||  *tmp == '?')        
		{            
	  		return 0;        
	 	}           
		tmp++;   
  	}       
	return 1;
}

/*******************************************************************************
 函数名称  : search_name_node
 功能描述  : 查找链表中地址池名字相同的节点
 输入参数  : 地址池名字
 输出参数  : 无
 返 回 值  : 1     成功
             0     失败
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
dhcp_server_pool * search_name_node(char *name)
{
	dhcp_server_pool * tmp = NULL;
	dl_list_for_each(tmp, &(chain_head.list), dhcp_server_pool, list)	
	{
		if(strcmp(name, tmp->pool_name) == 0)				
			return tmp;	
	}
	return NULL;
}

/*******************************************************************************
 函数名称  : del_dhcp_pool_chain
 功能描述  : 根据名字删除节点
 输入参数  : 地址池名字
 输出参数  : 无
 返 回 值  : 无
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
void del_dhcp_pool_chain(char * name)
{	
	dhcp_server_pool *tmp = NULL;	
	dl_list_for_each(tmp, &(chain_head.list), dhcp_server_pool, list)
	{		
		if(strcmp(name, tmp->pool_name) == 0)		
		{
			dl_list_del(&(tmp->list));					
			free(tmp);		
		}
	}
}

/*******************************************************************************
 函数名称  : dhcp_enable_command_fn
 功能描述  : 使能 DHCP 服务
 输入参数  : 用户输入命令
 输出参数  : 无
 返 回 值  : 无           成功
             错误信息     失败
 命    令  : dhcp enable
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
/*
static clib_error_t *
dhcp_enable_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	
	 //Get a line of input. 
	if (!unformat_user (input, unformat_line_input, line_input))
	  return clib_error_return (0, "mandatory argument(s) missing");	
	
	int ret = system ("dhcpd -cf /etc/dhcp/dhcpd.conf -lf /var/lib/dhcp/dhcpd.lease");
	if (ret == -1)
		return clib_error_return (0, "system() error");
	else if (ret == 127)
		return clib_error_return (0, "system() no such commands");
	
	unformat_free (line_input);
	return 0;	
}
*/
/*
VLIB_CLI_COMMAND (dhcp_enable_cli, static) = {
 .path = "dhcp enable",
 .short_help = "dhcp enable",
 .function = dhcp_enable_command_fn,
};
*/
/*******************************************************************************
 函数名称  : no_dhcp_enable_command_fn
 功能描述  : 禁止 DHCP 服务
 输入参数  : 用户输入命令
 输出参数  : 无
 返 回 值  : 无           成功
             错误信息     失败
 命    令  : no dhcp enable
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
/*
static clib_error_t *
no_dhcp_enable_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	
	// Get a line of input. 
	if (!unformat_user (input, unformat_line_input, line_input))
	  return clib_error_return (0, "mandatory argument(s) missing");	
	
	int ret = system ("kill `pidof dhcpd`");
	if (ret == -1)
		return clib_error_return (0, "system() error");
	else if (ret == 127)
		return clib_error_return (0, "system() no such commands");
	
	unformat_free (line_input);
	return 0;	
}
*/
/*
VLIB_CLI_COMMAND (no_dhcp_enable_cli, static) = {
 .path = "no dhcp enable",
 .short_help = "no dhcp enable",
 .function = no_dhcp_enable_command_fn,
};
*/
/*******************************************************************************
 函数名称  : dhcp_server_ip_pool_command_fn
 功能描述  : 创建地址池命令函数
 输入参数  : 用户输入命令
 输出参数  : 无
 返 回 值  : 无           成功
             错误信息     失败
 命    令  : dhcp server ip-pool <pool-name(1~35)>
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
static clib_error_t *
dhcp_server_ip_pool_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	char * pool_name = NULL;
	u32 parameter_num = 0;
	int rv = 0;
	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
	  return clib_error_return (0, "mandatory argument(s) missing");
	
	while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
       if (unformat (line_input, " %s", &pool_name))
       	{
			 if ((strlen ((char *)pool_name) >= 1) && (strlen ((char *)pool_name) <= 35))
			 	parameter_num++;	
			 else
		   		return clib_error_return (0, "Name is too short or too long");
	   }
	}
	rv = dhcp_check_pool_name (pool_name);
	if (!rv)
  		return clib_error_return (0, "The name format error");
  	if(parameter_num != 1)
  		return clib_error_return (0, "mandatory argument(s) missing");

	dhcp_server_pool * ret = create_dhcp_pool_chain (pool_name);
	if (ret == NULL)
		return clib_error_return (0, "Failed to create a node");

	unformat_free (line_input);
  	return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcp_server_ip_pool_cli, static) = {
 .path = "dhcp server ip-pool",
 .short_help = "dhcp server ip-pool <pool-name(1~35)>",
 .function = dhcp_server_ip_pool_command_fn,
};

/*******************************************************************************
 函数名称  : no_dhcp_ip_pool_command_fn
 功能描述  : 删除指定的地址池命令函数
 输入参数  : 用户输入命令
 输出参数  : 无
 返 回 值  : 无           成功
             错误信息     失败
 命    令  : no dhcp server ip-pool <pool-name(1~35)>
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
static clib_error_t *
no_dhcp_ip_pool_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	char * pool_name = NULL;
	u32 parameter_num = 0;
	int rv = 0;
	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
	  return clib_error_return (0, "mandatory argument(s) missing");
	
	while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
       if (unformat (line_input, " %s", &pool_name))
       	{
			 if ((strlen ((char *)pool_name) >= 1) && (strlen ((char *)pool_name) <= 35))
			 	parameter_num++;	
			 else
		   		return clib_error_return (0, "Name is too short or too long");
	   }
	}
	rv = dhcp_check_pool_name (pool_name);
	if (!rv)
		return clib_error_return (0, "The name format error");
	if(parameter_num != 1)
		return clib_error_return (0, "mandatory argument(s) missing");
	
	dhcp_server_pool * ret = search_name_node(pool_name);
	if (NULL == ret)
		return clib_error_return (0, "Don't have the address pool");
	else
		del_dhcp_pool_chain(pool_name);
	
	unformat_free (line_input);
	return 0;
}
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (no_dhcp_ip_pool_cli, static) = {
 .path = "no dhcp server ip-pool",
 .short_help = "no dhcp server ip-pool <pool-name(1~35)>",
 .function = no_dhcp_ip_pool_command_fn,
};

/*******************************************************************************
 函数名称  : check_ip_pool
 功能描述  : 检查输入的地址池是否冲突
 输入参数  : 地址池名 起始地址 结束地址
 输出参数  : 无
 返 回 值  : 链表头地址                地址冲突
 			 地址池名相同节点        查找到相应节点
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
dhcp_server_pool* check_ip_pool(char * pool_name, u32 start_ip, u32 end_ip)
{	
	dhcp_server_pool * tmp = NULL, *tmp_node = NULL;
	/*
	int input_ip[4], input_end[4], tmp_ip[4], tmp_end[4];	
	struct in_addr addr0, addr1, addr2;
	memcpy(&addr0, &start_ip, 4);
	sscanf(inet_ntoa(addr0), "%d.%d.%d.%d",	&input_ip[0], &input_ip[1], &input_ip[2], &input_ip[3]);
	memcpy(&addr0, &end_ip, 4);	
	sscanf(inet_ntoa(addr0), "%d.%d.%d.%d",	&input_end[0], &input_end[1], &input_end[2], &input_end[3]);
	*/
	dl_list_for_each(tmp, &(chain_head.list), dhcp_server_pool, list)	
	{	
		/*
		if(start_ip == tmp->start_ip)				
			return &chain_head;
		
		memcpy(&addr1, &tmp->start_ip, 4);
		memcpy(&addr2, &tmp->end_ip, 4);
		sscanf(inet_ntoa(addr1), "%d.%d.%d.%d", &tmp_ip[0], &tmp_ip[1], &tmp_ip[2], &tmp_ip[3]);
		sscanf(inet_ntoa(addr2), "%d.%d.%d.%d", &tmp_end[0], &tmp_end[1], &tmp_end[2], &tmp_end[3]);
		if((input_ip[0] == tmp_ip[0]) && (input_ip[1] == tmp_ip[1]) && (input_ip[2] == tmp_ip[2]))		
		{			
			if((input_ip[3] <= tmp_end[3] ) && (input_ip[3] >= tmp_ip[3]))				
				return &chain_head;			
			if((input_end[3]>= tmp_ip[3]) && (input_end[3] <=tmp_end[3]))				
				return &chain_head;		
		}
		*/
		if((ntohl(tmp->start_ip) <= ntohl(start_ip))&&(ntohl(start_ip)<=(ntohl(tmp->end_ip))))
			return &chain_head;
		if ((ntohl(tmp->start_ip) <= ntohl(end_ip))&&(ntohl(end_ip)<=(ntohl(tmp->end_ip))))
			return &chain_head;
		if(strcmp(pool_name, tmp->pool_name) == 0)	
		{
			tmp_node = tmp;	
		}
	}	
	return tmp_node;
}

/*******************************************************************************
 函数名称  : dhcp_address_range_command_fn
 功能描述  : 动态分配IP地址范围命令函数，每个地址池只能配置一个IP地址范围，
             如果多次执行命令，新的配置会覆盖已有配置。
 输入参数  : 用户输入命令
 输出参数  : 无
 返 回 值  : 无           成功
             错误信息     失败
 命    令  : dhcp address range <start-ip-address> <end-ip-address> <pool-name>
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
static clib_error_t *
dhcp_address_range_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	char * start_ip;
	char * end_ip;
	char * pool_name;
	u32 st_ip;
	u32 ed_ip;
	u32 ip_set = 0;
	u32 parameter_num = 0;
	dhcp_server_pool* ret = NULL;
	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
	  return clib_error_return (0, "mandatory argument(s) missing");
	while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
       if (unformat (line_input, " %s", &start_ip)){
 			ip_set++;}
	   if (unformat (line_input, " %s", &end_ip))
	   	{
 			parameter_num = 1;
 		}
	   if (unformat (line_input, " %s", &pool_name))
 			ip_set++;		
	}
	if ((ip_set != 2) || (parameter_num !=1))
		return clib_error_return (0, "mandatory argument(s) missing");
    st_ip = inet_addr(start_ip);
	ed_ip = inet_addr(end_ip);
	ret = check_ip_pool (pool_name, st_ip, ed_ip);
	
	if (&chain_head == ret)
		vlib_cli_output(vm, "The IP address range overlaps with existing IP address ranges in group default\n");
	else
	{
		ret->start_ip = st_ip;
		ret->end_ip = ed_ip;
	}
	unformat_free (line_input);
	return 0;
}
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcp_address_range_cli, static) = {
 .path = "dhcp address range",
 .short_help = "dhcp address range <start-ip-address> <end-ip-address> <pool-name>",
 .function = dhcp_address_range_command_fn,
};

/*******************************************************************************
 函数名称  : no_dhcp_address_range_command_fn
 功能描述  : 撤销动态分配IP地址范围命令函数
 输入参数  : 用户输入命令
 输出参数  : 无
 返 回 值  : 无           成功
             错误信息     失败
 命    令  : no dhcp address range <pool-name>
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
static clib_error_t *
no_dhcp_address_range_command_fn (vlib_main_t * vm,
                    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	char * pool_name;
	u32 num;
	dhcp_server_pool * ret = NULL;
	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
	    return clib_error_return (0, "mandatory argument(s) missing");	
	
 	if (unformat (line_input, " %s", &pool_name))
 		num = 1;
	if (!num)
		return clib_error_return (0, "mandatory argument(s) missing");

	ret = search_name_node(pool_name);
	if (NULL != ret)
	{
		ret->start_ip = 0;
		ret->end_ip = 0;
	}	
	unformat_free(line_input);
	return 0;
}
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (no_dhcp_address_range_cli, static) = {
 .path = "no dhcp address range",
 .short_help = "no dhcp address range <pool-name>",
 .function = no_dhcp_address_range_command_fn,
};

/*******************************************************************************
 函数名称  : dhcp_dns_list_command_fn
 功能描述  : 配置DNS服务器的IP地址命令函数。最多可以输入8个IP地址
 输入参数  : 用户输入命令
 输出参数  : 无
 返 回 值  : 无           成功
             错误信息     失败
 命    令  : dhcp dns-list <pool-name> <ip-1> [ip-2] [ip-3] [ip-4] [ip-5] [ip-6] [ip-7] [ip-8]
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
static clib_error_t *
dhcp_dns_list_command_fn (vlib_main_t * vm,
						unformat_input_t * input,
						vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	char * pool_name;
	char * dns_ip[LIST_LEN];
	u32 num = 0;
	int i = 0;
	dhcp_server_pool * ret = NULL;

	for (i = 0; i<LIST_LEN; i++)
		dns_ip[i] = NULL;
	
	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
	  return clib_error_return (0, "mandatory argument(s) missing");
	
	while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{      
	   if (unformat (line_input, " %s", &pool_name));
	   for (i = 0;i<LIST_LEN;i++)
	   {
       		if (unformat (line_input, " %s", &(dns_ip[i])));
       		    num++;
			if (dns_ip[i] == NULL)
				break;
	   	}
	}
	if (!num)
		return clib_error_return (0, "mandatory argument(s) missing");
	
	ret = search_name_node(pool_name);
	for (i = 0; i<LIST_LEN; i++)
	{
		if (dns_ip[i] == NULL)
		{
			ret->dns_list[i] = 0;
			continue;
		}
		ret->dns_list[i] = inet_addr(dns_ip[i]);
	}
	unformat_free(line_input);
	return 0;
}
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcp_dns_list_cli, static) = {
 .path = "dhcp dns-list",
 .short_help = "dhcp dns-list <pool-name> <ip-1> [ip-2] [ip-3] [ip-4] [ip-5] [ip-6] [ip-7] [ip-8]",
 .function = dhcp_dns_list_command_fn,
};

/*******************************************************************************
 函数名称  : no_dhcp_dns_list_command_fn
 功能描述  : 删除 DHCP 地址池为 DHCP 客户端分配的DNS服务器地址
 输入参数  : 用户输入命令
 输出参数  : 无
 返 回 值  : 无           成功
             错误信息     失败
 命    令  : no dhcp dns-list <ip-address | all> <pool-name>
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
static clib_error_t *
no_dhcp_dns_list_command_fn (vlib_main_t * vm,
						unformat_input_t * input,
						vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	char * pool_name;
	char * dns_ip;
	u32 set_all = 0;
	u32 set_ip = 0;
	int i = 0;
	dhcp_server_pool * ret = NULL;
	
	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
	  	return clib_error_return (0, "mandatory argument(s) missing");

	if (unformat (line_input, " all"))
		set_all = 1;
	else if (unformat (line_input, " %s", &dns_ip))
		set_ip = 1;
	
	if (unformat (line_input, " %s", &pool_name));
	
	ret = search_name_node(pool_name);
	
	if (set_all)
	{
		for (i = 0; i<LIST_LEN; i++)
			ret->dns_list[i] = 0;
	}
	if (set_ip)
	{
		for (i = 0; i<LIST_LEN; i++)
		{
			if (ret->dns_list[i] == inet_addr(dns_ip))
			{
				ret->dns_list[i] = 0;
				break;
			}
		}
	}
	unformat_free(line_input);
	return 0;		
}
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (no_dhcp_dns_list_cli, static) = {
 .path = "no dhcp dns-list",
 .short_help = "no dhcp dns-list <all | ip-address> <pool-name>",
 .function = no_dhcp_dns_list_command_fn,
};

/*******************************************************************************
 函数名称  : dhcp_gateway_list_command_fn
 功能描述  : DHCP 地址池为 DHCP 客户端分配的网关地址。最多可以输入8个IP地址
 输入参数  : 用户输入命令
 输出参数  : 无
 返 回 值  : 无           成功
             错误信息     失败
 命    令  : dhcp gateway-list <pool-name> <ip-1> [ip-2] [ip-3] [ip-4] [ip-5] [ip-6] [ip-7] [ip-8]
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
static clib_error_t *
dhcp_gateway_list_command_fn (vlib_main_t * vm,
						unformat_input_t * input,
						vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	char * pool_name;
	char * gateway_ip[LIST_LEN];
	u32 num = 0;
	int i = 0;
	dhcp_server_pool * ret = NULL;
	
	for (i=0; i<LIST_LEN;i++)
		gateway_ip[i] = NULL;

	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
	  return clib_error_return (0, "mandatory argument(s) missing");
	
	while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{      
		if (unformat (line_input, " %s", &pool_name));
       
        for (i = 0;i<LIST_LEN;i++)
	   {
       		if (unformat (line_input, " %s", &gateway_ip[i]))
       		    num++;
			if (gateway_ip[i] == NULL)
				break;
	   	}
	}
	if (!num)
		return clib_error_return (0, "mandatory argument(s) missing");
	
	ret = search_name_node(pool_name);
	for (i = 0; i<LIST_LEN; i++)
	{	
	    if (gateway_ip[i] == NULL)
			break;
		ret->gateway_list[i] = inet_addr(gateway_ip[i]);
	}
	unformat_free(line_input);
	return 0;
}
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcp_gateway_list_cli, static) = {
 .path = "dhcp gateway-list",
 .short_help = "dhcp gateway-list <pool-name> <ip-1> [ip-2] [ip-3] [ip-4] [ip-5] [ip-6] [ip-7] [ip-8]",
 .function = dhcp_gateway_list_command_fn,
};

/*******************************************************************************
 函数名称  : no_dhcp_gateway_list_command_fn
 功能描述  : 删除 DHCP 地址池为 DHCP 客户端分配的网关地址
 输入参数  : 用户输入命令
 输出参数  : 无
 返 回 值  : 无           成功
             错误信息     失败
 命    令  : no dhcp gateway-list <all | ip-address> <pool-name>
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
static clib_error_t *
no_dhcp_gateway_list_command_fn (vlib_main_t * vm,
						unformat_input_t * input,
						vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	char * pool_name;
	char * gateway_ip;
	u32 set_all = 0;
	u32 set_ip = 0;
	int i = 0;
	dhcp_server_pool * ret = NULL;
	
	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
	  	return clib_error_return (0, "mandatory argument(s) missing");

	if (unformat (line_input, " all"))
		set_all = 1;
	else if (unformat (line_input, " %s", &gateway_ip))
		set_ip = 1;
	
	if (unformat (line_input, " %s", &pool_name));
	
	ret = search_name_node(pool_name);
	
	if (set_all)
	{
		for (i = 0; i<LIST_LEN; i++)
			ret->gateway_list[i] = 0;
	}
	if (set_ip)
	{
		for (i = 0; i<LIST_LEN; i++)
		{
			if (ret->gateway_list[i] == inet_addr(gateway_ip))
			{
				ret->gateway_list[i] = 0;
				break;
			}
		}
	}
	unformat_free(line_input);
	return 0;		
}
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (no_dhcp_gateway_list_cli, static) = {
 .path = "no dhcp gateway-list",
 .short_help = "no dhcp gateway-list <ip-address | <all> <pool-name>",
 .function = no_dhcp_gateway_list_command_fn,
};

/*******************************************************************************
 函数名称  : dhcp_network_mask_command_fn
 功能描述  : 配置地址池动态分配的 IP 地址掩码
 输入参数  : 用户输入命令
 输出参数  : 无
 返 回 值  : 无           成功
             错误信息     失败
 命    令  : dhcp network mask <mask> <pool-name>
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
static clib_error_t *
dhcp_network_mask_command_fn (vlib_main_t * vm,
						unformat_input_t * input,
						vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	char * pool_name;
	char * net_mask;
	u32 set_mask = 0;
	dhcp_server_pool * ret = NULL;
	
	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
	  return clib_error_return (0, "mandatory argument(s) missing");

	if (unformat (line_input, " %s", &net_mask))
 		set_mask = 1;
	if (unformat (line_input, " %s", &pool_name));

	if (set_mask)
	{
		ret = search_name_node(pool_name);
		if (NULL != ret)
			ret->net_mask = inet_addr(net_mask);
	}
    else
		return clib_error_return (0, "mandatory argument(s) missing");
	unformat_free (line_input);
	return 0;
}
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcp_network_mask_cli, static) = {
 .path = "dhcp network mask",
 .short_help = "dhcp network mask <mask> <pool-name>",
 .function = dhcp_network_mask_command_fn,
};

/*******************************************************************************
 函数名称  : no_dhcp_network_mask_command_fn
 功能描述  : 删除动态分配的 IP 地址掩码
 输入参数  : 用户输入命令
 输出参数  : 无
 返 回 值  : 无           成功
             错误信息     失败
 命    令  : no dhcp network mask <mask> <pool-name>
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
static clib_error_t *
no_dhcp_network_mask_command_fn (vlib_main_t * vm,
						unformat_input_t * input,
						vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	char * pool_name;
	dhcp_server_pool * ret = NULL;
	
	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
	  return clib_error_return (0, "mandatory argument(s) missing");

	if (unformat (line_input, " %s", &pool_name));

	ret = search_name_node(pool_name);
	if (NULL != ret)
		ret->net_mask = 0;
	unformat_free (line_input);
	return 0;
}
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (no_dhcp_network_mask_cli, static) = {
 .path = "no dhcp network mask",
 .short_help = "no dhcp network mask <pool-name>",
 .function = no_dhcp_network_mask_command_fn,
};

/*******************************************************************************
 函数名称  : dhcp_expired_time_fn
 功能描述  : 配置接口引用的地址池
 输入参数  : 用户输入命令
 输出参数  : 无
 返 回 值  : 无           成功
             错误信息     失败
 命    令  : dhcp expired <time | unlimited> <pool-name>
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
static clib_error_t *
dhcp_expired_time_fn (vlib_main_t * vm,
							unformat_input_t * input,
							vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	char * pool_name = NULL;
	char * time = NULL;
	u32 set_time = 0;
	u32 set_unld = 0;
	dhcp_server_pool * ret = NULL;
	
		
	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
		return clib_error_return (0, "mandatory argument(s) missing");

	if (unformat (line_input, " %s", &time))
		set_time = 1;
	else if (unformat (line_input, " unlimited"))
		set_unld = 1;
	if (unformat (line_input, " %s", &pool_name));
	
	ret = search_name_node(pool_name);
	if (NULL != ret)
	{
		if (set_time)
			ret->max_time = atoi (time);
		else if (set_unld)
			ret->max_time = DHCP_YEAR_TIME;
	}
	unformat_free (line_input);
	return 0;
}
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcp_expired_time_cli, static) = {
 .path = "dhcp expired",
 .short_help = "dhcp expired <time | unlimited> <pool-name>",
 .function = dhcp_expired_time_fn,
};

/*******************************************************************************
 函数名称  : no_dhcp_expired_time_fn
 功能描述  : 配置接口引用的地址池
 输入参数  : 用户输入命令
 输出参数  : 无
 返 回 值  : 无           成功
             错误信息     失败
 命    令  : no dhcp expired <pool-name>
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
static clib_error_t *
no_dhcp_expired_time_fn (vlib_main_t * vm,
							unformat_input_t * input,
							vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	char * pool_name = NULL;
	dhcp_server_pool * ret = NULL;
			
	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
		return clib_error_return (0, "mandatory argument(s) missing");

	if (unformat (line_input, " %s", &pool_name));
	
	ret = search_name_node(pool_name);
	if (NULL != ret)
		ret->max_time = 0;
	unformat_free (line_input);
	return 0;
}
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (no_dhcp_expired_time_cli, static) = {
 .path = "no dhcp expired",
 .short_help = "no dhcp expired <pool-name>",
 .function = no_dhcp_expired_time_fn,
};

u32 netmask_len2str(u32 mask_len)
{
    int i = 1;
    u32 i_mask = 1;
    
    for (i = 1; i < mask_len; i++)
    {
        i_mask = (i_mask << 1) | 1;
    }

    i_mask = htonl(i_mask << (32 - mask_len));
    return i_mask;
}

/*******************************************************************************
 函数名称  : dhcp_server_apply_pool_command_fn
 功能描述  : 配置接口引用的地址池
 输入参数  : 用户输入命令
 输出参数  : 无
 返 回 值  : 无           成功
             错误信息     失败
 命    令  : dhcp server apply ip-pool <pool-name> <interface-name>
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
static clib_error_t *
dhcp_server_apply_pool_command_fn (vlib_main_t * vm,
							unformat_input_t * input,
							vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	char * pool_name;
	dhcp_server_pool * ret = NULL;
	vnet_interface_config * node = NULL;
	int if_sw_index = ~0;
	vnet_main_t * vnm = vnet_get_main ();
	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
		 return clib_error_return (0, "mandatory argument(s) missing");
	
	if (unformat (line_input, " %s", &pool_name));

	if (! unformat_user (line_input, unformat_vnet_sw_interface, vnm, &if_sw_index))
   		return clib_error_return (0, "index error");
	
	ret = search_name_node(pool_name);
	if (NULL == ret)
		return clib_error_return (0, "Don't have the dhcp server ip-pool");
	else
	{
		node = get_interface_message_by_sw_index(if_sw_index);
		u32 mask_u = netmask_len2str(node->mask);
		ret->if_subnet = ((node->ip_address)&(mask_u)); //接口网络地址
		ret->if_mask= mask_u;
	}
	
	unformat_free (line_input);
	return 0;
}
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (dhcp_server_apply_pool_cli, static) = {
 .path = "dhcp server apply ip-pool",
 .short_help = "dhcp server apply ip-pool <pool-name> <interface-name>",
 .function = dhcp_server_apply_pool_command_fn,
};

/*******************************************************************************
 函数名称  : no_dhcp_apply_pool_command_fn
 功能描述  : 配置接口引用的地址池
 输入参数  : 用户输入命令
 输出参数  : 无
 返 回 值  : 无           成功
             错误信息     失败
 命    令  : no dhcp server apply ip-pool <pool-name>
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 
 修改日期  : 
*******************************************************************************/
static clib_error_t *
no_dhcp_apply_pool_command_fn (vlib_main_t * vm,
							unformat_input_t * input,
							vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	char * pool_name;
	u32 set_name = 0;
	dhcp_server_pool * ret = NULL;
		
	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
		 return clib_error_return (0, "mandatory argument(s) missing");
	
	if (unformat (line_input, " %s", &pool_name))
        set_name = 1;

	if (set_name)
		ret = search_name_node(pool_name);
	if (NULL == ret)
		return clib_error_return (0, "Don't have the dhcp server ip-pool");
	else
	{
		ret->if_subnet= 0;
		ret->if_mask = 0;
	}
	
	unformat_free (line_input);
	return 0;
}
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (no_dhcp_apply_pool_cli, static) = {
 .path = "no dhcp server apply ip-pool",
 .short_help = "no dhcp server apply ip-pool <pool-name>",
 .function = no_dhcp_apply_pool_command_fn,
};

static clib_error_t *
display_dhcp_ipinuse_command_fn (vlib_main_t * vm,
							unformat_input_t * input,
							vlib_cli_command_t * cmd)
{
	unformat_input_t _line_input, *line_input = &_line_input;
	struct in_addr addr;
	/* Get a line of input. */
	if (!unformat_user (input, unformat_line_input, line_input))
		 return clib_error_return (0, "mandatory argument(s) missing");
	

	vlib_cli_output (vm,"IP address       Client-identifier/       Type");
	vlib_cli_output (vm,"                  Hardware address");
	dhcp_client_info_t * client_info = NULL;
	int i = 0;
	for (i = 0; i<DHCP_HASH_SIZE; i++)
	{  
	    rte_spinlock_lock(&dhcp_client_info[i].lock);
		dl_list_for_each (client_info, &dhcp_client_info[i].client_list, dhcp_client_info_t, client_list)
		{   
			if (client_info->ip >0)
			{
				memcpy (&addr, &(client_info->ip), 4);
				vlib_cli_output (vm,"%s     %02x:%02x:%02x:%02x:%02x:%02x     Auto:COMMITTED",inet_ntoa(addr),
										*(client_info->mac),*((client_info->mac)+1),*((client_info->mac)+2),
										*((client_info->mac)+3),*((client_info->mac)+4),*((client_info->mac)+5));
			}
		}
		rte_spinlock_unlock(&dhcp_client_info[i].lock);
	}
	unformat_free (line_input);
	return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (display_dhcp_ipinuse_cli, static) = {
 .path = "display dhcp server ip-in-use",
 .short_help = "display dhcp server ip-in-use",
 .function = display_dhcp_ipinuse_command_fn,
};


