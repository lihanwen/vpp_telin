/*
 * gre_interface.c: gre interfaces
 *
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
 * @brief L2-GRE over IPSec tunnel interface.
 *
 * Creates ipsec-gre tunnel interface.
 * Provides a command line interface so humans can interact with VPP.
 */

#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ipsec-gre/ipsec_gre.h>
#include <vnet/ip/format.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>
#include <vnet/portal/interface_portal.h>
#include <vnet/radius/interface_radius.h>
//#include <vnet/pppoe/interface_pppoe.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <vnet/dhcp/server_cmd.h>

#include "../../../plugins/snat-plugin/snat/snat.h"
 
int(*snat_write_pointer)(void) = NULL;


groupstruct* headnode = NULL;

u8 *
format_ipsec_gre_tunnel (u8 * s, va_list * args)
{
  ipsec_gre_tunnel_t *t = va_arg (*args, ipsec_gre_tunnel_t *);
  ipsec_gre_main_t *gm = &ipsec_gre_main;

  s = format (s,
	      "[%d] %U (src) %U (dst) local-sa %d remote-sa %d",
	      t - gm->tunnels,
	      format_ip4_address, &t->tunnel_src,
	      format_ip4_address, &t->tunnel_dst,
	      t->local_sa_id, t->remote_sa_id);
  return s;
}

static clib_error_t *
show_ipsec_gre_tunnel_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  ipsec_gre_main_t *igm = &ipsec_gre_main;
  ipsec_gre_tunnel_t *t;

  if (pool_elts (igm->tunnels) == 0)
    vlib_cli_output (vm, "No IPSec GRE tunnels configured...");

  /* *INDENT-OFF* */
  pool_foreach (t, igm->tunnels,
  ({
    vlib_cli_output (vm, "%U", format_ipsec_gre_tunnel, t);
  }));
  /* *INDENT-ON* */

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ipsec_gre_tunnel_command, static) = {
    .path = "show ipsec gre tunnel",
    .function = show_ipsec_gre_tunnel_command_fn,
};
/* *INDENT-ON* */

/* force inclusion from application's main.c */
clib_error_t *
ipsec_gre_interface_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (ipsec_gre_interface_init);

/**
 * @brief Add or delete ipsec-gre tunnel interface.
 *
 * @param *a vnet_ipsec_gre_add_del_tunnel_args_t - tunnel interface parameters
 * @param *sw_if_indexp u32 - software interface index
 * @return int - 0 if success otherwise <code>VNET_API_ERROR_</code>
 */
int
vnet_ipsec_gre_add_del_tunnel (vnet_ipsec_gre_add_del_tunnel_args_t * a,
			       u32 * sw_if_indexp)
{
  ipsec_gre_main_t *igm = &ipsec_gre_main;
  vnet_main_t *vnm = igm->vnet_main;
  ip4_main_t *im = &ip4_main;
  ipsec_gre_tunnel_t *t;
  vnet_hw_interface_t *hi;
  u32 hw_if_index, sw_if_index;
  u32 slot;
  uword *p;
  u64 key;
  ipsec_add_del_ipsec_gre_tunnel_args_t args;

  memset (&args, 0, sizeof (args));
  args.is_add = a->is_add;
  args.local_sa_id = a->lsa;
  args.remote_sa_id = a->rsa;
  args.local_ip.as_u32 = a->src.as_u32;
  args.remote_ip.as_u32 = a->dst.as_u32;

  key = (u64) a->src.as_u32 << 32 | (u64) a->dst.as_u32;
  p = hash_get (igm->tunnel_by_key, key);

  if (a->is_add)
    {
      /* check if same src/dst pair exists */
      if (p)
	return VNET_API_ERROR_INVALID_VALUE;

      pool_get_aligned (igm->tunnels, t, CLIB_CACHE_LINE_BYTES);
      memset (t, 0, sizeof (*t));

      if (vec_len (igm->free_ipsec_gre_tunnel_hw_if_indices) > 0)
	{
	  vnet_interface_main_t *im = &vnm->interface_main;

	  hw_if_index = igm->free_ipsec_gre_tunnel_hw_if_indices
	    [vec_len (igm->free_ipsec_gre_tunnel_hw_if_indices) - 1];
	  _vec_len (igm->free_ipsec_gre_tunnel_hw_if_indices) -= 1;

	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	  hi->dev_instance = t - igm->tunnels;
	  hi->hw_instance = hi->dev_instance;

	  /* clear old stats of freed tunnel before reuse */
	  sw_if_index = hi->sw_if_index;
	  vnet_interface_counter_lock (im);
	  vlib_zero_combined_counter
	    (&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_TX],
	     sw_if_index);
	  vlib_zero_combined_counter
	    (&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_RX],
	     sw_if_index);
	  vlib_zero_simple_counter
	    (&im->sw_if_counters[VNET_INTERFACE_COUNTER_DROP], sw_if_index);
	  vnet_interface_counter_unlock (im);
	}
      else
	{
	  hw_if_index = vnet_register_interface
	    (vnm, ipsec_gre_device_class.index, t - igm->tunnels,
	     ipsec_gre_hw_interface_class.index, t - igm->tunnels);
	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	  sw_if_index = hi->sw_if_index;
	}

      t->hw_if_index = hw_if_index;
      t->sw_if_index = sw_if_index;
      t->local_sa_id = a->lsa;
      t->remote_sa_id = a->rsa;
      t->local_sa = ipsec_get_sa_index_by_sa_id (a->lsa);
      t->remote_sa = ipsec_get_sa_index_by_sa_id (a->rsa);

      ip4_sw_interface_enable_disable (sw_if_index, 1);

      vec_validate_init_empty (igm->tunnel_index_by_sw_if_index,
			       sw_if_index, ~0);
      igm->tunnel_index_by_sw_if_index[sw_if_index] = t - igm->tunnels;

      vec_validate (im->fib_index_by_sw_if_index, sw_if_index);

      hi->min_packet_bytes = 64 + sizeof (gre_header_t) +
	sizeof (ip4_header_t) + sizeof (esp_header_t) + sizeof (esp_footer_t);
      hi->per_packet_overhead_bytes =
	/* preamble */ 8 + /* inter frame gap */ 12;

      /* Standard default gre MTU. */
      hi->max_l3_packet_bytes[VLIB_RX] = hi->max_l3_packet_bytes[VLIB_TX] =
	9000;

      clib_memcpy (&t->tunnel_src, &a->src, sizeof (t->tunnel_src));
      clib_memcpy (&t->tunnel_dst, &a->dst, sizeof (t->tunnel_dst));

      hash_set (igm->tunnel_by_key, key, t - igm->tunnels);

      slot = vlib_node_add_named_next_with_slot
	(vnm->vlib_main, hi->tx_node_index, "esp-encrypt",
	 IPSEC_GRE_OUTPUT_NEXT_ESP_ENCRYPT);

      ASSERT (slot == IPSEC_GRE_OUTPUT_NEXT_ESP_ENCRYPT);

    }
  else
    {				/* !is_add => delete */
      /* tunnel needs to exist */
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      t = pool_elt_at_index (igm->tunnels, p[0]);

      sw_if_index = t->sw_if_index;
      ip4_sw_interface_enable_disable (sw_if_index, 0);
      vnet_sw_interface_set_flags (vnm, sw_if_index, 0 /* down */ );
      /* make sure tunnel is removed from l2 bd or xconnect */
      set_int_l2_mode (igm->vlib_main, vnm, MODE_L3, sw_if_index, 0, 0, 0, 0);
      vec_add1 (igm->free_ipsec_gre_tunnel_hw_if_indices, t->hw_if_index);
      igm->tunnel_index_by_sw_if_index[sw_if_index] = ~0;

      hash_unset (igm->tunnel_by_key, key);
      pool_put (igm->tunnels, t);
    }

  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  return ipsec_add_del_ipsec_gre_tunnel (vnm, &args);
}

static clib_error_t *
create_ipsec_gre_tunnel_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  u32 num_m_args = 0;
  ip4_address_t src, dst;
  u32 lsa = 0, rsa = 0;
  vnet_ipsec_gre_add_del_tunnel_args_t _a, *a = &_a;
  int rv;
  u32 sw_if_index;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, "src %U", unformat_ip4_address, &src))
	num_m_args++;
      else if (unformat (line_input, "dst %U", unformat_ip4_address, &dst))
	num_m_args++;
      else if (unformat (line_input, "local-sa %d", &lsa))
	num_m_args++;
      else if (unformat (line_input, "remote-sa %d", &rsa))
	num_m_args++;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (num_m_args < 4)
    return clib_error_return (0, "mandatory argument(s) missing");

  if (memcmp (&src, &dst, sizeof (src)) == 0)
    return clib_error_return (0, "src and dst are identical");

  memset (a, 0, sizeof (*a));
  a->is_add = is_add;
  a->lsa = lsa;
  a->rsa = rsa;
  clib_memcpy (&a->src, &src, sizeof (src));
  clib_memcpy (&a->dst, &dst, sizeof (dst));

  rv = vnet_ipsec_gre_add_del_tunnel (a, &sw_if_index);

  switch (rv)
    {
    case 0:
      vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name,
		       vnet_get_main (), sw_if_index);
      break;
    case VNET_API_ERROR_INVALID_VALUE:
      return clib_error_return (0, "GRE tunnel already exists...");
    default:
      return clib_error_return (0,
				"vnet_ipsec_gre_add_del_tunnel returned %d",
				rv);
    }

  return 0;
}
static clib_error_t *
write_interface_config_file()
{	
	clib_error_t *error = 0;
	vnet_interface_config *tmp=clib_mem_alloc(sizeof(*tmp));
	tmp=vifm->next;
	FILE *fp;
	fp=fopen("/etc/interface_config.conf", "w+");
	if(fp==NULL)
	{
		error = clib_error_return (0, "open interface_config.config error");
		goto done;
	}
	while(tmp){
		fprintf(fp,  
				"#\n"
				"if_name %s\n"
				"if_type %d\n"
				"ip_address %d %d\n"
				"state %d\n"
				"portal.enable_portal %d\n"
				"portal.portal_bas_ip %d\n"
				"portal.apply_webs %s\n",
				tmp->if_name,
				tmp->if_type,
				tmp->ip_address,
				tmp->mask,
				tmp->state,
				tmp->if_portal.enable_portal,
				tmp->if_portal.portal_bas_ip,
				tmp->if_portal.apply_webs);
	tmp=tmp->next;
	}
	free(tmp);
	fclose(fp);
done:
return error;
}

static clib_error_t *
write_config_to_file_command_fn(vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{	
	clib_error_t *error = 0;
	if(write_interface_config_file())
	{
		vlib_cli_output(vm,"write interface file error\n");
		error = clib_error_return (0, "write file have error");
	}
	if(write_portal_config_file ())
	{
		vlib_cli_output(vm,"write portal file error\n");
		error = clib_error_return (0, "write file have error"); }
	if(write_radius_config_file ())
	{
		vlib_cli_output(vm,"write radius file error\n");
		error = clib_error_return (0, "write file have error");
	}
	if(write_radius_account_config_file ())
	{
		vlib_cli_output(vm,"write radius file error\n");
		error = clib_error_return (0, "write file have error");
	}
	if(write_dhcp_config_file())
	{
		vlib_cli_output(vm,"write dhcp config file error\n");
		error = clib_error_return (0, "write file have error");
	}
	if(write_dhcp_rdconfig_file())
	{
		vlib_cli_output(vm,"write dhcp rd config file error\n");
		error = clib_error_return (0, "write file have error");
	}
	if(snat_write_pointer != NULL)
	if(snat_write_pointer())
	{
		vlib_cli_output(vm,"write snat config file error\n");
		error = clib_error_return (0, "write file have error");
	}
	if(snat_write_pointer == NULL)	
		{
				vlib_cli_output(vm,"write snat config file error\n");
				error = clib_error_return (0, "write file have error");
		}

	
	return error;
}

static clib_error_t *
show_run_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
	struct in_addr addr;
	vnet_interface_config *tmp = clib_mem_alloc(sizeof(*tmp));
	memset(tmp,0,sizeof(*tmp));
	tmp=vifm->next;
	vlib_cli_output(vm,"#\n"
   	                  " system-working-mode standard\n"
   	                  " xbar load-single\n"
   	                  " password-recovery enable\n"
   	                  " lpu-type f-series\n");
	portal_qos_carl* carl_mag = qos_carl_msg;
	portal_qos_interface* qos_inter =  qos_interface;
	vlib_cli_output(vm,"#\n"
   	                  "qos carl config");
	for(int i=1;i<200;i++){
			if(carl_mag[i].carl_index==0)
				continue;
			memcpy(&addr, &carl_mag[i].ip_address, 4);
			vlib_cli_output(vm,"qos carl %d %s subnet %s %d\n",
			carl_mag[i].carl_index,
			carl_mag[i].ip_flag,
			inet_ntoa(addr),
			carl_mag[i].mask_length);

		}

    /* virtual interface */
	while(tmp!=NULL && VNET_INTERFACE_TYPE_VT == tmp->if_type){
		vlib_cli_output(vm,"#\n"
							"interface %s\n"
							" port link-mode route\n"
							" combo enable copper\n"
							" type %d\n",
							tmp->if_name,
							tmp->if_type);
		for(int i=0;i<qos_inter[tmp->if_index].inbound_index;i++){
		if(qos_inter[tmp->if_index].interface_car_inbound[i]!=NULL){
			if(qos_inter[tmp->if_index].interface_car_inbound[i]->any_flag==1){
			vlib_cli_output(vm,
							"Direction: Inbound\n"
							" Rule(s): If-match Any\n"
							" CIR %d (kbps) CBS %d (kbps)\n",
							qos_inter[tmp->if_index].interface_car_inbound[i]->cir,
							qos_inter[tmp->if_index].interface_car_inbound[i]->cbs);
			}else{
			vlib_cli_output(vm,
							"Direction: Inbound\n"
							" Rule(s): If-match CAEL %d\n"
							" CIR %d (kbps) CBS %d (kbps)\n",
							qos_inter[tmp->if_index].interface_car_inbound[i]->carl_index,
							qos_inter[tmp->if_index].interface_car_inbound[i]->cir,
							qos_inter[tmp->if_index].interface_car_inbound[i]->cbs);
			}

		}}
		
		for(int i=0;i<qos_inter[tmp->if_index].outbound_index;i++){
		if(qos_inter[tmp->if_index].interface_car_outbound[i]!=NULL){
			
			if(qos_inter[tmp->if_index].interface_car_outbound[i]->any_flag==1){
			vlib_cli_output(vm,
							"Direction: Outbound\n"
							" Rule(s): If-match Any\n"
							" CIR %d (kbps) CBS %d (kbps)\n",
							qos_inter[tmp->if_index].interface_car_outbound[i]->cir,
							qos_inter[tmp->if_index].interface_car_outbound[i]->cbs);
			}else{
			vlib_cli_output(vm,
							"Direction: Outbound\n"
							" Rule(s): If-match CAEL %d\n"
							" CIR %d (kbps) CBS %d (kbps)\n",
							qos_inter[tmp->if_index].interface_car_outbound[i]->carl_index,
							qos_inter[tmp->if_index].interface_car_outbound[i]->cir,
							qos_inter[tmp->if_index].interface_car_outbound[i]->cbs);
			}
			}}
			
#if 0		
		if(tmp->if_pppoe.timer_hold != 0)
			vlib_cli_output (vm, " timer-hold %d\n", tmp->if_pppoe.timer_hold);
		if(tmp->if_pppoe.timer_hold_retry != 0)
			vlib_cli_output (vm, " timer-hold retry %d\n", tmp->if_pppoe.timer_hold_retry);
		if(strlen(tmp->if_pppoe.auth_type) != 0)
			vlib_cli_output (vm, " ppp authentication-mode %s domain system \n",
				tmp->if_pppoe.auth_type);
		if(strlen(tmp->if_pppoe.dns1) != 0)
			vlib_cli_output (vm, " ppp ipcp dns %s ", tmp->if_pppoe.dns1);
		if(strlen(tmp->if_pppoe.dns2) != 0)
			vlib_cli_output (vm, "dns2 %s \n", tmp->if_pppoe.dns2);
		else
			vlib_cli_output (vm, "\n", tmp->if_pppoe.dns2);
		if(tmp->if_pppoe.timer_neg != 0)
			vlib_cli_output (vm, " ppp timer negotiate %d\n", tmp->if_pppoe.timer_neg);
		if(strlen(tmp->if_pppoe.pool_name) != 0)
			vlib_cli_output (vm, " remote address pool %s\n", tmp->if_pppoe.pool_name);
#endif			
        /* portal interface */
		if (tmp->if_portal.enable_portal)
			vlib_cli_output (vm, " portal enable method direct\n");
		if (tmp->if_portal.portal_bas_ip)
		{
			memcpy(&addr, &tmp->if_portal.portal_bas_ip, 4);
			vlib_cli_output (vm, " portal bas-ip %s\n", inet_ntoa(addr));
		}
		if (strlen((char *)tmp->if_portal.apply_webs) >0)
			vlib_cli_output (vm, " portal apply web-server %s\n", tmp->if_portal.apply_webs);
		tmp = tmp->next;
	}
	
	if(tmp!=NULL && tmp->if_type ==VNET_INTERFACE_TYPE_GE )
		vlib_cli_output (vm, "#\ninterface NULL0\n");
		
	/*GigabitEthernet0/0 interface*/
	while(tmp!=NULL && VNET_INTERFACE_TYPE_GE == tmp->if_type){
		vlib_cli_output (vm,"#\n"
							"interface %s\n"
							" port link-mode route\n"
							" combo enable copper\n",
							tmp->if_name);
#if 0
		/* pppoe */
		if(strlen(tmp->if_pppoe.bind_if) != 0)
			vlib_cli_output (vm, " pppoe-server bind virtual-template %s\n",
					tmp->if_pppoe.bind_if + (strlen(tmp->if_pppoe.bind_if) - 1));
		if(tmp->if_pppoe.timer_hold != 0)
			vlib_cli_output (vm, " pppoe-server access-delay %d\n",
					tmp->if_pppoe.access_delay);
#endif
      /* portal interface */
	    if (tmp->if_portal.enable_portal)
			vlib_cli_output (vm, " portal enable method direct\n");
		if (tmp->if_portal.portal_bas_ip)
		{
			memcpy(&addr, &tmp->if_portal.portal_bas_ip, 4);
			vlib_cli_output (vm, " portal bas-ip %s\n", inet_ntoa(addr));
		}
		if (strlen((char *)tmp->if_portal.apply_webs) >0)
			vlib_cli_output (vm, " portal apply web-server %s\n", tmp->if_portal.apply_webs);		
		tmp=tmp->next;
		}	

   /* radius */
    struct in_addr addr0, addr1, addr2;
    int i = 0;
    for (i = 0; i<RADIUS_MAX; i++)
    {      	
	    if (strlen((char *)radius_ser_info[i].radius_scheme_name) <=0)
			continue;
					
		vlib_cli_output(vm, "#\n");
		vlib_cli_output(vm, "radius scheme %s\n", radius_ser_info[i].radius_scheme_name);
	
        if (radius_ser_info[i].prim_auth_ip)
        {
			memcpy(&addr0, &radius_ser_info[i].prim_auth_ip, 4);
			vlib_cli_output (vm, " primary authentication %s\n", inet_ntoa(addr0));	
        }	
	    if (radius_ser_info[i].prim_account_ip)
	    {
			memcpy(&addr1, &radius_ser_info[i].prim_account_ip, 4);
			vlib_cli_output (vm, " primary accounting %s\n", inet_ntoa(addr1));
	    }
        if (radius_ser_info[i].security_policy_ip)
        {
          	memcpy(&addr2, &radius_ser_info[i].security_policy_ip, 4);
			vlib_cli_output (vm, " security-policy-server %s\n", inet_ntoa(addr2));
        }
		if (strlen((char *)radius_ser_info[i].key_auth) >0)
        	vlib_cli_output (vm, " key authentication simple %s\n", radius_ser_info[i].key_auth);
        if (strlen((char *)radius_ser_info[i].key_account) >0)
        	vlib_cli_output (vm, " key accounting simple %s\n", radius_ser_info[i].key_account);
    }
	/* portal web-server */
	for (i=0; i<PORTAL_WEBS_MAX; i++)
	{
	    if (strlen((char *)portal_webs_msg[i].portal_webs_name) <=0)
	   	    continue;								
					
		vlib_cli_output(vm, "#\n");
		vlib_cli_output(vm, "portal web-server %s\n", portal_webs_msg[i].portal_webs_name);
		if (strlen((char *)portal_webs_msg[i].webs_url) >0)
			vlib_cli_output(vm, " url %s\n", portal_webs_msg[i].webs_url);
	}
	/* portal server */
	struct in_addr addr3;	
	for (i=0; i<PORTAL_SERVER_MAX; i++)
	{
		if (strlen((char *)portal_server_msg[i].portal_server_name) <=0)
	   	 	continue;
		vlib_cli_output(vm, "#\n");			
		vlib_cli_output(vm, "portal server %s\n", portal_server_msg[i].portal_server_name);
		
		if (portal_server_msg[i].portal_server_ip && strlen((char *)portal_server_msg[i].key_portal))
		{
        	memcpy(&addr3, &portal_server_msg[i].portal_server_ip, 4);
			vlib_cli_output(vm, " ip %s key simple %s\n", inet_ntoa(addr3), portal_server_msg[i].key_portal);
		}
	}
		/* portal free rule */	
	int ret_num = 0, if_free_rule = 1;	
	for(i = 0; i < PORTAL_FREE_RUULE_NUM; i++)	
	{		
		ret_num	= search_portal_free_rule(i, -1);	
		if(ret_num == -1)/* ¡ã¡Á??¦Ì£¤¨ºy¡Á¨¦?D¨®DIP¦Ì??¡¤ */
		{		
			if(if_free_rule)
			{
				vlib_cli_output(vm, "#\n");
				if_free_rule = 0;
			}
			memcpy(&addr0, &(portal_free_rule[i]), 4);
			vlib_cli_output(vm, " portal free-rule %d destination ip %s\n", i, inet_ntoa(addr0));
		}
	}
		/*radius account*/
	struct in_addr addr4,addr5;	
		
	vlib_cli_output(vm, "#\n");
	
	vlib_cli_output(vm, "radius account\n");
	for(i=0;i<RADIUS_MAX;i++){
		if(0!=radius_account_info[i].radius_user_ip){	
		memcpy(&addr4, &radius_account_info[i].radius_user_ip, 4);
		memcpy(&addr5, &radius_account_info[i].subnet_mask, 4);
		vlib_cli_output(vm, " user_ip %s networkSegment %s switch %s account_type %s\n", inet_ntoa(addr4), inet_ntoa(addr5),radius_account_info[i].account_type);
		}
	}

////////////////////snat
					struct in_addr addrs, addre;
					groupstruct* temp = headnode;
					vlib_cli_output(vm, "#\n");
					vlib_cli_output(vm, "snat message\n");


					while(1)
					{
									if(temp == NULL)
										break; 
	
								    memcpy(&addrs, &temp->start_addr.data_u32, 4);
									memcpy(&addre, &temp->end_addr.data_u32, 4);
									vlib_cli_output(vm, "%s group %d ip start %s ", temp->giga, temp->groupnum, inet_ntoa(addrs));
									vlib_cli_output(vm, "ip end %s\n\n", inet_ntoa(addre));
									temp = temp->next;
	
					}  
	
	
	return 0;
}

static clib_error_t *
create_virtual_template_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  u32 num_m_args = 0;
  u32 id = 0;
  vnet_ppp_add_del_tunnel_args_t _a, *a = &_a;
  int rv;
  u32 sw_if_index;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	is_add = 0;
      else if (unformat (line_input, " %d", &id))
	num_m_args++;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (num_m_args < 1)
    return clib_error_return (0, "mandatory argument(s) missing");

  memset (a, 0, sizeof (*a));
  a->id=id;
  a->is_add = is_add;

  rv = vnet_add_del_virtual_template (a, &sw_if_index);

  switch (rv)
    {
    case 0:
      vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name,
		       vnet_get_main (), sw_if_index);
      break;
    case VNET_API_ERROR_INVALID_VALUE:
      return clib_error_return (0, "ppp tunnel already exists...");
    default:
      return clib_error_return (0,
				"vnet_ppp_add_del_tunnel returned %d",
				rv);
    }

  return 0;
}
int
vnet_add_del_virtual_template (vnet_ppp_add_del_tunnel_args_t * a,
			       u32 * sw_if_indexp)
{
  ipsec_ppp_main_t *ipm = &ipsec_ppp_main;
  vnet_main_t *vnm = ipm->vnet_main;
  ipsec_ppp_tunnel_t *t;
  vnet_hw_interface_t *hi;
  u32 hw_if_index=0, sw_if_index=0;
  u32 slot;
  uword *p;
  ipsec_add_del_ppp_tunnel_args_t args;

  memset (&args, 0, sizeof (args));
  args.id=a->id;
  args.is_add = a->is_add;
  
  p = hash_get (ipm->tunnel_by_key,(u64)a->id);

  if (a->is_add)
    {
      /* check if same src/dst pair exists */
      if (p)
	return VNET_API_ERROR_INVALID_VALUE;

      pool_get_aligned (ipm->tunnels, t, CLIB_CACHE_LINE_BYTES);
      memset (t, 0, sizeof (*t));

      if (vec_len (ipm->free_ppp_tunnel_hw_if_indices) > 0)
	{
	 // vnet_interface_main_t *im = &vnm->interface_main;

	  hw_if_index = ipm->free_ppp_tunnel_hw_if_indices
	    [vec_len (ipm->free_ppp_tunnel_hw_if_indices) - 1];
	  _vec_len (ipm->free_ppp_tunnel_hw_if_indices) -= 1;

	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	  hi->dev_instance = t - ipm->tunnels;
	  hi->hw_instance = hi->dev_instance;


	}
      else
	{
	  hw_if_index = vnet_register_interface
	    (vnm, ipsec_ppp_device_class.index, a->id,
	     ipsec_ppp_hw_interface_class.index, a->id);
	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	  sw_if_index = hi->sw_if_index;
	}
	  hash_set (ipm->tunnel_by_key, (u64)a->id, t - ipm->tunnels);

      slot = vlib_node_add_named_next_with_slot
	(vnm->vlib_main, hi->tx_node_index, "esp-encrypt",
	 IPSEC_GRE_OUTPUT_NEXT_ESP_ENCRYPT);
	  ASSERT (slot == IPSEC_GRE_OUTPUT_NEXT_ESP_ENCRYPT);

    }
  else
    {	
    /* tunnel needs to exist */
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      t = pool_elt_at_index (ipm->tunnels, p[0]);

      sw_if_index = t->sw_if_index;
      vec_add1 (ipm->free_ppp_tunnel_hw_if_indices, t->hw_if_index);

      ip4_sw_interface_enable_disable (sw_if_index, 0);
      vnet_sw_interface_set_flags (vnm, sw_if_index, 0 /* down */ );
	  //ethernet_delete_interface (vnm, t->hw_if_index);
      set_int_l2_mode (ipm->vlib_main, vnm, MODE_L3, sw_if_index, 0, 0, 0, 0);
      //ipm->tunnel_index_by_sw_if_index[sw_if_index] = ~0;
      hash_unset (ipm->tunnel_by_key, (u64)a->id);
      pool_put (ipm->tunnels, t);
    }

  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  return 0;
}
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_ipsec_gre_tunnel_command, static) = {
  .path = "create ipsec gre tunnel",
  .short_help = "create ipsec gre tunnel src <addr> dst <addr> "
                "local-sa <id> remote-sa <id> [del]",
  .function = create_ipsec_gre_tunnel_command_fn,
};
/* *INDENT-ON* */
VLIB_CLI_COMMAND (show_run_command, static) = {
  .path = "show run",
  .short_help = "show run",
  .function = show_run_command_fn,
};

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_virtual_template_command, static) = {
  .path = "create virtual-template",
  .short_help = "create virtual-template <id> [del]",
  .function = create_virtual_template_command_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (write_config_to_file_command, static) = {
  .path = "write file",
  .short_help = "write file",
  .function = write_config_to_file_command_fn,
};
/* *INDENT-ON* */

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
