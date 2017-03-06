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
 * ip/ip4_input.c: IP v4 input node
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

#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ppp/ppp.h>
#include <vnet/hdlc/hdlc.h>
#include <vnet/ethernet/packet.h>
#include <vnet/portal_redirect/portal_red.h>
#include <vnet/portal/portal.h>
#define DHCP_SERVER_TO_CLIENT_PORT 68

extern int portal_redirect_process (ip4_header_t * ip4, u32 sw_if_index,PORTAL_RED_USER_INFO *user_red);
extern vnet_device_class_t af_packet_device_class;

typedef struct {
  u8 packet_data[64];
} ip4_input_trace_t;

static u8 * format_ip4_input_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  ip4_input_trace_t * t = va_arg (*va, ip4_input_trace_t *);

  s = format (s, "%U",
	      format_ip4_header,
	      t->packet_data, sizeof (t->packet_data));

  return s;
}

typedef enum {
  IP4_INPUT_NEXT_DROP,
  IP4_INPUT_NEXT_PUNT,
  IP4_INPUT_NEXT_LOOKUP,
  IP4_INPUT_NEXT_LOOKUP_MULTICAST,
  IP4_INPUT_NEXT_ICMP_ERROR,
  IP4_INPUT_N_NEXT,
} ip4_input_next_t;
/* Validate IP v4 packets and pass them either to forwarding code
   or drop/punt exception packets. */
always_inline uword
ip4_input_inline (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame,
		  int verify_checksum)
{
  ip4_main_t * im = &ip4_main;
  vnet_main_t * vnm = vnet_get_main();
  ip_lookup_main_t * lm = &im->lookup_main;
  u32 n_left_from, * from, * to_next;
  ip4_input_next_t next_index;
  vlib_node_runtime_t * error_node = vlib_node_get_runtime (vm, ip4_input_node.index);
  vlib_simple_counter_main_t * cm;
  u32 cpu_index = os_get_cpu_number();

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    vlib_trace_frame_buffers_only (vm, node, from, frame->n_vectors,
				   /* stride */ 1,
				   sizeof (ip4_input_trace_t));

  cm = vec_elt_at_index (vnm->interface_main.sw_if_counters,
                         VNET_INTERFACE_COUNTER_IP4);

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  vlib_buffer_t * p0, * p1, *b0, *b1;
	  ip4_header_t * ip0, * ip1;
	  udp_header_t * udp0, *udp1;
	  vlib_frame_t * f0, *f1;
	  u32  *to_output0, * to_output1 = NULL;
	  u32 sw_if_index0, pi0, ip_len0, cur_len0, bi0, sw_output_id0, next0 = 0;
	  u32 sw_if_index1, pi1, ip_len1, cur_len1, bi1, sw_output_id1, next1 = 0;
	  i32 len_diff0, len_diff1;
	  u8 error0, error1, arc0, arc1;
	  vnet_hw_interface_t *hw0, *hw1, *output_if0, *output_if1;
	  vnet_sw_interface_t *sw0 = NULL; 
	  vnet_sw_interface_t *sw1 = NULL;
	  vnet_sw_interface_t *input_sw0 = NULL; 
	  vnet_sw_interface_t *input_sw1 = NULL;
	  ethernet_header_t *eth_header0, *eth_header1;
	  ethernet_header_t *eth_header_output0, *eth_header_output1;
	  ethernet_vlan_header_t *vlan_header0, *vlan_header1;

	  PORTAL_RED_USER_INFO red_user0;
	  PORTAL_RED_USER_INFO red_user1;
	 
	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t * p2, * p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);

	    CLIB_PREFETCH (p2->data, sizeof (ip0[0]), LOAD);
	    CLIB_PREFETCH (p3->data, sizeof (ip1[0]), LOAD);
	  }

	  to_next[0] = pi0 = from[0];
	  to_next[1] = pi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  p0 = vlib_get_buffer (vm, pi0);
	  p1 = vlib_get_buffer (vm, pi1);

	  ip0 = vlib_buffer_get_current (p0);
	  ip1 = vlib_buffer_get_current (p1);

	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer (p1)->sw_if_index[VLIB_RX];

	  arc0 = ip4_address_is_multicast (&ip0->dst_address) ? lm->mcast_feature_arc_index : lm->ucast_feature_arc_index;
	  arc1 = ip4_address_is_multicast (&ip1->dst_address) ? lm->mcast_feature_arc_index : lm->ucast_feature_arc_index;
          
	  if(arc0 != lm->mcast_feature_arc_index)
          {
		arc0 = ip4_address_is_broadcast (&ip0->dst_address) ? lm->mcast_feature_arc_index : lm->ucast_feature_arc_index;
	  }
	  if(arc1 != lm->mcast_feature_arc_index)
          {
		arc1 = ip4_address_is_broadcast (&ip1->dst_address) ? lm->mcast_feature_arc_index : lm->ucast_feature_arc_index;
	  }
          
	  vnet_buffer (p0)->ip.adj_index[VLIB_RX] = ~0;
	  vnet_buffer (p1)->ip.adj_index[VLIB_RX] = ~0;

	  vnet_feature_arc_start (arc0, sw_if_index0, &next0, p0);
	  vnet_feature_arc_start (arc1, sw_if_index1, &next1, p1);
	  output_if0 = hw0 = vnet_get_sup_hw_interface (vnm, vnet_buffer(p0)->sw_if_index[VLIB_RX]);
	  output_if1 = hw1 = vnet_get_sup_hw_interface (vnm, vnet_buffer(p1)->sw_if_index[VLIB_RX]);
	  input_sw0 = vnet_get_sw_interface(vnm, vnet_buffer(p0)->sw_if_index[VLIB_RX]);
	  input_sw1 = vnet_get_sw_interface(vnm, vnet_buffer(p1)->sw_if_index[VLIB_RX]);
<<<<<<< .mine
	  eth_header0 = ethernet_buffer_get_header(p0);
	  if(input_sw0->portal_index_info.portal_info.enable_portal && portal_redirect_process(ip0, eth_header0, sw_if_index0))
||||||| .r83
	  if(input_sw0->portal_index_info.portal_info.enable_portal && portal_redirect_process(ip0, sw_if_index0))
=======

	  eth_header0 = ethernet_buffer_get_header(p0);
	  eth_header1 = ethernet_buffer_get_header(p1);
	  red_user0.user_ip = ip0->src_address.as_u32;
	  red_user1.user_ip = ip1->src_address.as_u32;
	  clib_memcpy(red_user0.user_mac, eth_header0->src_address + 1, ETHER_MAC_LEN);	 
	  clib_memcpy(red_user1.user_mac, eth_header1->src_address + 1, ETHER_MAC_LEN);
	
	  if(input_sw0->portal_index_info.portal_info.enable_portal && portal_redirect_process(ip0, sw_if_index0,&red_user0))
>>>>>>> .r109
	  {
	  	 next0 = IP4_INPUT_NEXT_DROP;
	  }
	  if(input_sw1->portal_index_info.portal_info.enable_portal && portal_redirect_process(ip1, sw_if_index1,&red_user1))
	  {
	  	 next1 = IP4_INPUT_NEXT_DROP;
	  }
	  if(af_packet_device_class.index == hw0->dev_class_index)
	  {
	  	  ip4_tcp_udp_com_checksum(vm, p0);
		  next0 = IP4_INPUT_NEXT_LOOKUP;
		  if (ip0->protocol == IP_PROTOCOL_UDP )
	      {
	        	udp0 = (void *) (ip0 + 1);
				if(udp0->dst_port == clib_host_to_net_u16(DHCP_SERVER_TO_CLIENT_PORT))
				{
				    sw_output_id0 = 0;
					if(hw0->sub_int_flag)
				    {
				      	sw0 =  vnet_get_sw_interface(vnm, hw0->kernel_to_vpp_if_index);
				      	if(sw0)
				      	{
							output_if0 = vnet_get_hw_interface(vnm, sw0->host_hw_if_index);
							sw_output_id0 = sw0->sw_if_index;
						}
						if(!output_if0)
						{
							output_if0 = hw0;
						}
				    }
				    else if(INTERFACE_NULL_INDEX !=  hw0->kernel_to_vpp_if_index)
				    {
				    	output_if0 = vnet_get_hw_interface(vnm, hw0->kernel_to_vpp_if_index);
				    	if(output_if0)
						{
							sw_output_id0 = output_if0->sw_if_index;
						}
				    }
		            if(output_if0)
					{
						   if (vlib_buffer_alloc (vm, &bi0, 1)  == 1) 
						   {
								 b0 = vlib_get_buffer (vm, bi0);
								 f0 = vlib_get_frame_to_node (vm, output_if0->output_node_index);
								 vnet_buffer(b0)->sw_if_index[VLIB_TX] = sw_output_id0; 						  
								 to_output0 = vlib_frame_vector_args (f0);
								 to_output0[0] = bi0;
								 f0->n_vectors = 1;
								 eth_header_output0 = vlib_buffer_get_current(b0);					 
//					            eth_header0 = ethernet_buffer_get_header(p0);
						         clib_memcpy(eth_header_output0, eth_header0->dst_address + 1, ETHER_MAC_LEN + ETHER_MAC_LEN);
						         if(sw0 && sw0->is_sub_int)
						         {						         		
										eth_header_output0->type = clib_host_to_net_u16(ETH_PROTO_TYPE_VLAN);
										vlan_header0 = (ethernet_vlan_header_t*)(b0->data + ETHER_MAC_LEN + ETHER_MAC_LEN + ETH_PROTO_TYPE_LEN);
										vlan_header0->priority_cfi_and_id = sw0->sub.id;
										vlan_header0->type = ETH_PROTO_TYPE_IP;
										clib_memcpy( b0->data + ETH_HEADER_VLAN_HEADER_LEN, vlib_buffer_get_current(p0),   p0->current_length);
										b0->current_length = ETH_HEADER_VLAN_HEADER_LEN + p0->current_length;
						         }
								 else
								 {
										 eth_header_output0->type = clib_host_to_net_u16(ETH_PROTO_TYPE_IP);
										 clib_memcpy(b0->data + ETH_HEADER_LEN, vlib_buffer_get_current(p0),   p0->current_length);
										 b0->current_length = ETH_HEADER_LEN + p0->current_length;
								 }			
								vlib_put_frame_to_node (vm, output_if0->output_node_index, f0);
								next0 = IP4_INPUT_NEXT_DROP;
						   }				  		  
		            }
				 }
			      		
		  }

		  if(arc0 == lm->mcast_feature_arc_index)
		  {
		  	 next0 = IP4_INPUT_NEXT_LOOKUP_MULTICAST;
		  }
	  }

	  if(af_packet_device_class.index == hw1->dev_class_index)
	  {
	 	  ip4_tcp_udp_com_checksum(vm, p1);
		  next1 = IP4_INPUT_NEXT_LOOKUP;
		  if (ip1->protocol == IP_PROTOCOL_UDP )
	      {
	        	udp1 = (void *) (ip1 + 1);
				if(udp1->dst_port == clib_host_to_net_u16(DHCP_SERVER_TO_CLIENT_PORT))
				{
				    sw_output_id1 = 0;
					if(hw1->sub_int_flag)
				    {
				      	sw1 =  vnet_get_sw_interface(vnm, hw1->kernel_to_vpp_if_index);
				      	if(sw1)
						{
							output_if1 = vnet_get_hw_interface(vnm, sw1->host_hw_if_index);
							sw_output_id1 = sw1->sw_if_index;
						}
						if(!output_if1)
						{
							output_if1 = hw1;
						}
				    }
				    else if( INTERFACE_NULL_INDEX !=  hw1->kernel_to_vpp_if_index)
				    {
				    	output_if1 = vnet_get_hw_interface(vnm, hw1->kernel_to_vpp_if_index);
				    	if(output_if1)
						{
							sw_output_id1 = output_if1->sw_if_index;
						}
				    }
		            if(output_if1)
					{
						   if (vlib_buffer_alloc (vm, &bi1, 1)  == 1) 
						   {
								 b1 = vlib_get_buffer (vm, bi1);
								 f1 = vlib_get_frame_to_node (vm, output_if1->output_node_index);
								 vnet_buffer(b1)->sw_if_index[VLIB_TX] = sw_output_id1; 						  
								 to_output1 = vlib_frame_vector_args (f1);
								 to_output1[0] = bi1;
								 f1->n_vectors = 1;
								 eth_header_output1 = vlib_buffer_get_current(b1);					 
//					             eth_header1 = ethernet_buffer_get_header(p1);
						         clib_memcpy(eth_header_output1, eth_header1->dst_address + 1, ETHER_MAC_LEN + ETHER_MAC_LEN);
					       		 if(sw1 && sw1->is_sub_int)
						         {						         		
										eth_header_output1->type = clib_host_to_net_u16(ETH_PROTO_TYPE_VLAN);
										vlan_header1 = (ethernet_vlan_header_t*)(b1->data + ETHER_MAC_LEN + ETHER_MAC_LEN + ETH_PROTO_TYPE_LEN);
										vlan_header1->priority_cfi_and_id = clib_host_to_net_u16(sw1->sub.id);
										vlan_header1->type = clib_host_to_net_u16(ETH_PROTO_TYPE_IP);
										clib_memcpy( b1->data + ETH_HEADER_VLAN_HEADER_LEN, vlib_buffer_get_current(p1),   p1->current_length);
										b1->current_length = ETH_HEADER_VLAN_HEADER_LEN + p1->current_length;
						         }
								 else
								 {
										 eth_header_output1->type = clib_host_to_net_u16(ETH_PROTO_TYPE_IP);
										 clib_memcpy(b1->data + ETH_HEADER_LEN, vlib_buffer_get_current(p1),   p1->current_length);
										 b1->current_length = ETH_HEADER_LEN + p1->current_length;
								 }								
								vlib_put_frame_to_node (vm, output_if1->output_node_index, f1);
								next1 = IP4_INPUT_NEXT_DROP;
						   }				  		  
		            }
				 }
			      		
		  }
		  if(arc1 == lm->mcast_feature_arc_index)
		  {
		  	 next1 = IP4_INPUT_NEXT_LOOKUP_MULTICAST;
		  }
	  }

	  vlib_increment_simple_counter (cm, cpu_index, sw_if_index0, 1);
	  vlib_increment_simple_counter (cm, cpu_index, sw_if_index1, 1);

	  error0 = error1 = IP4_ERROR_NONE;

	  /* Punt packets with options. */
	  error0 = (ip0->ip_version_and_header_length & 0xf) != 5 ? IP4_ERROR_OPTIONS : error0;
	  error1 = (ip1->ip_version_and_header_length & 0xf) != 5 ? IP4_ERROR_OPTIONS : error1;

	  /* Version != 4?  Drop it. */
	  error0 = (ip0->ip_version_and_header_length >> 4) != 4 ? IP4_ERROR_VERSION : error0;
	  error1 = (ip1->ip_version_and_header_length >> 4) != 4 ? IP4_ERROR_VERSION : error1;

	  /* Verify header checksum. */
	  if (verify_checksum)
	    {
	      ip_csum_t sum0, sum1;

	      ip4_partial_header_checksum_x1 (ip0, sum0);
	      ip4_partial_header_checksum_x1 (ip1, sum1);

	      error0 = 0xffff != ip_csum_fold (sum0) ? IP4_ERROR_BAD_CHECKSUM : error0;
	      error1 = 0xffff != ip_csum_fold (sum1) ? IP4_ERROR_BAD_CHECKSUM : error1;
	    }

	  /* Drop fragmentation offset 1 packets. */
	  error0 = ip4_get_fragment_offset (ip0) == 1 ? IP4_ERROR_FRAGMENT_OFFSET_ONE : error0;
	  error1 = ip4_get_fragment_offset (ip1) == 1 ? IP4_ERROR_FRAGMENT_OFFSET_ONE : error1;

	  /* TTL < 1? Drop it. */
	  error0 = (ip0->ttl < 1 && arc0 == lm->ucast_feature_arc_index) ? IP4_ERROR_TIME_EXPIRED : error0;
	  error1 = (ip1->ttl < 1 && arc1 == lm->ucast_feature_arc_index) ? IP4_ERROR_TIME_EXPIRED : error1;

	  /* Verify lengths. */
	  ip_len0 = clib_net_to_host_u16 (ip0->length);
	  ip_len1 = clib_net_to_host_u16 (ip1->length);

	  /* IP length must be at least minimal IP header. */
	  error0 = ip_len0 < sizeof (ip0[0]) ? IP4_ERROR_TOO_SHORT : error0;
	  error1 = ip_len1 < sizeof (ip1[0]) ? IP4_ERROR_TOO_SHORT : error1;

	  cur_len0 = vlib_buffer_length_in_chain (vm, p0);
	  cur_len1 = vlib_buffer_length_in_chain (vm, p1);

	  len_diff0 = cur_len0 - ip_len0;
	  len_diff1 = cur_len1 - ip_len1;

	  error0 = len_diff0 < 0 ? IP4_ERROR_BAD_LENGTH : error0;
	  error1 = len_diff1 < 0 ? IP4_ERROR_BAD_LENGTH : error1;

	  p0->error = error_node->errors[error0];
	  p1->error = error_node->errors[error1];

      if (PREDICT_FALSE(error0 != IP4_ERROR_NONE))
        {
	  if (error0 == IP4_ERROR_TIME_EXPIRED) {
	    icmp4_error_set_vnet_buffer(p0, ICMP4_time_exceeded,
					ICMP4_time_exceeded_ttl_exceeded_in_transit, 0);
	    next0 = IP4_INPUT_NEXT_ICMP_ERROR;
	  } else
	    next0 = error0 != IP4_ERROR_OPTIONS ? IP4_INPUT_NEXT_DROP : IP4_INPUT_NEXT_PUNT;
        }
      if (PREDICT_FALSE(error1 != IP4_ERROR_NONE))
        {
	  if (error1 == IP4_ERROR_TIME_EXPIRED) {
	    icmp4_error_set_vnet_buffer(p1, ICMP4_time_exceeded,
					ICMP4_time_exceeded_ttl_exceeded_in_transit, 0);
	    next1 = IP4_INPUT_NEXT_ICMP_ERROR;
	  } else
	    next1 = error1 != IP4_ERROR_OPTIONS ? IP4_INPUT_NEXT_DROP : IP4_INPUT_NEXT_PUNT;
        }

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, pi1, next0, next1);
	}    
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t * p0, *b0;
	  ip4_header_t * ip0;
	  udp_header_t * udp0;
	  u32  * to_output0 = NULL;
	  u32 sw_if_index0, pi0, ip_len0, cur_len0, bi0,sw_output_id0, next0 = 0;
	  i32 len_diff0;
	  u8 error0, arc0;
	  vnet_hw_interface_t * hw, *output_if0;
	  vnet_sw_interface_t *input_sw0 = NULL; 
	  vnet_sw_interface_t *sw0 = NULL;
	  vlib_frame_t * f0;
	  ethernet_header_t *eth_header0;
	  ethernet_header_t *eth_header_output0;
	  ethernet_vlan_header_t *vlan_header0;

	  
	  PORTAL_RED_USER_INFO red_user;

	  pi0 = from[0];
	  to_next[0] = pi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip0 = vlib_buffer_get_current (p0);

	  sw_if_index0 = vnet_buffer (p0)->sw_if_index[VLIB_RX];

	  arc0 = ip4_address_is_multicast (&ip0->dst_address) ? lm->mcast_feature_arc_index : lm->ucast_feature_arc_index;
	  if(arc0 != lm->mcast_feature_arc_index)
          {
		arc0 = ip4_address_is_broadcast (&ip0->dst_address) ? lm->mcast_feature_arc_index : lm->ucast_feature_arc_index;
	  }
	  vnet_buffer (p0)->ip.adj_index[VLIB_RX] = ~0;
	  vnet_feature_arc_start (arc0, sw_if_index0, &next0, p0);
	  output_if0 = hw = vnet_get_sup_hw_interface (vnm, sw_if_index0);
	  input_sw0 = vnet_get_sw_interface(vnm, sw_if_index0);

	  eth_header0 = ethernet_buffer_get_header(p0);
	  red_user.user_ip = ip0->src_address.as_u32;
	  clib_memcpy(red_user.user_mac, eth_header0->src_address + 1, ETHER_MAC_LEN);
	  if(input_sw0->portal_index_info.portal_info.enable_portal && portal_redirect_process(ip0, sw_if_index0,&red_user))
	  {
	  	 next0 = IP4_INPUT_NEXT_DROP;
	  }
	  if(af_packet_device_class.index == hw->dev_class_index)
	  {	  	  
	  	  ip4_tcp_udp_com_checksum(vm, p0);
	  	  next0 = IP4_INPUT_NEXT_LOOKUP;
		  /*DHCP??????????????????????????????????????????????????????????????????*/
	      if (ip0->protocol == IP_PROTOCOL_UDP )
	      {
	        	udp0 = (void *) (ip0 + 1);
				if(udp0->dst_port == clib_host_to_net_u16(DHCP_SERVER_TO_CLIENT_PORT))
				{
				    sw_output_id0 = 0;
					if( hw->sub_int_flag && INTERFACE_NULL_INDEX != hw->kernel_to_vpp_if_index)
				    {
				      	sw0 =  vnet_get_sw_interface(vnm, hw->kernel_to_vpp_if_index);
				      	if(sw0)
				      	{
							output_if0 = vnet_get_sup_hw_interface(vnm, sw0->sup_sw_if_index);
							sw_output_id0 = sw0->sw_if_index;
						}
						if(!output_if0)
						{
							output_if0 = hw;
						}
				    }
				    else if(INTERFACE_NULL_INDEX !=  hw->kernel_to_vpp_if_index)
				    {
				    	output_if0 = vnet_get_hw_interface(vnm, hw->kernel_to_vpp_if_index);
				    	if(output_if0)
						{
							sw_output_id0 = output_if0->sw_if_index;
						}
				    }
		            if(output_if0 )
					{
						   if (vlib_buffer_alloc (vm, &bi0, 1)  == 1) 
						   {
								 b0 = vlib_get_buffer (vm, bi0);
								 f0 = vlib_get_frame_to_node (vm, output_if0->output_node_index);
								 vnet_buffer(b0)->sw_if_index[VLIB_TX] = sw_output_id0; 						  
								 to_output0 = vlib_frame_vector_args (f0);
								 to_output0[0] = bi0;
								 f0->n_vectors = 1;
								 eth_header_output0 = vlib_buffer_get_current(b0);					 
//					             eth_header0 = ethernet_buffer_get_header(p0);
						         clib_memcpy(eth_header_output0, eth_header0->dst_address + 1, ETHER_MAC_LEN + ETHER_MAC_LEN);
						         if(sw0 && sw0->is_sub_int)
						         {						         		
										eth_header_output0->type = clib_host_to_net_u16(ETH_PROTO_TYPE_VLAN);
										vlan_header0 = (ethernet_vlan_header_t*)(b0->data + ETHER_MAC_LEN + ETHER_MAC_LEN + ETH_PROTO_TYPE_LEN);
										vlan_header0->priority_cfi_and_id = clib_host_to_net_u16(sw0->sub.id);
										vlan_header0->type = clib_host_to_net_u16(ETH_PROTO_TYPE_IP);
										clib_memcpy( b0->data + ETH_HEADER_VLAN_HEADER_LEN, vlib_buffer_get_current(p0),   p0->current_length);
										b0->current_length = ETH_HEADER_VLAN_HEADER_LEN + p0->current_length;
						         }
						         else
						         {
						         		eth_header_output0->type = clib_host_to_net_u16(ETH_PROTO_TYPE_IP);
										clib_memcpy(b0->data + ETH_HEADER_LEN, vlib_buffer_get_current(p0),   p0->current_length);
										b0->current_length = ETH_HEADER_LEN + p0->current_length;
						         }
								
								vlib_put_frame_to_node (vm, output_if0->output_node_index, f0);
								next0 = IP4_INPUT_NEXT_DROP;
						   }				  		  
		            }
				 }
			      		
		  }
	  	  if(arc0 == lm->mcast_feature_arc_index)
		  {
		  	 next0 = IP4_INPUT_NEXT_LOOKUP_MULTICAST;
		  }
	  }
	  vlib_increment_simple_counter (cm, cpu_index, sw_if_index0, 1);

	  error0 = IP4_ERROR_NONE;

	  /* Punt packets with options. */
	  error0 = (ip0->ip_version_and_header_length & 0xf) != 5 ? IP4_ERROR_OPTIONS : error0;
	  /* Version != 4?  Drop it. */
	  error0 = (ip0->ip_version_and_header_length >> 4) != 4 ? IP4_ERROR_VERSION : error0;

	  /* Verify header checksum. */
	  if (verify_checksum)
	    {
	      ip_csum_t sum0;

	      ip4_partial_header_checksum_x1 (ip0, sum0);
	      error0 = 0xffff != ip_csum_fold (sum0) ? IP4_ERROR_BAD_CHECKSUM : error0;
	    }

	  /* Drop fragmentation offset 1 packets. */
	  error0 = ip4_get_fragment_offset (ip0) == 1 ? IP4_ERROR_FRAGMENT_OFFSET_ONE : error0;

	  /* TTL < 1? Drop it. */
          error0 = (ip0->ttl < 1 && arc0 == lm->ucast_feature_arc_index) ? IP4_ERROR_TIME_EXPIRED : error0;

	  /* Verify lengths. */
	  ip_len0 = clib_net_to_host_u16 (ip0->length);

	  /* IP length must be at least minimal IP header. */
	  error0 = ip_len0 < sizeof (ip0[0]) ? IP4_ERROR_TOO_SHORT : error0;

	  cur_len0 = vlib_buffer_length_in_chain (vm, p0);
	  len_diff0 = cur_len0 - ip_len0;
	  error0 = len_diff0 < 0 ? IP4_ERROR_BAD_LENGTH : error0;

	  p0->error = error_node->errors[error0];
      if (PREDICT_FALSE(error0 != IP4_ERROR_NONE))
        {
	  if (error0 == IP4_ERROR_TIME_EXPIRED) {
	    icmp4_error_set_vnet_buffer(p0, ICMP4_time_exceeded,
					ICMP4_time_exceeded_ttl_exceeded_in_transit, 0);
	    next0 = IP4_INPUT_NEXT_ICMP_ERROR;
	  } else
	    next0 = error0 != IP4_ERROR_OPTIONS ? IP4_INPUT_NEXT_DROP : IP4_INPUT_NEXT_PUNT;
        }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   pi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/** \brief IPv4 input node.
    @node ip4-input

    This is the IPv4 input node: validates ip4 header checksums,
    verifies ip header lengths, discards pkts with expired TTLs,
    and sends pkts to the set of ip feature nodes configured on
    the rx interface.

    @param vm vlib_main_t corresponding to the current thread
    @param node vlib_node_runtime_t
    @param frame vlib_frame_t whose contents should be dispatched

    @par Graph mechanics: buffer metadata, next index usage

    @em Uses:
    - vnet_feature_config_main_t cm corresponding to each pkt's dst address unicast / 
      multicast status.
    - <code>b->current_config_index</code> corresponding to each pkt's
      rx sw_if_index. 
         - This sets the per-packet graph trajectory, ensuring that
           each packet visits the per-interface features in order.

    - <code>vnet_buffer(b)->sw_if_index[VLIB_RX]</code>
        - Indicates the @c sw_if_index value of the interface that the
	  packet was received on.

    @em Sets:
    - <code>vnet_buffer(b)->ip.adj_index[VLIB_TX]</code>
        - The lookup result adjacency index.

    <em>Next Indices:</em>
    - Dispatches pkts to the (first) feature node:
      <code> vnet_get_config_data (... &next0 ...); </code>
      or @c error-drop 
*/
static uword
ip4_input (vlib_main_t * vm,
	   vlib_node_runtime_t * node,
	   vlib_frame_t * frame)
{
  return ip4_input_inline (vm, node, frame, /* verify_checksum */ 1);
}

static uword
ip4_input_no_checksum (vlib_main_t * vm,
		       vlib_node_runtime_t * node,
		       vlib_frame_t * frame)
{
  return ip4_input_inline (vm, node, frame, /* verify_checksum */ 0);
}

static char * ip4_error_strings[] = {
#define _(sym,string) string,
  foreach_ip4_error
#undef _
};

VLIB_REGISTER_NODE (ip4_input_node) = {
  .function = ip4_input,
  .name = "ip4-input",
  .vector_size = sizeof (u32),

  .n_errors = IP4_N_ERROR,
  .error_strings = ip4_error_strings,

  .n_next_nodes = IP4_INPUT_N_NEXT,
  .next_nodes = {
    [IP4_INPUT_NEXT_DROP] = "error-drop",
    [IP4_INPUT_NEXT_PUNT] = "error-punt",
    [IP4_INPUT_NEXT_LOOKUP] = "ip4-lookup",
    [IP4_INPUT_NEXT_LOOKUP_MULTICAST] = "ip4-lookup-multicast",
    [IP4_INPUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
  },

  .format_buffer = format_ip4_header,
  .format_trace = format_ip4_input_trace,
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_input_node, ip4_input)

VLIB_REGISTER_NODE (ip4_input_no_checksum_node,static) = {
  .function = ip4_input_no_checksum,
  .name = "ip4-input-no-checksum",
  .vector_size = sizeof (u32),

  .n_next_nodes = IP4_INPUT_N_NEXT,
  .next_nodes = {
    [IP4_INPUT_NEXT_DROP] = "error-drop",
    [IP4_INPUT_NEXT_PUNT] = "error-punt",
    [IP4_INPUT_NEXT_LOOKUP] = "ip4-lookup",
    [IP4_INPUT_NEXT_LOOKUP_MULTICAST] = "ip4-lookup-multicast",
    [IP4_INPUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
  },

  .format_buffer = format_ip4_header,
  .format_trace = format_ip4_input_trace,
};

VLIB_NODE_FUNCTION_MULTIARCH (ip4_input_no_checksum_node, ip4_input_no_checksum)

static clib_error_t * ip4_init (vlib_main_t * vm)
{
  clib_error_t * error;

  ethernet_register_input_type (vm, ETHERNET_TYPE_IP4,
				ip4_input_node.index);
  ppp_register_input_protocol (vm, PPP_PROTOCOL_ip4,
			       ip4_input_node.index);
  hdlc_register_input_protocol (vm, HDLC_PROTOCOL_ip4,
				ip4_input_node.index);

  {
    pg_node_t * pn;
    pn = pg_get_node (ip4_input_node.index);
    pn->unformat_edit = unformat_pg_ip4_header;
    pn = pg_get_node (ip4_input_no_checksum_node.index);
    pn->unformat_edit = unformat_pg_ip4_header;
  }

  if ((error = vlib_call_init_function (vm, ip4_cli_init)))
    return error;

  if ((error = vlib_call_init_function (vm, ip4_source_check_init)))
    return error;

  if ((error = vlib_call_init_function 
       (vm, ip4_source_and_port_range_check_init)))
    return error;

  /* Set flow hash to something non-zero. */
  ip4_main.flow_hash_seed = 0xdeadbeef;

  /* Default TTL for packets we generate. */
  ip4_main.host_config.ttl = 64;

  return error;
}

VLIB_INIT_FUNCTION (ip4_init);
