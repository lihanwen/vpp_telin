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
 * ip/ip_lookup.c: ip4/6 adjacency and lookup table managment
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
#include <vnet/adj/adj.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/mpls/mpls.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/dpo/classify_dpo.h>
#include <vnet/dpo/punt_dpo.h>
#include <vnet/dpo/receive_dpo.h>
#include <vnet/dpo/ip_null_dpo.h>
#include <arpa/inet.h>

/**
 * @file
 * @brief IPv4 and IPv6 adjacency and lookup table managment.
 *
 */

clib_error_t *
ip_interface_address_add_del (ip_lookup_main_t * lm,
			      u32 sw_if_index,
			      void * addr_fib,
			      u32 address_length,
			      u32 is_del,
			      u32 * result_if_address_index)
{
  vnet_main_t * vnm = vnet_get_main();
  ip_interface_address_t * a, * prev, * next;
  uword * p = mhash_get (&lm->address_to_if_address_index, addr_fib);

  vec_validate_init_empty (lm->if_address_pool_index_by_sw_if_index, sw_if_index, ~0);
  a = p ? pool_elt_at_index (lm->if_address_pool, p[0]) : 0;

  /* Verify given length. */
  if ((a && (address_length != a->address_length)) || (address_length == 0))
    {
      vnm->api_errno = VNET_API_ERROR_ADDRESS_LENGTH_MISMATCH;
      return clib_error_create 
        ( "%U wrong length (expected %d) for interface %U",
          lm->format_address_and_length, addr_fib,
          address_length, a? a->address_length : -1,
          format_vnet_sw_if_index_name, vnm, sw_if_index);
    }

  if (is_del)
    {
      if (!a) 
        {
          vnet_sw_interface_t * si = vnet_get_sw_interface (vnm, sw_if_index);
          vnm->api_errno = VNET_API_ERROR_ADDRESS_NOT_FOUND_FOR_INTERFACE;
          return clib_error_create ("%U not found for interface %U",
                                    lm->format_address_and_length, 
                                    addr_fib, address_length,
                                    format_vnet_sw_interface_name, vnm, si);
        }

      if (a->prev_this_sw_interface != ~0)
	{
	  prev = pool_elt_at_index (lm->if_address_pool, a->prev_this_sw_interface);
	  prev->next_this_sw_interface = a->next_this_sw_interface;
	}
      if (a->next_this_sw_interface != ~0)
	{
	  next = pool_elt_at_index (lm->if_address_pool, a->next_this_sw_interface);
	  next->prev_this_sw_interface = a->prev_this_sw_interface;

	  if(a->prev_this_sw_interface == ~0)
	         lm->if_address_pool_index_by_sw_if_index[sw_if_index]  = a->next_this_sw_interface;
	}

      if ((a->next_this_sw_interface  == ~0) &&  (a->prev_this_sw_interface == ~0))
	lm->if_address_pool_index_by_sw_if_index[sw_if_index] = ~0;

      mhash_unset (&lm->address_to_if_address_index, addr_fib,
		   /* old_value */ 0);
      pool_put (lm->if_address_pool, a);

      if (result_if_address_index)
	*result_if_address_index = ~0;
    }

  else if (! a)
    {
      u32 pi; /* previous index */
      u32 ai; 
      u32 hi; /* head index */

      pool_get (lm->if_address_pool, a);
      memset (a, ~0, sizeof (a[0]));
      ai = a - lm->if_address_pool;

      hi = pi = lm->if_address_pool_index_by_sw_if_index[sw_if_index];
      prev = 0;
      while (pi != (u32)~0)
        {
          prev = pool_elt_at_index(lm->if_address_pool, pi);
          pi = prev->next_this_sw_interface;
        }
      pi = prev ? prev - lm->if_address_pool : (u32)~0;

      a->address_key = mhash_set (&lm->address_to_if_address_index,
				  addr_fib, ai, /* old_value */ 0);
      a->address_length = address_length;
      a->sw_if_index = sw_if_index;
      a->flags = 0;
      a->prev_this_sw_interface = pi;
      a->next_this_sw_interface = ~0;
      if (prev)
          prev->next_this_sw_interface = ai;

      lm->if_address_pool_index_by_sw_if_index[sw_if_index] = 
        (hi != ~0) ? hi : ai;
      if (result_if_address_index)
	*result_if_address_index = ai;
    }
  else
    {
      if (result_if_address_index)
	*result_if_address_index = a - lm->if_address_pool;
    }
    

  return /* no error */ 0;
}

void ip_lookup_init (ip_lookup_main_t * lm, u32 is_ip6)
{
  /* ensure that adjacency is cacheline aligned and sized */
  STATIC_ASSERT(STRUCT_OFFSET_OF(ip_adjacency_t, cacheline0) == 0,
		"Cache line marker must be 1st element in struct");
  STATIC_ASSERT(STRUCT_OFFSET_OF(ip_adjacency_t, cacheline1) == CLIB_CACHE_LINE_BYTES,
		"Data in cache line 0 is bigger than cache line size");

  /* Preallocate three "special" adjacencies */
  lm->adjacency_heap = adj_pool;

  if (! lm->fib_result_n_bytes)
    lm->fib_result_n_bytes = sizeof (uword);

  lm->is_ip6 = is_ip6;
  if (is_ip6)
    {
      lm->format_address_and_length = format_ip6_address_and_length;
      mhash_init (&lm->address_to_if_address_index, sizeof (uword),
		  sizeof (ip6_address_fib_t));
    }
  else
    {
      lm->format_address_and_length = format_ip4_address_and_length;
      mhash_init (&lm->address_to_if_address_index, sizeof (uword),
		  sizeof (ip4_address_fib_t));
    }

  {
    int i;

    /* Setup all IP protocols to be punted and builtin-unknown. */
    for (i = 0; i < 256; i++)
      {
	lm->local_next_by_ip_protocol[i] = IP_LOCAL_NEXT_PUNT;
	lm->builtin_protocol_by_ip_protocol[i] = IP_BUILTIN_PROTOCOL_UNKNOWN;
      }

    lm->local_next_by_ip_protocol[IP_PROTOCOL_UDP] = IP_LOCAL_NEXT_UDP_LOOKUP;
    lm->local_next_by_ip_protocol[is_ip6 ? IP_PROTOCOL_ICMP6 : IP_PROTOCOL_ICMP] = IP_LOCAL_NEXT_ICMP;
    lm->builtin_protocol_by_ip_protocol[IP_PROTOCOL_UDP] = IP_BUILTIN_PROTOCOL_UDP;
    lm->builtin_protocol_by_ip_protocol[is_ip6 ? IP_PROTOCOL_ICMP6 : IP_PROTOCOL_ICMP] = IP_BUILTIN_PROTOCOL_ICMP;
  }
}

u8 * format_ip_flow_hash_config (u8 * s, va_list * args)
{
  flow_hash_config_t flow_hash_config = va_arg (*args, u32);
    
#define _(n,v) if (flow_hash_config & v) s = format (s, "%s ", #n);
  foreach_flow_hash_bit;
#undef _

  return s;
}

u8 * format_ip_lookup_next (u8 * s, va_list * args)
{
  ip_lookup_next_t n = va_arg (*args, ip_lookup_next_t);
  char * t = 0;

  switch (n)
    {
    default:
      s = format (s, "unknown %d", n);
      return s;

    case IP_LOOKUP_NEXT_DROP: t = "drop"; break;
    case IP_LOOKUP_NEXT_PUNT: t = "punt"; break;
    case IP_LOOKUP_NEXT_ARP: t = "arp"; break;
    case IP_LOOKUP_NEXT_MIDCHAIN: t="midchain"; break;
    case IP_LOOKUP_NEXT_GLEAN: t="glean"; break;
    case IP_LOOKUP_NEXT_REWRITE:
      break;
    }

  if (t)
    vec_add (s, t, strlen (t));

  return s;
}

u8 * format_ip_adjacency_packet_data (u8 * s, va_list * args)
{
  vnet_main_t * vnm = va_arg (*args, vnet_main_t *);
  u32 adj_index = va_arg (*args, u32);
  u8 * packet_data = va_arg (*args, u8 *);
  u32 n_packet_data_bytes = va_arg (*args, u32);
  ip_adjacency_t * adj = adj_get(adj_index);

  switch (adj->lookup_next_index)
    {
    case IP_LOOKUP_NEXT_REWRITE:
      s = format (s, "%U",
		  format_vnet_rewrite_header,
		  vnm->vlib_main, &adj->rewrite_header, packet_data, n_packet_data_bytes);
      break;

    default:
      break;
    }

  return s;
}

static uword unformat_dpo (unformat_input_t * input, va_list * args)
{
  dpo_id_t *dpo = va_arg (*args, dpo_id_t *);
  fib_protocol_t fp = va_arg (*args, int);
  dpo_proto_t proto;

  proto = fib_proto_to_dpo(fp);

  if (unformat (input, "drop"))
    dpo_copy(dpo, drop_dpo_get(proto));
  else if (unformat (input, "punt"))
    dpo_copy(dpo, punt_dpo_get(proto));
  else if (unformat (input, "local"))
    receive_dpo_add_or_lock(proto, ~0, NULL, dpo);
  else if (unformat (input, "null-send-unreach"))
      ip_null_dpo_add_and_lock(proto, IP_NULL_ACTION_SEND_ICMP_UNREACH, dpo);
  else if (unformat (input, "null-send-prohibit"))
      ip_null_dpo_add_and_lock(proto, IP_NULL_ACTION_SEND_ICMP_PROHIBIT, dpo);
  else if (unformat (input, "null"))
      ip_null_dpo_add_and_lock(proto, IP_NULL_ACTION_NONE, dpo);
  else if (unformat (input, "classify"))
    {
      u32 classify_table_index;

      if (!unformat (input, "%d", &classify_table_index))
        {
	  clib_warning ("classify adj must specify table index");
          return 0;
	}

      dpo_set(dpo, DPO_CLASSIFY, proto,
              classify_dpo_create(proto, classify_table_index));
    }
  else
    return 0;

  return 1;
}

const ip46_address_t zero_addr = {
    .as_u64 = {
	0, 0
    },
};

u32
fib_table_id_find_fib_index (fib_protocol_t proto,
			     u32 table_id)
{
    ip4_main_t *im4 = &ip4_main;
    ip6_main_t *im6 = &ip6_main;
    uword * p;

    switch (proto)
    {
    case FIB_PROTOCOL_IP4:
	p = hash_get(im4->fib_index_by_table_id, table_id);
	break;
    case FIB_PROTOCOL_IP6:
	p = hash_get(im6->fib_index_by_table_id, table_id);
	break;
    default:
	p = NULL;
	break;
    }
    if (NULL != p)
    {
	return (p[0]);
    }
    return (~0);
}


//modification
/*
#include <arpa/inet.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
typedef struct _unix_shared_memory_queue
{
  pthread_mutex_t mutex;  // 8 bytes 
  pthread_cond_t condvar; // 8 bytes 
  int head;
  int tail;
  int cursize;
  int maxsize;
  int elsize;
  int consumer_pid;
  int signal_when_queue_non_empty;
  char data[0];
} unix_shared_memory_queue_t;
void * vl_msg_api_alloc(int nbytes);
void vl_msg_api_send_shmem(unix_shared_memory_queue_t*, u8*);

typedef struct
{
	int link_events_on;
	int stats_on;
	int oam_events_on;
	
	unix_shared_memory_queue_t * vl_input_queue;
	u32 my_client_index;
}test_main_t;



#define VL_API_PACKED(x) x __attribute__ ((packed))
typedef VL_API_PACKED(struct _vl_api_ip_add_del_route {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 next_hop_sw_if_index;
    u32 table_id;
    u32 resolve_attempts;
    u32 classify_table_index;
    u32 next_hop_out_label;
    u32 next_hop_table_id;
    u8 create_vrf_if_needed;
    u8 resolve_if_needed;
    u8 is_add;
    u8 is_drop;
    u8 is_unreach;
    u8 is_prohibit;
    u8 is_ipv6;
    u8 is_local;
    u8 is_classify;
    u8 is_multipath;
    u8 is_resolve_host;
    u8 is_resolve_attached;
    u8 not_last;
    u8 next_hop_weight;
    u8 dst_address_length;
    u8 dst_address[16];
    u8 next_hop_address[16];
}) vl_api_ip_add_del_route_t;

void add_del_ip4_route (test_main_t * tm, int enable_disable)
{
  vl_api_ip_add_del_route_t *mp;
  u32 tmp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  //mp->_vl_msg_id = ntohs (VL_API_IP_ADD_DEL_ROUTE);
  mp->_vl_msg_id = ntohs (1);
  mp->client_index = tm->my_client_index;
  mp->context = 0xdeadbeef;
  mp->table_id = ntohl (0); 
  mp->create_vrf_if_needed = 1; 
  // Arp, please, if needed 
  mp->resolve_if_needed = 1; 
  mp->resolve_attempts = ntohl (10);

  mp->next_hop_sw_if_index = ntohl (5); 
  mp->is_add = enable_disable;
  mp->next_hop_weight = 1; 

  // Next hop: 10.10.40.97 
  tmp = ntohl (0x0a0a2861);
  clib_memcpy (mp->next_hop_address, &tmp, sizeof (tmp));

  // Destination: 192.168.100.0/24 
  tmp = ntohl (0xc0a8640);
  clib_memcpy (mp->dst_address, &tmp, sizeof (tmp));
  mp->dst_address_length = 8;

  vl_msg_api_send_shmem (tm->vl_input_queue, (u8 *) & mp);
}
*/
clib_error_t *
vnet_ip_route_cmd (vlib_main_t * vm,
		   unformat_input_t * main_input,
		   vlib_cli_command_t * cmd)
{
  

  unformat_input_t _line_input, * line_input = &_line_input;
  fib_route_path_t *rpaths = NULL, rpath;
  dpo_id_t dpo = DPO_INVALID, *dpos = NULL;
  fib_prefix_t *prefixs = NULL, pfx;
  clib_error_t * error = NULL;
  mpls_label_t out_label;
  u32 table_id, is_del;
  vnet_main_t * vnm;
  u32 fib_index;
  f64 count;
  int i;

  vnm = vnet_get_main();
  is_del = 0;
  table_id = 0;
  count = 1;
  memset(&pfx, 0, sizeof(pfx));

  /* Get a line of input. */
  if (! unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      memset(&rpath, 0, sizeof(rpath));

      if (unformat (line_input, "table %d", &table_id))
	;
      else if (unformat (line_input, "del"))
	is_del = 1;
      else if (unformat (line_input, "add"))
	is_del = 0;
      else if (unformat (line_input, "resolve-via-host"))
      {
	  if (vec_len(rpaths) == 0)
	  {
	      error = clib_error_return(0 , "Paths then flags");
	      goto done;
	  }
	  rpaths[vec_len(rpaths)-1].frp_flags |= FIB_ROUTE_PATH_RESOLVE_VIA_HOST;
      }
      else if (unformat (line_input, "resolve-via-attached"))
      {
	  if (vec_len(rpaths) == 0)
	  {
	      error = clib_error_return(0 , "Paths then flags");
	      goto done;
	  }
	  rpaths[vec_len(rpaths)-1].frp_flags |=
	      FIB_ROUTE_PATH_RESOLVE_VIA_ATTACHED;
      }
      else if (unformat (line_input, "out-label %U",
                         unformat_mpls_unicast_label, &out_label))
      {
	  if (vec_len(rpaths) == 0)
	  {
	      error = clib_error_return(0 , "Paths then labels");
	      goto done;
	  }
	  rpaths[vec_len(rpaths)-1].frp_label = out_label;
      }
      else if (unformat (line_input, "count %f", &count))
	;

      else if (unformat (line_input, "%U/%d",
			 unformat_ip4_address,
			 &pfx.fp_addr.ip4,
			 &pfx.fp_len))
      {
	  pfx.fp_proto = FIB_PROTOCOL_IP4;
	  vec_add1(prefixs, pfx);
      }
      else if (unformat (line_input, "%U/%d",
			 unformat_ip6_address,
			 &pfx.fp_addr.ip6,
			 &pfx.fp_len))
      {
	  pfx.fp_proto = FIB_PROTOCOL_IP6;
	  vec_add1(prefixs, pfx);
      }
      else if (unformat (line_input, "via %U %U weight %u",
			 unformat_ip4_address,
			 &rpath.frp_addr.ip4,
			 unformat_vnet_sw_interface, vnm,
			 &rpath.frp_sw_if_index,
			 &rpath.frp_weight))
      {
	  rpath.frp_label = MPLS_LABEL_INVALID;
	  rpath.frp_proto = FIB_PROTOCOL_IP4;
	  vec_add1(rpaths, rpath);
      }

      else if (unformat (line_input, "via %U %U weight %u",
			 unformat_ip6_address,
			 &rpath.frp_addr.ip6,
			 unformat_vnet_sw_interface, vnm,
			 &rpath.frp_sw_if_index,
			 &rpath.frp_weight))
      {
	  rpath.frp_label = MPLS_LABEL_INVALID;
	  rpath.frp_proto = FIB_PROTOCOL_IP6;
	  vec_add1(rpaths, rpath);
      }

      else if (unformat (line_input, "via %U %U",
			 unformat_ip4_address,
 			 &rpath.frp_addr.ip4,
			 unformat_vnet_sw_interface, vnm,
			 &rpath.frp_sw_if_index))
      {
	  rpath.frp_label = MPLS_LABEL_INVALID;
	  rpath.frp_weight = 1;
	  rpath.frp_proto = FIB_PROTOCOL_IP4;
	  vec_add1(rpaths, rpath);
      }
			 
      else if (unformat (line_input, "via %U %U",
			 unformat_ip6_address,
 			 &rpath.frp_addr.ip6,
			 unformat_vnet_sw_interface, vnm,
			 &rpath.frp_sw_if_index))
      {
	  rpath.frp_label = MPLS_LABEL_INVALID;
	  rpath.frp_weight = 1;
	  rpath.frp_proto = FIB_PROTOCOL_IP6;
	  vec_add1(rpaths, rpath);
      }
      else if (unformat (line_input, "via %U next-hop-table %d",
			 unformat_ip4_address,
  			 &rpath.frp_addr.ip4,
			 &rpath.frp_fib_index))
      {
	  rpath.frp_weight = 1;
	  rpath.frp_sw_if_index = ~0;
	  rpath.frp_label = MPLS_LABEL_INVALID;
	  rpath.frp_proto = FIB_PROTOCOL_IP4;
	  vec_add1(rpaths, rpath);
      }
      else if (unformat (line_input, "via %U next-hop-table %d",
			 unformat_ip6_address,
  			 &rpath.frp_addr.ip6,
			 &rpath.frp_fib_index))
      {
	  rpath.frp_weight = 1;
	  rpath.frp_sw_if_index = ~0;
	  rpath.frp_label = MPLS_LABEL_INVALID;
	  rpath.frp_proto = FIB_PROTOCOL_IP6;
	  vec_add1(rpaths, rpath);
      }
      else if (unformat (line_input, "via %U",
			 unformat_ip4_address,
  			 &rpath.frp_addr.ip4))
      {
	  /*
	   * the recursive next-hops are by default in the same table
	   * as the prefix
	   */
	  rpath.frp_fib_index = table_id;
	  rpath.frp_weight = 1;
	  rpath.frp_sw_if_index = ~0;
	  rpath.frp_label = MPLS_LABEL_INVALID;
	  rpath.frp_proto = FIB_PROTOCOL_IP4;
	  vec_add1(rpaths, rpath);
      }
      else if (unformat (line_input, "via %U",
			 unformat_ip6_address,
  			 &rpath.frp_addr.ip6))
      {
	  rpath.frp_fib_index = table_id;
	  rpath.frp_weight = 1;
	  rpath.frp_sw_if_index = ~0;
	  rpath.frp_label = MPLS_LABEL_INVALID;
	  rpath.frp_proto = FIB_PROTOCOL_IP6;
	  vec_add1(rpaths, rpath);
      }
      else if (unformat (line_input,
			 "lookup in table %d",
			 &rpath.frp_fib_index))
      {
	  rpath.frp_label = MPLS_LABEL_INVALID;
	  rpath.frp_proto = pfx.fp_proto;
	  rpath.frp_sw_if_index = ~0;
	  vec_add1(rpaths, rpath);
      }
      else if (vec_len (prefixs) > 0 &&
	       unformat (line_input, "via %U",
			 unformat_dpo, &dpo, prefixs[0].fp_proto))
      {
	  rpath.frp_label = MPLS_LABEL_INVALID;
	  vec_add1 (dpos, dpo);
      }
      else
      {
	  error = unformat_parse_error (line_input);
	  goto done;
      }
    }
    
  unformat_free (line_input);

  if (vec_len (prefixs) == 0)
  {
      error = clib_error_return (0, "expected ip4/ip6 destination address/length.");
      goto done;
    }

  if (!is_del && vec_len (rpaths) + vec_len (dpos) == 0)
    {
      error = clib_error_return (0, "expected paths.");
      goto done;
    }

  if (~0 == table_id)
  {
      /*
       * if no table_id is passed we will manipulate the default
       */
      fib_index = 0;
  }
  else
  {
      fib_index = fib_table_id_find_fib_index(prefixs[0].fp_proto,
					      table_id);

      if (~0 == fib_index)
      {
	  error = clib_error_return (0,
				     "Nonexistent table id %d", 
				     table_id);
	  goto done;
      }
  }

  for (i = 0; i < vec_len (prefixs); i++)
  {
      if (is_del && 0 == vec_len (rpaths))
      {
	  fib_table_entry_delete(fib_index,
				 &prefixs[i],
				 FIB_SOURCE_CLI);
      }
      else if (!is_del && 1 == vec_len (dpos))
      {
	  fib_table_entry_special_dpo_add(fib_index,
                                          &prefixs[i],
                                          FIB_SOURCE_CLI,
                                          FIB_ENTRY_FLAG_EXCLUSIVE,
                                          &dpos[0]);
	  dpo_reset(&dpos[0]);
      }
      else if (vec_len (dpos) > 0)
      {
	  error = clib_error_return(0 , "Load-balancing over multiple special adjacencies is unsupported");
	  goto done;
      }
      else if (0 < vec_len (rpaths))
      {
	  u32 k, j, n, incr;
	  ip46_address_t dst = prefixs[i].fp_addr;
	  f64 t[2];
	  n = count;
	  t[0] = vlib_time_now (vm);
	  incr = 1 << ((FIB_PROTOCOL_IP4 == prefixs[0].fp_proto ? 32 : 128) -
		       prefixs[i].fp_len);

	  for (k = 0; k < n; k++)
	  {
	      for (j = 0; j < vec_len (rpaths); j++)
	      {
		  u32 fi;
		  /*
		   * the CLI parsing stored table Ids, swap to FIB indicies
		   */
		  fi = fib_table_id_find_fib_index(prefixs[i].fp_proto,
						   rpaths[i].frp_fib_index);

		  if (~0 == fi)
		  {
		      error = clib_error_return(0 , "Via table %d does not exist",
						rpaths[i].frp_fib_index);
		      goto done;
		  }
		  rpaths[i].frp_fib_index = fi;

		  fib_prefix_t rpfx = {
		      .fp_len = prefixs[i].fp_len,
		      .fp_proto = prefixs[i].fp_proto,
		      .fp_addr = dst,
		  };

                  if (is_del)
                      fib_table_entry_path_remove2(fib_index,
                                                   &rpfx,
                                                   FIB_SOURCE_CLI,
                                                   &rpaths[j]);
                  else
                      fib_table_entry_path_add2(fib_index,
                                                &rpfx,
                                                FIB_SOURCE_CLI,
                                                FIB_ENTRY_FLAG_NONE,
                                                &rpaths[j]);
	      }

	      if (FIB_PROTOCOL_IP4 == prefixs[0].fp_proto)
	      {
		  dst.ip4.as_u32 =
		      clib_host_to_net_u32(incr +
					   clib_net_to_host_u32 (dst.ip4.as_u32));
	      }
	      else
	      {
		  int bucket = (incr < 64 ? 0 : 1);
		  dst.ip6.as_u64[bucket] =
		      clib_host_to_net_u64(incr +
					   clib_net_to_host_u64 (
					       dst.ip6.as_u64[bucket]));

	      }
	  }
	  t[1] = vlib_time_now (vm);
	  if (count > 1)
	      vlib_cli_output (vm, "%.6e routes/sec", count / (t[1] - t[0]));
      }
      else
      {
	  error = clib_error_return(0 , "Don't understand what you want...");
	  goto done;
      }
  }


 done:
  vec_free (dpos);
  vec_free (prefixs);
  vec_free (rpaths);
  return error;
}

// The headers
#define ERRIN(s) {printf("error in s\n"); } 
#include<stdio.h>
#include<sys/socket.h>
#include<string.h>
#include<linux/rtnetlink.h>

#include <stdlib.h>

unsigned long groups_hope;


// To printf the segment
void prtsgm(char *p){
   while (p != NULL && *p != ' ' && *p != '\n' && *p != '\t' && *p != '\0')
     putchar(*p++);
     putchar('\n');
   }

// To return the position of the next segment in the line.
	char * p2next(char *p){
     if(!p){fprintf(stderr,"p is NULL\n"); return NULL;}
     if(*p == '\0'){return NULL;}
		 if(*p == '\n'){return NULL;}
     while(*p != ' ' && *p != '\n' && *p != '\t')
       ++p;
//pass the spaces  
     if(*p == '\n'||*p == '\0' ){return NULL;}
     while(*p == ' '||*p == '\t')
       ++p;
     if(*p == '\n'||*p == '\0' ){return NULL;}
// Now, p points to the non-space char of the next segment. We can just return p  
     return p;
     }

void getnext(char* p, char* q){ 
  if(!p){fprintf(stderr,"p is NULL\n"); return;}
  if(*p == '\0'){return;}
  while(*p != ' ' && *p != '\n' && *p != '\t')
    ++p;
  if(*p == '\n'){return;}
//pass the spaces
  while(*p == ' '||*p == '\t')
    ++p;
// Now, p points to the non-space char of the next segment. We can just return p  
  	q = p;
    while(*p != ' ' && *p != '\n' && *p != '\0' && *p != '\t')
      *q++ = *p++;  
      *q = '\0';
}

// To return the position of the prefix part of each line.
  char* p2prefix(char *p){
    p = p2next(p);
    return p;
  }
  void getprefix(char *p, char *q){
    p = p2next(p);
    while(*p != ' ' && *p != '\n' && *p != '\0' && *p != '\t')
      *q++ = *p++;
      *q = '\0';
    }

// To return the position of the gateway part of each line.
   char* p2gate(char *p){
   p = p2next(p);
   p = p2next(p);
   return p;
   }
void getgate(char *p, char *q){
  p = p2next(p);
  p = p2next(p);
  while(*p != ' ' && *p != '\n' && *p != '\0' && *p != '\t')
    *q++ = *p++;
  *q = '\0';
}
// To return the position of the mask part of each line.
char* p2mask(char *p){
  int count = 7;
  while( count-- != 0)
    p = p2next(p);
  return p;
}
void getmask(char *p, char *q){
  int count = 7;
  while( count-- != 0)
    p = p2next(p);
  while(*p != ' ' && *p != '\n' && *p != '\0' && *p != '\t')
    *q++ = *p++;
  *q = '\0';
}
// Netmask transformation. For example, from FFFFFF00 to 24.
int msktrans(char * s){
  char t[9];
  char *p = s;
  char *q = t+7;
  int sum = 0;
  while(*p)
    *q-- = *p++;
  t[8] = '\0';
  q = t;
  while(*q){
    if(*q == '0')
      break;
    if(*q == 'F')
      sum += 4;
    else if(*q == 'E')
      sum += 3;
    else if(*q == 'C')
      sum += 2;
    else if(*q == '8')
      sum += 1;
    ++q;
}
  return sum;
}


// Preload the routes.
	#define VL_API_PACKED(x) x __attribute__ ((packed))
	typedef VL_API_PACKED(struct _vl_api_ip_add_del_route {
    u16 _vl_msg_id;
    u32 client_index;
    u32 context;
    u32 next_hop_sw_if_index;
    u32 table_id;
    u32 resolve_attempts;
    u32 classify_table_index;
    u32 next_hop_out_label;
    u32 next_hop_table_id;
    u8 create_vrf_if_needed;
    u8 resolve_if_needed;
    u8 is_add;
    u8 is_drop;
    u8 is_unreach;
    u8 is_prohibit;
    u8 is_ipv6;
    u8 is_local;
    u8 is_classify;
    u8 is_multipath;
    u8 is_resolve_host;
    u8 is_resolve_attached;
    u8 not_last;
    u8 next_hop_weight;
    u8 dst_address_length;
    u8 dst_address[16];
    u8 next_hop_address[16];
}) vl_api_ip_add_del_route_t;
	extern void vl_api_ip_add_del_route_t_handler(vl_api_ip_add_del_route_t *);

void *preload_routes(void* ptr){

	sleep(15);
  FILE * fp_hp;
  if(!(fp_hp = fopen("/proc/net/route","r"))){
    printf("Error in opening proc file!\n");
    return NULL;}


	// Preload the routes in the linux kernel from /proc/net/route

  char buf_hp[256];
	memset(buf_hp,0,256);
  char segment[128];
	memset(segment,0,128);
	char * pp=NULL;
  int count = 0;
	char temp_hp[3];
	memset(temp_hp,0,3);
	unsigned char p1,p2,p3,p4,g1,g2,g3,g4,plen;

	vl_api_ip_add_del_route_t mp;
	memset(&mp,0,sizeof(mp));
	mp._vl_msg_id = 1;
	mp.client_index = 1;
	mp.context = 0xdeadbeef;
	mp.next_hop_sw_if_index = ntohl(~0);
	mp.resolve_attempts = ntohl(10);
	mp.next_hop_out_label = ntohl(0x100000);
	mp.create_vrf_if_needed = 1;
	mp.resolve_if_needed = 1;
	mp.is_add = 1;
	mp.next_hop_weight = 1;

  while(fgets(buf_hp,256,fp_hp)){
    ++count;
   if(count == 1) {continue;}

	// Gateway
    getgate(buf_hp,segment);
    if(!strcmp(segment,"00000000")) {continue;}
		pp = segment;

		temp_hp[0] = *pp++;	
		temp_hp[1] = *pp++;	
		g4 = (unsigned char)strtol(temp_hp,NULL,16);

		temp_hp[0] = *pp++;	
		temp_hp[1] = *pp++;	
		g3 = (unsigned char)strtol(temp_hp,NULL,16);

		temp_hp[0] = *pp++;	
		temp_hp[1] = *pp++;	
		g2 = (unsigned char)strtol(temp_hp,NULL,16);

		temp_hp[0] = *pp++;	
		temp_hp[1] = *pp++;	
		g1 = (unsigned char)strtol(temp_hp,NULL,16);


	// Prefix
    getprefix(buf_hp,segment);
		pp = segment;

    temp_hp[0] = *pp++;
    temp_hp[1] = *pp++;
    p4 = (unsigned char)strtol(temp_hp,NULL,16);

    temp_hp[0] = *pp++;
    temp_hp[1] = *pp++;
    p3 = (unsigned char)strtol(temp_hp,NULL,16);

    temp_hp[0] = *pp++;
    temp_hp[1] = *pp++;
    p2 = (unsigned char)strtol(temp_hp,NULL,16);

    temp_hp[0] = *pp++;
    temp_hp[1] = *pp++;
    p1 = (unsigned char)strtol(temp_hp,NULL,16);

// Netmask
    getmask(buf_hp,segment);
   	plen =  (unsigned char)msktrans(segment);

// Prepare the parameters for the functions to add routes 
// The formation of parameters for the first function:




	mp.dst_address_length = plen;
	mp.dst_address[0] = p1;
	mp.dst_address[1] = p2;
	mp.dst_address[2] = p3;
	mp.dst_address[3] = p4;
	mp.next_hop_address[0] = g1;
	mp.next_hop_address[1] = g2;
	mp.next_hop_address[2] = g3;
	mp.next_hop_address[3] = g4;

	vl_api_ip_add_del_route_t_handler(&mp);



}
	return NULL;
}


void * listen_to_kernel(void* ptr){

	// Preload the routes
	//preload_routes();	
	//Use netlink to get route updates from the kernel
	sleep(10);

	vl_api_ip_add_del_route_t mp;
	memset(&mp,0,sizeof(mp));
	mp._vl_msg_id = 1;
	mp.client_index = 1;
	mp.context = 0xdeadbeef;
	mp.next_hop_sw_if_index = ntohl(~0);
	mp.resolve_attempts = ntohl(10);
	mp.next_hop_out_label = ntohl(0x100000);
	mp.create_vrf_if_needed = 1;
	mp.resolve_if_needed = 1;
	mp.is_add = 1;
	mp.next_hop_weight = 1;

  groups_hope = RTMGRP_LINK|RTMGRP_IPV4_ROUTE|RTMGRP_IPV4_IFADDR;
  unsigned char buf_hope[4096];
	unsigned char* p2buf;
  struct sockaddr_nl snl_hope;
  int ret_hope;
  int sock_hope = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if(sock_hope < 0){ printf("error in opening socket!\n");} 
  memset(&snl_hope, 0, sizeof(snl_hope));
  snl_hope.nl_family = AF_NETLINK;
  snl_hope.nl_groups = groups_hope;
  ret_hope = bind(sock_hope,(struct sockaddr*)&snl_hope, sizeof( snl_hope));
  if (ret_hope < 0){printf("error in binding the socket!\n");}
  struct iovec iov_hope={buf_hope,sizeof(buf_hope)};
  struct msghdr msg_hope={(void*)&snl_hope, sizeof(snl_hope), &iov_hope, 1,NULL,0,0};
  struct nlmsghdr *h_hope; 

	int status_hope;
	int loop_count = 0;
	unsigned char plus_flag = 0;

  while(1){
		++loop_count;
    status_hope = recvmsg(sock_hope,&msg_hope,0);
    if(status_hope < 0)ERRIN(recvmsg_hope);
    if(status_hope == 0) ERRIN(EOF);

    for(h_hope = (struct nlmsghdr*)buf_hope;NLMSG_OK(h_hope,(unsigned int)status_hope);h_hope = NLMSG_NEXT(h_hope,status_hope))
{
			plus_flag = buf_hope[4]; //If the plus_flag is 0x18, this is for adding routes. If the flag is 0x19, this is for deleting routes.
      if(h_hope -> nlmsg_type == NLMSG_DONE) break;
			p2buf = NLMSG_DATA(h_hope);	
	unsigned char p1,p2,p3,p4,g1,g2,g3,g4,plen;
	p1 = p2buf[24];
	p2 = p2buf[25];
	p3 = p2buf[26];
	p4 = p2buf[27];
	plen = p2buf[1];
	g1 = p2buf[32];
	g2 = p2buf[33];
	g3 = p2buf[34];
	g4 = p2buf[35];


	mp.dst_address_length = plen;
	mp.dst_address[0] = p1;
	mp.dst_address[1] = p2;
	mp.dst_address[2] = p3;
	mp.dst_address[3] = p4;
	mp.next_hop_address[0] = g1;
	mp.next_hop_address[1] = g2;
	mp.next_hop_address[2] = g3;
	mp.next_hop_address[3] = g4;


	if(plus_flag == 24){
		mp.is_add = 1;
		vl_api_ip_add_del_route_t_handler(&mp);
	}else if(plus_flag == 25){
		mp.is_add = 0;
		vl_api_ip_add_del_route_t_handler(&mp);
	}
}
	//modification
}
return NULL;
}



VLIB_CLI_COMMAND (vlib_cli_ip_command, static) = {
  .path = "ip",
  .short_help = "Internet protocol (IP) commands",
};

VLIB_CLI_COMMAND (vlib_cli_ip6_command, static) = {
  .path = "ip6",
  .short_help = "Internet protocol version 6 (IPv6) commands",
};

VLIB_CLI_COMMAND (vlib_cli_show_ip_command, static) = {
  .path = "show ip",
  .short_help = "Internet protocol (IP) show commands",
};

VLIB_CLI_COMMAND (vlib_cli_show_ip6_command, static) = {
  .path = "show ip6",
  .short_help = "Internet protocol version 6 (IPv6) show commands",
};

/*?
 * This command is used to add or delete IPv4 or IPv6 routes. All
 * IP Addresses ('<em><dst-ip-addr>/<width></em>',
 * '<em><next-hop-ip-addr></em>' and '<em><adj-hop-ip-addr></em>')
 * can be IPv4 or IPv6, but all must be of the same form in a single
 * command. To display the current set of routes, use the commands
 * '<em>show ip fib</em>' and '<em>show ip6 fib</em>'.
 *
 * @cliexpar
 * Example of how to add a straight forward static route:
 * @cliexcmd{ip route add 6.0.1.2/32 via 6.0.0.1 GigabitEthernet2/0/0}
 * Example of how to delete a straight forward static route:
 * @cliexcmd{ip route del 6.0.1.2/32 via 6.0.0.1 GigabitEthernet2/0/0}
 * Mainly for route add/del performance testing, one can add or delete
 * multiple routes by adding 'count N' to the previous item:
 * @cliexcmd{ip route add count 10 7.0.0.0/24 via 6.0.0.1 GigabitEthernet2/0/0}
 * Add multiple routes for the same destination to create equal-cost multipath:
 * @cliexcmd{ip route add 7.0.0.1/32 via 6.0.0.1 GigabitEthernet2/0/0}
 * @cliexcmd{ip route add 7.0.0.1/32 via 6.0.0.2 GigabitEthernet2/0/0}
 * For unequal-cost multipath, specify the desired weights. This
 * combination of weights results in 3/4 of the traffic following the
 * second path, 1/4 following the first path:
 * @cliexcmd{ip route add 7.0.0.1/32 via 6.0.0.1 GigabitEthernet2/0/0 weight 1}
 * @cliexcmd{ip route add 7.0.0.1/32 via 6.0.0.2 GigabitEthernet2/0/0 weight 3}
 * To add a route to a particular FIB table (VRF), use:
 * @cliexcmd{ip route add 172.16.24.0/24 table 7 via GigabitEthernet2/0/0}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip_route_command, static) = {
  .path = "ip route",
  .short_help = "ip route [add|del] [count <n>] <dst-ip-addr>/<width> [table <table-id>] [via <next-hop-ip-addr> [<interface>] [weight <weight>]] | [via arp <interface> <adj-hop-ip-addr>] | [via drop|punt|local<id>|arp|classify <classify-idx>] [lookup in table <out-table-id>]",
  .function = vnet_ip_route_cmd,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

/*
 * The next two routines address a longstanding script hemorrhoid.
 * Probing a v4 or v6 neighbor needs to appear to be synchronous,
 * or dependent route-adds will simply fail.
 */
static clib_error_t *
ip6_probe_neighbor_wait (vlib_main_t *vm, ip6_address_t * a, u32 sw_if_index,
			 int retry_count)
{
  vnet_main_t * vnm = vnet_get_main();
  clib_error_t * e;
  int i;
  int resolved = 0;
  uword event_type;
  uword *event_data = 0;

  ASSERT (vlib_in_process_context(vm));

  if (retry_count > 0)
    vnet_register_ip6_neighbor_resolution_event
      (vnm, a, vlib_get_current_process (vm)->node_runtime.node_index,
       1 /* event */, 0 /* data */);

  for (i = 0; i < retry_count; i++)
    {
      /* The interface may be down, etc. */
      e = ip6_probe_neighbor (vm, a, sw_if_index);

      if (e)
	return e;

      vlib_process_wait_for_event_or_clock (vm, 1.0);
      event_type = vlib_process_get_events (vm, &event_data);
      switch (event_type)
	{
	case 1: /* resolved... */
	  vlib_cli_output (vm, "Resolved %U",
			   format_ip6_address, a);
          resolved = 1;
          goto done;
          
        case ~0: /* timeout */
          break;
          
        default:
          clib_warning ("unknown event_type %d", event_type);
        }
      vec_reset_length (event_data);
    }
  
 done:

  if (!resolved)
    return clib_error_return (0, "Resolution failed for %U",
                              format_ip6_address, a);
  return 0;
}

static clib_error_t *
ip4_probe_neighbor_wait (vlib_main_t *vm, ip4_address_t * a, u32 sw_if_index,
                         int retry_count)
{
  vnet_main_t * vnm = vnet_get_main();
  clib_error_t * e;
  int i;
  int resolved = 0;
  uword event_type;
  uword *event_data = 0;

  ASSERT (vlib_in_process_context(vm));

  if (retry_count > 0)
    vnet_register_ip4_arp_resolution_event 
      (vnm, a, vlib_get_current_process (vm)->node_runtime.node_index,
       1 /* event */, 0 /* data */);
  
  for (i = 0; i < retry_count; i++)
    {
      /* The interface may be down, etc. */
      e = ip4_probe_neighbor (vm, a, sw_if_index);
      
      if (e)
        return e;
      
      vlib_process_wait_for_event_or_clock (vm, 1.0);
      event_type = vlib_process_get_events (vm, &event_data);
      switch (event_type) 
        {
        case 1: /* resolved... */
          vlib_cli_output (vm, "Resolved %U", 
                           format_ip4_address, a);
          resolved = 1;
          goto done;
          
        case ~0: /* timeout */
          break;
          
        default:
          clib_warning ("unknown event_type %d", event_type);
        }
      vec_reset_length (event_data);
    }
  
 done:

  vec_reset_length (event_data);

  if (!resolved)
    return clib_error_return (0, "Resolution failed for %U",
                              format_ip4_address, a);
  return 0;
}

static clib_error_t *
probe_neighbor_address (vlib_main_t * vm,
			unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  unformat_input_t _line_input, * line_input = &_line_input;
  ip4_address_t a4;
  ip6_address_t a6;
  clib_error_t * error = 0;
  u32 sw_if_index = ~0;
  int retry_count = 3;
  int is_ip4 = 1;
  int address_set = 0;

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) 
    {
      if (unformat_user (line_input, unformat_vnet_sw_interface, vnm, 
                         &sw_if_index))
        ;
      else if (unformat (line_input, "retry %d", &retry_count))
        ;

      else if (unformat (line_input, "%U", unformat_ip4_address, &a4))
        address_set++;
      else if (unformat (line_input, "%U", unformat_ip6_address, &a6))
        {
          address_set++;
          is_ip4 = 0;
        }
      else
        return clib_error_return (0, "unknown input '%U'",
                                  format_unformat_error, line_input);
    }

  unformat_free (line_input);

  if (sw_if_index == ~0)
    return clib_error_return (0, "Interface required, not set.");
  if (address_set == 0)
    return clib_error_return (0, "ip address required, not set.");
  if (address_set > 1)
    return clib_error_return (0, "Multiple ip addresses not supported.");
    
  if (is_ip4)
    error = ip4_probe_neighbor_wait (vm, &a4, sw_if_index, retry_count);
  else 
    error = ip6_probe_neighbor_wait (vm, &a6, sw_if_index, retry_count);

  return error;
}

/*?
 * The '<em>ip probe-neighbor</em>' command ARPs for IPv4 addresses or
 * attempts IPv6 neighbor discovery depending on the supplied IP address
 * format.
 *
 * @note This command will not immediately affect the indicated FIB; it
 * is not suitable for use in establishing a FIB entry prior to adding
 * recursive FIB entries. As in: don't use it in a script to probe a
 * gateway prior to adding a default route. It won't work. Instead,
 * configure a static ARP cache entry [see '<em>set ip arp</em>'], or
 * a static IPv6 neighbor [see '<em>set ip6 neighbor</em>'].
 *
 * @cliexpar
 * Example of probe for an IPv4 address:
 * @cliexcmd{ip probe-neighbor GigabitEthernet2/0/0 172.16.1.2}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip_probe_neighbor_command, static) = {
  .path = "ip probe-neighbor",
  .function = probe_neighbor_address,
  .short_help = "ip probe-neighbor <interface> <ip4-addr> | <ip6-addr> [retry nn]",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */
