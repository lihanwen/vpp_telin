#include <vnet/ip/ping.h>
#include <vnet/ip/icmp46_packet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <vnet/portal/portal_connectivity.h>
#include <vnet/portal/portal.h>

u32 portal_server_is_online = 0;
/* Fill in the ICMP ECHO structure, return the safety-checked and possibly shrunk data_len */
static u16
init_icmp46_echo_request (icmp46_echo_request_t * icmp46_echo,
                          u16 seq_host, u16 id_host, u16 data_len)
{
  int i;
  icmp46_echo->seq = clib_host_to_net_u16 (seq_host);
  icmp46_echo->id = clib_host_to_net_u16 (id_host);

  for (i = 0; i < sizeof (icmp46_echo->data); i++)
    {
      icmp46_echo->data[i] = i % 256;
    }

  if (data_len > sizeof (icmp46_echo_request_t))
    {
      data_len = sizeof (icmp46_echo_request_t);
    }
  return data_len;
}

void 
send_icmp4 (u16 seq_host, u16 id_host)
{
  icmp4_echo_request_header_t *h0;
  u32 bi0 = 0;
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t *p0;
  vlib_frame_t *f;
  u32 *to_next;
  u32 data_len = PING_DEFAULT_DATA_LEN;

  if (vlib_buffer_alloc (vm, &bi0, 1) == 1)
  {

	  p0 = vlib_get_buffer (vm, bi0);

	  /* Determine sw_if_index0 of the source intf, may be force-set via sw_if_index.  */
	  vnet_buffer (p0)->sw_if_index[VLIB_RX] = 0;
	  vnet_buffer (p0)->sw_if_index[VLIB_TX] = ~0;  /* use interface VRF */

	  h0 = vlib_buffer_get_current (p0);

	  /* Fill in ip4 header fields */
	  h0->ip4.checksum = 0;
	  h0->ip4.ip_version_and_header_length = 0x45;
	  h0->ip4.tos = 0;
	  h0->ip4.length = 0;           /* Set below */
	  h0->ip4.fragment_id = 0;
	  h0->ip4.flags_and_fragment_offset = 0;
	  h0->ip4.ttl = 0xff;
	  h0->ip4.protocol = IP_PROTOCOL_ICMP;
	  //h0->ip4.dst_address.data_u32 = inet_addr("10.10.52.1");
	  //h0->ip4.src_address.data_u32 = inet_addr("10.10.52.203");
	  
	  h0->ip4.dst_address.data_u32 = gs_portal_server;
	  h0->ip4.src_address.data_u32 = gs_bas_ip;

	  /* Fill in icmp fields */
	  h0->icmp.type = ICMP4_echo_request;
	  h0->icmp.code = 0;
	  h0->icmp.checksum = 0;

	  data_len =
      init_icmp46_echo_request (&h0->icmp_echo, seq_host, id_host, data_len);
	  h0->icmp_echo.time_sent = vlib_time_now (vm);

	  /* Fix up the lengths */
	  h0->ip4.length =
	    clib_host_to_net_u16 (data_len + sizeof (icmp46_header_t) +
	                          sizeof (ip4_header_t));

	  p0->current_length = clib_net_to_host_u16 (h0->ip4.length);

	  /* Calculate the IP and ICMP checksums */
	  h0->ip4.checksum = ip4_header_checksum (&(h0->ip4));
	  h0->icmp.checksum =
	    ~ip_csum_fold (ip_incremental_checksum (0, &(h0->icmp),
	                    p0->current_length - sizeof (ip4_header_t)));

	  /* Enqueue the packet right now */
	  f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
	  to_next = vlib_frame_vector_args (f);
	  to_next[0] = bi0;
	  f->n_vectors = 1;

	  //printf("---Send ping packaet---\n");

	  rember_time = clib_cpu_time_now();
	  disconnected_time ++;
	  
	  vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);

  }
}


static uword
portal_connectivity_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
	rember_time = 0;//初始赋值为0，直接触发发包函数
	disconnected_time = 0;
	portal_server_is_online = 0;
	u16 icmp_id, icmp_seq;
	
	static u32 rand_seed = 0;

  	if (PREDICT_FALSE(!rand_seed))
    	rand_seed = random_default_seed();
	icmp_id = random_u32(&rand_seed) & 0xffff;
	icmp_seq = 0;
	
	while(1)
	{
		
		//printf("$$$$$SEND ICMP Packet$$$$$$\n");
		vlib_process_suspend (vm, 1.0);//1秒一次循环
		
		u64 now_t = clib_cpu_time_now ();//得到现在的时间
		u64 internal_time = (now_t - rember_time) / vm->clib_time.clocks_per_second;
		if(internal_time > 1)//发包间隔1秒
		{
			icmp_seq++;
			send_icmp4(icmp_seq, icmp_id);
		}

		if(disconnected_time >= 3)
		{
			  //printf("global connective333333 = %d\n ",connective);
			  portal_server_is_online = 0;
		}
	}
	return f->n_vectors;
}


VLIB_REGISTER_NODE (portal_connectivity_process_node,static) = {
    .function = portal_connectivity_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "portal-connectivity",
};

