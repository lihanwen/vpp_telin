#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/format.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vnet/ip/udp.h>
#include <vnet/ipsec/ipsec.h>
#include <vppinfra/xxhash.h>

#include <vnet/ethernet/ethernet.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "radlib.h"
#include <arpa/inet.h>
#include <vnet/devices/dpdk/dpdk.h>
#include "md5.h"
#include <vnet/radius/radius_private.h>
#include "hashlist.h"
#include "radlib.h"
#include <vnet/portal/portal.h>
#include <vnet/portal/portal_hash.h>
#include <rte_rwlock.h>
#include <rte_eal.h>
#include <vnet/radius/interface_radius.h>
//#include <vnet/radius/interface_radius.h>


#define RAD_SRV_SOCKET	1813	/* accounting server (auth uses 1812) */
#define RAD_AUTH_PORT   1812

#define RAD_VENDOR_ID	123456

#define RADIUS_RESEND_TIMES 3


//calculate the length of str
int cal_strlen(char *s)
{
    int i=0;
    while(*s!='\0')
    {
        i++;
        s++;
    }
    return i;
}
void
hashnode_free(radius_packet_session *temp)
{
	free(temp);
}


void
radius_init_request_packet(u8 password_type, unsigned char challenge[MD5_DATA_LEN], u16 req_id, unsigned char *user_name, unsigned char *user_password, u32 ip_addr, unsigned char buf[MSGSIZE], u32 *msglen)
{
	struct rad_handle rad_h  ;
	
	rad_auth_init(&rad_h);
	if (rad_add_server(&rad_h, radius_get_primary_server(), RAD_AUTH_PORT, (const char *)radius_ser_info[0].key_auth, 5, 5, DEAD_TIME) < 0) {
    	fprintf(stderr, "failed to add server: %s\n", rad_strerror(&rad_h));
    }
   /*
	if (rad_add_server(rad_h, "10.10.63.3", RAD_AUTH_PORT, "123456", 5, 5, DEAD_TIME) < 0) {
    	fprintf(stderr, "failed to add server: %s\n", rad_strerror(rad_h));
    }
	*/
    if (rad_create_request(&rad_h, RAD_ACCESS_REQUEST)) {
    	fprintf(stderr, "failed to add server: %s\n", rad_strerror(&rad_h));
    }
	Portal_DEBUG("<<<<<<<<<<<<<**************>>>>>>>>>>>>>>>> :::::%s\n", user_name);
	rad_put_string(&rad_h, RAD_USER_NAME, (const char *)user_name);

	Portal_DEBUG("<<<<<<<<<<<<<**************>>>>>>>>>>>>>>>> :::::%s\n", user_name);


    if( PORTAL_ATTR_PASS_WORD == password_type)
    {
        //添加RAD_USER_PASSWORD字段，长度为小于等于16个字节，内容为PKT_REQ_AUTH报文中的密码字段
        rad_put_string(&rad_h, RAD_USER_PASSWORD, (const char *)user_password);
		Portal_DEBUG("RAD_USER_PASSWORD  %s\n",user_password);
    }
	else if( PORTAL_ATTR_CHAP_PASSWORD == password_type )
	{

       char chap_password[18];
        memset(chap_password, '\0', 18);
        //添加ChapId，长度一个字节，内容为portal报文头中的req_id字段的低八位
        *chap_password = (char )(req_id);
        //添加chap密码，长度为定长16个字节，内容为PKT_REQ_AUTH报文中的密码字段
        memcpy(chap_password+1, user_password, 16);
        //添加RAD_CHAP_PASSWORD字段
        rad_put_attr(&rad_h, RAD_CHAP_PASSWORD, chap_password, 17);
	}

	rad_put_attr(&rad_h, RAD_CHAP_CHALLENGE, challenge, 16);

    //rad_put_string(rad_h, RAD_USER_PASSWORD, (const char *)user_password);
    rad_put_int(&rad_h, RAD_NAS_PORT, 4223);
    rad_put_vendor_int(&rad_h, RAD_VENDOR_ID, 1, 1749);
    rad_put_vendor_string(&rad_h, RAD_VENDOR_ID, 2, "ghijklm");

	rad_send_request(&rad_h);
	clib_memcpy((char *)buf,(const char *)rad_h.out, rad_h.out_len);
	*msglen = rad_h.out_len;
}


int radius_response_is_valid(u16 in_len, unsigned char *in,unsigned int *ip)
{
      char authenticate [ AUTHEN_LEN ];
	int sus = 0;
	Portal_DEBUG("is_valib_response\n");

	MD5_CTX ctx;

	int len;
#ifdef WITH_SSL
	HMAC_CTX hctx;
	u_char resp[MSGSIZE], md[EVP_MAX_MD_SIZE];
	u_int md_len;
	int pos;
#endif

	/* Check the message length */


	if (in_len < POS_ATTRS)
		return 0;

	len = in[POS_LENGTH] << 8 | in[POS_LENGTH+1];


	if (len > in_len)
		return 0;

	sus = radius_delete_node_bypacketid(in[POS_IDENT], ip, authenticate);
	if(!sus)
	{
		return 0;
	}


	/*temp->deleted_by_radius = 1;*/
    //dl_list_del(&(temp->suspend_list));

//	rte_spinlock_unlock((&radius_hash[temp->record_msg.packet_id])->lock);


	/* Check the response authenticator */
       unsigned char md5[MD5_DIGEST_LENGTH];
	MD5_Init(&ctx);
	MD5_Update(&ctx, &in[POS_CODE], POS_AUTH - POS_CODE);
	MD5_Update(&ctx, &authenticate, LEN_AUTH);
	MD5_Update(&ctx, &in[POS_ATTRS], len - POS_ATTRS);
	MD5_Update(&ctx, radius_ser_info[0].key_auth, strlen((const char *)radius_ser_info[0].key_auth));
//	MD5_Update(&ctx, "123456", 6);
	MD5_Final(md5, &ctx);


    /*
    unsigned char str[128];

	memcpy(str, &in[POS_AUTH], POS_AUTH - POS_CODE);

	memcpy(&(str[POS_AUTH - POS_CODE]), &authenticate, LEN_AUTH);

	memcpy(&(str[POS_AUTH - POS_CODE + LEN_AUTH]), &in[POS_ATTRS], len - POS_ATTRS);

	memcpy(&(str[POS_AUTH - POS_CODE + LEN_AUTH + len - POS_ATTRS]), &radius_ser_info.key_auth, strlen(radius_ser_info.key_auth));

    MD5_Init(&ctx);

	MD5_Update(&ctx, str, (POS_AUTH - POS_CODE + LEN_AUTH + strlen(radius_ser_info.key_auth) + len - POS_ATTRS));

	MD5_Final(md5, &ctx);
    */


	if (memcmp(&in[POS_AUTH], md5, sizeof md5) != 0)
		return 0;

#ifdef WITH_SSL
	/*
	 * For non accounting responses check the message authenticator,
	 * if any.
	 */
	if (in[POS_CODE] != RAD_ACCOUNTING_RESPONSE) {

		memcpy(resp, in, MSGSIZE);
		pos = POS_ATTRS;

		/* Search and verify the Message-Authenticator */
		while (pos < len - 2) {

			if (in[pos] == RAD_MESSAGE_AUTHENTIC) {
				/* zero fill the Message-Authenticator */
				memset(&resp[pos + 2], 0, MD5_DIGEST_LENGTH);

				HMAC_CTX_init(&hctx);
				HMAC_Init(&hctx, srvp->secret,
				    strlen(srvp->secret), EVP_md5());
				HMAC_Update(&hctx, &in[POS_CODE],
				    POS_AUTH - POS_CODE);
				HMAC_Update(&hctx, &out[POS_AUTH],
				    LEN_AUTH);
				HMAC_Update(&hctx, &resp[POS_ATTRS],
				    in_len - POS_ATTRS);
				HMAC_Final(&hctx, md, &md_len);
				HMAC_CTX_cleanup(&hctx);
				HMAC_cleanup(&hctx);
				if (memcmp(md, &in[pos + 2],
				    MD5_DIGEST_LENGTH) != 0)
					return 0;
				break;
			}
			pos += in[pos + 1];
		}
	}
#endif
	return 1;
}


static vlib_node_registration_t suspend_config_node;


u8 g_test_debug = 0;

#define Test_DEBUG(str, arg...)  do{\
        if(g_test_debug)\
        {\
            FILE *debug_fp = fopen("/tmp/test_debug.log", "a");\
            if (NULL != debug_fp){\
            fprintf(debug_fp, "%d:L%d in %s, ", g_test_debug, __LINE__, __FILE__);\
            fprintf(debug_fp, str, ##arg);\
            time_t timep;\
            time(&timep);\
	        fprintf(debug_fp,"%s",asctime(gmtime(&timep)));\
            fflush(debug_fp);\
            fclose(debug_fp);\
            }\
            else g_test_debug++;\
        }\
}while(0)


static uword
suspend_config_process (vlib_main_t * vm,
					vlib_node_runtime_t * rt, vlib_frame_t * f)
{
	int flag =0;
	char auth[LEN_AUTH] = {0};
	unsigned char pkgid = 0;
	radius_packet_session *temp, *prev;

	while(1)
	{
			int i;
			for(i = 0; i < RADIUS_PACKET_SESSION_HASH_SIZE; i++)
			{
			        rte_spinlock_lock(&radius_packet_session_hash[i].lock);
				dl_list_for_each_safe(temp, prev, &(radius_packet_session_hash[i].radius_packet_session_list), struct clientsession_st, radius_packet_session_list)
				{
					u64 t = clib_cpu_time_now ();
					u64 start_time = (temp->record_msg.sustime)/vm->clib_time.clocks_per_second;
					if(((t/vm->clib_time.clocks_per_second)-start_time)> (temp->record_msg.timeout_sec))
					{
						//rte_spinlock_lock(&temp->lock);
						dl_list_del(&(temp->radius_packet_session_list));
						//rte_spinlock_unlock(&temp->lock);

						flag = 1;
						--i; /*重新遍历当前哈希链*/
						break;

					}
				  }
				rte_spinlock_unlock(&radius_packet_session_hash[i].lock);
				if(flag && temp)
				{
					if(1 == flag)
					{
						suspend_timer_deadline(temp, &pkgid, auth);
					}
					if(temp->resendCount < RADIUS_RESEND_TIMES)
					{

						   temp->record_msg.packet_id = pkgid;
						   temp->resendCount += 1;
						   clib_memcpy((char *)(temp->record_msg.authenticate), (const char *)auth, LEN_AUTH);
						   radius_insert_packet_session(temp);
					}

				}
				flag = 0;

		}

		vlib_process_suspend (vm, 2.0);

	}
	return flag;
}


VLIB_REGISTER_NODE (suspend_config_node,static) = {
    .function = suspend_config_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "suspend-config-process",
};





