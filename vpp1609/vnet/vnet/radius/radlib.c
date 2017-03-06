/*-
 * Copyright 1998 Juniper Networks, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define	MAX_FIELDS	7

/* We need the MPPE_KEY_LEN define - but we don't have netgraph/ng_mppc.h */
#define MPPE_KEY_LEN	16

#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vnet/radius/radius_private.h>


#ifndef __printflike
#define __printflike(m, n) __attribute__((format(printf, m, n)));
#endif

static void	 clear_password(struct rad_handle *);
static void	 generr(struct rad_handle *, const char *, ...)
		    __printflike(2, 3);
static void	 insert_scrambled_password(struct rad_handle *, int);
static void	 insert_request_authenticator(struct rad_handle *, int);
static void	 insert_message_authenticator(struct rad_handle *, int);

static int	 put_password_attr(struct rad_handle *, int,
		    const void *, size_t);
static int	 put_raw_attr(struct rad_handle *, int,
		    const void *, size_t);

static void
clear_password(struct rad_handle *h)
{
	if (h->pass_len != 0) {
		memset(h->pass, 0, h->pass_len);
		h->pass_len = 0;
	}
	h->pass_pos = 0;
}

static void
generr(struct rad_handle *h, const char *format, ...)
{
	va_list		 ap;

	va_start(ap, format);
	vsnprintf(h->errmsg, ERRSIZE, format, ap);
	va_end(ap);
}

static void
insert_scrambled_password(struct rad_handle *h, int srv)
{
	MD5_CTX ctx;
	unsigned char md5[MD5_DIGEST_LENGTH];
	const struct rad_server *srvp;
	int padded_len;
	int pos;

	srvp = &h->servers[srv];
	padded_len = h->pass_len == 0 ? 16 : (h->pass_len+15) & ~0xf;

	memcpy(md5, &h->out[POS_AUTH], LEN_AUTH);
	for (pos = 0;  pos < padded_len;  pos += 16) {
		int i;

		/* Calculate the new scrambler */
		MD5_Init(&ctx);
		MD5_Update(&ctx, srvp->secret, strlen(srvp->secret));
		MD5_Update(&ctx, md5, 16);
		MD5_Final(md5, &ctx);

		/*
		 * Mix in the current chunk of the password, and copy
		 * the result into the right place in the request.  Also
		 * modify the scrambler in place, since we will use this
		 * in calculating the scrambler for next time.
		 */
		for (i = 0;  i < 16;  i++)
			h->out[h->pass_pos + pos + i] =
			    md5[i] ^= h->pass[pos + i];
	}
}

static void
insert_request_authenticator(struct rad_handle *h, int resp)
{
	MD5_CTX ctx;
	const struct rad_server *srvp;

	srvp = &h->servers[h->srv];

	/* Create the request authenticator */
	MD5_Init(&ctx);
	MD5_Update(&ctx, &h->out[POS_CODE], POS_AUTH - POS_CODE);
	if (resp)
	    MD5_Update(&ctx, &h->in[POS_AUTH], LEN_AUTH);
	else
	    MD5_Update(&ctx, &h->out[POS_AUTH], LEN_AUTH);
	MD5_Update(&ctx, &h->out[POS_ATTRS], h->out_len - POS_ATTRS);
	MD5_Update(&ctx, srvp->secret, strlen(srvp->secret));
	MD5_Final(&h->out[POS_AUTH], &ctx);
}

static void
insert_message_authenticator(struct rad_handle *h, int resp)
{
#ifdef WITH_SSL
	u_char md[EVP_MAX_MD_SIZE];
	u_int md_len;
	const struct rad_server *srvp;
	HMAC_CTX ctx;
	srvp = &h->servers[h->srv];

	if (h->authentic_pos != 0) {
		HMAC_CTX_init(&ctx);
		HMAC_Init(&ctx, srvp->secret, strlen(srvp->secret), EVP_md5());
		HMAC_Update(&ctx, &h->out[POS_CODE], POS_AUTH - POS_CODE);
		if (resp)
		    HMAC_Update(&ctx, &h->in[POS_AUTH], LEN_AUTH);
		else
		    HMAC_Update(&ctx, &h->out[POS_AUTH], LEN_AUTH);
		HMAC_Update(&ctx, &h->out[POS_ATTRS],
		    h->out_len - POS_ATTRS);
		HMAC_Final(&ctx, md, &md_len);
		HMAC_CTX_cleanup(&ctx);
		HMAC_cleanup(&ctx);
		memcpy(&h->out[h->authentic_pos + 2], md, md_len);
	}
#endif
}


static int
put_password_attr(struct rad_handle *h, int type, const void *value, size_t len)
{
	int padded_len;
	int pad_len;

	if (h->pass_pos != 0) {
		generr(h, "Multiple User-Password attributes specified");
		return -1;
	}
	if (len > PASSSIZE)
		len = PASSSIZE;
	padded_len = len == 0 ? 16 : (len+15) & ~0xf;
	pad_len = padded_len - len;

	/*
	 * Put in a place-holder attribute containing all zeros, and
	 * remember where it is so we can fill it in later.
	 */
	clear_password(h);
	put_raw_attr(h, type, h->pass, padded_len);
	h->pass_pos = h->out_len - padded_len;

	/* Save the cleartext password, padded as necessary */
	memcpy(h->pass, value, len);
	h->pass_len = len;
	memset(h->pass + len, 0, pad_len);
	return 0;
}

static int
put_raw_attr(struct rad_handle *h, int type, const void *value, size_t len)
{
	if (len > 253) {
		generr(h, "Attribute too long");
		return -1;
	}
	if (h->out_len + 2 + len > MSGSIZE) {
		generr(h, "Maximum message length exceeded");
		return -1;
	}
	h->out[h->out_len++] = type;
	h->out[h->out_len++] = len + 2;
	memcpy(&h->out[h->out_len], value, len);
	h->out_len += len;
	return 0;
}

int
rad_add_server(struct rad_handle *h, const char *host, int port,
    const char *secret, int timeout, int tries, int dead_time)
{
	struct rad_server *srvp;

	if (h->num_servers >= MAXSERVERS) {
		generr(h, "Too many RADIUS servers specified");
		return -1;
	}
	if(!host)
	{
		return  -1;
	}
	srvp = &h->servers[h->num_servers];

	memset(&srvp->addr, 0, sizeof srvp->addr);
	srvp->addr.sin_family = AF_INET;//sin_family表示协议簇，一般用AF_INET表示TCP/IP协议
	if (!inet_aton(host, &srvp->addr.sin_addr)) {
		struct hostent *hent;

		if ((hent = gethostbyname(host)) == NULL) {
			generr(h, "%s: host not found", host);
			return -1;
		}
		memcpy(&srvp->addr.sin_addr, hent->h_addr,
		    sizeof srvp->addr.sin_addr);
	}
	if (port != 0)
		srvp->addr.sin_port = htons((u_short)port);
	else {
		struct servent *sent;

		if (h->type == RADIUS_AUTH)
			{
			srvp->addr.sin_port =
			    (sent = getservbyname("radius", "udp")) != NULL ?
				sent->s_port : htons(RADIUS_PORT);
			printf("srvp: addr.sin_port %d\n", srvp->addr.sin_port);
			}
		else
			{
			srvp->addr.sin_port =
			    (sent = getservbyname("radacct", "udp")) != NULL ?
				sent->s_port : htons(RADACCT_PORT);
			printf("srvp: addr.sin_port %d\n", srvp->addr.sin_port);
			}
	}
	if ((srvp->secret = strdup(secret)) == NULL) {
		generr(h, "Out of memory");
		return -1;
	}
	srvp->timeout = timeout;
	srvp->max_tries = tries;
	srvp->num_tries = 0;
	srvp->is_dead = 0;
	srvp->dead_time = dead_time;
	srvp->next_probe = 0;
	
	h->num_servers++;
	return 0;
}


/*
 * rad_init_send_request() must have previously been called.
 * Returns:
 *   0     The application should select on *fd with a timeout of tv before
 *         calling rad_continue_send_request again.
 *   < 0   Failure
 *   > 0   Success
 */
int
rad_continue_send_request(struct rad_handle *h, int selected, int *fd,
                          struct timeval *tv)
{
	int cur_srv;
	time_t now;

	if (h->type == RADIUS_SERVER) {
		generr(h, "denied function call");
		return (-1);
	}
	if (selected) {

		if (h->in_len == -1) {
			generr(h, "recvfrom: %s", strerror(errno));
			return -1;
		}
	}

	/*
         * Scan round-robin to the next server that has some
         * tries left.  There is guaranteed to be one, or we
         * would have exited this loop by now.
	 */
	cur_srv = h->srv;
	now = time(NULL);
	if (h->servers[h->srv].num_tries >= h->servers[h->srv].max_tries) {
		/* Set next probe time for this server */
		if (h->servers[h->srv].dead_time) {
			h->servers[h->srv].is_dead = 1;
			h->servers[h->srv].next_probe = now +
			    h->servers[h->srv].dead_time;
		}
		do {
		    	h->srv++;
			if (h->srv >= h->num_servers)
				h->srv = 0;
			if (h->servers[h->srv].is_dead == 0)
			    	break;
			if (h->servers[h->srv].dead_time &&
			    h->servers[h->srv].next_probe <= now) {
			    	h->servers[h->srv].is_dead = 0;
				h->servers[h->srv].num_tries = 0;
				break;
			}
		} while (h->srv != cur_srv);

		if (h->srv == cur_srv) {
			generr(h, "No valid RADIUS responses received");
			return (-1);
		}
	}

	if (h->out[POS_CODE] == RAD_ACCESS_REQUEST) {
		/* Insert the scrambled password into the request */
		if (h->pass_pos != 0)
			insert_scrambled_password(h, h->srv);
	}
	insert_message_authenticator(h, 0);

	if (h->out[POS_CODE] != RAD_ACCESS_REQUEST) {
		/* Insert the request authenticator into the request */
		memset(&h->out[POS_AUTH], 0, LEN_AUTH);
		insert_request_authenticator(h, 0);
	}
	h->servers[h->srv].num_tries++;
	tv->tv_usec = 0;

	return 0;
}


int
rad_create_request(struct rad_handle *h, int code)
{
	int i;

	if (h->type == RADIUS_SERVER) {
		generr(h, "denied function call");
		return (-1);
	}
	if (h->num_servers == 0) {
	    	generr(h, "No RADIUS servers specified");
		return (-1);
	}
	h->out[POS_CODE] = code;
	h->out[POS_IDENT] = ++h->ident;
	if (code == RAD_ACCESS_REQUEST) {
		/* Create a random authenticator */
		for (i = 0;  i < LEN_AUTH;  i += 2) {
			long r;
			r = random();
			h->out[POS_AUTH+i] = (u_char)r;
			h->out[POS_AUTH+i+1] = (u_char)(r >> 8);
		}
	} else
		memset(&h->out[POS_AUTH], 0, LEN_AUTH);
	h->out_len = POS_ATTRS;
	clear_password(h);
	h->authentic_pos = 0;
	h->out_created = 1;
	return 0;
}



/*
 * Returns -1 on error, 0 to indicate no event and >0 for success
 */
int
rad_init_send_request(struct rad_handle *h, int *fd, struct timeval *tv)
{
	int srv;
	time_t now;
	if (h->type == RADIUS_SERVER) {
		generr(h, "denied function call");
		return (-1);
	}

	if (h->out[POS_CODE] != RAD_ACCESS_REQUEST) {
		/* Make sure no password given */
		if (h->pass_pos || h->chap_pass) {
			generr(h, "User or Chap Password"
			    " in accounting request");
			return -1;
		}
	} else {
		if (h->eap_msg == 0) {
			/* Make sure the user gave us a password */
			if (h->pass_pos == 0 && !h->chap_pass) {
				generr(h, "No User or Chap Password"
				    " attributes given");
				return -1;
			}
			if (h->pass_pos != 0 && h->chap_pass) {
				generr(h, "Both User and Chap Password"
				    " attributes given");
				return -1;
			}
		}
	}

	/* Fill in the length field in the message */
	h->out[POS_LENGTH] = h->out_len >> 8;
	h->out[POS_LENGTH+1] = h->out_len;

	h->srv = 0;
	now = time(NULL);
	for (srv = 0;  srv < h->num_servers;  srv++)
		h->servers[srv].num_tries = 0;
	/* Find a first good server. */
	for (srv = 0;  srv < h->num_servers;  srv++) {
		if (h->servers[srv].is_dead == 0)
			break;
		if (h->servers[srv].dead_time &&
		    h->servers[srv].next_probe <= now) {
		    	h->servers[srv].is_dead = 0;
			break;
		}
		h->srv++;
	}

	/* If all servers was dead on the last probe, try from beginning */
	if (h->srv == h->num_servers) {
		for (srv = 0;  srv < h->num_servers;  srv++) 
        {
		  	h->servers[srv].is_dead = 0;
			h->servers[srv].next_probe = 0;
		}
		h->srv = 0;
	}

	return rad_continue_send_request(h, 0, fd, tv);
}

/*
 * Create and initialize a rad_handle structure, and return it to the
 * caller.  Can fail only if the necessary memory cannot be allocated.
 * In that case, it returns NULL.
 */

void rad_auth_init(struct rad_handle * h)
{
	struct timeval tv;
	if (h != NULL) {
		gettimeofday(&tv, NULL);
		srandom(tv.tv_sec ^ tv.tv_usec);
		memset(h, 0, sizeof(struct rad_handle));
		h->num_servers = 0;
		h->ident = random();
		h->errmsg[0] = '\0';
		h->pass_len = 0;
		h->pass_pos = 0;
		h->chap_pass = 0;
		h->authentic_pos = 0;
		h->type = RADIUS_AUTH;
		h->out_created = 0;
		h->eap_msg = 0;
		h->bindto = INADDR_ANY;
	}
	return ;
}


int
rad_put_attr(struct rad_handle *h, int type, const void *value, size_t len)
{
	int result;

	if (!h->out_created) {
		generr(h, "Please call rad_create_request()"
		    " before putting attributes");
		return -1;
	}

	if (h->out[POS_CODE] == RAD_ACCOUNTING_REQUEST) {
		if (type == RAD_EAP_MESSAGE) {
			generr(h, "EAP-Message attribute is not valid"
			    " in accounting requests");
			return -1;
		}
	}

	/*
	 * When proxying EAP Messages, the Message Authenticator
	 * MUST be present; see RFC 3579.
	 */
	if (type == RAD_EAP_MESSAGE) {
		if (rad_put_message_authentic(h) == -1)
			return -1;
	}

	if (type == RAD_USER_PASSWORD) {
		result = put_password_attr(h, type, value, len);
	} else if (type == RAD_MESSAGE_AUTHENTIC) {
		result = rad_put_message_authentic(h);
	} else {
		result = put_raw_attr(h, type, value, len);
		if (result == 0) {
			if (type == RAD_CHAP_PASSWORD)
				h->chap_pass = 1;
			else if (type == RAD_EAP_MESSAGE)
				h->eap_msg = 1;
		}
	}

	return result;
}

int
rad_put_int(struct rad_handle *h, int type, u_int32_t value)
{
	u_int32_t nvalue;

	nvalue = htonl(value);
	return rad_put_attr(h, type, &nvalue, sizeof nvalue);
}

int
rad_put_string(struct rad_handle *h, int type, const char *str)
{
	return rad_put_attr(h, type, str, strlen(str));
}

int
rad_put_message_authentic(struct rad_handle *h)
{
#ifdef WITH_SSL
	u_char md_zero[MD5_DIGEST_LENGTH];

	if (h->out[POS_CODE] == RAD_ACCOUNTING_REQUEST) {
		generr(h, "Message-Authenticator is not valid"
		    " in accounting requests");
		return -1;
	}

	if (h->authentic_pos == 0) {
		h->authentic_pos = h->out_len;
		memset(md_zero, 0, sizeof(md_zero));
		return (put_raw_attr(h, RAD_MESSAGE_AUTHENTIC, md_zero,
		    sizeof(md_zero)));
	}
	return 0;
#else
	generr(h, "Message Authenticator not supported,"
	    " please recompile libradius with SSL support");
	return -1;
#endif
}

/*
 * Returns the response type code on success, or -1 on failure.
 */
int
rad_send_request(struct rad_handle *h)
{
	struct timeval timelimit;
	struct timeval tv;
	int fd;
	int n;

	n = rad_init_send_request(h, &fd, &tv);

	if (n != 0)
		return n;

	gettimeofday(&timelimit, NULL);
	timeradd(&tv, &timelimit, &timelimit);//将时间更新为当前时间+允许时间


		n = rad_continue_send_request(h, n, &fd, &tv);

		if (n != 0)
			return n;

		gettimeofday(&timelimit, NULL);
		timeradd(&tv, &timelimit, &timelimit);
	
	return 0;
}

const char *
rad_strerror(struct rad_handle *h)
{
	return h->errmsg;
}


int
rad_put_vendor_attr(struct rad_handle *h, int vendor, int type,
    const void *value, size_t len)
{
	struct vendor_attribute *attr;
	int res;

	if (!h->out_created) {
		generr(h, "Please call rad_create_request()"
		    " before putting attributes");
		return -1;
	}

	if ((attr = malloc(len + 6)) == NULL) {
		generr(h, "malloc failure (%zu bytes)", len + 6);
		return -1;
	}

	attr->vendor_value = htonl(vendor);
	attr->attrib_type = type;
	attr->attrib_len = len + 2;
	memcpy(attr->attrib_data, value, len);

	res = put_raw_attr(h, RAD_VENDOR_SPECIFIC, attr, len + 6);
	free(attr);
	if (res == 0 && vendor == RAD_VENDOR_MICROSOFT
	    && (type == RAD_MICROSOFT_MS_CHAP_RESPONSE
	    || type == RAD_MICROSOFT_MS_CHAP2_RESPONSE)) {
		h->chap_pass = 1;
	}
	return (res);
}

int
rad_put_vendor_int(struct rad_handle *h, int vendor, int type, u_int32_t i)
{
	u_int32_t value;

	value = htonl(i);
	return (rad_put_vendor_attr(h, vendor, type, &value, sizeof value));
}

int
rad_put_vendor_string(struct rad_handle *h, int vendor, int type,
    const char *str)
{
	return (rad_put_vendor_attr(h, vendor, type, str, strlen(str)));
}

	
