#ifndef __VPP_PROVIDER_H__
#define __VPP_PROVIDER_H__


#include "vpp.h"


int Vpp_init();
int Vpp_daemonize();
int vpp_make_local_server_fd(char *socket_file);
void format_Time_String(char ptr[TIME_STRING_LEN], int clock);
int vpp_make_listen_tcp_fd(u_int16_t port, u_int32_t eth_addr );
int arp_get_mac(const char req_ip[MAX_IP_LEN], char req_mac[MAX_MAC_ADDR]);

#endif
