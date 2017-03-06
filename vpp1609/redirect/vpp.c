/*******************************************************************************
 Copyright (C) 2016 Hangzhou Telin Technologies Co.,Ltd. All Rights Reserved.
 --------------------------------------------------------------------------------
 文件名称: vpp.c 
 功能描述: 
*******************************************************************************/
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>


#include "vpp.h"
#include "cJSON.h"
#include "eloop.h"
#include "vpp_command.h"
#include "vpp_mem.h"
#include "vpp_provider.h"



int g_ac_debug = 0;

int main(int argc, char* argv[])
{
    int opt;
    int daemon_mode = 1;
	int listen_local_socket_fd;

    if (argc > 1)
    {
        while ((opt = getopt(argc, argv, "Nd")) != -1)
        {
            switch (opt)
            {
                case 'N':
                    daemon_mode = 0;
                    break;
                case 'd':
                    g_ac_debug = 1;
                    break;
                default: /* unknow command */
                  //  AP_usage();
                    exit(EXIT_FAILURE);
            }
        }
    }
VPP_DEBUG("start     ====================\n");
	if (daemon_mode)
	{
		//make to daemon mode

		if (Vpp_daemonize())
		{
			VPP_DEBUG("make daemon fail\n");
			exit(EXIT_FAILURE);
		}
	}

	/* 以下代码放在daemon后面允许多次尝试 */
    //初始化所有配置
    if( -1 == Vpp_init() )
    {
        return -1;
    }

        /* 监听 unix 端口 socket 用于与web端通信*/
    listen_local_socket_fd = vpp_make_local_server_fd(UNIX_SOCKET_JSON_FILE);
    if (listen_local_socket_fd < 0)
    {    
        VPP_log_error("listen web AC_make_local_server_fd fail\n");
        return 1;
    }

    /* 初始化eloop事件 */
    eloop_init();
	VPP_DEBUG("start	 ====================\n");
    //注册监听 web Unix端口到eloop中
    eloop_register_read_sock(listen_local_socket_fd, AC_ctrl_ap_fd, NULL, NULL);
        
    /* 事件开始运行 */
    eloop_run();
    eloop_destroy();

    VPP_DEBUG("End.\n");


	return 0;

}


