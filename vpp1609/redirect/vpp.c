/*******************************************************************************
 Copyright (C) 2016 Hangzhou Telin Technologies Co.,Ltd. All Rights Reserved.
 --------------------------------------------------------------------------------
 �ļ�����: vpp.c 
 ��������: 
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

	/* ���´������daemon���������γ��� */
    //��ʼ����������
    if( -1 == Vpp_init() )
    {
        return -1;
    }

        /* ���� unix �˿� socket ������web��ͨ��*/
    listen_local_socket_fd = vpp_make_local_server_fd(UNIX_SOCKET_JSON_FILE);
    if (listen_local_socket_fd < 0)
    {    
        VPP_log_error("listen web AC_make_local_server_fd fail\n");
        return 1;
    }

    /* ��ʼ��eloop�¼� */
    eloop_init();
	VPP_DEBUG("start	 ====================\n");
    //ע����� web Unix�˿ڵ�eloop��
    eloop_register_read_sock(listen_local_socket_fd, AC_ctrl_ap_fd, NULL, NULL);
        
    /* �¼���ʼ���� */
    eloop_run();
    eloop_destroy();

    VPP_DEBUG("End.\n");


	return 0;

}


