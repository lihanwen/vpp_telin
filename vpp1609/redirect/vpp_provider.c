/*******************************************************************************
 Copyright (C) 2015 Technologies Co.,Ltd. All Rights Reserved.
--------------------------------------------------------------------------------
 �ļ�����: ac_provider.c 
 ��������: 
*******************************************************************************/
#include <unistd.h>
#include <stdlib.h> 
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <time.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>


#include "vpp.h"
#include "cJSON.h"
#include "eloop.h"
#include "vpp_command.h"
#include "vpp_mem.h"
#include "vpp_provider.h"


/* �������¼�ӳ���pid, �ӳ���Ϊ 0 */
pid_t AC_g_pid;

/*******************************************************************************
 ��������  : Vpp_daemonize
 ��������  : ��Ϊdaemonģʽ��������������Զ�����
 �������  : ��
 �������  : ��
 �� �� ֵ  : 0      --�ɹ�
             ��0    --ʧ��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ : 
 �޸�����  : 
 �޸�Ŀ��  : ���º���
 �޸�����  : 2016.4.5
*******************************************************************************/
int Vpp_daemonize()
{
    int fd0, fd1,fd2;
    int i;
    FILE *fp;
    pid_t pid;
    struct rlimit rl;
    struct sigaction sa;

    /*clear file creation mask*/
    umask(0);

    /*get max number of file descriptor*/
    if(getrlimit(RLIMIT_NOFILE, &rl)<0)
    {
        perror("can not get file limit");
        return EXIT_FAILURE;
    }

    /*become a session leader to lose controlling TTY*/
    if( (pid = fork()) <0)
    {
        perror("can not fork");
        return EXIT_FAILURE;
    }
    else if (pid != 0) /*parent*/
    {
        exit(0);
    }

    /*write main pid into file*/
    //������д�ڵ�һ��
    fp = fopen(AC_PID_FILE, "w");
    if (fp != NULL)
    {
        //��ǰ���̵Ľ��̺�д��fd
        fprintf(fp, "%d", getpid());
        fclose(fp);
    }
    //���ӽ��̷��룬����ͬһ�飬�������������˲���Ӱ���ӽ���
    setsid();

    /*ensure future opens won't allocate controlling TTYs*/
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;        
    if(sigaction(SIGHUP, &sa, NULL) <0)
    {
        perror("can not ignore SIGHUP");
        return EXIT_FAILURE;
    }
    //��֤һֱ�и�daemon��������
    while (1)
    {
        if((pid = fork())< 0)
        {
            perror("can not fork for the 2nd time");
            return EXIT_FAILURE;
        }
        else if(pid != 0) /*parent*/
        {
            AC_g_pid = pid;
            
            //��������ӳ�����ֹ������fork�����������ӳ���
            wait(NULL);

            //�ӳ�5���ӣ����ӽ����˸ɾ�
            sleep(5);
            
            g_ac_debug++;
            VPP_DEBUG("Fork new process........\n");
            continue;
        }
        //�ӳ�����Ϊdaemon�����������
        break; 
    }

    /* �ӽ��� pid ���� */
    AC_g_pid = 0;
    
    /*write child pid into file*/
    //�ӽ���ÿ�θ����ں���
    fp = fopen(AC_PID_FILE, "a");
    if (fp != NULL)
    {
        fprintf(fp, " %d", getpid());
        fclose(fp);
    }
    
    /*change the current working directory to the root so we won't
    prevent file systems form being ummounted.*/
    //chdir()��������ǰ�Ĺ���Ŀ¼�ı���Բ���path ��ָ��Ŀ¼.
    if(chdir("/") < 0)
    {
        perror("can not change directory to /");
        return EXIT_FAILURE;
    }

    /*close all open file descriptors.*/
    if(rl.rlim_max == RLIM_INFINITY)
    {
        rl.rlim_max = 1024;
    }
    for(i = 0; i < (int)rl.rlim_max; i++)
    {
        close(i);
    }

    /* attach file descriptors 0, 1, and 2 to /dev/null */
    fd0 = open("/dev/null", O_RDWR);
    fd1 = dup(0);
    fd2 = dup(0);

    /*initialize the log file */
    if(fd0 != 0 || fd1 != 1 || fd2 != 2)
    {
        VPP_DEBUG("fd0...%d %d %d\n", fd0, fd1, fd2);
        perror("daemon error");
        return EXIT_FAILURE;
    }
    return 0;
}

/*******************************************************************************
 ��������  : Vpp_init
 ��������  : vpp��ʼ��
 �������  : ��
 �������  : ��
 �� �� ֵ  : 0 �ɹ� -1 ʧ��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ : 
 �޸�����  : 
 �޸�Ŀ��  : ���º���
 �޸�����  : 2016.12.24
*******************************************************************************/
int Vpp_init()
{
	link_head_init();
	link_user_head_init();
    return 0;
}

/*******************************************************************************
 ��������  : vpp_make_local_server_fd
 ��������  : ���ɷ������˱���socket�����ڽ���web������
 �������  : socket_file Ҫ�������ļ�
 �������  : ��
 �� �� ֵ  : socket     �ɹ�
             -1         ʧ��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ : 
 �޸�����  : 
 �޸�Ŀ��  : ���º���
 �޸�����  : 2016.4.5
*******************************************************************************/
int vpp_make_local_server_fd(char *socket_file)
{
    int val;
    int server_sock;
    //ɾ������ļ�
    unlink(socket_file);

    //�����׽���
    if(-1 == (server_sock = socket(AF_UNIX, SOCK_DGRAM, 0)) ) 
    {
        VPP_DEBUG("Create socket fail. Reason:%s\n", strerror(errno));
        return -1;
    }
    struct sockaddr_un server_addr;
    memset (&(server_addr), '\0', sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;  
    memcpy(server_addr.sun_path, socket_file, strlen(socket_file)); 
    
    val = 1;
    //�������ñ��ص�ַ�Ͷ˿�
    if(setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) 
    {    
        close(server_sock);
        return -1;
    }
    //�󶨶˿�
    if(-1 == bind(server_sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_un))) 
    {    
        VPP_DEBUG("Bind socket fail. Reason:%s\n", strerror(errno));
        close(server_sock);
        return -1;
    }

    return server_sock;  
}

/*******************************************************************************
 ��������  : vpp_make_listen_tcp_fd
 ��������  : ����tcp��socket
 �������  : port  �����Ķ˿ں� ������
             eth_addr  Ҫ������������ip��ַ ������
 �������  : ��
 �� �� ֵ  : socket     �ɹ�
             -1         ʧ��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ : 
 �޸�����  : 
 �޸�Ŀ��  : ���º���
 �޸�����  : 2016.11.22
*******************************************************************************/
int vpp_make_listen_tcp_fd(u_int16_t port, u_int32_t eth_addr )
{
    int socket_fd;
    struct sockaddr_in addr;
    int val;
    
    memset (&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = port;
//  addr.sin_addr.s_addr = htonl(eth_addr);
	addr.sin_addr.s_addr = (eth_addr);
    if (-1 == (socket_fd = socket(AF_INET, SOCK_STREAM, 0))) 
    {
        VPP_log_error("Create socket fail. Reason:%s\n", strerror(errno));
        return -1;
    }

    val = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) 
    {
        VPP_log_error("setsockopt socket fail. Reason:%s\n", strerror(errno));
        close(socket_fd);
        return -1;
    }

    if (-1 == bind(socket_fd, (struct sockaddr *)&addr, sizeof(addr))) 
    {
        VPP_log_error("Bind socket fail. Reason:%s\n", strerror(errno));
        close(socket_fd);
        return -1;
    }

    if( 0 != listen(socket_fd, 1))
    {
        VPP_log_error("listen socket fail. Reason:%s\n", strerror(errno));
        close(socket_fd);
        return -1;
    }

    return socket_fd;
    
}


/*******************************************************************************
 ��������  : format_Time_String
 ��������  : ��ȡ��ǰʱ��
 �������  : clock ��ȡ��ǰʱ������0
 �������  : ptr   ��ȡ�ĵ�ǰʱ���ַ���
 �� �� ֵ  : ��
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ : 
 �޸�����  : 
 �޸�Ŀ��  : ���º���
 �޸�����  : 2016.11.19
*******************************************************************************/
void format_Time_String(char ptr[TIME_STRING_LEN], int clock)
{
    struct tm *timePtr;
    time_t t;

    /*���ʱ���*/
    t = (clock == 0) ? time(NULL) : clock;
    
    /*ʱ��ת��Ϊ�ַ���*/
    timePtr = localtime(&t);
    
    //��ȡ���� ʱ��
    strftime(ptr, TIME_STRING_LEN,"%a, %d %b %Y %T GMT",timePtr);
}

/*******************************************************************************
 ��������  : arp_get_mac
 ��������  : ����ip��arp���л�ȡmac
 �������  : req_ip     Ҫ���ҵ�ip
 �������  : req_mac    Ҫ��ȡ��mac
 �� �� ֵ  : ����-1ʧ�ܣ�����0�ɹ�
--------------------------------------------------------------------------------
 ���һ���޸ļ�¼ : 
 �޸�����  : 
 �޸�Ŀ��  : ���º���
 �޸�����  : 2016.11.19
*******************************************************************************/
#define NOT_MAC_ADDR "00:00:00:00:00:00"
int arp_get_mac(const char req_ip[MAX_IP_LEN], char req_mac[MAX_MAC_ADDR])
{
    FILE *proc;
    char arp_ip[INET6_ADDRSTRLEN];

    memcpy(req_mac, NOT_MAC_ADDR, MAX_MAC_ADDR-1);
    req_mac[MAX_MAC_ADDR-1] = '\0';

    //��ȡarp�������
    if (!(proc = fopen("/proc/net/arp", "r")))
    {
        VPP_log_error("open file /proc/net/arp error\n");
        return -1;
    }

    //����arp��ĵ�һ��
    while (!feof(proc) && fgetc(proc) != '\n');

    //����ip������Ӧ��mac
    while (!feof(proc) && (fscanf(proc, " %15[0-9.] %*s %*s %17[A-Fa-f0-9:] %*s %*s", arp_ip, req_mac) == 2))
    {
        //������ҵ���macΪȫ0��������������һ��
        if( 0 != memcmp(req_mac, NOT_MAC_ADDR, MAX_MAC_ADDR-1))
        {
            //���ip����Ҫ���ҵ�ip������ѭ��
            if ( 0 == strncmp(arp_ip, req_ip, MAX_IP_LEN-1) )
            {
                break;
            }
            else
            {
                //û�л�ȡmac��ַ�����0
                memcpy(req_mac, NOT_MAC_ADDR, MAX_MAC_ADDR-1);
                req_mac[MAX_MAC_ADDR-1] = '\0';
            }
        }
    }
    
    //������ҵ���macΪȫ0�����ش���ֵ
    if( 0 == memcmp(req_mac, NOT_MAC_ADDR, MAX_MAC_ADDR-1))
    {
        fclose(proc);
        return -1;
    }

    fclose(proc);

    return 0;
}



