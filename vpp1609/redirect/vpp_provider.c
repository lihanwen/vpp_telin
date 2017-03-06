/*******************************************************************************
 Copyright (C) 2015 Technologies Co.,Ltd. All Rights Reserved.
--------------------------------------------------------------------------------
 文件名称: ac_provider.c 
 功能描述: 
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


/* 父程序记录子程序pid, 子程序为 0 */
pid_t AC_g_pid;

/*******************************************************************************
 函数名称  : Vpp_daemonize
 功能描述  : 变为daemon模式，如果出故障则自动重启
 输入参数  : 无
 输出参数  : 无
 返 回 值  : 0      --成功
             非0    --失败
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 2016.4.5
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
    //主进程写在第一个
    fp = fopen(AC_PID_FILE, "w");
    if (fp != NULL)
    {
        //当前进程的进程号写入fd
        fprintf(fp, "%d", getpid());
        fclose(fp);
    }
    //父子进程分离，不在同一组，这样父进程死了不会影响子进程
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
    //保证一直有个daemon程序运行
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
            
            //父程序等子程序终止后重新fork，继续派生子程序
            wait(NULL);

            //延迟5秒钟，等子进程退干净
            sleep(5);
            
            g_ac_debug++;
            VPP_DEBUG("Fork new process........\n");
            continue;
        }
        //子程序作为daemon程序继续运行
        break; 
    }

    /* 子进程 pid 清零 */
    AC_g_pid = 0;
    
    /*write child pid into file*/
    //子进程每次附加在后面
    fp = fopen(AC_PID_FILE, "a");
    if (fp != NULL)
    {
        fprintf(fp, " %d", getpid());
        fclose(fp);
    }
    
    /*change the current working directory to the root so we won't
    prevent file systems form being ummounted.*/
    //chdir()用来将当前的工作目录改变成以参数path 所指的目录.
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
 函数名称  : Vpp_init
 功能描述  : vpp初始化
 输入参数  : 无
 输出参数  : 无
 返 回 值  : 0 成功 -1 失败
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 2016.12.24
*******************************************************************************/
int Vpp_init()
{
	link_head_init();
	link_user_head_init();
    return 0;
}

/*******************************************************************************
 函数名称  : vpp_make_local_server_fd
 功能描述  : 生成服务器端本地socket，用于接收web的数据
 输入参数  : socket_file 要监听的文件
 输出参数  : 无
 返 回 值  : socket     成功
             -1         失败
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 2016.4.5
*******************************************************************************/
int vpp_make_local_server_fd(char *socket_file)
{
    int val;
    int server_sock;
    //删除这个文件
    unlink(socket_file);

    //创建套接字
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
    //允许重用本地地址和端口
    if(setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) 
    {    
        close(server_sock);
        return -1;
    }
    //绑定端口
    if(-1 == bind(server_sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_un))) 
    {    
        VPP_DEBUG("Bind socket fail. Reason:%s\n", strerror(errno));
        close(server_sock);
        return -1;
    }

    return server_sock;  
}

/*******************************************************************************
 函数名称  : vpp_make_listen_tcp_fd
 功能描述  : 生成tcp的socket
 输入参数  : port  监听的端口号 网络序
             eth_addr  要监听的网卡的ip地址 主机序
 输出参数  : 无
 返 回 值  : socket     成功
             -1         失败
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 2016.11.22
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
 函数名称  : format_Time_String
 功能描述  : 获取当前时间
 输入参数  : clock 获取当前时间是填0
 输出参数  : ptr   获取的当前时间字符串
 返 回 值  : 无
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 2016.11.19
*******************************************************************************/
void format_Time_String(char ptr[TIME_STRING_LEN], int clock)
{
    struct tm *timePtr;
    time_t t;

    /*获得时间戳*/
    t = (clock == 0) ? time(NULL) : clock;
    
    /*时间转化为字符串*/
    timePtr = localtime(&t);
    
    //获取日期 时间
    strftime(ptr, TIME_STRING_LEN,"%a, %d %b %Y %T GMT",timePtr);
}

/*******************************************************************************
 函数名称  : arp_get_mac
 功能描述  : 根据ip在arp表中获取mac
 输入参数  : req_ip     要查找的ip
 输出参数  : req_mac    要获取的mac
 返 回 值  : 返回-1失败，返回0成功
--------------------------------------------------------------------------------
 最近一次修改记录 : 
 修改作者  : 
 修改目的  : 增新函数
 修改日期  : 2016.11.19
*******************************************************************************/
#define NOT_MAC_ADDR "00:00:00:00:00:00"
int arp_get_mac(const char req_ip[MAX_IP_LEN], char req_mac[MAX_MAC_ADDR])
{
    FILE *proc;
    char arp_ip[INET6_ADDRSTRLEN];

    memcpy(req_mac, NOT_MAC_ADDR, MAX_MAC_ADDR-1);
    req_mac[MAX_MAC_ADDR-1] = '\0';

    //获取arp表的内容
    if (!(proc = fopen("/proc/net/arp", "r")))
    {
        VPP_log_error("open file /proc/net/arp error\n");
        return -1;
    }

    //跳过arp表的第一行
    while (!feof(proc) && fgetc(proc) != '\n');

    //根据ip查找相应的mac
    while (!feof(proc) && (fscanf(proc, " %15[0-9.] %*s %*s %17[A-Fa-f0-9:] %*s %*s", arp_ip, req_mac) == 2))
    {
        //如果查找到的mac为全0，跳过，查找下一个
        if( 0 != memcmp(req_mac, NOT_MAC_ADDR, MAX_MAC_ADDR-1))
        {
            //如果ip就是要查找的ip，跳出循环
            if ( 0 == strncmp(arp_ip, req_ip, MAX_IP_LEN-1) )
            {
                break;
            }
            else
            {
                //没有获取mac地址，填充0
                memcpy(req_mac, NOT_MAC_ADDR, MAX_MAC_ADDR-1);
                req_mac[MAX_MAC_ADDR-1] = '\0';
            }
        }
    }
    
    //如果查找到的mac为全0，返回错误值
    if( 0 == memcmp(req_mac, NOT_MAC_ADDR, MAX_MAC_ADDR-1))
    {
        fclose(proc);
        return -1;
    }

    fclose(proc);

    return 0;
}



