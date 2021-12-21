#include "netstat.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <iostream>

#define _PATH_PROCNET_TCP "/proc/net/tcp"
#define _PATH_PROCNET_TCP6 "/proc/net/tcp6"
#define _PATH_PROCNET_UDP "/proc/net/udp"
#define _PATH_PROCNET_UDP6 "/proc/net/udp6"

void print_node(const info_node &node)
{
    std::cout << node.key << "\t";
    if (node.proto == IPPROTO_TCP)
    {
        std::cout << "tcp";
        if (node.family == AF_INET6)
        {
            std::cout << "6";
            std::cout << "\t[" << node.local_addr << "]:" << node.local_port;
            std::cout << "\t\t[" << node.remote_addr << "]:" << node.remote_port;
        }
        else
        {
            std::cout << "\t" << node.local_addr << ":" << node.local_port;
            std::cout << "\t\t" << node.remote_addr << ":" << node.remote_port;
        }

        std::cout << "\t\t" << node.tcp_stat;
    }
    else if (node.proto == IPPROTO_UDP)
    {
        std::cout << "udp";
        if (node.family == AF_INET6)
        {
            std::cout << "6";
            std::cout << "\t[" << node.local_addr << "]:" << node.local_port;
            std::cout << "\t\t[" << node.remote_addr << "]:" << node.remote_port;
        }
        else
        {
            std::cout << "\t" << node.local_addr << ":" << node.local_port;
            std::cout << "\t\t[" << node.remote_addr << "]:" << node.remote_port;
        }
    }
    std::cout << std::endl;
}

FILE *proc_fopen(const char *name)
{
    static char *buffer = NULL;
    static size_t pagesz = 0;
    FILE *fd = fopen(name, "r");

    if (fd == NULL)
        return NULL;

    if (!buffer)
    {
        pagesz = getpagesize();
        buffer = (char *)malloc(pagesz);
    }

    setvbuf(fd, buffer, _IOFBF, pagesz);
    return fd;
}

const char *get_udp_state(int state)
{
    switch ((TCP_STATE)state)
    {
    case TCP_STATE::TCP_ESTABLISHED:
        return "ESTABLISHED";
    case TCP_STATE::TCP_CLOSE:
        return "";
    default:
        return "UNKNOWN";
    }
}

void get_tcp_info(netstat_infos &infos)
{
    char buffer[8192] = {0};
    FILE *procinfo = proc_fopen(_PATH_PROCNET_TCP);
    if (procinfo == NULL)
    {
        return;
    }
    else
    {
        int line_num = 0;
        do
        {
            if (fgets(buffer, sizeof(buffer), procinfo))
            {
                if (line_num++ == 0)
                {
                    continue;
                }
                unsigned long rxq, txq, time_len, retr, inode;
                int num, local_port, remote_port, d, state, uid, timer_run, timeout;
                char remote_addr[128] = {0};
                char local_addr[128] = {0};

                num = sscanf(buffer,
                             "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %*s\n",
                             &d, local_addr, &local_port, remote_addr, &remote_port, &state,
                             &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode);

                if (num < 11)
                {
                    continue;
                }

                info_node node;
                struct in_addr localaddr;
                struct in_addr remaddr;
                sscanf(local_addr, "%X", &localaddr.s_addr);
                sscanf(remote_addr, "%X", &remaddr.s_addr);
                inet_ntop(AF_INET, &localaddr, local_addr, sizeof(local_addr));
                inet_ntop(AF_INET, &remaddr, remote_addr, sizeof(remote_addr));
                node.local_addr = local_addr;
                node.remote_addr = remote_addr;

                node.local_port = local_port;
                node.remote_port = remote_port;

                node.key = inode;
                node.family = AF_INET;
                node.proto = IPPROTO_TCP;
                node.tcp_stat = tcp_state[state];

#ifdef DEBUG
                print_node(node);
#endif // DEBUG
                infos.push_back(std::move(node));
            }
        } while (!feof(procinfo));
        fclose(procinfo);
    }
}

void get_tcp6_info(netstat_infos &infos)
{
    char buffer[8192] = {0};
    FILE *procinfo = proc_fopen(_PATH_PROCNET_TCP6);
    if (procinfo == NULL)
    {
        return;
    }
    else
    {
        int line_num = 0;
        do
        {
            if (fgets(buffer, sizeof(buffer), procinfo))
            {
                if (line_num++ == 0)
                {
                    continue;
                }
                unsigned long rxq, txq, time_len, retr, inode;
                int num, local_port, remote_port, d, state, uid, timer_run, timeout;
                char remote_addr[128] = {0};
                char local_addr[128] = {0};

                num = sscanf(buffer,
                             "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %*s\n",
                             &d, local_addr, &local_port, remote_addr, &remote_port, &state,
                             &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode);

                if (num < 11)
                {
                    continue;
                }

                info_node node;
                struct in6_addr localaddr;
                struct in6_addr remaddr;
                sscanf(local_addr, "%08X%08X%08X%08X",
                       &localaddr.s6_addr32[0], &localaddr.s6_addr32[1],
                       &localaddr.s6_addr32[2], &localaddr.s6_addr32[3]);
                sscanf(remote_addr, "%08X%08X%08X%08X",
                       &remaddr.s6_addr32[0], &remaddr.s6_addr32[1],
                       &remaddr.s6_addr32[2], &remaddr.s6_addr32[3]);
                inet_ntop(AF_INET6, &localaddr, local_addr, sizeof(local_addr));
                inet_ntop(AF_INET6, &remaddr, remote_addr, sizeof(remote_addr));
                node.local_addr = local_addr;
                node.remote_addr = remote_addr;

                node.local_port = local_port;
                node.remote_port = remote_port;

                node.key = inode;
                node.family = AF_INET6;
                node.proto = IPPROTO_TCP;
                node.tcp_stat = tcp_state[state];

#ifdef DEBUG
                print_node(node);
#endif // DEBUG
                infos.push_back(std::move(node));
            }
        } while (!feof(procinfo));
        fclose(procinfo);
    }
}

void get_udp_info(netstat_infos &infos)
{
    char buffer[8192] = {0};
    FILE *procinfo = proc_fopen(_PATH_PROCNET_UDP);
    if (procinfo == NULL)
    {
        return;
    }
    else
    {
        int line_num = 0;
        do
        {
            if (fgets(buffer, sizeof(buffer), procinfo))
            {
                if (line_num++ == 0)
                {
                    continue;
                }

                int num, local_port, remote_port, d, state, timer_run, uid, timeout;
                unsigned long rxq, txq, time_len, retr, inode;
                char remote_addr[128] = {0};
                char local_addr[128] = {0};

                num = sscanf(buffer,
                             "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %*s\n",
                             &d, local_addr, &local_port,
                             remote_addr, &remote_port, &state,
                             &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode);

                if (num < 10)
                {
                    continue;
                }

                info_node node;
                struct in_addr localaddr;
                struct in_addr remaddr;
                sscanf(local_addr, "%X", &localaddr.s_addr);
                sscanf(remote_addr, "%X", &remaddr.s_addr);
                inet_ntop(AF_INET, &localaddr, local_addr, sizeof(local_addr));
                inet_ntop(AF_INET, &remaddr, remote_addr, sizeof(remote_addr));
                node.local_addr = local_addr;
                node.remote_addr = remote_addr;

                node.local_port = local_port;
                node.remote_port = remote_port;

                node.key = inode;
                node.family = AF_INET;
                node.proto = IPPROTO_UDP;
                node.udp_stat = get_udp_state(state);

#ifdef DEBUG
                print_node(node);
#endif // DEBUG
                infos.push_back(std::move(node));
            }
        } while (!feof(procinfo));
        fclose(procinfo);
    }
}

void get_udp6_info(netstat_infos &infos)
{
    char buffer[8192] = {0};
    FILE *procinfo = proc_fopen(_PATH_PROCNET_UDP6);
    if (procinfo == NULL)
    {
        return;
    }
    else
    {
        int line_num = 0;
        do
        {
            if (fgets(buffer, sizeof(buffer), procinfo))
            {
                if (line_num++ == 0)
                {
                    continue;
                }

                int num, local_port, remote_port, d, state, timer_run, uid, timeout;
                unsigned long rxq, txq, time_len, retr, inode;
                char remote_addr[128] = {0};
                char local_addr[128] = {0};

                num = sscanf(buffer,
                             "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %*s\n",
                             &d, local_addr, &local_port,
                             remote_addr, &remote_port, &state,
                             &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode);

                if (num < 10)
                {
                    continue;
                }

                info_node node;
                struct in6_addr localaddr;
                struct in6_addr remaddr;
                sscanf(local_addr, "%08X%08X%08X%08X",
                       &localaddr.s6_addr32[0], &localaddr.s6_addr32[1],
                       &localaddr.s6_addr32[2], &localaddr.s6_addr32[3]);
                sscanf(remote_addr, "%08X%08X%08X%08X",
                       &remaddr.s6_addr32[0], &remaddr.s6_addr32[1],
                       &remaddr.s6_addr32[2], &remaddr.s6_addr32[3]);
                inet_ntop(AF_INET6, &localaddr, local_addr, sizeof(local_addr));
                inet_ntop(AF_INET6, &remaddr, remote_addr, sizeof(remote_addr));
                node.local_addr = local_addr;
                node.remote_addr = remote_addr;

                node.local_port = local_port;
                node.remote_port = remote_port;

                node.key = inode;
                node.family = AF_INET6;
                node.proto = IPPROTO_UDP;
                node.udp_stat = get_udp_state(state);

#ifdef DEBUG
                print_node(node);
#endif // DEBUG
                infos.push_back(std::move(node));
            }
        } while (!feof(procinfo));
        fclose(procinfo);
    }
}

netstat_infos NetStat::GetInfo(const check_param &param)
{
    netstat_infos infos;

    if (param.tcp)
    {
        get_tcp_info(infos);
    }

    if (param.tcp6)
    {
        get_tcp6_info(infos);
    }

    if (param.udp)
    {
        get_udp_info(infos);
    }

    if (param.udp6)
    {
        get_udp6_info(infos);
    }

    return infos;
}