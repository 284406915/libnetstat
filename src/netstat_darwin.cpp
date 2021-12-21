#include "netstat.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <libproc.h>
#include <sys/socket.h>

#include <set>
#include <vector>
#include <iostream>

void print_node(const info_node &node)
{
    std::cout << node.key << "\t";
    if (node.proto == 6)
    {
        std::cout << "tcp";
        if (node.family == 10)
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
    else if (node.proto == 17)
    {
        std::cout << "udp";
        if (node.family == 10)
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

const char *get_tcp_state(int state)
{
    switch (state)
    {
    case TSI_S_CLOSED:
        return tcp_state[(int)TCP_STATE::TCP_CLOSE];
    case TSI_S_LISTEN:
        return tcp_state[(int)TCP_STATE::TCP_LISTEN];
    case TSI_S_SYN_SENT:
        return tcp_state[(int)TCP_STATE::TCP_SYN_SENT];
    case TSI_S_SYN_RECEIVED:
        return tcp_state[(int)TCP_STATE::TCP_SYN_RECV];
    case TSI_S_ESTABLISHED:
        return tcp_state[(int)TCP_STATE::TCP_ESTABLISHED];
    case TSI_S__CLOSE_WAIT:
        return tcp_state[(int)TCP_STATE::TCP_CLOSE_WAIT];
    case TSI_S_FIN_WAIT_1:
        return tcp_state[(int)TCP_STATE::TCP_FIN_WAIT1];
    case TSI_S_CLOSING:
        return tcp_state[(int)TCP_STATE::TCP_CLOSING];
    case TSI_S_LAST_ACK:
        return tcp_state[(int)TCP_STATE::TCP_LAST_ACK];
    case TSI_S_FIN_WAIT_2:
        return tcp_state[(int)TCP_STATE::TCP_FIN_WAIT2];
    case TSI_S_TIME_WAIT:
        return tcp_state[(int)TCP_STATE::TCP_TIME_WAIT];
    case TSI_S_RESERVED:
        return "RESERVED";
    default:
        return "UNKNOWN";
    }
}

std::set<int> get_proc_list()
{
    std::set<int> pid_list;
    int bufsize = proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0);
    if (bufsize <= 0)
    {
#ifdef DEBUG
        std::cout << "An error occurred retrieving the process list" << std::endl;
#endif
        return pid_list;
    }

    std::vector<pid_t> pids(sizeof(pid_t) * bufsize);
    bufsize = proc_listpids(PROC_ALL_PIDS, 0, pids.data(), sizeof(pid_t) * bufsize);
    if (bufsize <= 0)
    {
#ifdef DEBUG
        std::cout << "An error occurred retrieving the process list" << std::endl;
#endif
        return pid_list;
    }

    size_t num_pids = bufsize / sizeof(pid_t);
    for (size_t i = 0; i < num_pids; ++i)
    {
        if (pids[i] < 0)
        {
            continue;
        }
        pid_list.insert(pids[i]);
    }
    return pid_list;
}

void parse_socket_info(const struct socket_fdinfo &socket_info, info_node &node)
{
    // Set socket protocol.
    const struct in_sockinfo *in = nullptr;
    if (socket_info.psi.soi_kind == SOCKINFO_TCP)
    {
        const struct tcp_sockinfo *tcp_in = &socket_info.psi.soi_proto.pri_tcp;
        in = &tcp_in->tcpsi_ini;
        node.tcp_stat = get_tcp_state(tcp_in->tcpsi_state);
    }
    else
    {
        in = &socket_info.psi.soi_proto.pri_in;
    }

    if (socket_info.psi.soi_family == AF_INET)
    {
        char local[INET_ADDRSTRLEN] = {0};
        char remote[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &(in->insi_laddr.ina_46.i46a_addr4), local, sizeof(local));
        inet_ntop(AF_INET, &(in->insi_faddr.ina_46.i46a_addr4), remote, sizeof(remote));
        node.local_addr = local;
        node.remote_addr = remote;
    }
    else if (socket_info.psi.soi_family == AF_INET6)
    {
        char local[INET6_ADDRSTRLEN] = {0};
        char remote[INET6_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET6, &(in->insi_laddr.ina_6), local, sizeof(local));
        inet_ntop(AF_INET6, &(in->insi_faddr.ina_6), remote, sizeof(remote));
        node.local_addr = local;
        node.remote_addr = remote;
    }

    node.local_port = ntohs(in->insi_lport);
    node.remote_port = ntohs(in->insi_fport);
}

bool need_input(const check_param &param, int family, int kind)
{
    bool ret = false;

    if (param.tcp && family == AF_INET && kind == SOCKINFO_TCP)
    {
        ret = true;
    }

    if (param.udp && family == AF_INET && kind != SOCKINFO_TCP)
    {
        ret = true;
    }

    if (param.tcp6 && family == AF_INET6 && kind == SOCKINFO_TCP)
    {
        ret = true;
    }

    if (param.udp6 && family == AF_INET6 && kind != SOCKINFO_TCP)
    {
        ret = true;
    }

    return ret;
}

void get_socket_descriptor(int pid, int descriptor, netstat_infos &infos, const check_param &param)
{
    struct socket_fdinfo si;
    if (proc_pidfdinfo(pid,
                       descriptor,
                       PROC_PIDFDSOCKETINFO,
                       &si,
                       PROC_PIDFDSOCKETINFO_SIZE) <= 0)
    {
        return;
    }

    if (!need_input(param, si.psi.soi_family, si.psi.soi_kind))
    {
        return;
    }

    if (si.psi.soi_family == AF_INET || si.psi.soi_family == AF_INET6)
    {
        info_node node;
        node.key = pid;

        // Darwin/OSX AF_INET6 == 30
        if (si.psi.soi_family == AF_INET)
        {
            node.family = 2;
        }
        else
        {
            node.family = 10;
        }

        // Darwin/OSX SOCKINFO_TCP is not IPPROTO_TCP
        if (si.psi.soi_kind == SOCKINFO_TCP)
        {
            node.proto = 6;
        }
        else
        {
            node.proto = 17;
        }

        parse_socket_info(si, node);
#ifdef _DEBUG
        print_node(node);
#endif // _DEBUG
        infos.push_back(std::move(node));
    }
}

netstat_infos get_open_sockers(const check_param &param)
{
    netstat_infos infos;
    auto pid_list = get_proc_list();
    for (auto &pid : pid_list)
    {
        int bufsize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, 0, 0);
        if (bufsize == -1)
        {
#ifdef DEBUG
            std::cout << "Could not list descriptors for pid: " << pid << std::endl;
#endif
            continue;
        }

        std::vector<proc_fdinfo> proc_fd_list(bufsize / PROC_PIDLISTFD_SIZE);
        proc_pidinfo(pid, PROC_PIDLISTFDS, 0, proc_fd_list.data(), bufsize);

        for (auto fdinfo : proc_fd_list)
        {
            if (fdinfo.proc_fdtype == PROX_FDTYPE_SOCKET)
            {
                get_socket_descriptor(pid, fdinfo.proc_fd, infos, param);
            }
        }
    }
    return infos;
}

netstat_infos NetStat::GetInfo(const check_param &param)
{
    return get_open_sockers(param);
}