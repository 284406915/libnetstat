#include "netstat.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>

#include <iostream>

// Need to link with Iphlpapi.lib and Ws2_32.lib
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

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
            std::cout << "\t\t*:*";
        }
        else
        {
            std::cout << "\t" << node.local_addr << ":" << node.local_port;
            std::cout << "\t\t*:*";
        }
    }
    std::cout << std::endl;
}

const char *get_tcp_state(DWORD dwState)
{
    switch (dwState)
    {
    case MIB_TCP_STATE_CLOSED:
        return tcp_state[(int)TCP_STATE::TCP_CLOSE];
    case MIB_TCP_STATE_LISTEN:
        return tcp_state[(int)TCP_STATE::TCP_LISTEN];
    case MIB_TCP_STATE_SYN_SENT:
        return tcp_state[(int)TCP_STATE::TCP_SYN_SENT];
    case MIB_TCP_STATE_SYN_RCVD:
        return tcp_state[(int)TCP_STATE::TCP_SYN_RECV];
    case MIB_TCP_STATE_ESTAB:
        return tcp_state[(int)TCP_STATE::TCP_ESTABLISHED];
    case MIB_TCP_STATE_FIN_WAIT1:
        return tcp_state[(int)TCP_STATE::TCP_FIN_WAIT1];
    case MIB_TCP_STATE_FIN_WAIT2:
        return tcp_state[(int)TCP_STATE::TCP_FIN_WAIT2];
    case MIB_TCP_STATE_CLOSE_WAIT:
        return tcp_state[(int)TCP_STATE::TCP_CLOSE_WAIT];
    case MIB_TCP_STATE_CLOSING:
        return tcp_state[(int)TCP_STATE::TCP_CLOSING];
    case MIB_TCP_STATE_LAST_ACK:
        return tcp_state[(int)TCP_STATE::TCP_LAST_ACK];
    case MIB_TCP_STATE_TIME_WAIT:
        return tcp_state[(int)TCP_STATE::TCP_TIME_WAIT];
    case MIB_TCP_STATE_DELETE_TCB:
        return "DELETE_TCB";
    default:
        return "UNKNOWN";
    }
}

void get_tcp_info(netstat_infos &infos)
{
    do
    {
        PMIB_TCPTABLE2 pTcpTable = NULL;
        ULONG ulSize = 0;
        DWORD dwRetVal = 0;

        // Make an initial call to GetTcpTable2 to get the necessary size into the ulSize variable
        if ((dwRetVal = GetTcpTable2(pTcpTable, &ulSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER)
        {
            pTcpTable = (MIB_TCPTABLE2 *)MALLOC(ulSize);
            if (pTcpTable == NULL)
            {
                break;
            }
        }
        else
        {
            break;
        }

        // Make a second call to GetTcpTable2 to get the actual data we require
        if ((dwRetVal = GetTcpTable2(pTcpTable, &ulSize, TRUE)) == NO_ERROR)
        {
            for (int i = 0; i < (int)pTcpTable->dwNumEntries; i++)
            {
                info_node node;
                // local_addr
                char temp_addr_local[16] = {0}; // 16
                IN_ADDR local_addr;
                local_addr.S_un.S_addr = pTcpTable->table[i].dwLocalAddr;
                inet_ntop(AF_INET, &local_addr, temp_addr_local, 16);
                node.local_addr = temp_addr_local;
                // local_port
                node.local_port = ntohs((USHORT)pTcpTable->table[i].dwLocalPort);
                // remote_addr
                char temp_addr_remote[16] = {0};
                IN_ADDR remote_addr;
                remote_addr.S_un.S_addr = pTcpTable->table[i].dwRemoteAddr;
                inet_ntop(AF_INET, &remote_addr, temp_addr_remote, 16);
                node.remote_addr = temp_addr_remote;
                // remote_port
                node.remote_port = ntohs((USHORT)pTcpTable->table[i].dwRemotePort);
                // pid
                node.key = pTcpTable->table[i].dwOwningPid;

                // protocol
                node.family = AF_INET;
                node.proto = IPPROTO_TCP;
                node.tcp_stat = get_tcp_state(pTcpTable->table[i].dwState);

#ifdef _DEBUG
                print_node(node);
#endif // _DEBUG
                infos.push_back(std::move(node));
            }
        }
        FREE(pTcpTable);
    } while (false);
}

void get_tcp6_info(netstat_infos &infos)
{
    do
    {
        PMIB_TCP6TABLE2 pTcpTable = NULL;
        ULONG ulSize = 0;
        DWORD dwRetVal = 0;

        // Make an initial call to GetTcpTable2 to get the necessary size into the ulSize variable
        if ((dwRetVal = GetTcp6Table2(pTcpTable, &ulSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER)
        {
            pTcpTable = (MIB_TCP6TABLE2 *)MALLOC(ulSize);
            if (pTcpTable == NULL)
            {
                break;
            }
        }
        else
        {
            break;
        }

        // Make a second call to GetTcpTable2 to get the actual data we require
        if ((dwRetVal = GetTcp6Table2(pTcpTable, &ulSize, TRUE)) == NO_ERROR)
        {
            for (int i = 0; i < (int)pTcpTable->dwNumEntries; i++)
            {
                info_node node;
                // local_addr
                char temp_addr_local[46] = {0}; // 46
                // RtlIpv6AddressToStringA(&pTcpTable->table[i].LocalAddr, temp_addr_local);
                inet_ntop(AF_INET6, &pTcpTable->table[i].LocalAddr, temp_addr_local, 46);
                node.local_addr = temp_addr_local;
                // local_port
                node.local_port = ntohs((USHORT)pTcpTable->table[i].dwLocalPort);
                // remote_addr
                char temp_addr_remote[46] = {0};
                // RtlIpv6AddressToStringA(&pTcpTable->table[i].RemoteAddr, temp_addr_remote);
                inet_ntop(AF_INET6, &pTcpTable->table[i].RemoteAddr, temp_addr_remote, 46);
                node.remote_addr = temp_addr_remote;
                // remote_port
                node.remote_port = ntohs((USHORT)pTcpTable->table[i].dwRemotePort);
                // pid
                node.key = pTcpTable->table[i].dwOwningPid;

                // protocol
                node.family = AF_INET6;
                node.proto = IPPROTO_TCP;
                node.tcp_stat = get_tcp_state(pTcpTable->table[i].State);

#ifdef _DEBUG
                print_node(node);
#endif // _DEBUG
                infos.push_back(std::move(node));
            }
        }
        FREE(pTcpTable);
    } while (false);
}

void get_udp_info(netstat_infos &infos)
{
    MIB_UDPTABLE_OWNER_PID *pUdpTable = NULL;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;

    do
    {
        if (dwRetVal = GetExtendedUdpTable(NULL, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, NULL) == ERROR_INSUFFICIENT_BUFFER)
        {
            pUdpTable = (MIB_UDPTABLE_OWNER_PID *)MALLOC(dwSize);
            if (pUdpTable == NULL)
            {
                break;
            }
        }
        else
        {
            break;
        }

        if (dwRetVal = GetExtendedUdpTable(pUdpTable, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, NULL) == NO_ERROR)
        {
            for (DWORD i = 0; i < pUdpTable->dwNumEntries; i++)
            {
                info_node node;
                // local_addr
                char temp_addr_local[16] = {0}; // 16
                IN_ADDR local_addr;
                local_addr.S_un.S_addr = pUdpTable->table[i].dwLocalAddr;
                inet_ntop(AF_INET, &local_addr, temp_addr_local, 16);
                node.local_addr = temp_addr_local;
                // local_port
                node.local_port = ntohs((USHORT)pUdpTable->table[i].dwLocalPort);
                // pid
                node.key = pUdpTable->table[i].dwOwningPid;

                // protocol
                node.family = AF_INET;
                node.proto = IPPROTO_UDP;

#ifdef _DEBUG
                print_node(node);
#endif // _DEBUG
                infos.push_back(std::move(node));
            }
        }
        FREE(pUdpTable);
    } while (false);
}

void get_udp6_info(netstat_infos &infos)
{
    MIB_UDP6TABLE_OWNER_PID *pUdpTable = NULL;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;

    do
    {
        if (dwRetVal = GetExtendedUdpTable(NULL, &dwSize, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, NULL) == ERROR_INSUFFICIENT_BUFFER)
        {
            pUdpTable = (MIB_UDP6TABLE_OWNER_PID *)MALLOC(dwSize);
            if (pUdpTable == NULL)
            {
                break;
            }
        }
        else
        {
            break;
        }

        if (dwRetVal = GetExtendedUdpTable(pUdpTable, &dwSize, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, NULL) == NO_ERROR)
        {
            for (DWORD i = 0; i < pUdpTable->dwNumEntries; i++)
            {
                info_node node;
                // local_addr
                char temp_addr_local[46] = {0}; // 46
                inet_ntop(AF_INET6, &pUdpTable->table[i].ucLocalAddr, temp_addr_local, 46);
                node.local_addr = temp_addr_local;
                // local_port
                node.local_port = ntohs((USHORT)pUdpTable->table[i].dwLocalPort);
                // pid
                node.key = pUdpTable->table[i].dwOwningPid;

                // protocol
                node.family = AF_INET6;
                node.proto = IPPROTO_UDP;

#ifdef _DEBUG
                print_node(node);
#endif // _DEBUG
                infos.push_back(std::move(node));
            }
        }
        FREE(pUdpTable);
    } while (false);
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