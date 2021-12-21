#pragma once

#include <string>
#include <vector>

enum class IP_TYPE
{
    IPV4 = 1,
    IPV6
};

enum class TCP_STATE
{
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING
};

static const char *tcp_state[] =
{
    "",
    "ESTABLISHED",
    "SYN_SENT",
    "SYN_RECV",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "TIME_WAIT",
    "CLOSE",
    "CLOSE_WAIT",
    "LAST_ACK",
    "LISTEN",
    "CLOSING"
};

struct info_node
{
    std::string local_addr;
    std::string remote_addr;

    int local_port = 0;
    int remote_port = 0;

    IP_TYPE ip_type = IP_TYPE::IPV4;
    int proto = 256;
    std::string tcp_stat;

    int key;
};

struct check_param
{
    bool tcp = true;
    bool tcp6 = true;
    bool udp = true;
    bool udp6 = true;
};

typedef std::vector<info_node> netstat_infos;

class NetStat
{
public:
    netstat_infos GetInfo(const check_param &param);
private:
    void get_tcp_info(netstat_infos &infos);
    void get_tcp6_info(netstat_infos &infos);

    void get_udp_info(netstat_infos &infos);
    void get_udp6_info(netstat_infos &infos);
};

