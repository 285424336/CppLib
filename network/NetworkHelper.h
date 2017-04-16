#ifndef NETWORK_HELPER_H_INCLUDED
#define NETWORK_HELPER_H_INCLUDED

#if defined(_MSC_VER)
#include <WS2tcpip.h>
#include <algorithm\AlgorithmHelper.h>
#elif defined(__GNUC__)
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <algorithm/AlgorithmHelper.h>
#else
#error unsupported compiler
#endif
#include <set>
#include <string>

class NetworkHelper
{
public:
    static in_addr IPStr2Addr(const std::string &addr);
    static std::string IPAddr2Str(const in_addr &addr);
    static std::string IPAddr2Str(const u_int &addr);
    static std::set<std::string> GetNetIPs(const in_addr &int_eth_ip, const in_addr &int_net_mask);
    static std::set<u_int> GetNetIPs(const u_int &int_eth_ip, const u_int &int_net_mask);
};
#endif