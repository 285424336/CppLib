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
#include <string.h>
#else
#error unsupported compiler
#endif
#include <set>
#include <string>
#include <vector>

class NetworkHelper
{
public:
    /**
    *change the addr string to addr, can only change ipv4
    *addr(in): addr string
    *return ipv4 addr
    */
    static in_addr IPStr2Addr(const std::string &addr);
    /**
    *change the addr to addr string, can only change ipv4
    *addr(in): addr
    *return ipv4 addr string
    */
    static std::string IPAddr2Str(const in_addr &addr);
    /**
    *change the addr string to addr, can only change ipv6
    *addr(in): addr string
    *return ipv6 addr
    */
    static in6_addr IPStr2AddrV6(const std::string &addr);
    /**
    *change the addr to addr string, can only change ipv6
    *addr(in): addr
    *return ipv6 addr string
    */
    static std::string IPAddr2StrV6(const in6_addr &addr);
    /**
    *change the addr to addr string, can only change ipv4
    *addr(in): addr
    *return ipv4 addr string
    */
    static std::string IPAddr2Str(const u_int &addr);
    /**
    *is empty mac
    *mac(in): pointer to mac, must be sizeof 6
    */
    static bool IsValidMac(const char *mac);
    /**
    *is zero ip
    *ip(in): ipv4
    */
    static bool IsValidIp(const u_int &ip);
    /**
    *is zero ip
    *ip(in): ipv4
    */
    static bool IsValidIp(const in_addr &ip);
    /**
    *is zero ip
    *ip(in): ipv6
    */
    static bool IsValidIp(const in6_addr &ip);
    /**
    *is zero ip
    *ip(in): ipv4 or ipv6
    */
    static bool IsValidIp(const sockaddr &ip);
    /**
    *get all the device ips in current network
    *int_eth_ip(in): ip addr, can be any ip in current network, mostly is gateway or local ip
    *int_net_mask(in): network net mask
    *return all device ips in current network
    */
    static std::set<std::string> GetNetIPs(const in_addr &int_eth_ip, const in_addr &int_net_mask);
    /**
    *get all the device ips in current network
    *int_eth_ip(in): ip addr, can be any ip in current network, mostly is gateway or local ip
    *int_net_mask(in): network net mask
    *return all device ips in current network
    */
    static std::set<u_int> GetNetIPs(const u_int &int_eth_ip, const u_int &int_net_mask);
    /**
    *get the host addr of the name specify
    *name(in): host name
    *return a list of addr of the host, if name is a addr then the addr will be return, can only support ipv4
    */
    static std::vector<int> ResolveName(const std::string &name);
    /**
    *get the host name of the addr specify
    *addr(in): host addr
    *return the host name of the addr
    */
    static std::string ResolveAddr(int addr);
#if defined(_MSC_VER)
    /**
    *get the host name of the addr specify
    *addr(in): host addr
    *return the host name of the addr
    */
    static std::wstring ResolveAddrW(int addr);
#endif
    /**
    *computer the check sum of TCP or UDP packet
    *src(in): src addr
    *dst(in): dst addr
    *is_tcp(in): is tcp packet
    *buf(in): tcp or udp data
    *len(in): buf len
    *return check sum result
    */
    static u_short ComputerTcpOUdpSum(const struct in_addr &src, const struct in_addr &dst, bool is_tcp, const void *buf, u_short len);
};
#endif