#if defined(_MSC_VER)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <atlbase.h>
#include <ImageHlp.h>
#include <wlanapi.h>
#include <netlistmgr.h>
#include <pugixml\pugixml.hpp>
#include <string\StringHelper.h>
#include <uid\UidHelper.h>
#include <algorithm\AlgorithmHelper.h>
#include <socket\protocal\ICMPHelper.h>
#pragma comment(lib, "ImageHlp.lib")
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "oleaut32.lib")
#elif defined(__GNUC__)
#include <unistd.h>
#include <linux/filter.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>
#include <string/StringHelper.h>
#include <kernel32/Kernel32Helper.h>
#include <sys/time.h>
#include <string.h>
#include <net/route.h>
#include <algorithm/AlgorithmHelper.h>
#include <ifaddrs.h>
#else
#error unsupported compiler
#endif
#include "ArpTableHelper.h"
#include "NetworkInfoHelper.h"

std::mutex NetworkInfoHelper::m_netowrk_info_lock;

NetworkInfoHelper& NetworkInfoHelper::GetInstance()
{
    static NetworkInfoHelper instance;
    return instance;
}

u_int NetworkInfoHelper::GetAllNetworkInfo(NetworkInfo *infos, u_int count, bool need_gateway_mac)
{
    AdaptInfo *adapt_infos = NULL;
    u_int adapt_count = 0;
    adapt_count = GetAllAdaptInfo(adapt_infos, 0, need_gateway_mac);
    if (infos == NULL) return adapt_count;
    WifiInfo *wifi_infos = NULL;
    u_int wifi_count = 0;
    wifi_count = GetAllWifiInfo(NULL, wifi_count);
    u_int valid_count = 0;
    do
    {
        if (adapt_count)
        {
            adapt_infos = new (std::nothrow) AdaptInfo[adapt_count];
            if (adapt_infos == NULL) break;
            adapt_count = GetAllAdaptInfo(adapt_infos, adapt_count, need_gateway_mac);
        }

        if (wifi_count)
        {
            wifi_infos = new (std::nothrow) WifiInfo[wifi_count];
            if (wifi_infos == NULL) break;
            wifi_count = GetAllWifiInfo(wifi_infos, wifi_count);
        }

        for (u_int i = 0; i < adapt_count; i++)
        {
            valid_count++;
            if (valid_count > count) break;
            NetworkInfo *info = &infos[valid_count - 1];
            AdaptInfo *adapt_info = &adapt_infos[i];
            WifiInfo  *wifi_info = NULL;
            for (u_int j = 0; j < wifi_count; j++)
            {
                WifiInfo  *tmp_wifi_info = &wifi_infos[j];
#if defined(_MSC_VER)
                if (("{" + tmp_wifi_info->adapter_name + "}") == adapt_info->adapter_name)
                {
                    wifi_info = tmp_wifi_info;
                    break;
                }
#elif defined(__GNUC__)
                if (tmp_wifi_info->adapter_name == adapt_info->adapter_name)
                {
                    wifi_info = tmp_wifi_info;
                    break;
                }
#else
#error unsupported compiler
#endif
            }
            info->adapt_info = *adapt_info;
            if (wifi_info)
            {
                info->is_wifi = true;
                info->wifi_info = *wifi_info;
            }
            info->category_info = GetCategoryInfo(info->adapt_info.guid);
        }

    } while (0);
    if (wifi_infos)
    {
        delete[]wifi_infos;
        wifi_infos = NULL;
    }
    if (adapt_infos)
    {
        delete[]adapt_infos;
        adapt_infos = NULL;
    }
    return valid_count;
}

std::string NetworkInfoHelper::GetMacFromAddress(const std::string& _ip, u_int timeout, int eth_index, const std::string& src_ip)
{
    std::string ret = "";

    if (_ip.empty()) return ret;

    unsigned char mac[6] = { 0 };
    in_addr addr;
    addr.s_addr = NetworkHelper::IPStr2Addr(_ip).s_addr;
    in_addr src_addr = { 0 };
    if (!src_ip.empty())
    {
        src_addr.s_addr = NetworkHelper::IPStr2Addr(src_ip).s_addr;
    }
    u_long Len = sizeof(mac);
#if defined(_MSC_VER)
    u_int RetD = SendARP(addr.s_addr, src_addr.s_addr, mac, &Len);
#elif defined(__GNUC__)
    u_int RetD = SendARP(addr.s_addr, src_addr.s_addr, mac, &Len, timeout);
#else
#error unsupported compiler
#endif
    if (RetD == 0 && Len == 6)
    {
        ret = StringHelper::byte2basestr((u_char *)mac, 6, NETWORK_INFO_MAC_SPLITE, StringHelper::hex, 2);
    }

    do
    {
        if (!ret.empty())
        {
            break;
        }

        if (eth_index == -1)
        {
            eth_index = GetEthIndexFromAddress(addr);
        }
        if (eth_index == -1)
        {
            break;
        }
        auto table = ArpTableHelper::GetArpTable(eth_index);
        if (table.find(_ip) != table.end())
        {
            ret = table[_ip];
        }
    } while (0);

    return ret;
}

std::string NetworkInfoHelper::GetMacFromAddress(const in_addr & _ip, u_int timeout, int eth_index, const in_addr& src_ip)
{
    std::string ret = "";

    if (!_ip.s_addr) return ret;

    unsigned char mac[6] = { 0 };
    u_long Len = sizeof(mac);
#if defined(_MSC_VER)
    u_int RetD = SendARP(_ip.s_addr, src_ip.s_addr, mac, &Len);
#elif defined(__GNUC__)
    u_int RetD = SendARP(_ip.s_addr, src_ip.s_addr, mac, &Len, timeout);
#else
#error unsupported compiler
#endif
    if (RetD == 0 && Len == 6)
    {
        ret = StringHelper::byte2basestr((u_char *)mac, 6, NETWORK_INFO_MAC_SPLITE, StringHelper::hex, 2);
    }

    do
    {
        if (!ret.empty())
        {
            break;
        }
        if (eth_index == -1)
        {
            eth_index = GetEthIndexFromAddress(_ip);
        }
        if (eth_index == -1)
        {
            break;
        }
        auto table = ArpTableHelper::GetArpTable(eth_index);
        std::string ip_str = NetworkHelper::IPAddr2Str(_ip);
        if (ip_str.empty())
        {
            break;
        }
        if (table.find(ip_str) != table.end())
        {
            ret = table[ip_str];
        }
    } while (0);
    return ret;
}

int NetworkInfoHelper::GetEthIndexFromAddress(const std::string& ip)
{

    if (ip.empty())
    {
        return -1;
    }

    return GetEthIndexFromAddress(NetworkHelper::IPStr2Addr(ip));
}

int NetworkInfoHelper::GetEthIndexFromAddress(const in_addr& _ip)
{
    if (!_ip.s_addr)
    {
        return -1;
    }

    AdaptInfo *adapt_infos = NULL;
    u_int adapt_count = GetAllAdaptInfo(adapt_infos, 0, false);
    if (adapt_count == 0)
    {
        return -1;
    }

    adapt_infos = new (std::nothrow) AdaptInfo[adapt_count];
    if (adapt_infos == NULL)
    {
        return -1;
    }

    adapt_count = GetAllAdaptInfo(adapt_infos, adapt_count, false);
    int eth_index = -1;
    for (unsigned int i = 0; i < adapt_count; i++)
    {
        if ((adapt_infos[i].local_ip_address_int.s_addr & adapt_infos[i].subnet_ip_mask_int.s_addr)
            == (_ip.s_addr & adapt_infos[i].subnet_ip_mask_int.s_addr))
        {
            eth_index = adapt_infos[i].index;
        }
    }

    if (adapt_infos)
    {
        delete[]adapt_infos;
        adapt_infos = NULL;
    }
    return eth_index;
}

u_int NetworkInfoHelper::GetAllRouteInfo(RouteInfo *info, u_int size)
{
    u_int valid_size = 0;

#if defined(_MSC_VER)
    ULONG len;
    u_int ret;
    MIB_IPFORWARDTABLE *ipftable = NULL;

    for (len = sizeof(ipftable[0]); ; ) {
        if (ipftable) {
            free(ipftable);
        }
        ipftable = (MIB_IPFORWARDTABLE *)malloc(len);
        if (ipftable == NULL) {
            return 0;
        }
        ret = GetIpForwardTable(ipftable, &len, FALSE);
        if (ret == NO_ERROR) {
            break;
        }
        else if (ret != ERROR_INSUFFICIENT_BUFFER) {
            return 0;
        }
    }

    if (info == NULL) {
        u_int count = ipftable->dwNumEntries;
        free(ipftable);
        return count;
    }

    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    do
    {
        ULONG ulLen = 0;
        ::GetAdaptersInfo(pAdapterInfo, &ulLen);
        pAdapterInfo = (PIP_ADAPTER_INFO)::GlobalAlloc(GPTR, ulLen);
        if (pAdapterInfo == NULL) {
            break;
        }
        if (::GetAdaptersInfo(pAdapterInfo, &ulLen) != ERROR_SUCCESS)
        {
            ::GlobalFree(pAdapterInfo);
            pAdapterInfo = NULL;
            break;
        }
    } while (0);

    for (valid_size = 0; valid_size<(u_int)ipftable->dwNumEntries && valid_size<size; valid_size++) {
        info[valid_size].dstAddr = ipftable->table[valid_size].dwForwardDest;
        info[valid_size].dstmask = ipftable->table[valid_size].dwForwardMask;
        if (ipftable->table[valid_size].ForwardType == MIB_IPROUTE_TYPE_INDIRECT) {
            info[valid_size].gateWay = ipftable->table[valid_size].dwForwardNextHop;
        }
        else if (ipftable->table[valid_size].ForwardType == MIB_IPROUTE_TYPE_DIRECT) {
            info[valid_size].srcAddr = ipftable->table[valid_size].dwForwardNextHop;
        }
        info[valid_size].metric = ipftable->table[valid_size].dwForwardMetric1;
        info[valid_size].index = ipftable->table[valid_size].dwForwardIfIndex;
        if (!info[valid_size].srcAddr && pAdapterInfo != NULL) {

            PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
            while (pAdapter != NULL)
            {
                DWORD dwGatewayIP = NetworkHelper::IPStr2Addr(pAdapter->GatewayList.IpAddress.String).s_addr;
                DWORD dwLocalIP = NetworkHelper::IPStr2Addr(pAdapter->IpAddressList.IpAddress.String).s_addr;
                DWORD dwIPMask = NetworkHelper::IPStr2Addr(pAdapter->IpAddressList.IpMask.String).s_addr;
                if (dwGatewayIP == 0 || dwLocalIP == 0 || dwIPMask == 0)
                {
                    pAdapter = pAdapter->Next;
                    continue;
                }
                if (pAdapter->Index != info[valid_size].index) {
                    pAdapter = pAdapter->Next;
                    continue;
                }
                info[valid_size].srcAddr = dwLocalIP;
                break;
            }
        }
    }

    if (pAdapterInfo) {
        ::GlobalFree(pAdapterInfo);
    }
    if (ipftable) {
        free(ipftable);
    }
#elif defined(__GNUC__)
    struct nlmsghdr *nlMsg = NULL;
    struct rtmsg *rtMsg = NULL;
    int sock, len, msgSeq = 0;
    char msgBuf[4096 * 2] = { 0 };

    if ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) return valid_size;
    nlMsg = (struct nlmsghdr *)msgBuf;
    rtMsg = (struct rtmsg *)NLMSG_DATA(nlMsg);
    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)); // Length of message.
    nlMsg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table .
    nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump.
    nlMsg->nlmsg_seq = msgSeq++; // Sequence of the message packet.
    nlMsg->nlmsg_pid = getpid(); // PID of process sending the request.

    do
    {
        if (send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0) break;
        if ((len = ReadNlSock(sock, msgBuf, sizeof(msgBuf), msgSeq, getpid())) <= 0) break;
        for (; NLMSG_OK(nlMsg, len); nlMsg = NLMSG_NEXT(nlMsg, len)) {
            RouteInfo *rtinfo = NULL;
            if (info)
            {
                if (valid_size >= size) break;
                rtinfo = &info[valid_size];
            }
            if (!ParseOneRoute(nlMsg, rtinfo))
                continue;
            else
                valid_size++;
        }
    } while (0);
    close(sock);
#else
#error unsupported compiler
#endif
    if (info) {
        qsort(info, valid_size, sizeof(info[0]), [](const void *left, const void *right) {
            RouteInfo *r1 = (RouteInfo *)left;
            RouteInfo *r2 = (RouteInfo *)right;

            int r1_bit = AlgorithmHelper::BitCount(r1->dstmask);
            int r2_bit = AlgorithmHelper::BitCount(r2->dstmask);
            if (r1_bit < r2_bit) {
                return 1;
            }
            else if (r1_bit > r2_bit) {
                return -1;
            }

            if (r1->metric < r2->metric) {
                return -1;
            }
            else if (r1->metric > r2->metric) {
                return 1;
            }

            /* Compare addresses of equal elements to make the sort stable, as suggested
            by the Glibc manual. */
            if (r1 < r2) {
                return -1;
            }
            else if (r1 > r2) {
                return 1;
            }
            return 0;
        });
    }
    return valid_size;
}

bool NetworkInfoHelper::GetDstRoute(NetworkInfoHelper::Route &route, const in_addr &dst)
{
    return NetworkInfoHelper::GetDstRoute(route, dst.s_addr);
}

bool NetworkInfoHelper::GetDstRoute(Route &route, int dst)
{
    if (dst >> 24 == 127) {
        //dont support loopback
        return false;
    }

    NetworkInfoHelper::AdaptInfo if_info = NetworkInfoHelper::GetAdaptInfoByIp(dst, false, false);
    if (!if_info.local_ip_address.empty()) {
        //dont support loopback
        return false;
    }

    u_int route_count = NetworkInfoHelper::GetAllRouteInfo(NULL, 0);
    if (!route_count) {
        return false;
    }

    NetworkInfoHelper::RouteInfo *route_infos = new (std::nothrow) NetworkInfoHelper::RouteInfo[route_count];
    if (route_infos == NULL)
    {
        return false;
    }
    memset(route_infos, 0, route_count * sizeof(*route_infos));
    route_count = NetworkInfoHelper::GetAllRouteInfo(route_infos, route_count);
    bool match = false;
    for (u_int i = 0; i < route_count; i++) {
        if ((dst&route_infos[i].dstmask) != route_infos[i].dstAddr) {
            continue;
        }
        NetworkInfoHelper::AdaptInfo if_info = NetworkInfoHelper::GetAdaptInfoByIp(route_infos[i].srcAddr, false, false);
        if (if_info.local_ip_address.empty()) {
            break;
        }
        match = true;
        route.dstAddr = dst;
        route.index = if_info.index;
        route.srcAddr = if_info.local_ip_address_int.s_addr;
        memcpy(route.srcMac, if_info.local_mac_address_int, sizeof(route.srcMac));
        break;
    }
    if (route_infos) {
        delete[]route_infos;
        route_infos = NULL;
    }
    return match;
}

NetworkInfoHelper::NetworkInfo NetworkInfoHelper::GetNetworkInfoByIp(u_int ip, bool use_mask, bool need_gateway_mac)
{
    NetworkInfo info;
    u_int count = GetAllNetworkInfo(NULL, 0, need_gateway_mac);
    if (!count)
    {
        return info;
    }
    NetworkInfo *network_infos = new (std::nothrow) NetworkInfo[count];
    if (!network_infos)
    {
        return info;
    }
    count = GetAllNetworkInfo(network_infos, count, need_gateway_mac);
    for (u_int i = 0; i < count; i++)
    {
        if (use_mask)
        {
            if ((network_infos[i].adapt_info.local_ip_address_int.s_addr&network_infos[i].adapt_info.subnet_ip_mask_int.s_addr)
                == (ip&network_infos[i].adapt_info.subnet_ip_mask_int.s_addr))
            {
                info = network_infos[i];
                break;
            }
        }
        else
        {
            if (network_infos[i].adapt_info.local_ip_address_int.s_addr == ip)
            {
                info = network_infos[i];
                break;
            }
        }
    }
    if (network_infos) {
        delete[]network_infos;
        network_infos = NULL;
    }
    return info;
}

NetworkInfoHelper::AdaptInfo NetworkInfoHelper::GetAdaptInfoByIp(u_int ip, bool use_mask, bool need_gateway_mac)
{
    AdaptInfo info;
    u_int count = GetAllAdaptInfo(NULL, 0, need_gateway_mac);
    if (!count)
    {
        return info;
    }
    AdaptInfo *network_infos = new (std::nothrow) AdaptInfo[count];
    if (!network_infos)
    {
        return info;
    }
    count = GetAllAdaptInfo(network_infos, count, need_gateway_mac);
    for (u_int i = 0; i < count; i++)
    {
        if (use_mask)
        {
            if ((network_infos[i].local_ip_address_int.s_addr&network_infos[i].subnet_ip_mask_int.s_addr)
                == (ip&network_infos[i].subnet_ip_mask_int.s_addr))
            {
                info = network_infos[i];
                break;
            }
        }
        else
        {
            if (network_infos[i].local_ip_address_int.s_addr == ip)
            {
                info = network_infos[i];
                break;
            }
        }
    }
    if (network_infos) {
        delete[]network_infos;
        network_infos = NULL;
    }
    return info;
}

#define GET_DEVICES_TOTAL_WAIT_SECOND 10
#define GET_DEVICES_ONE_WAIT_MILL_SECOND 10
#define GET_DEVICES_WAIT_NEW_LOOP_SECOND 1

std::map<std::string, std::string> NetworkInfoHelper::GetAllNeighborDevices(const NetworkInfoHelper::NetworkInfo &network_info)
{
    if (network_info.adapt_info.local_ip_address.empty())
    {
        return std::map<std::string, std::string>();
    }

#if defined(_MSC_VER)
    ArpTableHelper::DeleteArpTable(network_info.adapt_info.index);
    std::set<std::string> ip_list = NetworkHelper::GetNetIPs(NetworkHelper::IPStr2Addr(network_info.adapt_info.local_ip_address), NetworkHelper::IPStr2Addr(network_info.adapt_info.subnet_ip_mask));
    std::vector<std::thread> t;

    ICMPHelper icmp(network_info.adapt_info.local_ip_address_int.s_addr);
    bool stop = false;
    for (int i = 0; i < (GET_DEVICES_TOTAL_WAIT_SECOND / GET_DEVICES_WAIT_NEW_LOOP_SECOND); i++)
    {
        t.emplace_back([&network_info, &ip_list, &icmp, &stop]
        {
            if (!icmp.Init())
            {
                return;
            }

            for (int i = 0; i < (GET_DEVICES_TOTAL_WAIT_SECOND * 1000 / 254 / GET_DEVICES_ONE_WAIT_MILL_SECOND + 1); i++)
            {
                if (stop)
                {
                    break;
                }
                for (auto device : ip_list)
                {
                    if (stop)
                    {
                        break;
                    }
                    icmp.SendICMPPingRequest(device);
                    std::this_thread::sleep_for(std::chrono::milliseconds(GET_DEVICES_ONE_WAIT_MILL_SECOND));
                }
            }
        });
        std::this_thread::sleep_for(std::chrono::seconds(GET_DEVICES_WAIT_NEW_LOOP_SECOND));
    }
    stop = true;
    for (auto it = t.begin(); it != t.end(); it++)
    {
        it->join();
    }
    return ArpTableHelper::GetArpTable(network_info.adapt_info.index);
#elif defined(__GNUC__)
    std::map<std::string, std::string> result;

    int rawSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (rawSock == -1)
    {
        return result;
    }

    struct timeval recv_time_out = { 0 };
    recv_time_out.tv_usec = 100 * 1000;
    if (setsockopt(rawSock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&recv_time_out, sizeof(recv_time_out)) != 0)
    {
        close(rawSock);
        return result;
    }

    struct timeval  send_time_out = { 0 };
    send_time_out.tv_usec = 100 * 1000;
    if (setsockopt(rawSock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&send_time_out, sizeof(send_time_out)) != 0)
    {
        close(rawSock);
        return result;
    }

    int nRecvBuf = 2 * 1024 * 1024;
    if (setsockopt(rawSock, SOL_SOCKET, SO_RCVBUF, (const char*)&nRecvBuf, sizeof(int)))
    {
        close(rawSock);
        return result;
    }

    bool stop = false;
    std::thread send_thread([&network_info, &stop, rawSock]
    {
        std::vector<std::thread> t;
        std::set<u_int> ip_list = NetworkHelper::GetNetIPs(NetworkHelper::IPStr2Addr(network_info.adapt_info.local_ip_address).s_addr, NetworkHelper::IPStr2Addr(network_info.adapt_info.subnet_ip_mask).s_addr);

        for (int i = 0; i < (GET_DEVICES_TOTAL_WAIT_SECOND / GET_DEVICES_WAIT_NEW_LOOP_SECOND); i++)
        {
            t.emplace_back([&network_info, &ip_list, &stop, rawSock]
            {
                for (int i = 0; i < (GET_DEVICES_TOTAL_WAIT_SECOND * 1000 / 254 / GET_DEVICES_ONE_WAIT_MILL_SECOND + 1); i++)
                {
                    if (stop)
                    {
                        break;
                    }
                    for (auto device : ip_list)
                    {
                        if (stop)
                        {
                            break;
                        }
                        ArpPacket pack;
                        GenerateArpRequestPacket(pack, device, network_info.adapt_info.local_ip_address_int.s_addr, network_info.adapt_info.local_mac_address);
                        struct sockaddr_ll saddr_ll = { 0 };
                        saddr_ll.sll_ifindex = network_info.adapt_info.index;
                        saddr_ll.sll_family = AF_PACKET;
                        sendto(rawSock, (char *)&pack, sizeof(pack), 0, (struct sockaddr *)&saddr_ll, sizeof(struct sockaddr_ll));
                        std::this_thread::sleep_for(std::chrono::milliseconds(GET_DEVICES_ONE_WAIT_MILL_SECOND));
                    }
                }
            });
            std::this_thread::sleep_for(std::chrono::seconds(GET_DEVICES_WAIT_NEW_LOOP_SECOND));
        }
        for (auto it = t.begin(); it != t.end(); it++)
        {
            it->join();
        }
    });
    const int szPlanRecv = sizeof(NetworkInfoHelper::ArpPacket);
    uint8_t ucBuffer[1024];
    struct timeval tmp;
    gettimeofday(&tmp, NULL);
    unsigned long long start = tmp.tv_sec * 1000000 + tmp.tv_usec;
    while (1)
    {
        ssize_t szRecv = recv(rawSock, ucBuffer, sizeof(ucBuffer), 0);
        if (szRecv >= szPlanRecv)
        {
            NetworkInfoHelper::ArpPacket *recv = (NetworkInfoHelper::ArpPacket *)ucBuffer;
            if ((network_info.adapt_info.local_ip_address_int.s_addr & network_info.adapt_info.subnet_ip_mask_int.s_addr)
                == (recv->ah.SourceIpAdd & network_info.adapt_info.subnet_ip_mask_int.s_addr))
            {
                std::string ip = StringHelper::byte2basestr((unsigned char *)&recv->ah.SourceIpAdd, 4, ".", StringHelper::dec);
                std::string mac = StringHelper::byte2basestr((unsigned char *)&recv->ah.SourceMacAdd, 6, NETWORK_INFO_MAC_SPLITE, StringHelper::hex, 2);
                result[ip] = mac;
            }
        }
        gettimeofday(&tmp, NULL);
        unsigned long long cur = tmp.tv_sec * 1000000 + tmp.tv_usec;
        if ((cur - start) > (GET_DEVICES_TOTAL_WAIT_SECOND * 1000 * 1000))
        {
            break;
        }
    }
    stop = true;
    send_thread.join();
    return result;
#endif
}

bool NetworkInfoHelper::GetAllNeighborDevices(const NetworkInfoHelper::NetworkInfo &network_info, NetworkInfoHelper::GetDevicesCallBack callback)
{
    if (network_info.adapt_info.local_ip_address.empty())
    {
        return false;
    }
    std::thread([network_info, callback] {
#if defined(_MSC_VER)
        bool stop = false;
        std::thread send_thread([network_info, &stop]
        {
            std::vector<std::thread> t;
            ArpTableHelper::DeleteArpTable(network_info.adapt_info.index);
            std::set<std::string> ip_list = NetworkHelper::GetNetIPs(NetworkHelper::IPStr2Addr(network_info.adapt_info.local_ip_address), NetworkHelper::IPStr2Addr(network_info.adapt_info.subnet_ip_mask));

            ICMPHelper icmp(network_info.adapt_info.local_ip_address_int.s_addr);
            for (int i = 0; i < (GET_DEVICES_TOTAL_WAIT_SECOND / GET_DEVICES_WAIT_NEW_LOOP_SECOND); i++)
            {
                if (stop)
                {
                    break;
                }
                t.emplace_back([&network_info, &ip_list, &icmp, &stop]
                {
                    if (!icmp.Init())
                    {
                        return;
                    }

                    for (int i = 0; i < (GET_DEVICES_TOTAL_WAIT_SECOND * 1000 / 254 / GET_DEVICES_ONE_WAIT_MILL_SECOND + 1); i++)
                    {
                        if (stop)
                        {
                            break;
                        }
                        for (auto device : ip_list)
                        {
                            if (stop)
                            {
                                break;
                            }
                            icmp.SendICMPPingRequest(device);
                            std::this_thread::sleep_for(std::chrono::milliseconds(GET_DEVICES_ONE_WAIT_MILL_SECOND));
                        }
                    }
                });
                std::this_thread::sleep_for(std::chrono::seconds(GET_DEVICES_WAIT_NEW_LOOP_SECOND));
            }
            for (auto it = t.begin(); it != t.end(); it++)
            {
                it->join();
            }
        });

        std::map<std::string, std::string> device_found;
        for (int i = 0; (i < (GET_DEVICES_TOTAL_WAIT_SECOND / GET_DEVICES_WAIT_NEW_LOOP_SECOND)) && !stop; i++)
        {
            bool is_last = (i == ((GET_DEVICES_TOTAL_WAIT_SECOND / GET_DEVICES_WAIT_NEW_LOOP_SECOND) - 1));
            std::this_thread::sleep_for(std::chrono::seconds(GET_DEVICES_WAIT_NEW_LOOP_SECOND));
            auto arp_table = ArpTableHelper::GetArpTable(network_info.adapt_info.index);
            for (auto device : arp_table)
            {
                auto addr = NetworkHelper::IPStr2Addr(device.first);
                if ((network_info.adapt_info.local_ip_address_int.s_addr & network_info.adapt_info.subnet_ip_mask_int.s_addr)
                    != (addr.s_addr & network_info.adapt_info.subnet_ip_mask_int.s_addr))
                {
                    continue;
                }

                if (device_found.find(device.first) == device_found.end())
                {
                    stop = !callback(device.first, device.second, false);
                    device_found[device.first] = device.second;
                }
            }
            if (is_last) {
                stop = callback("", "", true);
            }
        }
        stop = true;
        send_thread.join();
#elif defined(__GNUC__)
        std::map<std::string, std::string> result;

        int rawSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (rawSock == -1)
        {
            callback("", "", true);
            return;
        }

        struct timeval recv_time_out = { 0 };
        recv_time_out.tv_usec = 100 * 1000;
        if (setsockopt(rawSock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&recv_time_out, sizeof(recv_time_out)) != 0)
        {
            close(rawSock);
            callback("", "", true);
            return;
        }

        struct timeval  send_time_out = { 0 };
        send_time_out.tv_usec = 100 * 1000;
        if (setsockopt(rawSock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&send_time_out, sizeof(send_time_out)) != 0)
        {
            close(rawSock);
            callback("", "", true);
            return;
        }

        int nRecvBuf = 2 * 1024 * 1024;
        if (setsockopt(rawSock, SOL_SOCKET, SO_RCVBUF, (const char*)&nRecvBuf, sizeof(int)))
        {
            close(rawSock);
            callback("", "", true);
            return;
        }

        bool stop = false;
        std::thread send_thread([&network_info, &stop, rawSock]
        {
            std::vector<std::thread> t;
            std::set<u_int> ip_list = NetworkHelper::GetNetIPs(NetworkHelper::IPStr2Addr(network_info.adapt_info.local_ip_address).s_addr, NetworkHelper::IPStr2Addr(network_info.adapt_info.subnet_ip_mask).s_addr);

            for (int i = 0; i < (GET_DEVICES_TOTAL_WAIT_SECOND / GET_DEVICES_WAIT_NEW_LOOP_SECOND); i++)
            {
                t.emplace_back([&network_info, &ip_list, &stop, rawSock]
                {
                    for (int i = 0; i < (GET_DEVICES_TOTAL_WAIT_SECOND * 1000 / 254 / GET_DEVICES_ONE_WAIT_MILL_SECOND + 1); i++)
                    {
                        if (stop)
                        {
                            break;
                        }
                        for (auto device : ip_list)
                        {
                            if (stop)
                            {
                                break;
                            }
                            ArpPacket pack;
                            GenerateArpRequestPacket(pack, device, network_info.adapt_info.local_ip_address_int.s_addr, network_info.adapt_info.local_mac_address);
                            struct sockaddr_ll saddr_ll = { 0 };
                            saddr_ll.sll_ifindex = network_info.adapt_info.index;
                            saddr_ll.sll_family = AF_PACKET;
                            sendto(rawSock, (char *)&pack, sizeof(pack), 0, (struct sockaddr *)&saddr_ll, sizeof(struct sockaddr_ll));
                            std::this_thread::sleep_for(std::chrono::milliseconds(GET_DEVICES_ONE_WAIT_MILL_SECOND));
                        }
                    }
                });
                std::this_thread::sleep_for(std::chrono::seconds(GET_DEVICES_WAIT_NEW_LOOP_SECOND));
            }
            for (auto it = t.begin(); it != t.end(); it++)
            {
                it->join();
            }
        });
        const int szPlanRecv = sizeof(NetworkInfoHelper::ArpPacket);
        uint8_t ucBuffer[1024];
        struct timeval tmp;
        gettimeofday(&tmp, NULL);
        unsigned long long start = tmp.tv_sec * 1000000 + tmp.tv_usec;
        std::map<std::string, std::string> device_found;
        while (!stop)
        {
            ssize_t szRecv = recv(rawSock, ucBuffer, sizeof(ucBuffer), 0);
            if (szRecv >= szPlanRecv)
            {
                NetworkInfoHelper::ArpPacket *recv = (NetworkInfoHelper::ArpPacket *)ucBuffer;
                if ((network_info.adapt_info.local_ip_address_int.s_addr & network_info.adapt_info.subnet_ip_mask_int.s_addr)
                    == (recv->ah.SourceIpAdd & network_info.adapt_info.subnet_ip_mask_int.s_addr))
                {
                    std::string ip = StringHelper::byte2basestr((unsigned char *)&recv->ah.SourceIpAdd, 4, ".", StringHelper::dec);
                    std::string mac = StringHelper::byte2basestr((unsigned char *)&recv->ah.SourceMacAdd, 6, NETWORK_INFO_MAC_SPLITE, StringHelper::hex, 2);
                    if (device_found.find(ip) == device_found.end())
                    {
                        stop = !callback(ip, mac, false);
                        device_found[ip] = mac;
                    }
                }
            }
            gettimeofday(&tmp, NULL);
            unsigned long long cur = tmp.tv_sec * 1000000 + tmp.tv_usec;
            if ((cur - start) > (GET_DEVICES_TOTAL_WAIT_SECOND * 1000 * 1000))
            {
                stop = callback("", "", true);
                break;
            }
        }
        stop = true;
        send_thread.join();
#endif
    }).detach();
    return true;
}

#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3
bool NetworkInfoHelper::GetIpv6ByIndex(in6_addr &ipv6, u_int index)
{
#if defined(_MSC_VER)
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    unsigned int i = 0;
    // Set the flags to pass to GetAdaptersAddresses
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    // default to unspecified address family (both)
    ULONG family = AF_INET6;
    LPVOID lpMsgBuf = NULL;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    ULONG outBufLen = 0;
    ULONG Iterations = 0;
    PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
    IP_ADAPTER_PREFIX *pPrefix = NULL;
    bool ret = false;

    if (index == 0) {
        return false;
    }

    // Allocate a 15 KB buffer to start with.
    outBufLen = WORKING_BUFFER_SIZE;
    do {
        pAddresses = (IP_ADAPTER_ADDRESSES *)new (std::nothrow) char[outBufLen];
        if (pAddresses == NULL) {
            return ret;
        }
        dwRetVal = GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);
        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            delete[]pAddresses;
            pAddresses = NULL;
        }
        else {
            break;
        }
        Iterations++;
    } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));

    if (dwRetVal == NO_ERROR) {
        // If successful, output some information from the data we received
        pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            if (pCurrAddresses->IfIndex != index) {
                pCurrAddresses = pCurrAddresses->Next;
                continue;
            }
            pPrefix = pCurrAddresses->FirstPrefix;
            if (pPrefix) {
                in6_addr tmp = { 0 };
                for (i = 0; pPrefix != NULL; i++) {
                    if (pPrefix->Address.lpSockaddr) {
                        if (pPrefix->Address.lpSockaddr->sa_family == AF_INET6)
                        {
                            sockaddr_in6* ipv6_in = (sockaddr_in6*)pPrefix->Address.lpSockaddr;
                            if (((int *)ipv6_in->sin6_addr.s6_addr)[3]) {
                                tmp = ipv6_in->sin6_addr;
                            }
                        }
                    }
                    pPrefix = pPrefix->Next;
                }
                if (NetworkHelper::IsValidIp(tmp)) {
                    ipv6 = tmp;
                    ret = true;
                }
            }
            break;
        }
    }
    if (pAddresses) {
        delete[]pAddresses;
    }
    return ret;
#elif defined(__GNUC__)
    struct ifaddrs *ifa, *p;
    int family;
    char address[200];

    if (getifaddrs(&ifa)) {
        return false;
    }

    bool ret = false;
    for (p = ifa; p != NULL; p = p->ifa_next) {
        if (p->ifa_addr == NULL) {
            continue;
        }
        family = p->ifa_addr->sa_family;
        /* Just check IPv6 address */
        if (family != AF_INET6) {
            continue;
        }
        if (IfNameToIndex(p->ifa_name) != index) {
            continue;
        }
        ipv6 = ((struct sockaddr_in6 *)(p->ifa_addr))->sin6_addr;
        ret = true;
        break;
    }
    freeifaddrs(ifa);
    return ret;
#endif
}

#if defined(_MSC_VER)

#define NUM_NETWORK		20
#define STATUS_SUCCESS               ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH  ((NTSTATUS)0xC0000004L)

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef LONG KPRIORITY; // Thread priority
typedef struct _SYSTEM_PROCESS_INFORMATION_DETAILD
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    ULONG InheritedFromUniqueProcessId;
    ULONG HandleCount;
    BYTE Reserved4[4];
    PVOID Reserved5[11];
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION_DETAILD, *PSYSTEM_PROCESS_INFORMATION_DETAILD;

typedef NTSTATUS(WINAPI *PFN_NT_QUERY_SYSTEM_INFORMATION)(
    IN       SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OUT   PVOID SystemInformation,
    IN       ULONG SystemInformationLength,
    OUT OPTIONAL  PULONG ReturnLength
    );

DWORD NetworkInfoHelper::GetProcessIdByProcessName(LPCWSTR pszProcessName)
{
    ULONG bufferSize = 1024 * sizeof(SYSTEM_PROCESS_INFORMATION_DETAILD);
    PSYSTEM_PROCESS_INFORMATION_DETAILD pspid = NULL;
    HANDLE hHeap = GetProcessHeap();
    PBYTE pBuffer = NULL;
    ULONG ReturnLength;
    PFN_NT_QUERY_SYSTEM_INFORMATION pfnNtQuerySystemInformation = (PFN_NT_QUERY_SYSTEM_INFORMATION)
        GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQuerySystemInformation");
    NTSTATUS status;
    int uLen = lstrlenW(pszProcessName) * sizeof(WCHAR);

    __try {
        pBuffer = (PBYTE)HeapAlloc(hHeap, 0, bufferSize);
#pragma warning(disable: 4127)
        while (TRUE) {
#pragma warning(default: 4127)
            status = pfnNtQuerySystemInformation(SystemProcessInformation, (PVOID)pBuffer,
                bufferSize, &ReturnLength);
            if (status == STATUS_SUCCESS)
                break;
            else if (status != STATUS_INFO_LENGTH_MISMATCH) { // 0xC0000004L
                return 1;   // error
            }

            bufferSize *= 2;
            pBuffer = (PBYTE)HeapReAlloc(hHeap, 0, (PVOID)pBuffer, bufferSize);
        }

        for (pspid = (PSYSTEM_PROCESS_INFORMATION_DETAILD)pBuffer; ;
            pspid = (PSYSTEM_PROCESS_INFORMATION_DETAILD)(pspid->NextEntryOffset + (PBYTE)pspid)) {

            if (pspid->ImageName.Length == uLen && lstrcmpiW(pspid->ImageName.Buffer, pszProcessName) == 0)
                return (DWORD)pspid->UniqueProcessId;

            if (pspid->NextEntryOffset == 0) break;
        }
    }
    __finally {
        HeapFree(hHeap, 0, pBuffer);
        pBuffer = NULL;
    }
    return 0;
}

BOOL NetworkInfoHelper::SetCurrentPrivilege(LPCTSTR pszPrivilege, BOOL bEnablePrivilege)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    TOKEN_PRIVILEGES tpPrevious;
    DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);
    BOOL bSuccess = FALSE;

    //get hte privilege uid
    if (!LookupPrivilegeValue(NULL, pszPrivilege, &luid))
        return FALSE;

    //open process token and ready to change the token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
        return FALSE;

    // first pass.  get current privilege setting
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = 0;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &tpPrevious, &cbPrevious);

    if (GetLastError() == ERROR_SUCCESS)
    {
        // second pass.  set privilege based on previous setting
        tpPrevious.PrivilegeCount = 1;
        tpPrevious.Privileges[0].Luid = luid;
        if (bEnablePrivilege)
            tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
        else
            tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED & tpPrevious.Privileges[0].Attributes);
        AdjustTokenPrivileges(hToken, FALSE, &tpPrevious, cbPrevious, NULL, NULL);

        if (GetLastError() == ERROR_SUCCESS)
            bSuccess = TRUE;

        CloseHandle(hToken);
    }
    else
    {
        DWORD dwErrorCode = GetLastError();

        CloseHandle(hToken);
        SetLastError(dwErrorCode);
    }

    return(bSuccess);
}

int NetworkInfoHelper::DecryptKeyMaterial(char *pKeyMaterial, char *pPassBuf, int pPassBufLen)
{
    int lRetVal = 0;
    BOOL lIsSuccess, lImpersonated = FALSE;
    HANDLE lHandleProcess = NULL, lHandleProcessToken = NULL;
    DATA_BLOB lDataOut, lDataVerify;
    BYTE lBinaryKey[1024];
    DWORD lBinary, lFlags, lSkip;
    DWORD lProcessId = 0;

    //get the process id of winlogon
    if ((lProcessId = GetProcessIdByProcessName(L"winlogon.exe")) == 0)
    {
        lRetVal = 1;
        goto END;
    }

    //set the debug privilege of current process
    if (!(lIsSuccess = SetCurrentPrivilege(SE_DEBUG_NAME, TRUE)))
    {
        lRetVal = 2;
        goto END;
    }

    //open winlogon process
    if (!(lHandleProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, lProcessId)))
    {
        lRetVal = 3;
        goto END;
    }

    //get the token of winlogon process
    if (!(lIsSuccess = OpenProcessToken(lHandleProcess, MAXIMUM_ALLOWED, &lHandleProcessToken)))
    {
        lRetVal = 4;
        goto END;
    }

    //use winlogon process token Simulate user login
    if (!(lIsSuccess = ImpersonateLoggedOnUser(lHandleProcessToken)))
    {
        lRetVal = 5;
        goto END;
    }

    //hex string To binary
    lImpersonated = TRUE;
    lBinary = sizeof(lBinaryKey);
    if (!(lIsSuccess = CryptStringToBinaryA(pKeyMaterial, lstrlenA(pKeyMaterial), CRYPT_STRING_HEX, lBinaryKey, &lBinary, &lSkip, &lFlags)))
    {
        lRetVal = 6;
        goto END;
    }

    //decrpt the data
    lDataOut.cbData = lBinary;
    lDataOut.pbData = (BYTE*)lBinaryKey;
    if (CryptUnprotectData(&lDataOut, NULL, NULL, NULL, NULL, 0, &lDataVerify))
    {
        sprintf_s(pPassBuf, pPassBufLen, "%hs", lDataVerify.pbData);
    }
    else
    {
        lRetVal = 6;
    }

END:
    if (lImpersonated)
        RevertToSelf();

    if (lHandleProcess)
        CloseHandle(lHandleProcess);

    if (lHandleProcessToken)
        CloseHandle(lHandleProcessToken);

    return(lRetVal);
}

bool NetworkInfoHelper::GetWStrWifiSSID(std::wstring &wstrWifiSSID, HANDLE hClient, const GUID *guid)
{
    WLAN_CONNECTION_ATTRIBUTES *pConnectionAttributes = NULL;
    DWORD dwSize = sizeof(WLAN_CONNECTION_ATTRIBUTES);
    DWORD   dwResult = 0;

    dwResult = WlanQueryInterface(hClient, guid, wlan_intf_opcode_current_connection, NULL, &dwSize, (PVOID*)&pConnectionAttributes, NULL);
    if (dwResult != ERROR_SUCCESS) return false;
    wstrWifiSSID = pConnectionAttributes->strProfileName;
    if (pConnectionAttributes)
    {
        WlanFreeMemory(pConnectionAttributes);
        pConnectionAttributes = NULL;
    }
    return true;
}

void NetworkInfoHelper::GetWifiSSIDAndPwd(std::string &ssid, std::string &pwd, std::wstring &wstrWifiSSID, HANDLE hClient, const GUID *guid)
{
    DWORD   dwResult = 0;
    LPWSTR pProfileXML = NULL;
    dwResult = WlanGetProfile(hClient, guid, wstrWifiSSID.c_str(), NULL, &pProfileXML, 0, 0);
    std::wstring wstrXML;
    if (ERROR_SUCCESS == dwResult)
    {
        wstrXML = pProfileXML;
        if (pProfileXML != NULL)
        {
            WlanFreeMemory(pProfileXML);
            pProfileXML = NULL;
        }
    }

    std::wstring wstrDetailWifiSSID;
    pugi::xml_document doc;
    std::string strXML;
    std::string asHexData;
    strXML = StringHelper::tochar(wstrXML);
    const int status = doc.load(strXML.c_str()).status;
    if (status == pugi::status_ok)
    {
        pugi::xpath_node ssid_name_node = doc.select_single_node("//SSID/name");
        std::string strWifiSSID = ssid_name_node.node().text().as_string();
        wstrDetailWifiSSID = StringHelper::towchar(strWifiSSID);

        pugi::xpath_node keyMaterial_node = doc.select_single_node("//security/sharedKey/keyMaterial");
        asHexData = keyMaterial_node.node().text().as_string();
    }

    if (!wstrDetailWifiSSID.empty())
    {
        //Overwrite by detail ssid info
        wstrWifiSSID = wstrDetailWifiSSID;
        ssid = StringHelper::tochar(wstrWifiSSID);
    }

    // Get the SHA1 of wifi password
    char password[1025] = { 0 };
    if (!asHexData.empty())
    {
        if (DecryptKeyMaterial((char*)asHexData.c_str(), password, 1024) == 0)
        {
            pwd = password;
        }
    }
}

void NetworkInfoHelper::GetWifiDot11AuthAndCipherAlgorthim(int &dot11DefaultAuthAlgorithm, int &dot11DefaultCipherAlgorithm, const std::wstring &wstrWifiSSID, HANDLE hClient, const GUID *guid)
{
    PWLAN_AVAILABLE_NETWORK_LIST pBssList = NULL;
    DWORD   dwResult = 0;
    //Get the authentication and encryption real-time.
    dwResult = WlanGetAvailableNetworkList(hClient, guid, 0, NULL, &pBssList);
    if (dwResult == ERROR_SUCCESS)
    {
        for (DWORD j = 0; j < pBssList->dwNumberOfItems; j++)
        {
            PWLAN_AVAILABLE_NETWORK pBssEntry = (WLAN_AVAILABLE_NETWORK *)& pBssList->Network[j];

            //Get the wifi name
            std::wstring wstrWifiName;
            for (ULONG k = 0; k < pBssEntry->dot11Ssid.uSSIDLength; k++)
            {
                wstrWifiName += pBssEntry->dot11Ssid.ucSSID[k];
            }

            //Check Weather it is equal to
            if (wstrWifiSSID == wstrWifiName)
            {
                //Matched
                dot11DefaultAuthAlgorithm = pBssEntry->dot11DefaultAuthAlgorithm;
                dot11DefaultCipherAlgorithm = pBssEntry->dot11DefaultCipherAlgorithm;
            }
        }
    }
    if (pBssList)
    {
        WlanFreeMemory(pBssList);
    }
}

void NetworkInfoHelper::GetWifiBSSID(std::string &bssid, const std::wstring &wstrWifiSSID, HANDLE hClient, const GUID *guid)
{
    // Get current bssid which ssid belongs to
    PWLAN_BSS_LIST pWlanBssList;
    DWORD   dwResult = 0;
    dwResult = WlanGetNetworkBssList(hClient, guid, nullptr, dot11_BSS_type_any, NULL, nullptr, &pWlanBssList);
    if (dwResult == ERROR_SUCCESS)
    {
        for (DWORD j = 0; j < pWlanBssList->dwNumberOfItems; j++)
        {
            //Get the wifi name
            std::wstring wstrWifiName;
            for (ULONG k = 0; k < pWlanBssList->wlanBssEntries[j].dot11Ssid.uSSIDLength; k++)
            {
                wstrWifiName += pWlanBssList->wlanBssEntries[j].dot11Ssid.ucSSID[k];
            }
            //Check Weather it is equal to
            if (wstrWifiSSID == wstrWifiName)
            {
                std::wstring wstrBssid;
                char buff[128] = { 0 };
                sprintf_s(buff, "%02X:%02X:%02X:%02X:%02X:%02X",
                    pWlanBssList->wlanBssEntries[j].dot11Bssid[0],
                    pWlanBssList->wlanBssEntries[j].dot11Bssid[1],
                    pWlanBssList->wlanBssEntries[j].dot11Bssid[2],
                    pWlanBssList->wlanBssEntries[j].dot11Bssid[3],
                    pWlanBssList->wlanBssEntries[j].dot11Bssid[4],
                    pWlanBssList->wlanBssEntries[j].dot11Bssid[5]);
                bssid = buff;
                break;
            }

        }
    }
    if (pWlanBssList)
    {
        WlanFreeMemory(pWlanBssList);
    }
}
#elif defined(__GNUC__)
NetworkInfoHelper::ArpPacket NetworkInfoHelper::m_request_arp_pack = PreBuildARPRequestPack();

NetworkInfoHelper::ArpPacket NetworkInfoHelper::PreBuildARPRequestPack()
{
    ArpPacket pack = { 0 };
    memset(pack.eh.DestMAC, 0xff, 6);
    memset(pack.ah.DestMacAdd, 0x00, 6);
    pack.eh.EthType = htons(NETWORKINFO_ETH_ARP);
    pack.ah.HardwareType = htons(NETWORKINFO_ARP_HARDWARE);
    pack.ah.ProtocolType = htons(NETWORKINFO_ETH_IP);
    pack.ah.HardwareAddLen = 6;
    pack.ah.ProtocolAddLen = 4;
    pack.ah.DestIpAdd = 0;
    pack.ah.OperationField = htons(NETWORKINFO_ARP_REQUEST);
    return pack;
}

void NetworkInfoHelper::GenerateArpRequestPacket(ArpPacket &pack, u_int dest_iP, u_int src_iP, std::string src_mac)
{
    memcpy(&pack, &m_request_arp_pack, sizeof(pack));
    pack.ah.DestIpAdd = dest_iP;
    pack.ah.SourceIpAdd = src_iP;
    StringHelper::hex2byte(StringHelper::replace(src_mac, NETWORK_INFO_MAC_SPLITE, ""), (char *)pack.ah.SourceMacAdd, sizeof(pack.ah.SourceMacAdd));
    memcpy(pack.eh.SourMAC, pack.ah.SourceMacAdd, ETH_ALEN);
}

u_int NetworkInfoHelper::SendARP(u_int DestIP, u_int SrcIP, u_char *mac, u_long *len, u_int timeout)
{
    if (mac == NULL || len == NULL || *len < 6) return -1;
    if (DestIP == 0) return -1;

    NetworkInfo info;
    if (SrcIP)
        info = GetNetworkInfoByIp(SrcIP, false);
    else
        info = GetNetworkInfoByIp(DestIP, true);
    if (info.adapt_info.local_ip_address.empty()) return -1;

    return SendARPPrivate(DestIP, info.adapt_info, mac, len, timeout);
}

u_int NetworkInfoHelper::SendARPPrivate(u_int DestIP, const AdaptInfo &info, u_char *mac, u_long *len, u_int timeout)
{
    if (mac == NULL || len == NULL || *len < 6) return -1;
    if (DestIP == 0) return -1;
    if (info.local_ip_address.empty()) return -1;

    int rawSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (rawSock == -1) return -1;

    struct timeval recv_time_out = { 0 };
    recv_time_out.tv_usec = 100 * 1000;
    if (setsockopt(rawSock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&recv_time_out, sizeof(recv_time_out)) != 0)
    {
        close(rawSock);
        return -1;
    }

    struct timeval  send_time_out = { 0 };
    send_time_out.tv_usec = 100 * 1000;
    if (setsockopt(rawSock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&send_time_out, sizeof(send_time_out)) != 0)
    {
        close(rawSock);
        return -1;
    }

    ArpPacket pack;
    GenerateArpRequestPacket(pack, DestIP, info.local_ip_address_int.s_addr, info.local_mac_address);

    struct sockaddr_ll saddr_ll = { 0 };
    saddr_ll.sll_ifindex = info.index;
    saddr_ll.sll_family = AF_PACKET;

    const int szPlanRecv = sizeof(pack);
    uint8_t ucBuffer[1024] = { 0 };
    struct timeval tmp;
    gettimeofday(&tmp, NULL);
    unsigned long long start = tmp.tv_sec * 1000000 + tmp.tv_usec;
    while (1)
    {
        sendto(rawSock, (char *)&pack, sizeof(pack), 0, (struct sockaddr *)&saddr_ll, sizeof(struct sockaddr_ll));
        ssize_t szRecv = recv(rawSock, ucBuffer, sizeof(ucBuffer), 0);
        if (szRecv >= szPlanRecv)
        {
            ArpPacket *recv = (ArpPacket *)ucBuffer;
            if (recv->ah.SourceIpAdd == DestIP)
            {
                memcpy(mac, recv->ah.SourceMacAdd, 6);
                *len = 6;
                close(rawSock);
                return 0;
            }
        }
        gettimeofday(&tmp, NULL);
        unsigned long long cur = tmp.tv_sec * 1000000 + tmp.tv_usec;
        if ((cur - start) > (timeout * 1000))
        {
            close(rawSock);
            return -1;
        }
    }
}

bool NetworkInfoHelper::GetDefaultGateway(u_int &ip, u_int &eth_index)
{
    u_int route_count = GetAllRouteInfo(NULL, 0);
    if (!route_count) return false;
    RouteInfo *route_infos = new (std::nothrow) RouteInfo[route_count];
    if (route_infos == NULL) return false;
    route_count = GetAllRouteInfo(route_infos, route_count);
    for (int i = 0; i < route_count; i++)
    {
        if (!route_infos[i].dstAddr)
        {
            eth_index = route_infos[i].index;
            ip = route_infos[i].gateWay;
        }
    }
    if (route_infos) delete[]route_infos;
    return true;
}

int NetworkInfoHelper::ReadNlSock(int sockFd, char *bufPtr, int buf_size, int seqNum, int pId)
{
    struct nlmsghdr *nlHdr = NULL;
    int readLen = 0, msgLen = 0;
    do {
        if ((readLen = recv(sockFd, bufPtr, buf_size - msgLen, 0)) < 0) return -1;
        nlHdr = (struct nlmsghdr *)bufPtr;
        if ((NLMSG_OK(nlHdr, readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR)) return -1;
        if (nlHdr->nlmsg_type == NLMSG_DONE)
        {
            break;
        }
        else
        {
            bufPtr += readLen;
            msgLen += readLen;
        }
        if ((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0) break;
    } while ((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));
    return msgLen;
}

bool NetworkInfoHelper::ParseOneRoute(struct nlmsghdr *nlHdr, RouteInfo *rtInfo)
{
    struct rtmsg *rtMsg = NULL;
    struct rtattr *rtAttr = NULL;
    int rtLen = 0;

    rtMsg = (struct rtmsg *)NLMSG_DATA(nlHdr);
    if ((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN)) return false;
    if (rtInfo == NULL) return true;

    rtAttr = (struct rtattr *)RTM_RTA(rtMsg);
    rtLen = RTM_PAYLOAD(nlHdr);
    for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen)) {
        switch (rtAttr->rta_type) {
        case RTA_OIF:
            rtInfo->index = *(int *)RTA_DATA(rtAttr);
            break;
        case RTA_GATEWAY:
            rtInfo->gateWay = *(u_int *)RTA_DATA(rtAttr);
            break;
        case RTA_PREFSRC:
            rtInfo->srcAddr = *(u_int *)RTA_DATA(rtAttr);
            break;
        case RTA_DST:
            rtInfo->dstAddr = *(u_int *)RTA_DATA(rtAttr);
            break;
        case RTA_PRIORITY:
            rtInfo->metric = *(u_int *)RTA_DATA(rtAttr);
            break;
        default:
            break;
        }
    }

    do
    {
        int fd, intrface;
        struct ifreq buf[40] = { { 0 } };
        struct ifconf ifc;

        if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            break;
        }
        ifc.ifc_len = sizeof buf;
        ifc.ifc_buf = (caddr_t)buf;
        if (ioctl(fd, SIOCGIFCONF, (char *)&ifc))
        {
            close(fd);
            break;
        }

        intrface = ifc.ifc_len / sizeof(struct ifreq);
        while (intrface-- > 0)
        {
            if (ioctl(fd, SIOCGIFFLAGS, (char *)&buf[intrface])) {
                continue;
            }
            if (!(buf[intrface].ifr_flags&IFF_UP)) {
                continue;
            }
            //get index
            if (ioctl(fd, SIOCGIFINDEX, (char *)&buf[intrface])) {
                continue;
            }
            if (rtInfo->index != buf[intrface].ifr_ifindex) {
                continue;
            }
            if (!ioctl(fd, SIOCGIFADDR, (char *)&buf[intrface])) {
                rtInfo->srcAddr = ((struct sockaddr_in*)(&buf[intrface].ifr_addr))->sin_addr.s_addr;
            }
            //get net mask
            if (!ioctl(fd, SIOCGIFNETMASK, (char *)&buf[intrface])) {
                int net_mask = ((struct sockaddr_in*)(&buf[intrface].ifr_netmask))->sin_addr.s_addr;
                if (rtInfo->dstAddr && net_mask) {
                    if (rtInfo->dstAddr == (rtInfo->dstAddr&net_mask)) {
                        rtInfo->dstmask = net_mask;
                    }
                    else {
                        rtInfo->dstmask = 0XFFFFFFFF;
                    }
                }
            }
            break;
        }
        close(fd);
    } while (0);

    return true;
}

u_int NetworkInfoHelper::IfNameToIndex(const std::string &name)
{
    int fd, intrface;
    struct ifreq buf[40] = { { 0 } };
    struct ifconf ifc;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return 0;
    }
    ifc.ifc_len = sizeof buf;
    ifc.ifc_buf = (caddr_t)buf;
    if (ioctl(fd, SIOCGIFCONF, (char *)&ifc))
    {
        close(fd);
        return 0 ;
    }

    u_int index = 0;
    intrface = ifc.ifc_len / sizeof(struct ifreq);
    while (intrface-- > 0)
    {
        if (ioctl(fd, SIOCGIFFLAGS, (char *)&buf[intrface])) {
            continue;
        }
        if (ioctl(fd, SIOCGIFINDEX, (char *)&buf[intrface])) {
            continue;
        }
        //get index
        if (StringHelper::tolower(name) != StringHelper::tolower(buf[intrface].ifr_name)) {
            continue;
        }
        index = buf[intrface].ifr_ifindex;
        break;
    }
    close(fd);
    return index;
}
#else
#error unsupported compiler
#endif

u_int NetworkInfoHelper::GetAllWifiInfo(WifiInfo *infos, u_int count)
{
    u_int valid_count = 0;
#if defined(_MSC_VER)
    HANDLE                      hClient = NULL;
    PWLAN_INTERFACE_INFO_LIST   pIfList = NULL;
    do
    {
        DWORD   dwMaxClient = 2;
        DWORD   dwCurVersion = 0;
        DWORD   dwResult = 0;

        dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
        if (dwResult != ERROR_SUCCESS)
        {
            break;
        }
        dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
        if (dwResult != ERROR_SUCCESS)
        {
            break;
        }

        for (DWORD i = 0; i != pIfList->dwNumberOfItems; i++)
        {
            PWLAN_INTERFACE_INFO pIfInfo = (WLAN_INTERFACE_INFO *)&pIfList->InterfaceInfo[i];
            std::wstring wstrWifiSSID;
            if (pIfInfo->isState != wlan_interface_state_connected) continue;
            if (!GetWStrWifiSSID(wstrWifiSSID, hClient, &pIfInfo->InterfaceGuid)) continue;
            valid_count++;
            if (infos == NULL) continue;
            if (valid_count > count) break;
            WifiInfo *cur_info = &infos[valid_count - 1];
            GetWifiSSIDAndPwd(cur_info->ssid, cur_info->pwsd, wstrWifiSSID, hClient, &pIfInfo->InterfaceGuid);
            cur_info->adapter_name = StringHelper::tolower(UidHelper::UUIDToString(pIfInfo->InterfaceGuid));
            cur_info->adapter_dec = StringHelper::tolower(StringHelper::tochar(std::wstring(pIfInfo->strInterfaceDescription)));
            GetWifiDot11AuthAndCipherAlgorthim(cur_info->dot11DefaultAuthAlgorithm, cur_info->dot11DefaultCipherAlgorithm, wstrWifiSSID, hClient, &pIfInfo->InterfaceGuid);
            GetWifiBSSID(cur_info->bssid, wstrWifiSSID, hClient, &pIfInfo->InterfaceGuid);
        }
    } while (0);

    if (pIfList)
    {
        WlanFreeMemory(pIfList);
        pIfList = NULL;
    }
    if (hClient)
    {
        WlanCloseHandle(hClient, NULL);
        hClient = NULL;
    }
#elif defined(__GNUC__)
    int fd, intrface;
    struct ifreq buf[40] = { { 0 } };
    struct iwreq wreq = { 0 };
    struct ifconf ifc;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return valid_count;
    ifc.ifc_len = sizeof buf;
    ifc.ifc_buf = (caddr_t)buf;
    if (ioctl(fd, SIOCGIFCONF, (char *)&ifc))
    {
        close(fd);
        return valid_count;
    }

    intrface = ifc.ifc_len / sizeof(struct ifreq);
    while (intrface-- > 0)
    {
        if (ioctl(fd, SIOCGIFFLAGS, (char *)&buf[intrface])) continue;
        if (!(buf[intrface].ifr_flags&IFF_UP)) continue;
        snprintf(wreq.ifr_name, sizeof(wreq.ifr_name), "%s", buf[intrface].ifr_name);
        char buffer[64] = { 0 };
        wreq.u.essid.pointer = buffer;
        wreq.u.essid.length = sizeof(buffer);
        if (ioctl(fd, SIOCGIWESSID, &wreq)) continue;
        valid_count++;
        if (infos == NULL) continue;
        if (valid_count > count) break;
        WifiInfo *info = &infos[valid_count - 1];
        info->adapter_name = StringHelper::tolower(buf[intrface].ifr_name);
        info->ssid = buffer;
        if (!ioctl(fd, SIOCGIWAP, &wreq))
        {
            info->bssid = StringHelper::byte2basestr((unsigned char *)wreq.u.ap_addr.sa_data, 6, NETWORK_INFO_MAC_SPLITE, StringHelper::hex, 2);
        }
        std::string cmd = "grep ^psk $(find /etc/NetworkManager -name " + info->ssid + " | head -1) | awk -F= '{print $2}'";
        info->pwsd = StringHelper::replace(Kernel32Helper::ExecuteCMDAndGetResult(cmd), "\n", "");
    }
    close(fd);
#else
#error unsupported compiler
#endif
    return valid_count;
}

u_int NetworkInfoHelper::GetAllAdaptInfo(AdaptInfo *infos, u_int count, bool need_gateway_mac)
{
    u_int valid_count = 0;
#if defined(_MSC_VER)
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    ULONG ulLen = 0;

    ::GetAdaptersInfo(pAdapterInfo, &ulLen);
    pAdapterInfo = (PIP_ADAPTER_INFO)::GlobalAlloc(GPTR, ulLen);
    if (pAdapterInfo == NULL)
    {
        return valid_count;
    }
    if (::GetAdaptersInfo(pAdapterInfo, &ulLen) != ERROR_SUCCESS)
    {
        ::GlobalFree(pAdapterInfo);
        return valid_count;
    }

    PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
    while (pAdapter != NULL)
    {
        DWORD dwGatewayIP = NetworkHelper::IPStr2Addr(pAdapter->GatewayList.IpAddress.String).s_addr;
        DWORD dwLocalIP = NetworkHelper::IPStr2Addr(pAdapter->IpAddressList.IpAddress.String).s_addr;
        DWORD dwIPMask = NetworkHelper::IPStr2Addr(pAdapter->IpAddressList.IpMask.String).s_addr;
        if (dwGatewayIP == 0 || dwLocalIP == 0 || dwIPMask == 0)
        {
            pAdapter = pAdapter->Next;
            continue;
        }
        valid_count++;
        if (infos == NULL)
        {
            pAdapter = pAdapter->Next;
            continue;
        }
        if (valid_count > count) break;
        AdaptInfo *info = &infos[valid_count - 1];
        info->local_mac_address = StringHelper::byte2basestr((u_char *)pAdapter->Address, 6, NETWORK_INFO_MAC_SPLITE, StringHelper::hex, 2);
        memcpy(info->local_mac_address_int, pAdapter->Address, sizeof(info->local_mac_address_int));
        in_addr in;
        in.s_addr = dwLocalIP;
        info->local_ip_address = pAdapter->IpAddressList.IpAddress.String;
        info->local_ip_address_int = in;
        in.s_addr = dwGatewayIP;
        info->gateway_ip_address = pAdapter->GatewayList.IpAddress.String;
        info->gateway_ip_address_int = in;
        if (need_gateway_mac) {
            info->gateway_mac_address = GetMacFromAddress(in, 3000, pAdapter->Index, info->local_ip_address_int);
            StringHelper::hex2byte(StringHelper::replace(info->gateway_mac_address, NETWORK_INFO_MAC_SPLITE, ""), (char *)info->gateway_mac_address_int, sizeof(info->gateway_mac_address_int));
        }
        in.s_addr = dwIPMask;
        info->subnet_ip_mask = pAdapter->IpAddressList.IpMask.String;
        info->subnet_ip_mask_int = in;
        in.s_addr = NetworkHelper::IPStr2Addr(pAdapter->DhcpServer.IpAddress.String).s_addr;
        info->dhcp_ip_address = pAdapter->DhcpServer.IpAddress.String;
        info->dhcp_ip_address_int = in;
        info->adapter_name = StringHelper::tolower(pAdapter->AdapterName);
        info->adapter_dec = StringHelper::tolower(pAdapter->Description);
        info->guid = UidHelper::StringToUUID(StringHelper::towchar(info->adapter_name));
        info->index = pAdapter->Index;
        if (GetIpv6ByIndex(info->local_ipv6_address_int, info->index))
        {
            info->local_ipv6_address = NetworkHelper::IPAddr2StrV6(info->local_ipv6_address_int);
        }
        pAdapter = pAdapter->Next;
    }
    ::GlobalFree(pAdapterInfo);
#elif defined(__GNUC__)
    int fd, intrface;
    struct ifreq buf[40] = { { 0 } };
    struct ifconf ifc;
    RouteInfo *route_infos = NULL;
    u_int route_count = 0;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return valid_count;
    ifc.ifc_len = sizeof buf;
    ifc.ifc_buf = (caddr_t)buf;
    if (ioctl(fd, SIOCGIFCONF, (char *)&ifc))
    {
        close(fd);
        return valid_count;
    }

    if (infos)
    {
        route_count = GetAllRouteInfo(NULL, 0);
        if (route_count)
        {
            route_infos = new (std::nothrow) RouteInfo[route_count];
            if (route_infos == NULL) return valid_count;
            route_count = GetAllRouteInfo(route_infos, route_count);
        }
    }

    intrface = ifc.ifc_len / sizeof(struct ifreq);
    while (intrface-- > 0)
    {
        if (ioctl(fd, SIOCGIFFLAGS, (char *)&buf[intrface])) continue;
        if (!(buf[intrface].ifr_flags&IFF_UP)) continue;
        valid_count++;
        if (infos == NULL) continue;
        if (valid_count > count) break;
        AdaptInfo *info = &infos[valid_count - 1];
        info->adapter_name = StringHelper::tolower(buf[intrface].ifr_name);
        //get local ip
        if (!ioctl(fd, SIOCGIFADDR, (char *)&buf[intrface]))
        {
            info->local_ip_address = ::inet_ntoa(((struct sockaddr_in*)(&buf[intrface].ifr_addr))->sin_addr);
            info->local_ip_address_int = ((struct sockaddr_in*)(&buf[intrface].ifr_addr))->sin_addr;
        }
        //get local mac
        if (!ioctl(fd, SIOCGIFHWADDR, (char *)&buf[intrface]))
        {
            info->local_mac_address = StringHelper::byte2basestr((u_char *)buf[intrface].ifr_hwaddr.sa_data, 6, NETWORK_INFO_MAC_SPLITE, StringHelper::hex, 2);
            memcpy(info->local_mac_address_int, buf[intrface].ifr_hwaddr.sa_data, sizeof(info->local_mac_address_int));
        }
        //get net mask
        if (!ioctl(fd, SIOCGIFNETMASK, (char *)&buf[intrface]))
        {
            info->subnet_ip_mask = ::inet_ntoa(((struct sockaddr_in*)(&buf[intrface].ifr_netmask))->sin_addr);
            info->subnet_ip_mask_int = ((struct sockaddr_in*)(&buf[intrface].ifr_netmask))->sin_addr;
        }
        //get index
        if (!ioctl(fd, SIOCGIFINDEX, (char *)&buf[intrface]))
        {
            info->index = buf[intrface].ifr_ifindex;
            if (GetIpv6ByIndex(info->local_ipv6_address_int, info->index))
            {
                info->local_ipv6_address = NetworkHelper::IPAddr2StrV6(info->local_ipv6_address_int);
            }
        }
        //get gateway info
        for (int i = 0; i < route_count; i++)
        {
            RouteInfo *route_info = &route_infos[i];
            if (route_info->index != info->index) continue;
            if (!route_info->gateWay) continue;
            info->gateway_ip_address_int.s_addr = route_info->gateWay;
            info->gateway_ip_address = NetworkHelper::IPAddr2Str(info->gateway_ip_address_int);
            if (need_gateway_mac) {
                char buff[128] = { 0 };
                unsigned char mac[6] = { 0 };
                u_long len = sizeof(mac);
                if (SendARPPrivate(info->gateway_ip_address_int.s_addr, *info, mac, &len, 1000) == 0 && len == 6)
                {
                    info->gateway_mac_address = StringHelper::byte2basestr(mac, 6, NETWORK_INFO_MAC_SPLITE, StringHelper::hex, 2);
                    memcpy(info->gateway_mac_address_int, mac, sizeof(info->gateway_mac_address_int));
                }
            }
            break;
        }
    }
    close(fd);
    if (route_infos) delete[]route_infos;
#else
#error unsupported compiler
#endif
    return valid_count;
}

/**
*get the network category info
*guid(in) eth guid
*max_wait_time(in) max wait time for this func
*/
NetworkInfoHelper::CategoryInfo NetworkInfoHelper::GetCategoryInfo(const GUID &guid, u_int max_wait_time)
{
    CategoryInfo result;
#if defined(_MSC_VER)
    HRESULT hr = S_OK;
    HRESULT hrCoinit = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (!SUCCEEDED(hrCoinit) && !(RPC_E_CHANGED_MODE == hrCoinit))
    {
        return result;
    }

    do
    {
        CComPtr<INetworkListManager> pNLM;
        hr = CoCreateInstance(CLSID_NetworkListManager, NULL, CLSCTX_ALL, __uuidof(INetworkListManager), (LPVOID*)&pNLM);
        if (!SUCCEEDED(hr))
        {
            break;
        }

        CComPtr<IEnumNetworkConnections> pEnumNetworks;
        hr = pNLM->GetNetworkConnections(&pEnumNetworks);
        if (hr != S_OK)
        {
            break;
        }

        CComPtr<INetwork> pNetwork;
        BOOL  bDone = FALSE;
        while (!bDone)
        {
            INetworkConnection* pNetworks[NUM_NETWORK];
            ULONG cFetched = 0;
            hr = pEnumNetworks->Next(_countof(pNetworks), pNetworks, &cFetched);
            if (hr != S_OK || cFetched == 0)
            {
                bDone = true;
                continue;
            }

            for (ULONG i = 0; i < cFetched; i++)
            {
                GUID adapt_id;
                hr = pNetworks[i]->GetAdapterId(&adapt_id);
                if (hr != S_OK)
                {
                    continue;
                }
                if (!memcmp(&adapt_id, &guid, sizeof(adapt_id)))
                {
                    pNetworks[i]->GetNetwork(&pNetwork);
                    bDone = true;
                    break;
                }
            }
            for (ULONG i = 0; i < cFetched; i++)
            {
                pNetworks[i]->Release();
            }
        }

        if (pNetwork == NULL)
        {
            break;
        }

        u_int count = 0;
        WCHAR *buf = NULL;
        do
        {
            hr = pNetwork->GetName(reinterpret_cast<BSTR*>(&buf));
            if (hr == S_OK)
            {
                result.category_name = StringHelper::tochar(buf);
                StringHelper::tolower(result.category_name);
                SysFreeString(reinterpret_cast<BSTR>(buf));
                buf = NULL;
            }

            if (result.category_name.find("identifying") != std::string::npos)
            {
                count++;
                Sleep(500);
            }
        } while (count && count < max_wait_time / 500);

        VARIANT_BOOL bNetworkIsConnectedToInternet;
        hr = pNetwork->get_IsConnectedToInternet(&bNetworkIsConnectedToInternet);
        if (hr == S_OK)
        {
            result.is_connect_to_internet = bNetworkIsConnectedToInternet;
        }

        VARIANT_BOOL bNetworkIsConnected;
        hr = pNetwork->get_IsConnected(&bNetworkIsConnected);
        if (hr == S_OK)
        {
            result.is_connected = bNetworkIsConnected;
        }

        hr = pNetwork->GetDescription(reinterpret_cast<BSTR*>(&buf));
        if (hr == S_OK)
        {
            result.category_dec = StringHelper::tochar(buf);
            StringHelper::tolower(result.category_dec);
            SysFreeString(reinterpret_cast<BSTR>(buf));
            buf = NULL;
        }

        NLM_NETWORK_CATEGORY category;
        hr = pNetwork->GetCategory(&category);
        if (hr == S_OK)
        {
            result.network_category = category;
        }

        NLM_DOMAIN_TYPE domain_type;
        hr = pNetwork->GetDomainType(&domain_type);
        if (hr == S_OK)
        {
            result.domain_type = domain_type;
        }

        NLM_CONNECTIVITY connective;
        hr = pNetwork->GetConnectivity(&connective);
        if (hr == S_OK)
        {
            result.connective = connective;
        }
    } while (0);

    if (RPC_E_CHANGED_MODE != hrCoinit)
    {
        CoUninitialize();
    }
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif
    return result;
}

NetworkInfoHelper::NetworkInfoHelper()
{
    bool is_network_changed;
    UpadteNetworkInfo(is_network_changed);
}

NetworkInfoHelper::~NetworkInfoHelper()
{
}

std::string NetworkInfoHelper::GetNetWorkName()
{
    std::unique_lock<std::mutex> lck(m_netowrk_info_lock);

    std::string work_name;
#if defined(_MSC_VER)
    if (m_cur_network_info.is_wifi)
    {
        work_name = m_cur_network_info.wifi_info.ssid;
    }
    else
    {
        work_name = m_cur_network_info.adapt_info.adapter_dec;
    }
#elif defined(__GNUC__)
    work_name = m_cur_network_info.adapt_info.adapter_name;
#else
#error unsupported compiler
#endif
    return work_name;
}

std::string NetworkInfoHelper::GetGatewayMac()
{
    std::unique_lock<std::mutex> lck(m_netowrk_info_lock);

    if (!m_cur_network_info.adapt_info.gateway_mac_address.empty())
    {
        return m_cur_network_info.adapt_info.gateway_mac_address;
    }

    if (m_cur_network_info.adapt_info.gateway_ip_address.empty())
    {
        return "";
    }

    m_cur_network_info.adapt_info.gateway_mac_address = GetMacFromAddress(m_cur_network_info.adapt_info.gateway_ip_address_int, 3000, m_cur_network_info.adapt_info.index, m_cur_network_info.adapt_info.local_ip_address_int);
    StringHelper::hex2byte(StringHelper::replace(m_cur_network_info.adapt_info.gateway_mac_address, NETWORK_INFO_MAC_SPLITE, ""), (char *)m_cur_network_info.adapt_info.gateway_mac_address_int, sizeof(m_cur_network_info.adapt_info.gateway_mac_address_int));
    return m_cur_network_info.adapt_info.gateway_mac_address;
}

std::string NetworkInfoHelper::GetPreNetworkGatewayMac()
{
    std::unique_lock<std::mutex> lck(m_netowrk_info_lock);
    return m_pre_network_info.adapt_info.gateway_mac_address;
}

bool NetworkInfoHelper::IsConnectToInternet()
{
    std::unique_lock<std::mutex> lck(m_netowrk_info_lock);
#if defined(_MSC_VER)
    return m_cur_network_info.category_info.is_connect_to_internet == -1 ? true : false;
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif
    return false;
}

bool NetworkInfoHelper::GetWifiInfo()
{
    bool bGetWifiInfo = false;
#if defined(_MSC_VER)
    HANDLE                      hClient = NULL;
    PWLAN_INTERFACE_INFO_LIST   pIfList = NULL;
    do
    {
        DWORD   dwMaxClient = 2;
        DWORD   dwCurVersion = 0;
        DWORD   dwResult = 0;

        dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
        if (dwResult != ERROR_SUCCESS)
        {
            break;
        }
        dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
        if (dwResult != ERROR_SUCCESS)
        {
            break;
        }

        for (DWORD i = 0; i != pIfList->dwNumberOfItems; i++)
        {
            PWLAN_INTERFACE_INFO pIfInfo = (WLAN_INTERFACE_INFO *)&pIfList->InterfaceInfo[i];
            std::wstring wstrWifiSSID;
            if (pIfInfo->isState != wlan_interface_state_connected) continue;
            if (!GetWStrWifiSSID(wstrWifiSSID, hClient, &pIfInfo->InterfaceGuid)) continue;
            GetWifiSSIDAndPwd(m_last_update_network_info.wifi_info.ssid, m_last_update_network_info.wifi_info.pwsd, wstrWifiSSID, hClient, &pIfInfo->InterfaceGuid);
            m_last_update_network_info.wifi_info.adapter_name = StringHelper::tolower(UidHelper::UUIDToString(pIfInfo->InterfaceGuid));
            m_last_update_network_info.wifi_info.adapter_dec = StringHelper::tolower(StringHelper::tochar(std::wstring(pIfInfo->strInterfaceDescription)));
            GetWifiDot11AuthAndCipherAlgorthim(m_last_update_network_info.wifi_info.dot11DefaultAuthAlgorithm, m_last_update_network_info.wifi_info.dot11DefaultCipherAlgorithm, wstrWifiSSID, hClient, &pIfInfo->InterfaceGuid);
            GetWifiBSSID(m_last_update_network_info.wifi_info.bssid, wstrWifiSSID, hClient, &pIfInfo->InterfaceGuid);
            bGetWifiInfo = true;
            break;
        }
    } while (0);

    if (pIfList)
    {
        WlanFreeMemory(pIfList);
        pIfList = NULL;
    }
    if (hClient)
    {
        WlanCloseHandle(hClient, NULL);
        hClient = NULL;
    }
#elif defined(__GNUC__)
    int fd, intrface;
    struct ifreq buf[40] = { { 0 } };
    struct iwreq wreq = { 0 };
    struct ifconf ifc;
    u_int gateway_eth_index;
    u_int gateway_ip = 0;
    GetDefaultGateway(gateway_ip, gateway_eth_index);
    if (!gateway_ip) return bGetWifiInfo;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return bGetWifiInfo;
    ifc.ifc_len = sizeof buf;
    ifc.ifc_buf = (caddr_t)buf;
    if (ioctl(fd, SIOCGIFCONF, (char *)&ifc))
    {
        close(fd);
        return bGetWifiInfo;
    }

    intrface = ifc.ifc_len / sizeof(struct ifreq);
    while (intrface-- > 0)
    {
        if (ioctl(fd, SIOCGIFFLAGS, (char *)&buf[intrface])) continue;
        if (!(buf[intrface].ifr_flags&IFF_UP)) continue;
        if (ioctl(fd, SIOCGIFINDEX, (char *)&buf[intrface])) continue;
        if (buf[intrface].ifr_ifindex != gateway_eth_index) continue;
        snprintf(wreq.ifr_name, sizeof(wreq.ifr_name), "%s", buf[intrface].ifr_name);
        char buffer[64] = { 0 };
        wreq.u.essid.pointer = buffer;
        wreq.u.essid.length = sizeof(buffer);
        if (ioctl(fd, SIOCGIWESSID, &wreq)) break;
        bGetWifiInfo = true;
        m_last_update_network_info.wifi_info.adapter_name = StringHelper::tolower(buf[intrface].ifr_name);
        m_last_update_network_info.wifi_info.ssid = buffer;
        if (!ioctl(fd, SIOCGIWAP, &wreq))
        {
            m_last_update_network_info.wifi_info.bssid = StringHelper::byte2basestr((unsigned char *)wreq.u.ap_addr.sa_data, 6, NETWORK_INFO_MAC_SPLITE, StringHelper::hex, 2);
        }
        std::string cmd = "grep ^psk $(find /etc/NetworkManager -name " + m_last_update_network_info.wifi_info.ssid + " | head -1) | awk -F= '{print $2}'";
        m_last_update_network_info.wifi_info.pwsd = StringHelper::replace(Kernel32Helper::ExecuteCMDAndGetResult(cmd),"\n","");
    }
    close(fd);
#else
#error unsupported compiler
#endif
    return bGetWifiInfo;
}

void NetworkInfoHelper::GetAdaptInfo()
{
#if defined(_MSC_VER)
    u_char  ucLocalMac[6] = { 0 };
    DWORD   dwGatewayIP = 0;
    DWORD   dwLocalIP = 0;
    DWORD   dwIPMask = 0;
    DWORD   dwDHCPIP = 0;
    DWORD   index = -1;
    std::string adapt_name;
    std::string adapt_dec;

    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    ULONG ulLen = 0;
    u_int valid_count = 0;

    ::GetAdaptersInfo(pAdapterInfo, &ulLen);
    pAdapterInfo = (PIP_ADAPTER_INFO)::GlobalAlloc(GPTR, ulLen);
    if (pAdapterInfo == NULL) return;
    if (::GetAdaptersInfo(pAdapterInfo, &ulLen) != ERROR_SUCCESS)
    {
        ::GlobalFree(pAdapterInfo);
        return;
    }

    PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
    while (pAdapter != NULL)
    {
        memcpy(ucLocalMac, pAdapter->Address, 6);
        dwGatewayIP = NetworkHelper::IPStr2Addr(pAdapter->GatewayList.IpAddress.String).s_addr;
        dwLocalIP = NetworkHelper::IPStr2Addr(pAdapter->IpAddressList.IpAddress.String).s_addr;
        dwIPMask = NetworkHelper::IPStr2Addr(pAdapter->IpAddressList.IpMask.String).s_addr;
        dwDHCPIP = NetworkHelper::IPStr2Addr(pAdapter->DhcpServer.IpAddress.String).s_addr;
        index = pAdapter->Index;
        std::string adapt_name_tmp = pAdapter->AdapterName;
        StringHelper::tolower(adapt_name_tmp);
        std::string adapt_dec_tmp = pAdapter->Description;
        StringHelper::tolower(adapt_dec_tmp);
        if (m_last_update_network_info.is_wifi)
        {
            if (("{" + m_last_update_network_info.wifi_info.adapter_name + "}") == adapt_name_tmp)
            {
                adapt_name = adapt_name_tmp;
                adapt_dec = adapt_dec_tmp;
                break;
            }
        }
        else if (dwGatewayIP != 0 && dwLocalIP != 0 && dwIPMask != 0)
        {
            adapt_name = adapt_name_tmp;
            adapt_dec = adapt_dec_tmp;
            break;
        }

        dwGatewayIP = 0;
        dwLocalIP = 0;
        dwIPMask = 0;
        dwDHCPIP = 0;
        index = -1;
        pAdapter = pAdapter->Next;
    }
    ::GlobalFree(pAdapterInfo);

    m_last_update_network_info.adapt_info.local_mac_address = StringHelper::byte2basestr(ucLocalMac, 6, NETWORK_INFO_MAC_SPLITE, StringHelper::hex, 2);
    memcpy(m_last_update_network_info.adapt_info.local_mac_address_int, ucLocalMac, sizeof(m_last_update_network_info.adapt_info.local_mac_address_int));

    in_addr in;
    in.s_addr = dwLocalIP;
    m_last_update_network_info.adapt_info.local_ip_address = NetworkHelper::IPAddr2Str(in);
    m_last_update_network_info.adapt_info.local_ip_address_int = in;

    in.s_addr = dwGatewayIP;
    m_last_update_network_info.adapt_info.gateway_ip_address = NetworkHelper::IPAddr2Str(in);
    m_last_update_network_info.adapt_info.gateway_mac_address = GetMacFromAddress(in, 3000, index, m_last_update_network_info.adapt_info.local_ip_address_int);
    m_last_update_network_info.adapt_info.gateway_ip_address_int = in;
    StringHelper::hex2byte(StringHelper::replace(m_last_update_network_info.adapt_info.gateway_mac_address, NETWORK_INFO_MAC_SPLITE, ""), (char *)m_last_update_network_info.adapt_info.gateway_mac_address_int, sizeof(m_last_update_network_info.adapt_info.gateway_mac_address_int));

    in.s_addr = dwIPMask;
    m_last_update_network_info.adapt_info.subnet_ip_mask = NetworkHelper::IPAddr2Str(in);
    m_last_update_network_info.adapt_info.subnet_ip_mask_int = in;

    in.s_addr = dwDHCPIP;
    m_last_update_network_info.adapt_info.dhcp_ip_address = NetworkHelper::IPAddr2Str(in);
    m_last_update_network_info.adapt_info.dhcp_ip_address_int = in;

    m_last_update_network_info.adapt_info.adapter_name = adapt_name;
    m_last_update_network_info.adapt_info.adapter_dec = adapt_dec;
    m_last_update_network_info.adapt_info.guid = UidHelper::StringToUUID(StringHelper::towchar(adapt_name));

    m_last_update_network_info.adapt_info.index = index;

    if (GetIpv6ByIndex(m_last_update_network_info.adapt_info.local_ipv6_address_int, m_last_update_network_info.adapt_info.index))
    {
        m_last_update_network_info.adapt_info.local_ipv6_address = NetworkHelper::IPAddr2StrV6(m_last_update_network_info.adapt_info.local_ipv6_address_int);
    }
#elif defined(__GNUC__)
    int fd, intrface;
    struct ifreq buf[40] = { { 0 } };
    struct ifconf ifc;
    u_int gateway_eth_index;
    u_int gateway_ip = 0;
    GetDefaultGateway(gateway_ip, gateway_eth_index);
    if (!gateway_ip) return;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return;
    ifc.ifc_len = sizeof buf;
    ifc.ifc_buf = (caddr_t)buf;
    if (ioctl(fd, SIOCGIFCONF, (char *)&ifc))
    {
        close(fd);
        return;
    }

    intrface = ifc.ifc_len / sizeof(struct ifreq);
    while (intrface-- > 0)
    {
        if (ioctl(fd, SIOCGIFFLAGS, (char *)&buf[intrface])) continue;
        if (!(buf[intrface].ifr_flags&IFF_UP)) continue;
        if (ioctl(fd, SIOCGIFINDEX, (char *)&buf[intrface])) continue;
        //get index
        if (buf[intrface].ifr_ifindex != gateway_eth_index) continue;
        m_last_update_network_info.adapt_info.index = buf[intrface].ifr_ifindex;
        if (GetIpv6ByIndex(m_last_update_network_info.adapt_info.local_ipv6_address_int, m_last_update_network_info.adapt_info.index))
        {
            m_last_update_network_info.adapt_info.local_ipv6_address = NetworkHelper::IPAddr2StrV6(m_last_update_network_info.adapt_info.local_ipv6_address_int);
        }
        m_last_update_network_info.adapt_info.adapter_name = StringHelper::tolower(buf[intrface].ifr_name);
        //get local ip
        if (!ioctl(fd, SIOCGIFADDR, (char *)&buf[intrface]))
        {
            m_last_update_network_info.adapt_info.local_ip_address = ::inet_ntoa(((struct sockaddr_in*)(&buf[intrface].ifr_addr))->sin_addr);
            m_last_update_network_info.adapt_info.local_ip_address_int = ((struct sockaddr_in*)(&buf[intrface].ifr_addr))->sin_addr;
        }
        //get local mac
        if (!ioctl(fd, SIOCGIFHWADDR, (char *)&buf[intrface]))
        {
            m_last_update_network_info.adapt_info.local_mac_address = StringHelper::byte2basestr((unsigned char*)buf[intrface].ifr_hwaddr.sa_data, 6, NETWORK_INFO_MAC_SPLITE, StringHelper::hex, 2);
            memcpy(m_last_update_network_info.adapt_info.local_mac_address_int, buf[intrface].ifr_hwaddr.sa_data, sizeof(m_last_update_network_info.adapt_info.local_mac_address_int));
        }
        //get net mask
        if (!ioctl(fd, SIOCGIFNETMASK, (char *)&buf[intrface]))
        {
            m_last_update_network_info.adapt_info.subnet_ip_mask = ::inet_ntoa(((struct sockaddr_in*)(&buf[intrface].ifr_netmask))->sin_addr);
            m_last_update_network_info.adapt_info.subnet_ip_mask_int = ((struct sockaddr_in*)(&buf[intrface].ifr_netmask))->sin_addr;
        }
        //get gateway info
        m_last_update_network_info.adapt_info.gateway_ip_address_int.s_addr = gateway_ip;
        m_last_update_network_info.adapt_info.gateway_ip_address = NetworkHelper::IPAddr2Str(m_last_update_network_info.adapt_info.gateway_ip_address_int);
        char buff[128] = { 0 };
        unsigned char mac[6] = { 0 };
        u_long len = sizeof(mac);
        if (SendARPPrivate(m_last_update_network_info.adapt_info.gateway_ip_address_int.s_addr, m_last_update_network_info.adapt_info, mac, &len, 1000) == 0 && len == 6)
        {
            m_last_update_network_info.adapt_info.gateway_mac_address = StringHelper::byte2basestr(mac, 6, NETWORK_INFO_MAC_SPLITE, StringHelper::hex, 2);
            memcpy(m_last_update_network_info.adapt_info.gateway_mac_address_int, mac, sizeof(m_last_update_network_info.adapt_info.gateway_mac_address_int));
        }
        break;
    }
    close(fd);
#else
#error unsupported compiler
#endif
}

void NetworkInfoHelper::UpadteNetworkInfo(bool &is_network_change)
{
    std::unique_lock<std::mutex> lck(m_netowrk_info_lock);
    is_network_change = false;
    m_last_update_network_info.clear();
    m_last_update_network_info.is_wifi = GetWifiInfo();
    GetAdaptInfo();
    m_last_update_network_info.category_info = GetCategoryInfo(m_last_update_network_info.adapt_info.guid);
    AdaptGatewayMacAddress();
    if ((m_last_update_network_info.adapt_info.gateway_ip_address_int.s_addr == 0 && m_last_update_network_info.adapt_info.local_ip_address_int.s_addr == 0)
        || (m_last_update_network_info.adapt_info.gateway_ip_address_int.s_addr != 0 && m_last_update_network_info.adapt_info.local_ip_address_int.s_addr != 0 && (u_char)(m_last_update_network_info.adapt_info.local_ip_address_int.s_addr>>24) != 169))
    {//the condition present valid network info
        if ((m_last_update_network_info.adapt_info.gateway_mac_address != m_cur_network_info.adapt_info.gateway_mac_address)
            || (m_last_update_network_info.adapt_info.gateway_mac_address.empty() && m_last_update_network_info.adapt_info.gateway_ip_address_int.s_addr != m_cur_network_info.adapt_info.gateway_ip_address_int.s_addr))
        {
            m_pre_network_info = m_cur_network_info;
            m_cur_network_info = m_last_update_network_info;
            is_network_change = true;
        }
    }
}

bool NetworkInfoHelper::IsWifi()
{
    std::unique_lock<std::mutex> lck(m_netowrk_info_lock);
    return m_cur_network_info.is_wifi;
}

NetworkInfoHelper::NetworkInfo NetworkInfoHelper::GetNetworkInfo()
{
    std::unique_lock<std::mutex> lck(m_netowrk_info_lock);
    return m_cur_network_info;
}

NetworkInfoHelper::NetworkInfo NetworkInfoHelper::GetPreNetworkInfo()
{
    std::unique_lock<std::mutex> lck(m_netowrk_info_lock);
    return m_pre_network_info;
}

void NetworkInfoHelper::AdaptGatewayMacAddress()
{
    if (!m_last_update_network_info.adapt_info.gateway_mac_address.empty())
    {
        return;
    }

    if (m_last_update_network_info.adapt_info.gateway_ip_address == m_cur_network_info.adapt_info.gateway_ip_address
        && m_last_update_network_info.adapt_info.local_ip_address == m_cur_network_info.adapt_info.local_ip_address)
    {
        m_last_update_network_info.adapt_info.gateway_mac_address = m_cur_network_info.adapt_info.gateway_mac_address;
        memcpy(m_last_update_network_info.adapt_info.gateway_mac_address_int, m_cur_network_info.adapt_info.gateway_mac_address_int, sizeof(m_last_update_network_info.adapt_info.gateway_mac_address_int));
    }
}
