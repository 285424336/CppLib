
#define WIN32_LEAN_AND_MEAN

#include "ArpTableHelper.h"
#include <string>
#include <map>
#include <stdio.h>
#include <stdlib.h>
#if defined(_MSC_VER)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <iphlpapi.h>
#include <network\NetworkHelper.h>
#include <string\StringHelper.h>
#elif defined(__GNUC__)
#include <network/NetworkHelper.h>
#include <network/NetworkInfoHelper.h>
#include <kernel32/Kernel32Helper.h>
#include <string/StringHelper.h>
#include <net/if.h>
#else
#error unsupported compiler
#endif

#if defined(_MSC_VER)
#pragma comment(lib, "IPHLPAPI.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif

std::map<std::string, std::string> ArpTableHelper::GetArpTable(const unsigned int eth_index)
{
    std::map<std::string, std::string> arp_info;
#if defined(_MSC_VER)
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    unsigned int i = 0, j = 0;
    MIB_IPNETTABLE *pArpTable = NULL;
    MIB_IPNETROW *pArpRow = NULL;

    pArpTable = (MIB_IPNETTABLE *)MALLOC(sizeof(MIB_IPNETTABLE));
    if (pArpTable == NULL) return arp_info;

    dwSize = sizeof(MIB_IPNETTABLE);
    if (GetIpNetTable(pArpTable, &dwSize, FALSE) == ERROR_INSUFFICIENT_BUFFER)
    {
        FREE(pArpTable);
        pArpTable = (MIB_IPNETTABLE *)MALLOC(dwSize);
        if (pArpTable == NULL) return arp_info;
    }
    if ((dwRetVal = GetIpNetTable(pArpTable, &dwSize, FALSE)) != NO_ERROR)
    {
        FREE(pArpTable);
        pArpTable = NULL;
        return arp_info;
    }

    for (i = 0; i < pArpTable->dwNumEntries; i++) {
        pArpRow = (MIB_IPNETROW *)& pArpTable->table[i];
        if (eth_index != pArpRow->dwIndex) continue;
        unsigned char *paddr = (unsigned char *)&pArpRow->dwAddr;
        if (!pArpRow->dwAddr || paddr[0]>(unsigned char)223) continue;
        IN_ADDR addr = { 0 };
        addr.s_addr = pArpRow->dwAddr;
        std::string ip = NetworkHelper::IPAddr2Str(addr);
        std::string mac = StringHelper::byte2basestr(pArpRow->bPhysAddr, pArpRow->dwPhysAddrLen, ":", StringHelper::hex, 2);
        if (mac == "00:00:00:00:00:00" || mac == "FF:FF:FF:FF:FF:FF") continue;
        arp_info[ip] = mac;
    }

    FREE(pArpTable);
    pArpTable = NULL;
    return arp_info;
#elif defined(__GNUC__)
    char buf[40] = { 0 };
    if (if_indextoname(eth_index, buf) == NULL)
    {
        return arp_info;
    }

    std::string cmd = std::string() + "arp -n | grep -i " + buf + " | grep -v grep | awk '{print $1\" \"$3}'";
    std::string result = Kernel32Helper::ExecuteCMDAndGetResult(cmd);
    auto arps = StringHelper::split(result, "\n");
    for (auto arp : arps)
    {
        if (arp.empty())
        {
            continue;
        }

        auto pair = StringHelper::split(arp, " ");
        if (pair.size() != 2)
        {
            continue;
        }

        if (pair[0].empty() || pair[1].empty() || pair[1].find(":")==std::string::npos)
        {
            continue;
        }
        arp_info[pair[0]] = pair[1];
    }
    return arp_info;
#if 0
    //another way to get arp cache, but ubuntu dont support compile
    int mib[6] = { 0 };
    char *buf = NULL;
    size_t lenp = 0;
    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_INET;		/* only addresses of this family */
    mib[4] = NET_RT_FLAGS;
    mib[5] = RTF_LLINFO;
    if (sysctl(mib, 6, NULL, &lenp, NULL, 0) < 0)
    {
        return arp_info;
    }

    if ((buf = new (std::nothrow) char[lenp]) == NULL)
    {
        return arp_info;
    }

    do
    {
        if (sysctl(mib, 6, buf, &lenp, NULL, 0) < 0)
        {
            break;
        }

        struct rt_msghdr *rtm = NULL;
        struct sockaddr_inarp *sin = NULL;
        struct sockaddr_dl *sdl = NULL;
        char *next = buf;
        for (; next < buf + lenp; next += rtm->rtm_msglen)
        {
            rtm = (struct rt_msghdr *)next;
            sin = (struct sockaddr_inarp *)(rtm + 1);
            sdl = (struct sockaddr_dl *)(sin + 1);

            if (sdl->sdl_alen == 6)
            {
                std::string ip = NetworkHelper::IPAddr2Str(sin->sin_addr.s_addr);
                if (ip.empty())
                {
                    continue;
                }
                u_char *cp = LLADDR(sdl);
                std::string mac = StringHelper::byte2basestr(cp, 6, ":", StringHelper::hex, 2);
                arp_info[ip] = mac;
            }
        }

    } while (0);
    delete[]buf;
    return arp_info;
#endif
#else
#error unsupported compiler
#endif
}

bool ArpTableHelper::DeleteArpTable(const unsigned int eth_index)
{
#if defined(_MSC_VER)
    if (FlushIpNetTable(eth_index) != NO_ERROR) return false;
    return true;
#elif defined(__GNUC__)
    auto arps = GetArpTable(eth_index);
    for (auto arp : arps)
    {
        if (arp.first.empty())
        {
            continue;
        }
        std::string cmd = "arp -d " + arp.first;
        Kernel32Helper::ExecuteCMDAndGetResult(cmd);
    }
    return true;
#else
#error unsupported compiler
#endif
}