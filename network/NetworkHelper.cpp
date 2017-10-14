#include "NetworkHelper.h"

#if defined(_MSC_VER)
#pragma comment(lib,"ws2_32.lib")
#elif defined(__GNUC__)
#include <netdb.h>
#else
#error unsupported compiler
#endif

#ifdef __GNUC__
typedef struct
{
    union
    {
        struct
        {
            u_char s_b1, s_b2, s_b3, s_b4;
        } S_un_b; //An IPv4 address formatted as four u_chars.
        struct
        {
            u_short s_w1, s_w2;
        } S_un_w; //An IPv4 address formatted as two u_shorts
        u_long S_addr;//An IPv4 address formatted as a u_long
    } S_un;
    //#define s_addr  S_un.S_addr /* can be used for most tcp & ip code */
#define s_host  S_un.S_un_b.s_b2    // host on imp
#define s_net   S_un.S_un_b.s_b1    // network
#define s_imp   S_un.S_un_w.s_w2    // imp
#define s_impno S_un.S_un_b.s_b4    // imp #
#define s_lh    S_un.S_un_b.s_b3    // logical host
}IN_ADDR;
#endif // !WIN32

in_addr NetworkHelper::IPStr2Addr(const std::string &addr)
{
    in_addr result = { 0 };
    inet_pton(AF_INET, addr.c_str(), (void *)&result);
    return result;
}

std::string NetworkHelper::IPAddr2Str(const in_addr &addr)
{
    char str_buf[46] = { 0 };
    if (inet_ntop(AF_INET, (void *)&addr, str_buf, sizeof(str_buf)) == NULL) return "";
    return str_buf;
}

std::string NetworkHelper::IPAddr2Str(const u_int &addr)
{
    char str_buf[46] = { 0 };
    if (inet_ntop(AF_INET, (void *)&addr, str_buf, sizeof(str_buf)) == NULL) return "";
    return str_buf;
}

in6_addr NetworkHelper::IPStr2AddrV6(const std::string &addr)
{
    in6_addr result = { 0 };
    inet_pton(AF_INET6, addr.c_str(), (void *)&result);
    return result;
}

std::string NetworkHelper::IPAddr2StrV6(const in6_addr &addr)
{
    char str_buf[46] = { 0 };
    if (inet_ntop(AF_INET6, (void *)&addr, str_buf, sizeof(str_buf)) == NULL) return "";
    return str_buf;
}

bool NetworkHelper::IsValidMac(const char *mac)
{
    static char zero_mac[6] = { 0 };
    if (!mac) {
        return false;
    }
    return memcmp(mac, zero_mac, 6) != 0;
}

bool NetworkHelper::IsValidIp(const u_int &ip)
{
    return ip != 0;
}

bool NetworkHelper::IsValidIp(const in_addr &ip)
{
    return IsValidIp(ip.s_addr);
}

bool NetworkHelper::IsValidIp(const in6_addr &ip)
{
    static in6_addr zero_ip = { 0 };
    return memcmp(&ip, &zero_ip, sizeof(in6_addr)) != 0;
}

bool NetworkHelper::IsValidIp(const sockaddr &ip)
{
    if (ip.sa_family == AF_INET) {
        sockaddr_in *ipv4 = (sockaddr_in*)&ip;
        return IsValidIp(ipv4->sin_addr);
    }
    else if (ip.sa_family == AF_INET6) {
        sockaddr_in6 *ipv6 = (sockaddr_in6*)&ip;
        return IsValidIp(ipv6->sin6_addr);
    }
    return false;
}

std::set<std::string> NetworkHelper::GetNetIPs(const in_addr &int_eth_ip, const in_addr &int_net_mask)
{
    std::set<std::string> result;
    IN_ADDR int_ip_mask = { 0 };
    int_ip_mask.S_un.S_addr = int_eth_ip.s_addr & int_net_mask.s_addr;

    int device_count = (1 << (32 - AlgorithmHelper::BitCount((unsigned int)int_net_mask.s_addr))) - 2;

    for (int i = 1; i < device_count + 1; i++)
    {
        int_ip_mask.s_impno += 1;
        result.insert(IPAddr2Str(int_ip_mask.S_un.S_addr));
        if (int_ip_mask.s_impno != 255 || i >= device_count)
        {
            continue;
        }

        i++;
        int_ip_mask.s_impno = 0;
        int_ip_mask.s_lh += 1;
        result.insert(IPAddr2Str(int_ip_mask.S_un.S_addr));
        if (int_ip_mask.s_lh != 255 || i >= device_count)
        {
            continue;
        }

        i++;
        int_ip_mask.s_lh = 0;
        int_ip_mask.s_host += 1;
        result.insert(IPAddr2Str(int_ip_mask.S_un.S_addr));
        if (int_ip_mask.s_host != 255 || i >= device_count)
        {
            continue;
        }

        i++;
        int_ip_mask.s_host = 0;
        int_ip_mask.s_net += 1;
        result.insert(IPAddr2Str(int_ip_mask.S_un.S_addr));
    }
    return std::move(result);
}

std::set<u_int> NetworkHelper::GetNetIPs(const u_int &int_eth_ip, const u_int &int_net_mask)
{
    std::set<u_int> result;
    IN_ADDR int_ip_mask = { 0 };
    int_ip_mask.S_un.S_addr = int_eth_ip & int_net_mask;

    int device_count = (1 << (32 - AlgorithmHelper::BitCount(int_net_mask))) - 2;

    for (int i = 1; i < device_count + 1; i++)
    {
        int_ip_mask.s_impno += 1;
        result.insert(int_ip_mask.S_un.S_addr);
        if (int_ip_mask.s_impno != 255 || i >= device_count)
        {
            continue;
        }

        i++;
        int_ip_mask.s_impno = 0;
        int_ip_mask.s_lh += 1;
        result.insert(int_ip_mask.S_un.S_addr);
        if (int_ip_mask.s_lh != 255 || i >= device_count)
        {
            continue;
        }

        i++;
        int_ip_mask.s_lh = 0;
        int_ip_mask.s_host += 1;
        result.insert(int_ip_mask.S_un.S_addr);
        if (int_ip_mask.s_host != 255 || i >= device_count)
        {
            continue;
        }

        i++;
        int_ip_mask.s_host = 0;
        int_ip_mask.s_net += 1;
        result.insert(int_ip_mask.S_un.S_addr);
    }
    return std::move(result);
}

std::vector<int> NetworkHelper::ResolveName(const std::string &name)
{
    addrinfo *addrs = NULL;
    std::vector<int> result;

    if (name.empty())
    {
        return result;
    }

    do
    {
        int rc = 0;
        struct addrinfo hints = { 0 };
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags &= ~AI_NUMERICHOST;
        hints.ai_family = AF_INET;
        rc = getaddrinfo(name.c_str(), NULL, &hints, &addrs);
        if (rc != 0 || addrs == NULL)
        {
            break;
        }
        for (addrinfo *addr = addrs; addr != NULL; addr = addr->ai_next)
        {
            if (addr->ai_family == AF_INET)
            {
                const struct sockaddr_in *sin = (struct sockaddr_in *) addr->ai_addr;
                result.emplace_back(sin->sin_addr.s_addr);
            }
        }
    } while (0);

    if (addrs)
    {
        freeaddrinfo(addrs);
    }

    return result;
}

std::string NetworkHelper::ResolveAddr(int addr)
{
    char buf[NI_MAXHOST];
    buf[0] = 0;
    struct sockaddr sa;
    struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = addr;
    socklen_t sa_len = sizeof(struct sockaddr_in);
    getnameinfo(&sa, sa_len, buf, sizeof(buf), NULL, 0, NI_NAMEREQD);
    return buf;
}

#if defined(_MSC_VER)
std::wstring NetworkHelper::ResolveAddrW(int addr)
{
    wchar_t buf[NI_MAXHOST];
    buf[0] = 0;
    struct sockaddr sa;
    struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = addr;
    socklen_t sa_len = sizeof(struct sockaddr_in);
    GetNameInfoW(&sa, sa_len, buf, sizeof(buf), NULL, 0, NI_NAMEREQD);
    return buf;
}
#endif

u_short NetworkHelper::ComputerTcpOUdpSum(const struct in_addr &src, const struct in_addr &dst, bool is_tcp, const void *buf, u_short len)
{
    struct pseudo {
        struct in_addr src;
        struct in_addr dst;
        unsigned char zero;
        unsigned char proto;
        unsigned short length;
    } hdr;
    int sum = 0;

    hdr.src = src;
    hdr.dst = dst;
    hdr.zero = 0;
    hdr.proto = is_tcp ? 6 : 17;
    hdr.length = htons(len);

    /* Get the ones'-complement sum of the pseudo-header. */
    sum = AlgorithmHelper::CheckSumAdd((unsigned char *)&hdr, sizeof(hdr), sum);
    /* Add it to the sum of the packet. */
    sum = AlgorithmHelper::CheckSumAdd((unsigned char *)buf, len, sum);
    /* Fold in the carry, take the complement, and return. */
    sum = CKSUM_CARRY(sum);
    /* RFC 768: "If the computed  checksum  is zero,  it is transmitted  as all
    * ones (the equivalent  in one's complement  arithmetic).   An all zero
    * transmitted checksum  value means that the transmitter  generated  no
    * checksum" */
    if (!is_tcp && sum == 0) {
        sum = 0xFFFF;
    }
    return sum;
}