#include "NetworkHelper.h"

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
    if (inet_ntop(AF_INET, (void *)&addr, str_buf, sizeof(str_buf))==NULL) return "";
    return str_buf;
}

std::string NetworkHelper::IPAddr2Str(const u_int &addr)
{
    char str_buf[46] = { 0 };
    if (inet_ntop(AF_INET, (void *)&addr, str_buf, sizeof(str_buf)) == NULL) return "";
    return str_buf;
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