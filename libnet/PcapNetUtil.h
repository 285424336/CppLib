#ifndef PACAP_NET_UTIL_H_INCLUDED
#define PACAP_NET_UTIL_H_INCLUDED

#include "NetBase.h"

#define ARP_DEFAULT_TIMEOUT 3000   //ms
#ifndef ARP_INTERVAL_TIMEOUT
#define ARP_INTERVAL_TIMEOUT 10   //ms
#endif // !ARP_INTERVAL_TIMEOUT

class PcapNetUtil
{
public:
    static bool DoArp(u_char *dst_mac, u_long dst_mac_len, u_int DestIP, u_int SrcIP, u_char *src_mac, u_long src_mac_len, u_int timeout = ARP_DEFAULT_TIMEOUT);

private:
    static std::shared_ptr<NetBase> GenerateArpPacket(u_int DestIP, u_int SrcIP, u_char *src_mac, u_long src_mac_len);
};

#endif