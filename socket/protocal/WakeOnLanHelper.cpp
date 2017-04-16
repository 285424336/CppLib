#if defined(_MSC_VER)
#include <network\NetworkHelper.h>
#elif defined(__GNUC__)
#include <network/NetworkHelper.h>
#else
#error unsupported compiler
#endif
#include "WakeOnLanHelper.h"
#ifdef DEBUG
#include <iostream>
#endif

sockaddr_in WakeOnLanHelper::m_broadcast_addr = GetBroadcastSockaddr();

sockaddr_in WakeOnLanHelper::GetBroadcastSockaddr()
{
    sockaddr_in broadcast_addr = { 0 };
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(9);
    broadcast_addr.sin_addr.s_addr = INADDR_BROADCAST;
    return broadcast_addr;
}

void WakeOnLanHelper::GenerateMagicPacket(u_char *pack, const u_char *eth_mac)
{
    memset(pack, 0xff, 6);
    int packetsize = 6;
    for (int i = 0; i<16; i++)
    {
        memcpy(pack + packetsize, eth_mac, 6);
        packetsize += 6;
    }
}

bool WakeOnLanHelper::SendMagicPacket(const std::string &dst_eth_mac)
{
    SOCKET fd = GetSocket();
    if (fd == -1) return false;
    if (dst_eth_mac.size() < 12) return false;

    u_char mac_buf[6] = { 0 };
    u_char pack_buf[102] = { 0 };
    if (!StringHelper::hex2byte(StringHelper::replace(dst_eth_mac, ":", ""), (char *)mac_buf, sizeof(mac_buf))) return false;
    GenerateMagicPacket(pack_buf, mac_buf);
    int ret = sendto(fd, (const char *)pack_buf, sizeof(pack_buf), 0, (struct sockaddr*) &m_broadcast_addr, sizeof(m_broadcast_addr));
    if (ret == SOCKET_ERROR)
    {
        m_fail_result = GetLastSocketError();
        return false;
    }

    return true;
}
