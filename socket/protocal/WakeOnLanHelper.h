#ifndef WAKEONLAN_HELPER_H_INCLUDED
#define WAKEONLAN_HELPER_H_INCLUDED

#if defined(_MSC_VER)
#include <string\StringHelper.h>
#include <socket\SocketHelper.h>
#elif defined(__GNUC__)
#include <string/StringHelper.h>
#include <socket/SocketHelper.h>
#include <string.h>
#else
#error unsupported compiler
#endif
#include <string>
#include <vector>
#include <mutex>

class WakeOnLanHelper : public BroadcastSocket
{
public:
    WakeOnLanHelper(u_int src_ip = INADDR_ANY) : BroadcastSocket(src_ip, 0) {}
    ~WakeOnLanHelper(){}
    bool SendMagicPacket(const std::string &dst_eth_mac = "");

private:
    static void GenerateMagicPacket(u_char *pack, const u_char *eth_mac);

public:
    static sockaddr_in GetBroadcastSockaddr();

private:
    static sockaddr_in m_broadcast_addr;
};

#endif