#ifndef UPNP_HELPER_H_INCLUDED
#define UPNP_HELPER_H_INCLUDED

#if defined(_MSC_VER)
#include <socket\SocketHelper.h>
#include <string\StringHelper.h>
#include <network\NetworkHelper.h>
#elif defined(__GNUC__)
#include <socket/SocketHelper.h>
#include <string/StringHelper.h>
#include <network/NetworkHelper.h>
#include <string.h>
#else
#error unsupported compiler
#endif
#include <string>
#include <vector>
#include <set>
#include <map>
#include <mutex>

#define UPNP_RECV_TIMEOUT 2000
#define UPNP_SEND_TIMEOUT 1000
#define UPNP_MCAST_ADDR "239.255.255.250"
#define UPNP_MCAST_ADDR_INT 0XEFFFFFFA
#define UPNP_MCAST_PORT 1900
#define UPNP_RESPONCE_BUFSIZE 2048

class UPNPHelper : public MulticastSocket
{
public:
    /**
    *eth_ip: which eth you want to bind to send upnp multcast, empty for all eth
    */
    UPNPHelper(u_int src_ip = INADDR_ANY, u_short src_port = 0) :MulticastSocket(src_ip, src_port, htonl(UPNP_MCAST_ADDR_INT)) {}
    ~UPNPHelper(){}
    /**
    *send upnp muiltcast
    */
    bool SendUPNPSearchRequest();
    /**
    *recv next upnp responce
    *from_ip(out): recv from 
    *location(out): the location in the upnp packet
    */
    bool RecvNextUPNPData(std::string &from_ip, std::string &location);

public:
    static sockaddr_in GetUPNPSockaddr();
    static bool CheckUPNPResponcevalidity(char *data, int size);
    static bool DealUPNPData(std::string &location, char *data, int size);

private:
    static sockaddr_in m_upnp_addr;
    static char        m_upnp_search[];
};

#endif