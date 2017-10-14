#ifndef UPNP_HELPER_H_INCLUDED
#define UPNP_HELPER_H_INCLUDED

#if defined(_MSC_VER)
#include <socket\SocketHelper.h>
#include <string\StringHelper.h>
#include <network\NetworkHelper.h>
#include <json\json.h>
#include <pugixml\pugixml.hpp>
#elif defined(__GNUC__)
#include <socket/SocketHelper.h>
#include <string/StringHelper.h>
#include <network/NetworkHelper.h>
#include <json/json.h>
#include <pugixml/pugixml.hpp>
#include <string.h>
#else
#error unsupported compiler
#endif
#include <string>
#include <vector>
#include <set>
#include <map>
#include <mutex>

#define WSDD_RECV_TIMEOUT 2000
#define WSDD_SEND_TIMEOUT 1000
#define WSDD_MCAST_ADDR "239.255.255.250"
#define WSDD_MCAST_ADDR_INT 0XEFFFFFFA
#define WSDD_MCAST_PORT 3702
#define WSDD_RESPONCE_BUFSIZE 4096

class WSDDHelper : public MulticastSocket
{
public:
    /**
    *eth_ip: which eth you want to bind to send upnp multcast, empty for all eth
    */
    WSDDHelper(u_int src_ip = INADDR_ANY, u_short src_port = 0) : MulticastSocket(src_ip, src_port, htonl(WSDD_MCAST_ADDR_INT)) {}
    ~WSDDHelper(){}
    /**
    *send wsdd muiltcast
    */
    bool SendWSDDProbe();
    /**
    *recv next wsdd responce
    *from_ip(out): recv from 
    *location(out): the location in the upnp packet
    */
    bool RecvNextWSDDData(std::string &from_ip, Json::Value &info);

public:
    static sockaddr_in GetWSDDSockaddr();
    static std::string GetXmlNameWithoutNamespace(const std::string &name);
    static void GetSoapWsdNamespace(std::string &soap_namespace, std::string &wsd_name_space, const pugi::xml_node &root);
    static std::string GetBodyInfoPath(const std::string &soap_namespace, const std::string &wsd_name_space, const std::string &Suffix);
    static void RepeatWalkXml(Json::Value &info, pugi::xml_node &node);
    static bool GetWSDDDataInfo(Json::Value &info, char *data, int size);

public:
    static std::pair<std::string, std::string> g_wsdd_deal_list[2];

private:
    static sockaddr_in g_wsdd_addr;
    static char        g_wsdd_probe[];
};

#endif