#include "WSDDHelper.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#ifdef DEBUG
#include <iostream>
#endif

#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

sockaddr_in WSDDHelper::g_wsdd_addr = GetWSDDSockaddr();
char WSDDHelper::g_wsdd_probe[] = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"><s:Header><a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action><a:MessageID>urn:uuid:f8b67a0a-6d5f-475d-5165-0a7f003b4fc6</a:MessageID><a:To s:mustUnderstand=\"1\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To></s:Header><s:Body><d:Probe/></s:Body></s:Envelope>";
std::pair<std::string,std::string> WSDDHelper::g_wsdd_deal_list[2] = {
    {"http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches", "ProbeMatches"},
    {"http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello", "Hello"}
};

sockaddr_in WSDDHelper::GetWSDDSockaddr()
{
    sockaddr_in wsdd_addr = { 0 };
    wsdd_addr.sin_family = AF_INET;
wsdd_addr.sin_port = htons(WSDD_MCAST_PORT);
wsdd_addr.sin_addr.s_addr = NetworkHelper::IPStr2Addr(WSDD_MCAST_ADDR).s_addr;
return wsdd_addr;
}

bool WSDDHelper::SendWSDDProbe()
{
    SOCKET fd = GetSocket();
    if (fd == -1) return false;

    int ret = sendto(fd, g_wsdd_probe, sizeof(g_wsdd_probe), 0, (struct sockaddr *) &g_wsdd_addr, sizeof(g_wsdd_addr));
    if (ret == SOCKET_ERROR)
    {
        m_fail_result = GetLastSocketError();
        return false;
    }

    return true;
}

bool WSDDHelper::RecvNextWSDDData(std::string &from_ip, Json::Value &info)
{
    char recvbuf[WSDD_RESPONCE_BUFSIZE] = { 0 };

    SOCKET fd = GetSocket();
    if (fd == -1) return false;

    while (1)
    {
        int size = 0;
        struct sockaddr_in from = { 0 };
#if defined(_MSC_VER)
        int len = sizeof(struct sockaddr_in);
#elif defined(__GNUC__)
        socklen_t len = sizeof(struct sockaddr_in);
#else
#error unsupported compiler
#endif
        size = recvfrom(fd, recvbuf, sizeof(recvbuf), 0, (struct sockaddr*)&from, &len);
        if (size == SOCKET_ERROR)
        {
            m_fail_result = GetLastSocketError();
            return false;
        }

        if (!GetWSDDDataInfo(info, recvbuf, size))
        {
#ifdef DEBUG
            std::cout << __FUNCTION__ << " GetWSDDDataInfo failed! " << std::endl;
#endif // DEBUG
            continue;
        }

        from_ip = NetworkHelper::IPAddr2Str(from.sin_addr);
        return true;
    }
}

std::string WSDDHelper::GetXmlNameWithoutNamespace(const std::string &value)
{
    std::string name(value);
    auto pos = name.find_last_of(":");
    if (pos != name.npos)
    {
        name = std::string(name, pos + 1);
    }
    return name;
}

void WSDDHelper::GetSoapWsdNamespace(std::string &soap_namespace, std::string &wsd_name_space, const pugi::xml_node &root)
{
    for (auto attr : root.attributes())
    {
        if (std::string(attr.value()) == "http://www.w3.org/2003/05/soap-envelope")
        {
            soap_namespace = GetXmlNameWithoutNamespace(attr.name());
        }

        if (std::string(attr.value()) == "http://schemas.xmlsoap.org/ws/2005/04/discovery")
        {
            wsd_name_space = GetXmlNameWithoutNamespace(attr.name());
        }
    }
}

std::string WSDDHelper::GetBodyInfoPath(const std::string &soap_namespace, const std::string &wsd_name_space, const std::string &Suffix)
{
    std::string path = "/";
    if (!soap_namespace.empty())
    {
        path += soap_namespace + ":Envelope/" + soap_namespace + ":Body/";
    }
    else
    {
        path += "Envelope/Body/";
    }
    if (!wsd_name_space.empty())
    {
        path += wsd_name_space + ":" + Suffix;
    }
    else
    {
        path += Suffix;
    }
    return path;
}

void WSDDHelper::RepeatWalkXml(Json::Value &info, pugi::xml_node &node)
{
    if (node.empty())
    {
        return;
    }

    std::string node_value = node.text().as_string();
    if (!node_value.empty())
    {
        info[GetXmlNameWithoutNamespace(node.name())] = node_value;
        return;
    }

    Json::ArrayIndex index = 0;
    for (auto child : node)
    {
        RepeatWalkXml(info[GetXmlNameWithoutNamespace(node.name())][index++], child);
    }
}

bool WSDDHelper::GetWSDDDataInfo(Json::Value &info, char *data, int size)
{
    if (data == NULL || size == 0)
    {
        return false;
    }

    bool is_match = false;
    std::string data_str(data, size);
    for (auto match : g_wsdd_deal_list)
    {
        if (data_str.find(match.first) == data_str.npos)
        {
            continue;
        }

        is_match = true;
        pugi::xml_document doc;
        const int status = doc.load_string(data_str.c_str()).status;
        if (pugi::status_ok != status)
        {
            return false;
        }

        std::string soap_namespace;
        std::string wsd_name_space;
        GetSoapWsdNamespace(soap_namespace, wsd_name_space, doc.first_child());
        pugi::xpath_node result = doc.select_single_node(GetBodyInfoPath(soap_namespace, wsd_name_space, match.second).c_str());
        RepeatWalkXml(info, result.node());
        break;
    }

    return is_match;
}
