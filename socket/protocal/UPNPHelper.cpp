#include "UPNPHelper.h"
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

sockaddr_in UPNPHelper::m_upnp_addr = GetUPNPSockaddr();
char UPNPHelper::m_upnp_search[] = "M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMan: \"ssdp:discover\"\r\nMx: 3\r\nST: upnp:rootdevice\r\n\r\n";

sockaddr_in UPNPHelper::GetUPNPSockaddr()
{
    sockaddr_in upnp_addr = { 0 };
    upnp_addr.sin_family = AF_INET;
    upnp_addr.sin_port = htons(UPNP_MCAST_PORT);
    upnp_addr.sin_addr.s_addr = NetworkHelper::IPStr2Addr(UPNP_MCAST_ADDR).s_addr;
    return upnp_addr;
}

bool UPNPHelper::SendUPNPSearchRequest()
{
    SOCKET fd = GetSocket();
    if (fd == -1) return false;

    int ret = sendto(fd, m_upnp_search, sizeof(m_upnp_search), 0, (struct sockaddr *) &m_upnp_addr, sizeof(m_upnp_addr));
    if (ret == SOCKET_ERROR)
    {
        m_fail_result = GetLastSocketError();
        return false;
    }

    return true;
}

bool UPNPHelper::RecvNextUPNPData(std::string &from_ip, std::string &location)
{
    static char recvbuf[UPNP_RESPONCE_BUFSIZE] = { 0 };

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

        if (!CheckUPNPResponcevalidity(recvbuf, size))
        {
#ifdef DEBUG
            std::cout << __FUNCTION__ << " CheckMDNSResponcevalidity failed! " << std::endl;
#endif // DEBUG
            continue;
        }

        from_ip = NetworkHelper::IPAddr2Str(from.sin_addr);

        if (!DealUPNPData(location, recvbuf, size))
        {
#ifdef DEBUG
            std::cout << __FUNCTION__ << " DealMDNSResponce failed! " << std::endl;
#endif // DEBUG
            return false;
        }
        return true;
    }
}

bool UPNPHelper::CheckUPNPResponcevalidity(char *data, int size)
{
    static char upnp_resp_headline[] = "HTTP/1.1 200 OK";
    static char upnp_notify_headline[] = "NOTIFY * HTTP/1.1";

    if (data == NULL)
    {
        return false;
    } 

    if (size < std::min(sizeof(upnp_resp_headline), sizeof(upnp_notify_headline)))
    {
        return false;
    }

    int cmp_size = 0;
    const char *cmp_head = NULL;
    if (data[0] == 'H' || data[0] == 'h')
    {
        cmp_size = sizeof(upnp_resp_headline) - 1;
        cmp_head = upnp_resp_headline;
    }
    else if (data[0] == 'N' || data[0] == 'n')
    {
        cmp_size = sizeof(upnp_notify_headline) - 1;
        cmp_head = upnp_notify_headline;
    }
    else
    {
        return false;
    }

    std::string comp_head_line(StringHelper::toupper(std::string(data, cmp_size)));
    if (comp_head_line != cmp_head)
    {
        return false;
    }

    return true;
}

bool UPNPHelper::DealUPNPData(std::string &location, char *data, int size)
{
    static char cmp_location[] = "LOCATION:";

    std::string str_data(data, size);

    std::vector<std::string> tmp1 = StringHelper::split(str_data, "\r");
    for (auto tmp : tmp1)
    {
        std::vector<std::string> tmp2 = StringHelper::split(tmp, "\n");
        for (auto line : tmp2)
        {
            if (!line.empty() && line.length()>sizeof(cmp_location))
            {
                if (StringHelper::toupper(std::string(line.c_str(), sizeof(cmp_location) - 1)) == cmp_location)
                {
                    location = std::string(line.c_str() + sizeof(cmp_location) - 1);
                    return true;
                }
            }
        }
    }

    return false;
}
