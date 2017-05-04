
#include "DHCPHelper.h"
#if defined(_MSC_VER)
#include <string\StringHelper.h>
#elif defined(__GNUC__)
#include <string/StringHelper.h>
#else
#error unsupported compiler
#endif

#define UDP_PLUS_IP_HDR_LEN  (IPV4_HDR_LEN + UDP_HDR_LEN)
#define MAX_DHCP_UDP_IP_HDR_LEN  (UDP_PLUS_IP_HDR_LEN + sizeof(DHCPHelper::dhcp_packet_t))
#define MIN_DHCP_UDP_IP_HDR_LEN (UDP_PLUS_IP_HDR_LEN + offsetof(DHCPHelper::dhcp_packet_t, options))

DHCPHelper::DHCPHelper() : RawSocket(INADDR_ANY, IPPROTO_UDP)
{
}

DHCPHelper::~DHCPHelper()
{
}

bool DHCPHelper::DhcpRequestPackCheck(const char *buf, int buf_len)
{
    bool ret;

    ret = DhcpPackCheck(buf, buf_len);
    if (ret == false)
    {
        return false;
    }

    struct dhcp_packet_t *ptrDHCPPacket = NULL;
    ptrDHCPPacket = (struct dhcp_packet_t *)(buf + UDP_PLUS_IP_HDR_LEN);
    if (*((char*)ptrDHCPPacket + 236 + 4) != 0x35 || *((char*)ptrDHCPPacket + 236 + 4 + 2) != 0x03)
    {
        return false;
    }
    return true;
}

bool DHCPHelper::DhcpPackCheck(const char *buf, int buf_len)
{
    struct ip_header *ptrIPHeader = NULL;
    struct udp_header *ptrUDPHeader = NULL;
    struct dhcp_packet_t *ptrDHCPPacket = NULL;

    if (buf_len > MAX_DHCP_UDP_IP_HDR_LEN)
    {
        return false;
    }
    if (buf_len < MIN_DHCP_UDP_IP_HDR_LEN)
    {
        return false;
    }

    ptrIPHeader = (struct ip_header *)(buf);
    if (ptrIPHeader->protocol != IPPROTO_UDP)
    {
        return false;
    }

    ptrUDPHeader = (struct udp_header *)(buf + IPV4_HDR_LEN);
    if (ntohs(ptrUDPHeader->uh_dport) != 67)
    {
        return false;
    }
    if (ntohs(ptrUDPHeader->uh_sport) != 68)
    {
        return false;
    }

    ptrDHCPPacket = (struct dhcp_packet_t *)(buf + UDP_PLUS_IP_HDR_LEN);
    if (htonl(ptrDHCPPacket->option_format) != DHCP_MAGIC_COOKIE)
    {
        return false;
    }
    return true;
}

void DHCPHelper::ParseDhcpData(const char *dhcp, int len, DhcpParseResult &res)
{
    struct dhcp_packet_t *ptrDHCPPacket = (struct dhcp_packet_t *)(dhcp + UDP_PLUS_IP_HDR_LEN);
    struct ip_header *ptrIPHeader = (struct ip_header *)(dhcp);
    int szUDPData;
    uint8_t *ptrOptionEntity = NULL;
    uint8_t optionEntityLen = 0;
    uint8_t *ptrOptionValue = NULL;
    szUDPData = len - UDP_PLUS_IP_HDR_LEN;
    // get client MAC address in DHCP
    res.chaddr = StringHelper::byte2basestr(ptrDHCPPacket->chaddr, 6, ":", StringHelper::hex, 2);

    // get client host name
    ptrOptionEntity = GetOptionEntityFromDHCPPkt(ptrDHCPPacket, szUDPData, DHCP_OPTION_HOSTNAME);

    std::stringstream ssHostname;
    if (ptrOptionEntity)
    {
        optionEntityLen = GetOptionEntityLen(ptrOptionEntity);

        if (optionEntityLen >= 0) {
            ptrOptionValue = ptrOptionEntity + 2;
            for (int i = 0; i < optionEntityLen; i++) {
                ssHostname << *(ptrOptionValue + i);
            }
            res.hostname = ssHostname.str();
        }
    }

    // get requested ip address
    ptrOptionEntity = GetOptionEntityFromDHCPPkt(ptrDHCPPacket, szUDPData, DHCP_OPTION_REQUESTED_IP);

    if (ptrOptionEntity)
    {

        optionEntityLen = GetOptionEntityLen(ptrOptionEntity);
        if (optionEntityLen >= 0)
        {
            ptrOptionValue = ptrOptionEntity + 2;
            res.ciaddr = StringHelper::byte2basestr(ptrOptionValue, 4, ".", StringHelper::dec);
        }
    }
    if (res.ciaddr.empty())
    {
        // extract ip from IP header
        res.ciaddr = StringHelper::byte2basestr((unsigned char *)&ptrIPHeader->saddr, 4, ".", StringHelper::dec);
        res.ciaddr = (res.ciaddr == "0.0.0.0") ? "" : res.ciaddr;
    }

    // get dhcp server ip address
    ptrOptionEntity = GetOptionEntityFromDHCPPkt(ptrDHCPPacket, szUDPData, DHCP_OPTION_SERVER_ID);

    if (ptrOptionEntity)
    {

        optionEntityLen = GetOptionEntityLen(ptrOptionEntity);
        if (optionEntityLen >= 0)
        {
            ptrOptionValue = ptrOptionEntity + 2;
            res.siaddr = StringHelper::byte2basestr(ptrOptionValue, 4, ".", StringHelper::dec);
        }
    }
}

unsigned char *DHCPHelper::GetOptionEntityFromDHCPPkt(const dhcp_packet_t *_packet, int _sizetPacketSize, dhcp_option_code _opCode)
{
    int sizetSize = _sizetPacketSize - offsetof(dhcp_packet_t, options);
    if (sizetSize < 0)
    {
        return NULL;
    }

    int sizetWhere = 0;
    const unsigned char *data = &_packet->options[sizetWhere];
    while (sizetWhere < sizetSize) 
    {
        if (data[0] == 0) 
        { /* padding */
            sizetWhere++;
            continue;
        }

        // TODO: some case it will overflow
        if ((sizetWhere + 2) > sizetSize)
        {
            return NULL;
        }

        if ((sizetWhere + 2 + data[1]) > sizetSize)
        {
            return NULL;
        }

        if (data[0] == _opCode)
        {
            return (unsigned char *)data;
        }

        sizetWhere += data[1] + 2;
        data += data[1] + 2;
    }

    return NULL;
}

unsigned char DHCPHelper::GetOptionEntityLen(const unsigned char* _ptrOptionEntity)
{
    unsigned char len = -1;
    if (!_ptrOptionEntity)
        return len;
    len = *(_ptrOptionEntity + 1);
    return len;
}