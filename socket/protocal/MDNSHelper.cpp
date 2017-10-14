#include "MDNSHelper.h"
#if defined(_MSC_VER)
#include <network\NetworkInfoHelper.h>
#elif defined(__GNUC__)
#include <network/NetworkInfoHelper.h>
#else
#error unsupported compiler
#endif
#ifdef DEBUG
#include <iostream>
#endif

sockaddr_in MDNSHelper::m_mdns_addr = MDNSHelper::GetMDNSSockaddr();
MDNSHelper::TypeDataOpType MDNSHelper::m_mdns_type_data_op = MDNSHelper::RegistTypeDataOp();
sockaddr_in6 MDNSHelperV6::m_mdns_addr = MDNSHelperV6::GetMDNSSockaddr();
MDNSHelper::TypeDataOpType MDNSHelperV6::m_mdns_type_data_op = MDNSHelper::RegistTypeDataOp();

DNSHeader MDNSHelper::GetMDNSQueryHeader()
{
    DNSHeader req_header;
    memset(&req_header, 0, sizeof(req_header));
    req_header.qdcount = htons(1);
    return req_header;
}

sockaddr_in MDNSHelper::GetMDNSSockaddr()
{
    sockaddr_in mdns_addr = { 0 };
    mdns_addr.sin_family = AF_INET;
    mdns_addr.sin_port = htons(MDNS_MCAST_PORT);
    mdns_addr.sin_addr.s_addr = htonl(MDNS_MCAST_ADDR_INT);
    return mdns_addr;
}

MDNSHelper::TypeDataOpType MDNSHelper::RegistTypeDataOp()
{
    TypeDataOpType mdns_type_data_op;
    mdns_type_data_op[DNS_RECODE_TYPE_PTR] =   ParseMdnsPtrdata;
    mdns_type_data_op[DNS_RECODE_TYPE_TXT] =   ParseMdnsTextdata;
    mdns_type_data_op[DNS_RECODE_TYPE_SRV] =   ParseMdnsSrvdata;
    mdns_type_data_op[DNS_RECODE_TYPE_A]   =   ParseAdata;
    mdns_type_data_op[DNS_RECODE_TYPE_HINFO] = ParseHINFOdata;
    return mdns_type_data_op;
}

bool MDNSHelper::SendMDNSRequest(const std::string &server)
{
    SOCKET fd = GetSocket();
    if (fd==-1) return false;
    char sendbuf[MDNS_QUERY_BUFSIZE] = { 0 };
    size_t len = sizeof(sendbuf);
    if (!GeneraterMDNSQueryPacket(server, sendbuf, len))
    {
#ifdef DEBUG
        std::cout << __FUNCTION__ << " GeneraterMDNSQueryPacket() failed!" << std::endl;
#endif // DEBUG
        return false;
    }

    int ret = sendto(fd, sendbuf, (int)len, 0, (struct sockaddr*) &m_mdns_addr, sizeof(m_mdns_addr));
    if (ret == SOCKET_ERROR)
    {
        m_fail_result = GetLastSocketError();
        return false;
    }

    return true;
}

bool MDNSHelper::GeneraterMDNSQueryPacket(const std::string &server, char *buf, size_t &size)
{
    static DNSQueryBody::tc tc = { htons(DNS_RECODE_TYPE_ANY), htons(1) };
    static DNSHeader req_header = MDNSHelper::GetMDNSQueryHeader();

    if (buf==NULL || size<MDNS_QUERY_PACK_MINI_SIZE)
    {
        return false;
    }

    size_t pos = 0;
    memcpy(&buf[pos], &req_header, sizeof(req_header));
    pos += sizeof(req_header);
    size_t name_len = size - pos - sizeof(DNSQueryBody::tc);
    if (!EncodeDotStr(server, &buf[pos], name_len))
    {
        return false;
    }
    pos += name_len;
    memcpy(&buf[pos], &tc, sizeof(tc));
    pos += sizeof(tc);
    size = pos;
    return true;
}

bool MDNSHelper::EncodeDotStr(const std::string &type, char *byte, size_t &size)
{
    if (type.empty() || byte==NULL)
    {
        return false;
    }

    std::vector<std::string> vc = StringHelper::split(type, ".");
    if (vc.empty())
    {
        return false;
    }

    size_t need_size = 0;
    for (auto str : vc)
    {
        need_size += str.length() + 1;
    }
    if (need_size + 1 > size)
    {
        return false;
    }

    size_t cur_ptr = 0;
    for (auto str : vc)
    {
        if (str.length() > 63)
        {
            return false;
        }

        if (str.empty())
        {
            continue;
        }

        byte[cur_ptr] = (char)str.length();
        memcpy(byte + cur_ptr + 1, str.c_str(), str.length());
        cur_ptr += str.length() + 1;
    }
    byte[cur_ptr] = 0;
    size = cur_ptr + 1;
    return true;
}

bool MDNSHelper::DecodeDotStr(std::string &type, const char *packet, int size, int &deal_off)
{
    if (size <=0 || packet == NULL || deal_off >= size)
    {
        return false;
    }

    const char *p = packet;
    int  pos = deal_off;
    for (; pos < size;)
    {
        if (p[pos] == 0)
        {
            pos++;
            break;
        }

        if (!MDNS_TYPE_IS_PTR(p[pos]))
        {
            int len = p[pos++];
            type += std::string(&p[pos], len);
            pos += len;
            if (p[pos])
            {
                type += ".";
            }
        }
        else
        {
            RecuName name = { 0 };
            memcpy(&name, &p[pos], sizeof(name));
            name.name.name = ntohs(name.name.name);
            int recu_pos = name.name.name_in.off;
            DecodeDotStr(type, packet, size, recu_pos);
            pos += 2;
            break;
        }
    }

    deal_off = pos;
    return true;
}

bool MDNSHelper::RecvNextMDNSResponce(std::string &from_ip, Json::Value &info)
{
    char recvbuf[MDNS_RESPONCE_BUFSIZE] = { 0 };
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

        from_ip = NetworkHelper::IPAddr2Str(from.sin_addr);

        if (!CheckMDNSDataValidity(recvbuf, size))
        {
#ifdef DEBUG
            std::cout << __FUNCTION__ << " CheckMDNSResponcevalidity failed! " << std::endl;
#endif // DEBUG
            continue;
        }

        if (!DealMDNSData(info, recvbuf, size))
        {
#ifdef DEBUG
            std::cout << __FUNCTION__ << " DealMDNSResponce failed! " << std::endl;
#endif // DEBUG
            return false;
        }
        return true;
    }
}

bool MDNSHelper::CheckMDNSDataValidity(char *data, int size)
{
    if (data == NULL)
    {
        return false;
    }

    if (size < MDNS_RESPONCE_PACK_MINI_SIZE)
    {
        return false;
    }

    DNSHeader *header = (DNSHeader *)data;
    if (header->ancount==0 && header->arcount==0 && header->nscount==0)
    {
        return false;
    }

    return true;
}

bool MDNSHelper::DealMDNSData(Json::Value &info, char *data, int size)
{
    int pos = 0;
    bool ret = false;
    DNSHeader *header = (DNSHeader *)data;

    pos += sizeof(DNSHeader);
    //deal question
    for (int i = 0; i < ntohs(header->qdcount); i++)
    {
        std::string domain_name;
        DecodeDotStr(domain_name, data, size, pos);
        pos += sizeof(DNSQueryBody::tc);
    }

    Json::ArrayIndex count = 0;
    //deal others
    for (;pos>=0 && pos<size;)
    {
        std::string domain_name;
        DecodeDotStr(domain_name, data, size, pos);
        DNSResponceBody::tctd *ptctd = (DNSResponceBody::tctd *)&data[pos];
        ptctd->rdlen = ntohs(ptctd->rdlen);
        ptctd->rtype = ntohs(ptctd->rtype);
        ptctd->rclass = ntohs(ptctd->rclass);
        ptctd->rttl = htonl(ptctd->rttl);
        pos += sizeof(DNSResponceBody::tctd);
        if (m_mdns_type_data_op.find(ptctd->rtype) == m_mdns_type_data_op.end())
        {
            info[count]["domain"] = domain_name;
            info[count]["ttl"] = (int)ptctd->rttl;
            info[count]["type_index"] = (int)ptctd->rtype;
            info[count]["class_index"] = (int)(ptctd->rclass & 0X7FFF);
            if (((unsigned short)pos + ptctd->rdlen) <= size)
            {
                info[count]["data"][0] = "0X" + StringHelper::byte2basestr((unsigned char*)data+pos, ptctd->rdlen, "", StringHelper::hex, 2);
            }
            count++;
            pos += ptctd->rdlen;
            continue;
        }
        info[count]["domain"] = domain_name;
        info[count]["ttl"] = (int)ptctd->rttl;
        info[count]["type_index"] = (int)ptctd->rtype;
        info[count]["class_index"] = (int)(ptctd->rclass & 0X7FFF);
        ret = m_mdns_type_data_op[ptctd->rtype](data, size, pos, ptctd->rdlen, info[count]);
        count++;
        pos += ptctd->rdlen;
        if (!ret)
        {
            return false;
        }
    }
    return true;
}

bool MDNSHelper::ParseMdnsPtrdata(const char *data, int size, int pos, int len, Json::Value &names)
{
    std::string domain_name;
    bool ret = DecodeDotStr(domain_name, data, size, pos);
    names["type"] = "PTR";
    names["data"][0] = domain_name;
    return ret;
}

bool MDNSHelper::ParseMdnsTextdata(const char *data, int size, int pos, int len, Json::Value &names)
{
    int off = 0;

    names["type"] = "TXT";
    names["data"] = Json::Value(Json::arrayValue);
    Json::ArrayIndex count = 0;
    while (off>=0 && off<len)
    {
        const DNSResponceData_Text *srv = (const DNSResponceData_Text *)&data[pos + off];
        off += 1;
        if (srv->text_len)
        {
            if (srv->text_len > (len - off))
            {
#ifdef DEBUG
                std::cout << __FUNCTION__ << "srv->text_len is too long " << srv->text_len << " than leave" << len - off << std::endl;
#endif // DEBUG
                return false;
            }
            names["data"][count++] = std::string((char *)&srv->text, srv->text_len);
            off += srv->text_len;
        }
    }
    return true;
}

bool MDNSHelper::ParseMdnsSrvdata(const char *data, int size, int pos, int len, Json::Value &names)
{
    const DNSResponceData_Srv * srv = (const DNSResponceData_Srv *)&data[pos];

    names["type"] = "SRV";
    std::string domain_name;
    int off = pos + offsetof(DNSResponceData_Srv, target);
    bool ret = DecodeDotStr(domain_name, data, size, off);
    names["data"][0] = domain_name;
    names["port"] = htons(srv->port);
    return true;
}

bool MDNSHelper::ParseAdata(const char *data, int size, int pos, int len, Json::Value &names)
{
    const DNSResponceData_A * a = (const DNSResponceData_A *)&data[pos];

    names["type"] = "A";
    names["data"][0] = NetworkHelper::IPAddr2Str(a->ip);
    return true;
}

bool MDNSHelper::ParseHINFOdata(const char *data, int size, int pos, int len, Json::Value &names)
{
    const DNSResponceHINFO_A *hinfo = (const DNSResponceHINFO_A *)&data[pos];

    names["type"] = "HINFO";
    if (hinfo->len+1 < len) 
    {
        names["data"][0] = "CUP:" + std::string((char *)hinfo + 1, hinfo->len);
        hinfo = (const DNSResponceHINFO_A *)((char *)hinfo + hinfo->len + 1);
        len = len - (hinfo->len + 1);
        if (hinfo->len + 1 < len)
        {
            names["data"][1] = "OS:" + std::string((char *)hinfo + 1, hinfo->len);
        }
    }
    return true;
}

sockaddr_in6 MDNSHelperV6::GetMDNSSockaddr()
{
    sockaddr_in6 mdns_addr = { 0 };
    mdns_addr.sin6_family = AF_INET6;
    mdns_addr.sin6_port = htons(MDNS_MCAST_PORT);
    inet_pton(AF_INET6, MDNS_MCAST_ADDR6, (void *)&mdns_addr.sin6_addr);
    return mdns_addr;
}

bool MDNSHelperV6::SendMDNSRequest(const std::string &server)
{
    SOCKET fd = GetSocket();
    if (fd == -1) return false;
    char sendbuf[MDNS_QUERY_BUFSIZE] = { 0 };
    size_t len = sizeof(sendbuf);
    if (!MDNSHelper::GeneraterMDNSQueryPacket(server, sendbuf, len))
    {
#ifdef DEBUG
        std::cout << __FUNCTION__ << " GeneraterMDNSQueryPacket() failed!" << std::endl;
#endif // DEBUG
        return false;
    }

    int ret = sendto(fd, sendbuf, (int)len, 0, (struct sockaddr*) &m_mdns_addr, sizeof(m_mdns_addr));
    if (ret == SOCKET_ERROR)
    {
        m_fail_result = GetLastSocketError();
        return false;
    }

    return true;
}

bool MDNSHelperV6::RecvNextMDNSResponce(std::string &from_ip, Json::Value &info)
{
    char recvbuf[MDNS_RESPONCE_BUFSIZE] = { 0 };
    SOCKET fd = GetSocket();
    if (fd == -1) return false;

    while (1)
    {
        int size = 0;
        struct sockaddr_in6 from = { 0 };
#if defined(_MSC_VER)
        int len = sizeof(struct sockaddr_in6);
#elif defined(__GNUC__)
        socklen_t len = sizeof(struct sockaddr_in6);
#else
#error unsupported compiler
#endif
        size = recvfrom(fd, recvbuf, sizeof(recvbuf), 0, (struct sockaddr*)&from, &len);
        if (size == SOCKET_ERROR)
        {
            m_fail_result = GetLastSocketError();
            return false;
        }

        from_ip = NetworkHelper::IPAddr2StrV6(from.sin6_addr);

        if (!MDNSHelper::CheckMDNSDataValidity(recvbuf, size))
        {
#ifdef DEBUG
            std::cout << __FUNCTION__ << " CheckMDNSResponcevalidity failed! " << std::endl;
#endif // DEBUG
            continue;
        }

        if (!MDNSHelper::DealMDNSData(info, recvbuf, size))
        {
#ifdef DEBUG
            std::cout << __FUNCTION__ << " DealMDNSResponce failed! " << std::endl;
#endif // DEBUG
            return false;
        }
        return true;
    }
}

void MDNSHelperV6::ResetSrcIp(const std::string &src_ip)
{
    in_addr src_ip_int = NetworkHelper::IPStr2Addr(src_ip);
    NetworkInfoHelper::AdaptInfo info= NetworkInfoHelper::GetAdaptInfoByIp(src_ip_int.s_addr, true, false);
    if (info.local_ip_address_int.s_addr == src_ip_int.s_addr)
    {
        this->MulticastSocketV6::ResetSrcIp(info.index);
    }
}