#if defined(_MSC_VER)
#include <network\NetworkHelper.h>
#elif defined(__GNUC__)
#include <network/NetworkHelper.h>
#else
#error unsupported compiler
#endif
#include "NBNSHelper.h"
#include <algorithm>
#ifdef DEBUG
#include <iostream>
#endif
sockaddr_in NBNSHelper::m_nbns_addr = NBNSHelper::GetNBNSSockaddr();
NBNSHelper::TypeDataOpType NBNSHelper::m_nbns_type_data_op = RegistTypeDataOp();

NBNSHeader NBNSHelper::GetNBNSQueryHeader(bool is_broad)
{
    NBNSHeader req_header;
    memset(&req_header, 0, sizeof(req_header));
    req_header.id = htons(0X8888);
    if (is_broad)
    {
        req_header.flag.flag_in.flag_z = 1;
    }
    req_header.flag.flags = htons(req_header.flag.flags);
    req_header.qdcount = htons(1);
    return req_header;
}

sockaddr_in NBNSHelper::GetNBNSSockaddr()
{
    sockaddr_in NBNS_addr = { 0 };
    NBNS_addr.sin_family = AF_INET;
    NBNS_addr.sin_port = htons(NBNS_BCAST_PORT);
    NBNS_addr.sin_addr.s_addr = INADDR_BROADCAST;
    return NBNS_addr;
}

NBNSHelper::TypeDataOpType NBNSHelper::RegistTypeDataOp()
{
    TypeDataOpType NBNS_type_data_op;
    NBNS_type_data_op[NBNS_RECODE_TYPE_NBSTAT] = ParseNBSTATData;
    return NBNS_type_data_op;
}

bool NBNSHelper::SendNBSTATRequest(u_int dst, const std::string &name, const std::string &scope)
{
    SOCKET fd = GetSocket();
    if (fd == -1) return false;
    m_nbns_addr.sin_addr.s_addr = dst;
    char sendbuf[NBNS_QUERY_BUFSIZE] = { 0 };
    size_t  len = sizeof(sendbuf);
    if (!GeneraterNBNSQueryPacket(name, scope, sendbuf, len, (dst&0XFF)==0XFF))
    {
#ifdef DEBUG
        std::cout << __FUNCTION__ << " GeneraterNBNSQueryPacket() failed!" << std::endl;
#endif // DEBUG
        return false;
    }

    int ret = sendto(fd, sendbuf, (int)len, 0, (struct sockaddr *) &m_nbns_addr, sizeof(m_nbns_addr));
    if (ret == SOCKET_ERROR)
    {
        m_fail_result = GetLastSocketError();
        return false;
    }

    return true;
}

bool NBNSHelper::GeneraterNBNSQueryPacket(const std::string &name, const std::string &scope, char *buf, size_t &size, bool is_broad)
{
    static NBNSQueryBody::tc tc = { htons(NBNS_RECODE_TYPE_NBSTAT), htons(1) };
    static NBNSHeader broad_req_header = NBNSHelper::GetNBNSQueryHeader(true);
    static NBNSHeader unbroad_req_header = NBNSHelper::GetNBNSQueryHeader(false);

    if (buf == NULL || size<NBNS_QUERY_PACK_MINI_SIZE)
    {
        return false;
    }

    NBNSHeader *req_header = is_broad ? &broad_req_header : &unbroad_req_header;

    size_t pos = 0;
    memcpy(&buf[pos], req_header, sizeof(NBNSHeader));
    pos += sizeof(NBNSHeader);

    char tmp_buf[NBNS_NAME_MAX_LENGTH * 2] = { 0 };
    if (!LevelOneEncode(name, tmp_buf))
    {
        return false;
    }

    std::string server = std::string(tmp_buf, sizeof(tmp_buf)) + "." + scope;
    size_t name_len = size - pos - sizeof(NBNSQueryBody::tc);
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

bool NBNSHelper::LevelOneEncode(const std::string &name, char *out)
{
    if (out == NULL)
    {
        return false;
    }

    u_char buf[NBNS_NAME_MAX_LENGTH] = { 0 };
    auto copy_length = std::min(name.length(), (size_t)NBNS_NAME_MAX_LENGTH);
    auto pend_length = NBNS_NAME_MAX_LENGTH - copy_length;
    memcpy(buf, StringHelper::toupper(std::string(name)).c_str(), copy_length);
    char pend = 0x20;
    if (name == "*")
    {
        pend = 0;
    }
    if (pend_length)
    {
        memset(&buf[copy_length], pend, pend_length);
    }

    for (int i = 0; i < NBNS_NAME_MAX_LENGTH; i++)
    {
        out[2 * i] = ((buf[i] & 0XF0) >> 4) + 0X41;
        out[2 * i + 1] = (buf[i] & 0X0F) + 0X41;
    }
    return true;
}

bool NBNSHelper::LevelOneDecode(std::string &name, char *in)
{
    if (in == NULL)
    {
        return false;
    }

    char buf[NBNS_NAME_MAX_LENGTH + 1] = { 0 };
    for (int i = 0; i < NBNS_NAME_MAX_LENGTH; i++)
    {
        buf[i] = ((in[2 * i] - 0X41) << 4) & (in[2 * i + 1] - 0X41);
    }

    name = buf;
    return true;
}

bool NBNSHelper::EncodeDotStr(const std::string &type, char *byte, size_t &size)
{
    if (type.empty() || byte == NULL)
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

bool NBNSHelper::DecodeDotStr(std::string &type, const char *packet, int size, int &deal_off)
{
    if (size <= 0 || packet == NULL || deal_off >= size)
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

        if (!NBNS_TYPE_IS_PTR(p[pos]))
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

bool NBNSHelper::RecvNextNBSTATResponce(std::string &from_ip, NBStatTypeNameMap &info)
{
    static char recvbuf[NBNS_RESPONCE_BUFSIZE] = { 0 };

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

        if (!CheckNBNSResponcevalidity(recvbuf, size))
        {
#ifdef DEBUG
            std::cout << __FUNCTION__ << " CheckNBNSResponcevalidity failed! " << std::endl;
#endif // DEBUG
            continue;
        }

        from_ip = NetworkHelper::IPAddr2Str(from.sin_addr);

        if (!DealNBNSResponce(info, recvbuf, size))
        {
#ifdef DEBUG
            std::cout << __FUNCTION__ << " DealNBNSResponce failed! " << std::endl;
#endif // DEBUG
            return false;
        }
        return true;
    }
}

bool NBNSHelper::CheckNBNSResponcevalidity(char *data, int size)
{
    if (data == NULL)
    {
        return false;
    }

    if (size < NBNS_RESPONCE_PACK_MINI_SIZE)
    {
        return false;
    }

    NBNSHeader *header = (NBNSHeader *)data;
    header->flag.flags = ntohs(header->flag.flags);
    if (!header->flag.flag_in.flag_qr)
    {
        return false;
    }

    return true;
}

bool NBNSHelper::DealNBNSResponce(NBStatTypeNameMap &info, char *data, int size)
{
    int pos = 0;
    bool ret = false;
    NBNSHeader *header = (NBNSHeader *)data;

    pos += sizeof(NBNSHeader);
    //deal question
    for (int i = 0; i < ntohs(header->qdcount); i++)
    {
        std::string domain_name;
        DecodeDotStr(domain_name, data, size, pos);
        pos += sizeof(NBNSQueryBody::tc);
    }

    //deal others
    for (; pos < size;)
    {
        std::string domain_name;
        DecodeDotStr(domain_name, data, size, pos);
        NBNSResponceBody::tctd *ptctd = (NBNSResponceBody::tctd *)&data[pos];
        ptctd->rdlen = ntohs(ptctd->rdlen);
        ptctd->rtype = ntohs(ptctd->rtype);
        pos += sizeof(NBNSResponceBody::tctd);
        if (m_nbns_type_data_op.find(ptctd->rtype) == m_nbns_type_data_op.end())
        {
            pos += ptctd->rdlen;
            continue;
        }
        ret = m_nbns_type_data_op[ptctd->rtype](data, size, pos, ptctd->rdlen, info);
        pos += ptctd->rdlen;
        if (!ret)
        {
            return false;
        }
    }
    return true;
}

bool NBNSHelper::ParseNBSTATData(const char *data, int size, int pos, int len, NBStatTypeNameMap &info)
{
    NBStatResponceData::num_names *num_names =  (NBStatResponceData::num_names *)&data[pos] ;
    pos += sizeof(NBStatResponceData::num_names);
    for (int i = 0; i < num_names->num_of_names; i++)
    {
        NBStatResponceData::name_entry *name_entry = (NBStatResponceData::name_entry *)&data[pos];
        pos += sizeof(NBStatResponceData::name_entry);
        int type = name_entry->name[15];
        name_entry->falg.flags = ntohs(name_entry->falg.flags);
        if (name_entry->falg.flag_in.g)
        {
            type = NBNS_RECODE_NAME_GROUP;
        }
        info.map[type].insert(std::string(name_entry->name, 15));
    }

    pos += sizeof(NBStatResponceData::statistics);
    return true;
}
