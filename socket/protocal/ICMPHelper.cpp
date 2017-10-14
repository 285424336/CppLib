#include "ICMPHelper.h"

ICMPHelper::IcmpPacket ICMPHelper::m_icmp_data = GenerateICMPPingData();

bool ICMPHelper::SendICMPPingRequest(const std::string &dst)
{
    SOCKET fd = GetSocket();
    if (fd == -1) return false;
    if (dst.empty()) return false;
    sockaddr_in dst_addr = { 0 };
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = 0;
    dst_addr.sin_addr.s_addr = NetworkHelper::IPStr2Addr(dst).s_addr;
    if (!dst_addr.sin_addr.s_addr) return false;
    int ret = sendto(fd, (char *)&m_icmp_data, sizeof(m_icmp_data), 0, (struct sockaddr *) &dst_addr, sizeof(dst_addr));
    if (ret == SOCKET_ERROR)
    {
        m_fail_result = GetLastError();
        return false;
    }
    return true;
}

ICMPHelper::IcmpPacket ICMPHelper::GenerateICMPPingData()
{
    IcmpPacket icmp = { 0 };
    icmp.header.i_type = ICMP_ECHO; // Request an ICMP echo, type is 8
    icmp.header.i_code = 0;    // code is 0
    icmp.header.i_cksum = 0;
    icmp.header.i_id = (unsigned short)0X8888;
    icmp.header.i_seq = (unsigned short)0X6666;
    memset(icmp.data, 'r', sizeof(icmp.data));
    icmp.header.i_cksum = AlgorithmHelper::CheckSum((unsigned char *)&icmp, sizeof(icmp));
    return icmp;
}