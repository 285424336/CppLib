#include "ICMPV6Helper.h"
#if defined(_MSC_VER)
#include <time\TimeHelper.h>
#elif defined(__GNUC__)
#include <time/TimeHelper.h>
#else
#error unsupported compiler
#endif

bool ICMPV6Helper::DoND(u_char *dst_mac, u_int len, const u_char *src_mac, const std::string &dst, time_t time_out)
{
    if (dst_mac == NULL || len < 6 || src_mac == NULL) {
        return false;
    }
    SOCKET fd = GetSocket();
    if (fd == -1) {
        return false;
    }
    unsigned char send_frame[ICMPV6_HDR_LEN + sizeof(icmpv6_msg_nd)] = { 0 };
    unsigned char recv_frame[ICMPV6_HDR_LEN + sizeof(icmpv6_msg_nd) + 1024];
    in6_addr dst_ip = NetworkHelper::IPStr2AddrV6(dst);
    icmpv6_pack_hdr_ns_mac(send_frame, dst_ip.s6_addr, *src_mac);
    in6_addr dst_ip_out = dst_ip;
    unsigned char multicast_prefix[13] = { 0 };
    multicast_prefix[0] = 0xff;
    multicast_prefix[1] = 0x02;
    multicast_prefix[11] = 0x1;
    multicast_prefix[12] = 0xff;
    memcpy(&dst_ip_out, multicast_prefix, sizeof(multicast_prefix));
    sockaddr_in6 dst_addr = { 0 };
    dst_addr.sin6_family = AF_INET6;
    dst_addr.sin6_port = 0;
    dst_addr.sin6_addr = dst_ip_out;

    struct timeval tmp;
    gettimeofday(&tmp, NULL);
    unsigned long long start = tmp.tv_sec * 1000000 + tmp.tv_usec;
    sendto(fd, (char *)send_frame, sizeof(send_frame), 0, (struct sockaddr *) &dst_addr, sizeof(dst_addr));
    while (1)
    {
        struct sockaddr_in6 from = { 0 };
#if defined(_MSC_VER)
        int len = sizeof(struct sockaddr_in6);
#elif defined(__GNUC__)
        socklen_t len = sizeof(struct sockaddr_in6);
#else
#error unsupported compiler
#endif
        int szRecv = recvfrom(fd, (char *)recv_frame, sizeof(recv_frame), 0, (struct sockaddr*)&from, &len);
        if (szRecv == SOCKET_ERROR) 
        {
            sendto(fd, (char *)send_frame, sizeof(send_frame), 0, (struct sockaddr *) &dst_addr, sizeof(dst_addr));
        }
        else if (szRecv >= (ICMPV6_HDR_LEN + (int)sizeof(icmpv6_msg_nd)))
        {
            struct icmpv6_hdr *nh;
            nh = (struct icmpv6_hdr *)recv_frame;
            if (nh->icmpv6_type==ICMPV6_NEIGHBOR_ADVERTISEMENT || nh->icmpv6_type==ICMPV6_NEIGHBOR_SOLICITATION)
            {
                struct icmpv6_msg_nd *na;
                na = (struct icmpv6_msg_nd *)(recv_frame + ICMPV6_HDR_LEN);
                if (memcmp(&from.sin6_addr, &dst_ip, 16) == 0 && 
                    (nh->icmpv6_type==ICMPV6_NEIGHBOR_ADVERTISEMENT || memcmp(src_mac, na->icmpv6_mac, 6)!=0)) {
                    memcpy(dst_mac, &na->icmpv6_mac, 6);
                    return true;
                }
            }
        }
        gettimeofday(&tmp, NULL);
        unsigned long long cur = tmp.tv_sec * 1000000 + tmp.tv_usec;
        if ((cur - start) > (unsigned long long)(time_out * 1000))
        {
            return false;
        }
    }
    return true;
}

bool ICMPV6Helper::StartNDListern(NDListernCallback callback)
{
    if (is_dn_listern_start) {
        return false;
    }
    if (nd_listen_thread) {
        nd_listen_thread->join();
    }
    SOCKET fd = GetSocket();
    if (fd == -1) {
        return false;
    }
    is_dn_listern_start = true;
    nd_listen_thread = std::make_shared<std::thread>([this, callback, fd]{
        while (is_dn_listern_start)
        {
            unsigned char recv_frame[ICMPV6_HDR_LEN + sizeof(icmpv6_msg_nd) + 1024];
            struct sockaddr_in6 from = { 0 };
#if defined(_MSC_VER)
            int len = sizeof(struct sockaddr_in6);
#elif defined(__GNUC__)
            socklen_t len = sizeof(struct sockaddr_in6);
#else
#error unsupported compiler
#endif
            int szRecv = recvfrom(fd, (char *)recv_frame, sizeof(recv_frame), 0, (struct sockaddr*)&from, &len);
            if (szRecv >= (ICMPV6_HDR_LEN + (int)sizeof(icmpv6_msg_nd)))
            {
                struct icmpv6_hdr *nh;
                nh = (struct icmpv6_hdr *)recv_frame;
                if (nh->icmpv6_type == ICMPV6_NEIGHBOR_ADVERTISEMENT || nh->icmpv6_type == ICMPV6_NEIGHBOR_SOLICITATION)
                {
                    struct icmpv6_msg_nd *na;
                    na = (struct icmpv6_msg_nd *)(recv_frame + ICMPV6_HDR_LEN);
                    if (!IsBindIp(from.sin6_addr) && NetworkHelper::IsValidIp(from.sin6_addr) && !callback(from.sin6_addr, na->icmpv6_mac))
                    {
                        break;
                    }
                }
            }
        }
        is_dn_listern_start = false;
    });
    if (!nd_listen_thread)
    {
        is_dn_listern_start = false;
        return false;
    }
    return true;
}

void ICMPV6Helper::StopNDListern()
{
    is_dn_listern_start = false;
    if (nd_listen_thread) {
        nd_listen_thread->join();
    }
}

bool ICMPV6Helper::IsBindIp(const in6_addr &addr)
{
    return memcmp(&addr, &m_src_ip, sizeof(in6_addr)) == 0;
}