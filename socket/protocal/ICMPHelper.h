#ifndef ICMP_HELPER_H_INCLUDED
#define ICMP_HELPER_H_INCLUDED

#if defined(_MSC_VER)
#include <socket\SocketHelper.h>
#include <algorithm\AlgorithmHelper.h>
#include <network\NetworkHelper.h>
#elif defined(__GNUC__)
#include <socket/SocketHelper.h>
#include <algorithm/AlgorithmHelper.h>
#include <network/NetworkHelper.h>
#else
#error unsupported compiler
#endif
#include <string>
#include <mutex>

#define ICMP_IP_RECORD_ROUTE  0x7

#define ICMP_ECHO        8
#define ICMP_ECHOREPLY   0
#define ICMP_MIN         8 // Minimum 8-byte ICMP packet (header)

#define ICMP_DEF_PACKET_SIZE  32        // Default packet size
#define ICMP_MAX_PACKET       1024      // Max ICMP packet size
#define ICMP_MAX_IP_HDR_SIZE  60        // Max IP header size w/options

#define ICMP_RECV_TIMEOUT 2000
#define ICMP_SEND_TIMEOUT 1000

class ICMPHelper : public RawSocket
{
public:

    // IP header structure
    typedef struct _iphdr
    {
        //Suppose the BYTE_ORDER is LITTLE_ENDIAN
        unsigned int   h_len : 4;        // Length of the header
        unsigned int   version : 4;      // Version of IP
        unsigned char  tos;            // Type of service
        unsigned short total_len;      // Total length of the packet
        unsigned short id;             // Unique identification
        unsigned short frag_offset;    // Fragment offset
        unsigned char  ttl;            // Time to live
        unsigned char  protocol;       // Protocol (TCP, UDP etc)
        unsigned short checksum;       // IP checksum
        unsigned int   sourceIP;       // Source IP
        unsigned int   destIP;         // Destination IP
    } IpHeader;

    // ICMP header structure
    // This is not the standard header, but we reserve space for time
    typedef struct _icmphdr
    {
        unsigned char  i_type;
        unsigned char  i_code;                 // Type sub code
        unsigned short i_cksum;
        unsigned short i_id;
        unsigned short i_seq;
    } IcmpHeader;

    typedef struct _icmppacket
    {
        IcmpHeader     header;
        unsigned char  data[16];
    } IcmpPacket;

    // IP option header - use with socket option IP_OPTIONS
    typedef struct _ipoptionhdr
    {
        unsigned char code;        // Option type
        unsigned char len;         // Length of option hdr
        unsigned char ptr;         // Offset into options
        unsigned long addr[9];     // List of IP addrs
    } IpOptionHeader;

public:
    /**
    *eth_ip: which eth you want to bind to send upnp multcast, empty for all eth
    */
    explicit ICMPHelper(u_int src_ip = INADDR_ANY) : RawSocket(src_ip, IPPROTO_ICMP,255){}
    virtual ~ICMPHelper() {}
    bool SendICMPPingRequest(const std::string &dst)
    {
        SOCKET fd = GetSocket();
        if (fd == -1) return false;
        if (dst.empty()) return false;
        sockaddr_in dst_addr;
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

private:
    static IcmpPacket GenerateICMPPingData()
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

private:
    static IcmpPacket m_icmp_data;
};

ICMPHelper::IcmpPacket ICMPHelper::m_icmp_data = GenerateICMPPingData();
#endif