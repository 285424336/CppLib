// SocketHelper.cpp : Defines the entry point for the console application.
//
#if defined(_MSC_VER)
#include <socket\SocketHelper.h>
#include <algorithm\AlgorithmHelper.h>
#include <network\NetworkHelper.h>
#include <network\NetworkInfoHelper.h>
#elif defined(__GNUC__)
#include <socket/SocketHelper.h>
#include <algorithm/AlgorithmHelper.h>
#include <network/NetworkHelper.h>
#include <network/NetworkInfoHelper.h>
#include <string.h>
#else
#error unsupported compiler
#endif
#include <thread>
#include <iostream>

#define ICMP_IP_RECORD_ROUTE  0x7
#define ICMP_ECHO        8
#define ICMP_ECHOREPLY   0
#define ICMP_MIN         8 // Minimum 8-byte ICMP packet (header)
#define ICMP_DEF_PACKET_SIZE  32        // Default packet size
#define ICMP_MAX_PACKET       1024      // Max ICMP packet size
#define ICMP_MAX_IP_HDR_SIZE  60        // Max IP header size w/options
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

IcmpPacket GenerateICMPPingData()
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

IcmpPacket echo_req_data = GenerateICMPPingData();

bool SendICMPPingRequest(SOCKET fd, u_int dst)
{
    if (fd==-1) return false;
    if (!dst) return false;
    sockaddr_in dst_addr;
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = 0;
    dst_addr.sin_addr.s_addr = dst;
    int ret = sendto(fd, (char *)&echo_req_data, sizeof(echo_req_data), 0, (struct sockaddr*) &dst_addr, sizeof(dst_addr));
    if (ret == SOCKET_ERROR)
    {
        return false;
    }
    return true;
}

int main()
{
    NetworkInfoHelper::NetworkInfo network_info = NetworkInfoHelper::GetInstance().GetNetworkInfo();
    std::set<u_int> ip_list = NetworkHelper::GetNetIPs(NetworkHelper::IPStr2Addr(network_info.adapt_info.local_ip_address).s_addr, NetworkHelper::IPStr2Addr(network_info.adapt_info.subnet_ip_mask).s_addr);

    RawSocket icmp(network_info.adapt_info.local_ip_address_int.s_addr, IPPROTO_ICMP, 1);
    if (!icmp.Init())
    {
        std::cout << icmp.LastError() << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(5));
        exit(0);
    }
    RawSocket icmp2 = std::move(icmp);
    swap(icmp2, icmp);
    for (auto device : ip_list)
    {
        SendICMPPingRequest(icmp.GetSocket(), device);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return 0;
}

