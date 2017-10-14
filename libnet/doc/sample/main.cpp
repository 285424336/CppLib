// LibNet.cpp : Defines the entry point for the console application.
//
#define WIN32_LEAN_AND_MEAN

#if defined(_MSC_VER)
#include <Windows.h>
#elif defined(__GNUC__)
#else
#error unsupported compiler
#endif

#include <algorithm>
#if defined(_MSC_VER)
#include <string\StringHelper.h>
#include <algorithm\AlgorithmHelper.h>
#include <network\NetworkHelper.h>
#include <libnet\EthernetHeader.h>
#include <libnet\ArpHeader.h>
#include <libnet\IPv4Header.h>
#include <libnet\ICMPv4Header.h>
#include <libnet\UDPHeader.h>
#include <libnet\TCPHeader.h>
#include <libnet\RawData.h>
#include <libnet\PacketParser.h>
#include <libnet\PcapHelper.h>
#include <libnet\PcapNetUtil.h>
#elif defined(__GNUC__)
#include <network/NetworkHelper.h>
#include <string/StringHelper.h>
#include <algorithm/AlgorithmHelper.h>
#include <libnet/EthernetHeader.h>
#include <libnet/ArpHeader.h>
#include <libnet/IPv4Header.h>
#include <libnet/ICMPv4Header.h>
#include <libnet/UDPHeader.h>
#include <libnet/TCPHeader.h>
#include <libnet/RawData.h>
#include <libnet/PacketParser.h>
#include <libnet/PcapHelper.h>
#include <libnet/PcapNetUtil.h>
#else
#error unsupported compiler
#endif

#include <iostream>
#include <vector>

void EthernetHeaderTest()
{
    std::cout << __FUNCTION__ << " **************start*************" << std::endl;
    unsigned char src_mac[] = { 0X12, 0X23, 0X34, 0X45, 0X56, 0X67 };
    unsigned char dst_mac[] = { 0X23, 0X34, 0X45, 0X56, 0X67, 0X78 };
    auto eth = std::make_shared<EthernetHeader>();
    eth->SetEtherType();
    eth->SetSrcMAC(src_mac, sizeof(src_mac));
    eth->SetDstMAC(dst_mac, sizeof(dst_mac));
    std::string json_info = eth->Repr();
    std::cout << json_info << std::endl;

    {
        std::cout << "String Parse Test" << std::endl;
        auto info = PacketParser::ParsePacketString(json_info);
        if (info) {
            std::cout << info->Repr() << std::endl;
        }
    }

    {
        std::cout << "Raw Parse Test" << std::endl;
        std::string data = eth->AllData();
        auto info = PacketParser::ParsePacketRaw((unsigned char *)data.c_str(), data.size(), true);
        if (info) {
            std::cout << info->Repr() << std::endl;
        }
    }

    {
        std::cout << "Serialize Test" << std::endl;
        auto eth_info = eth->Serialize();
        std::cout << "Serialize data\n" << eth_info.toStyledString() << std::endl;
        auto eth_2 = std::make_shared<EthernetHeader>();
        eth_2->UnSerialize(eth_info);
        std::cout << "UnSerialize data\n" << eth_2->Serialize().toStyledString() << std::endl;
    }
}

void ARPHeaderTest()
{
    std::cout << __FUNCTION__ << " **************start*************" << std::endl;
    unsigned char src_mac[] = { 0X00 , 0x87 , 0x36 , 0x3C , 0x02 , 0x43 };
    unsigned char dst_mac[] = { 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF };
    in_addr ip_src = NetworkHelper::IPStr2Addr("192.168.1.111");
    in_addr ip_dst = NetworkHelper::IPStr2Addr("192.168.1.123");
    auto eth = std::make_shared<EthernetHeader>();
    eth->SetEtherType(ETHTYPE_ARP);
    eth->SetSrcMAC(src_mac, sizeof(src_mac));
    eth->SetDstMAC(dst_mac, sizeof(dst_mac));
    auto arp = std::make_shared<ArpHeader>();
    eth->SetNext(arp);
    arp->SetHardwareType();
    arp->SetProtocolType();
    arp->SetHwAddrLen();
    arp->SetProtoAddrLen();
    arp->SetOpCode(OP_ARP_REQUEST);
    arp->SetSenderMAC(src_mac, sizeof(src_mac));
    arp->SetSenderIP(ip_src);
    arp->SetTargetMAC(dst_mac, sizeof(dst_mac));
    arp->SetTargetIP(ip_dst);
    std::string json_info = eth->Repr();
    std::cout << json_info << std::endl;

    {
        std::cout << "String Parse Test" << std::endl;
        auto info = PacketParser::ParsePacketString(json_info);
        if (info) {
            std::cout << info->Repr() << std::endl;
        }
    }

    {
        std::cout << "Raw Parse Test" << std::endl;
        std::string data = eth->AllData();
        auto info = PacketParser::ParsePacketRaw((unsigned char *)data.c_str(), data.size(), true);
        if (info) {
            std::cout << info->Repr() << std::endl;
        }
    }

    {
        std::cout << "Serialize Test" << std::endl;
        auto arp_info = arp->Serialize();
        std::cout << "Serialize data\n" << arp_info.toStyledString() << std::endl;
        auto arp_2 = std::make_shared<ArpHeader>();
        arp_2->UnSerialize(arp_info);
        std::cout << "UnSerialize data\n" << arp_2->Serialize().toStyledString() << std::endl;
    }

    {
        in_addr ip_src_int = NetworkHelper::IPStr2Addr("192.168.1.111");
        PcapHelper helper(ip_src_int);
        helper.SendEthPacket(eth);
        helper.PcapSetFilter("arp");
        std::shared_ptr<NetBase> packet;
        helper.GetOneReplayPacket(packet);
        if (packet) {
            std::cout << packet->Repr() << std::endl;
            std::cout << "is resp " << PacketParser::IsResponse(eth, packet) << std::endl;
        }
        else {
            std::cout << "get arp packet error!" << std::endl;
        }
        unsigned char dst_mac[6];
        in_addr arp_ip_dst = NetworkHelper::IPStr2Addr("192.168.1.1");
        if (PcapNetUtil::DoArp(dst_mac, 6, arp_ip_dst.s_addr, ip_src.s_addr, src_mac, 6)) {
            std::cout << StringHelper::byte2basestr(dst_mac, 6, ":", StringHelper::hex, 2) << std::endl;
        }
    }
}

void IPv4HeaderTest()
{
    std::cout << __FUNCTION__ << " **************start*************" << std::endl;
    unsigned char src_mac[] = { 0X12, 0X23, 0X34, 0X45, 0X56, 0X67 };
    unsigned char dst_mac[] = { 0X23, 0X34, 0X45, 0X56, 0X67, 0X78 };
    in_addr ip_src = NetworkHelper::IPStr2Addr("192.168.1.2");
    in_addr ip_dst = NetworkHelper::IPStr2Addr("192.168.1.1");
    auto eth = std::make_shared<EthernetHeader>();
    eth->SetEtherType();
    eth->SetSrcMAC(src_mac, sizeof(src_mac));
    eth->SetDstMAC(dst_mac, sizeof(dst_mac));
    auto ipv4 = std::make_shared<IPv4Header>();
    eth->SetNext(ipv4);
    ipv4->SetVersion();
    ipv4->SetTOS(1);
    ipv4->SetIdentification(1234);
    ipv4->SetFragOffset(5);
    ipv4->SetRF();
    ipv4->SetDF();
    ipv4->SetMF();
    ipv4->SetTTL(255);
    ipv4->SetNextProto(HEADER_TYPE_TCP);
    ipv4->SetDestinationAddress(ip_dst);
    ipv4->SetSourceAddress(ip_src);
    {
        auto str = ipv4->GenerateTimestampOpts(true);
        ipv4->SetOpts((unsigned char *)str.c_str(), str.size());
        ipv4->SetTotalLength();
        ipv4->SetSum();
        std::string json_info = eth->Repr();
        std::cout << json_info << std::endl;

        {
            std::cout << "String Parse Test" << std::endl;
            auto info = PacketParser::ParsePacketString(json_info);
            if (info) {
                std::cout << info->Repr() << std::endl;
            }
        }

        {
            std::cout << "Raw Parse Test" << std::endl;
            std::string data = eth->AllData();
            auto info = PacketParser::ParsePacketRaw((unsigned char *)data.c_str(), data.size(), true);
            if (info) {
                std::cout << info->Repr() << std::endl;
            }
        }

        {
            std::cout << "Serialize Test" << std::endl;
            auto ipv4_info = ipv4->Serialize();
            std::cout << "Serialize data\n" << ipv4_info.toStyledString() << std::endl;
            auto ipv4_2 = std::make_shared<IPv4Header>();
            ipv4_2->UnSerialize(ipv4_info);
            std::cout << "UnSerialize data\n" << ipv4_2->Serialize().toStyledString() << std::endl;
        }
    }
    {
        std::vector<struct in_addr> v;
        std::string s[] = {
        "192.168.1.11",
        "192.168.1.12",
        "192.168.1.13",
        "192.168.1.14",
        "192.168.1.15",
        "192.168.1.16",
        "192.168.1.17",
        "192.168.1.18"
        };
        for (auto ip : s)
        {
        v.emplace_back(NetworkHelper::IPStr2Addr(ip));
        }
        auto str = ipv4->GenerateRouteOpts(false, true, v);
        ipv4->SetOpts((unsigned char *)str.c_str(), str.size());
        ipv4->SetTotalLength();
        ipv4->SetSum();
        std::string json_info = eth->Repr();
        std::cout << json_info << std::endl;

        {
            std::cout << "String Parse Test" << std::endl;
            auto info = PacketParser::ParsePacketString(json_info);
            if (info) {
                std::cout << info->Repr() << std::endl;
            }
        }

        {
            std::cout << "Raw Parse Test" << std::endl;
            std::string data = eth->AllData();
            auto info = PacketParser::ParsePacketRaw((unsigned char *)data.c_str(), data.size(), true);
            if (info) {
                std::cout << info->Repr() << std::endl;
            }
        }

        {
            std::cout << "Serialize Test" << std::endl;
            auto ipv4_info = ipv4->Serialize();
            std::cout << "Serialize data\n" << ipv4_info.toStyledString() << std::endl;
            auto ipv4_2 = std::make_shared<IPv4Header>();
            ipv4_2->UnSerialize(ipv4_info);
            std::cout << "UnSerialize data\n" << ipv4_2->Serialize().toStyledString() << std::endl;
        }
    }
}

void ICMPHeaderTest()
{
    std::cout << __FUNCTION__ << " **************start*************" << std::endl;
    unsigned char src_mac[] = { 0X12, 0X23, 0X34, 0X45, 0X56, 0X67 };
    unsigned char dst_mac[] = { 0X23, 0X34, 0X45, 0X56, 0X67, 0X78 };
    in_addr ip_src = NetworkHelper::IPStr2Addr("192.168.1.2");
    in_addr ip_dst = NetworkHelper::IPStr2Addr("192.168.1.1");
    auto eth = std::make_shared<EthernetHeader>();
    eth->SetEtherType();
    eth->SetSrcMAC(src_mac, sizeof(src_mac));
    eth->SetDstMAC(dst_mac, sizeof(dst_mac));
    auto ipv4 = std::make_shared<IPv4Header>();
    eth->SetNext(ipv4);
    ipv4->SetVersion();
    ipv4->SetTOS(1);
    ipv4->SetIdentification(1234);
    ipv4->SetFragOffset(5);
    ipv4->SetRF();
    ipv4->SetDF();
    ipv4->SetMF();
    ipv4->SetTTL(255);
    ipv4->SetNextProto(HEADER_TYPE_ICMPv4);
    ipv4->SetDestinationAddress(ip_dst);
    ipv4->SetSourceAddress(ip_src);
    auto icmpv4 = std::make_shared<ICMPv4Header>();
    ipv4->SetNext(icmpv4);
    icmpv4->SetType(ICMP_ROUTERADVERT);
    icmpv4->AddRouterAdvEntry(ip_src, ip_dst.s_addr);
    icmpv4->SetSum();
    ipv4->SetTotalLength();
    ipv4->SetSum();
    std::string json_info = eth->Repr();
    std::cout << json_info << std::endl;

    {
        std::cout << "String Parse Test" << std::endl;
        auto info = PacketParser::ParsePacketString(json_info);
        if (info) {
            std::cout << info->Repr() << std::endl;
        }
    }

    {
        std::cout << "Raw Parse Test" << std::endl;
        std::string data = eth->AllData();
        auto info = PacketParser::ParsePacketRaw((unsigned char *)data.c_str(), data.size(), true);
        if (info) {
            std::cout << info->Repr() << std::endl;
        }
    }
    
    {
        std::cout << "Serialize Test" << std::endl;
        auto icmp_info = icmpv4->Serialize();
        std::cout << "Serialize data\n" << icmp_info.toStyledString() << std::endl;
        auto icmp_2 = std::make_shared<ICMPv4Header>();
        icmp_2->UnSerialize(icmp_info);
        std::cout << "UnSerialize data\n" << icmp_2->Serialize().toStyledString() << std::endl;
    }
}

void UDPHeaderTest()
{
    std::cout << __FUNCTION__ << " **************start*************" << std::endl;
    unsigned char src_mac[] = { 0X12, 0X23, 0X34, 0X45, 0X56, 0X67 };
    unsigned char dst_mac[] = { 0X23, 0X34, 0X45, 0X56, 0X67, 0X78 };
    in_addr ip_src = NetworkHelper::IPStr2Addr("192.168.1.2");
    in_addr ip_dst = NetworkHelper::IPStr2Addr("192.168.1.1");
    auto eth = std::make_shared<EthernetHeader>();
    eth->SetEtherType();
    eth->SetSrcMAC(src_mac, sizeof(src_mac));
    eth->SetDstMAC(dst_mac, sizeof(dst_mac));
    auto ipv4 = std::make_shared<IPv4Header>();
    eth->SetNext(ipv4);
    ipv4->SetVersion();
    ipv4->SetTOS(1);
    ipv4->SetIdentification(1234);
    ipv4->SetFragOffset(5);
    ipv4->SetRF();
    ipv4->SetDF();
    ipv4->SetMF();
    ipv4->SetTTL(255);
    ipv4->SetNextProto(HEADER_TYPE_UDP);
    ipv4->SetDestinationAddress(ip_dst);
    ipv4->SetSourceAddress(ip_src);
    auto udp = std::make_shared<UDPHeader>();
    ipv4->SetNext(udp);
    udp->SetSourcePort(1234);
    udp->SetDestinationPort(5678);
    udp->SetTotalLength();
    udp->SetSum();
    ipv4->SetTotalLength();
    ipv4->SetSum();
    std::string json_info = eth->Repr();
    std::cout << json_info << std::endl;

    {
        std::cout << "String Parse Test" << std::endl;
        auto info = PacketParser::ParsePacketString(json_info);
        if (info) {
            std::cout << info->Repr() << std::endl;
        }
    }

    {
        std::cout << "Raw Parse Test" << std::endl;
        std::string data = eth->AllData();
        auto info = PacketParser::ParsePacketRaw((unsigned char *)data.c_str(), data.size(), true);
        if (info) {
            std::cout << info->Repr() << std::endl;
        }
    }

    {
        std::cout << "Serialize Test" << std::endl;
        auto udp_info = udp->Serialize();
        std::cout << "Serialize data\n" << udp_info.toStyledString() << std::endl;
        auto udp_2 = std::make_shared<UDPHeader>();
        ipv4->SetNext(udp_2);
        udp_2->UnSerialize(udp_info);
        std::cout << "UnSerialize data\n" << udp_2->Serialize().toStyledString() << std::endl;
    }
}

void TCPHeaderTest()
{
    std::cout << __FUNCTION__ << " **************start*************" << std::endl;
    unsigned char src_mac[] = { 0X12, 0X23, 0X34, 0X45, 0X56, 0X67 };
    unsigned char dst_mac[] = { 0X23, 0X34, 0X45, 0X56, 0X67, 0X78 };
    in_addr ip_src = NetworkHelper::IPStr2Addr("192.168.1.2");
    in_addr ip_dst = NetworkHelper::IPStr2Addr("192.168.1.1");
    auto eth = std::make_shared<EthernetHeader>();
    eth->SetEtherType();
    eth->SetSrcMAC(src_mac, sizeof(src_mac));
    eth->SetDstMAC(dst_mac, sizeof(dst_mac));
    auto ipv4 = std::make_shared<IPv4Header>();
    eth->SetNext(ipv4);
    ipv4->SetVersion();
    ipv4->SetTOS(1);
    ipv4->SetIdentification(1234);
    ipv4->SetFragOffset(5);
    ipv4->SetRF();
    ipv4->SetDF();
    ipv4->SetMF();
    ipv4->SetTTL(255);
    ipv4->SetNextProto(HEADER_TYPE_TCP);
    ipv4->SetDestinationAddress(ip_dst);
    ipv4->SetSourceAddress(ip_src);
    auto tcp = std::make_shared<TCPHeader>();
    ipv4->SetNext(tcp);
    tcp->SetSourcePort(1234);
    tcp->SetDestinationPort(1234);
    tcp->SetSeq(12345);
    tcp->SetAck(56789);
    tcp->SetReserved(12);
    tcp->SetCWR();
    tcp->SetECE();
    tcp->SetURG();
    tcp->SetACK();
    tcp->SetPSH();
    tcp->SetRST();
    tcp->SetSYN();
    tcp->SetFIN();
    tcp->SetWindow(65535);
    tcp->SetUrgPointer(60);
    unsigned char tcp_op_buf[MAX_TCP_OPTIONS_LEN] = { 0 };
    size_t used = 0;
    used += TCPHeader::GenerateMssOpt(tcp_op_buf + used, sizeof(tcp_op_buf) - used, 1460);
    used += TCPHeader::GenerateSackPermOpt(tcp_op_buf + used, sizeof(tcp_op_buf) - used);
    used += TCPHeader::GenerateWinScaleOpt(tcp_op_buf + used, sizeof(tcp_op_buf) - used, 12);
    used += TCPHeader::GenerateTimestampOpt(tcp_op_buf + used, sizeof(tcp_op_buf) - used, 1234, 5678);
    std::vector<std::pair<unsigned int, unsigned int>> sack;
    sack.emplace_back(std::pair<unsigned int, unsigned int>(123, 456));
    sack.emplace_back(std::pair<unsigned int, unsigned int>(124, 457));
    sack.emplace_back(std::pair<unsigned int, unsigned int>(134, 467));
    //sack.emplace_back(std::pair<unsigned int, unsigned int>(156, 789));
    used += TCPHeader::GenerateSackOpt(tcp_op_buf + used, sizeof(tcp_op_buf) - used, sack);
    {
        int i = 0, s = (used) % 4;
        s = s == 0 ? 0 : 4 - s;
        for (i = 0; i < s; i++) {
            used += TCPHeader::GenerateNopOpt(tcp_op_buf + used, sizeof(tcp_op_buf) - used);
        }
    }
    tcp->SetOptions(tcp_op_buf, used);
    tcp->SetSum();
    ipv4->SetTotalLength();
    ipv4->SetSum();
    std::string json_info = eth->Repr();
    std::cout << json_info << std::endl;

    {
        std::cout << "String Parse Test" << std::endl;
        auto info = PacketParser::ParsePacketString(json_info);
        if (info) {
            std::cout << info->Repr() << std::endl;
        }
    }

    {
        std::cout << "Raw Parse Test" << std::endl;
        std::string data = eth->AllData();
        auto info = PacketParser::ParsePacketRaw((unsigned char *)data.c_str(), data.size(), true);
        if (info) {
            std::cout << info->Repr() << std::endl;
        }
    }

    {
        std::cout << "Serialize Test" << std::endl;
        auto tcp_info = tcp->Serialize();
        std::cout << "Serialize data\n" << tcp_info.toStyledString() << std::endl;
        auto tcp_2 = std::make_shared<TCPHeader>();
        ipv4->SetNext(tcp_2);
        tcp_2->UnSerialize(tcp_info);
        std::cout << "UnSerialize data\n" << tcp_2->Serialize().toStyledString() << std::endl;
    }
}

void RawDataTest()
{
    std::cout << __FUNCTION__ << " **************start*************" << std::endl;
    unsigned char src_mac[] = { 0X12, 0X23, 0X34, 0X45, 0X56, 0X67 };
    unsigned char dst_mac[] = { 0X23, 0X34, 0X45, 0X56, 0X67, 0X78 };
    in_addr ip_src = NetworkHelper::IPStr2Addr("192.168.1.2");
    in_addr ip_dst = NetworkHelper::IPStr2Addr("192.168.1.1");
    auto eth = std::make_shared<EthernetHeader>();
    eth->SetEtherType();
    eth->SetSrcMAC(src_mac, sizeof(src_mac));
    eth->SetDstMAC(dst_mac, sizeof(dst_mac));
    auto ipv4 = std::make_shared<IPv4Header>();
    eth->SetNext(ipv4);
    ipv4->SetVersion();
    ipv4->SetTOS(1);
    ipv4->SetIdentification(1234);
    ipv4->SetFragOffset(5);
    ipv4->SetRF();
    ipv4->SetDF();
    ipv4->SetMF();
    ipv4->SetTTL(255);
    ipv4->SetNextProto(HEADER_TYPE_TCP);
    ipv4->SetDestinationAddress(ip_dst);
    ipv4->SetSourceAddress(ip_src);
    auto tcp = std::make_shared<TCPHeader>();
    ipv4->SetNext(tcp);
    tcp->SetSourcePort(1234);
    tcp->SetDestinationPort(1234);
    tcp->SetSeq(12345);
    tcp->SetAck(56789);
    tcp->SetReserved(12);
    tcp->SetCWR();
    tcp->SetECE();
    tcp->SetURG();
    tcp->SetACK();
    tcp->SetPSH();
    tcp->SetRST();
    tcp->SetSYN();
    tcp->SetFIN();
    tcp->SetWindow(65535);
    tcp->SetUrgPointer(60);
    unsigned char tcp_op_buf[MAX_TCP_OPTIONS_LEN] = { 0 };
    size_t used = 0;
    used += TCPHeader::GenerateMssOpt(tcp_op_buf + used, sizeof(tcp_op_buf) - used, 1460);
    used += TCPHeader::GenerateSackPermOpt(tcp_op_buf + used, sizeof(tcp_op_buf) - used);
    used += TCPHeader::GenerateWinScaleOpt(tcp_op_buf + used, sizeof(tcp_op_buf) - used, 12);
    used += TCPHeader::GenerateTimestampOpt(tcp_op_buf + used, sizeof(tcp_op_buf) - used, 1234, 5678);
    std::vector<std::pair<unsigned int, unsigned int>> sack;
    sack.emplace_back(std::pair<unsigned int, unsigned int>(123, 456));
    sack.emplace_back(std::pair<unsigned int, unsigned int>(124, 457));
    sack.emplace_back(std::pair<unsigned int, unsigned int>(134, 467));
    //sack.emplace_back(std::pair<unsigned int, unsigned int>(156, 789));
    used += TCPHeader::GenerateSackOpt(tcp_op_buf + used, sizeof(tcp_op_buf) - used, sack);
    {
        int i = 0, s = (used) % 4;
        s = s == 0 ? 0 : 4 - s;
        for (i = 0; i < s; i++) {
            used += TCPHeader::GenerateNopOpt(tcp_op_buf + used, sizeof(tcp_op_buf) - used);
        }
    }
    tcp->SetOptions(tcp_op_buf, used);
    auto rawdata = std::make_shared<RawData>();
    tcp->SetNext(rawdata);
    {
        std::string data = "abcdefghijklmnopqrstuvwxyz";
        rawdata->StorePacket((unsigned char *)data.c_str(), data.size());
        tcp->SetSum();
        ipv4->SetTotalLength();
        ipv4->SetSum();
        std::string json_info = eth->Repr();
        std::cout << json_info << std::endl;

        {
            std::cout << "String Parse Test" << std::endl;
            auto info = PacketParser::ParsePacketString(json_info);
            if (info) {
                std::cout << info->Repr() << std::endl;
            }
        }

        {
            std::cout << "Raw Parse Test" << std::endl;
            std::string data = eth->AllData();
            auto info = PacketParser::ParsePacketRaw((unsigned char *)data.c_str(), data.size(), true);
            if (info) {
                std::cout << info->Repr() << std::endl;
            }
        }

        {
            std::cout << "Serialize Test" << std::endl;
            auto raw_data_info = rawdata->Serialize();
            std::cout << "Serialize data\n" << raw_data_info.toStyledString() << std::endl;
            auto rawdata_2 = std::make_shared<RawData>();
            rawdata_2->UnSerialize(raw_data_info);
            std::cout << "UnSerialize data\n" << rawdata_2->Serialize().toStyledString() << std::endl;
        }
    }
    {
        char *data = new char[strlen("abcdefghijklmnopqrstuvwxyz")];
        memcpy(data, "abcdefghijklmnopqrstuvwxyz", strlen("abcdefghijklmnopqrstuvwxyz"));
        rawdata->StoreRaw((unsigned char *)data, strlen("abcdefghijklmnopqrstuvwxyz"));
        tcp->SetSum();
        ipv4->SetTotalLength();
        ipv4->SetSum();
        std::string json_info = eth->Repr();
        std::cout << json_info << std::endl;

        {
            std::cout << "String Parse Test" << std::endl;
            auto info = PacketParser::ParsePacketString(json_info);
            if (info) {
                std::cout << info->Repr() << std::endl;
            }
        }

        {
            std::cout << "Raw Parse Test" << std::endl;
            std::string data = eth->AllData();
            auto info = PacketParser::ParsePacketRaw((unsigned char *)data.c_str(), data.size(), true);
            if (info) {
                std::cout << info->Repr() << std::endl;
            }
        }

        {
            std::cout << "Serialize Test" << std::endl;
            auto raw_data_info = rawdata->Serialize();
            std::cout << "Serialize data\n" << raw_data_info.toStyledString() << std::endl;
            auto rawdata_2 = std::make_shared<RawData>();
            rawdata_2->UnSerialize(raw_data_info);
            std::cout << "UnSerialize data\n" << rawdata_2->Serialize().toStyledString() << std::endl;
        }
    }
}

int main()
{
    //EthernetHeaderTest();
    ARPHeaderTest();
    //IPv4HeaderTest();
    //ICMPHeaderTest();
    //UDPHeaderTest();
    //TCPHeaderTest();
    //RawDataTest();
    return 0;
}

