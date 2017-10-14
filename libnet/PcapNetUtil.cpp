#include "PcapNetUtil.h"
#include "EthernetHeader.h"
#include "ArpHeader.h"
#include "PcapHelper.h"
#if defined(_MSC_VER)
#include <string\StringHelper.h>
#elif defined(__GNUC__)
#include <string/StringHelper.h>
#else
#error unsupported compiler
#endif

bool PcapNetUtil::DoArp(u_char *dst_mac, u_long dst_mac_len, u_int DestIP, u_int SrcIP, u_char *src_mac, u_long src_mac_len, u_int timeout)
{
    if (dst_mac == NULL && dst_mac_len < 6) {
        return false;
    }
    if (src_mac == NULL && src_mac_len < 6) {
        return false;
    }
    if (DestIP == 0 || SrcIP == 0) {
        return false;
    }
    if (timeout == 0) {
        timeout = ARP_DEFAULT_TIMEOUT;
    }
    struct in_addr src_ip;
    src_ip.s_addr = SrcIP;
    PcapHelper arp_helper(src_ip, BUFSIZ, ARP_INTERVAL_TIMEOUT);
    if (!arp_helper.IsInit()) {
        return false;
    }
    std::string filter = "arp and arp[14:4] = 0x" + StringHelper::byte2basestr((unsigned char *)&DestIP, 4, "", StringHelper::hex, 2)
        + " and arp[18:4] = 0x" + StringHelper::byte2basestr(src_mac, 4, "", StringHelper::hex, 2)
        + " and arp[22:2] = 0x" + StringHelper::byte2basestr(src_mac + 4, 2, "", StringHelper::hex, 2)
        + " and arp[24:4] = 0x" + StringHelper::byte2basestr((unsigned char *)&SrcIP, 4, "", StringHelper::hex, 2);
    if (arp_helper.PcapSetFilter(filter.c_str())) {
        return false;
    }
    std::shared_ptr<NetBase> arp_send = PcapNetUtil::GenerateArpPacket(DestIP, SrcIP, src_mac, src_mac_len);
    if (!arp_send) {
        return false;
    }
    u_int max_do_count = timeout / ARP_INTERVAL_TIMEOUT;
    std::shared_ptr<NetBase> packet;
    do {
        arp_helper.SendEthPacket(arp_send);
        if (!arp_helper.GetOneReplayPacket(packet) && packet) {
            break;
        }
    } while (max_do_count--);
    if (!packet) {
        return false;
    }
    std::shared_ptr<NetBase> arp_packet = packet->ProtocalData(HEADER_TYPE_ARP);
    if (!arp_packet) {
        return false;
    }
    ArpHeader *arpheader = (ArpHeader *)arp_packet.get();
    arpheader->GetSenderMAC(dst_mac, 6);
    return true;
}

std::shared_ptr<NetBase> PcapNetUtil::GenerateArpPacket(u_int DestIP, u_int SrcIP, u_char *src_mac, u_long src_mac_len)
{
    unsigned char eth_dst_mac[] = { 0xFF,0XFF,0XFF,0XFF,0XFF,0XFF };
    unsigned char arp_dst_mac[6] = { 0 };
    std::shared_ptr<EthernetHeader> eth = std::make_shared<EthernetHeader>();
    if (!eth) {
        return std::shared_ptr<NetBase>();
    }
    eth->SetEtherType(ETHTYPE_ARP);
    eth->SetSrcMAC(src_mac, src_mac_len);
    eth->SetDstMAC(eth_dst_mac, sizeof(eth_dst_mac));
    std::shared_ptr<ArpHeader> arp = std::make_shared<ArpHeader>();
    if (!arp) {
        return std::shared_ptr<NetBase>();
    }
    eth->SetNext(arp);
    arp->SetHardwareType();
    arp->SetProtocolType();
    arp->SetHwAddrLen();
    arp->SetProtoAddrLen();
    arp->SetOpCode(OP_ARP_REQUEST);
    arp->SetSenderMAC(src_mac, src_mac_len);
    arp->SetSenderIP(SrcIP);
    arp->SetTargetMAC(arp_dst_mac, sizeof(arp_dst_mac));
    arp->SetTargetIP(DestIP);
    return eth;
}