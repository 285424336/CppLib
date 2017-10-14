#include "ArpHeader.h"
#if defined(_MSC_VER)
#include <string\StringHelper.h>
#include <network\NetworkHelper.h>
#elif defined(__GNUC__)
#include <string/StringHelper.h>
#include <network/NetworkHelper.h>
#else
#error unsupported compiler
#endif

ArpHeader::ArpHeader() : NetBase()
{
    this->Reset();
}

ArpHeader::~ArpHeader()
{

}

void ArpHeader::Reset()
{
    memset(&this->h, 0, sizeof(this->h));
    this->length = ARP_HEADER_LEN;
}

int ArpHeader::ProtocolId() const
{
    return HEADER_TYPE_ARP;
}

std::string ArpHeader::Data() const
{
    return std::string((char *)&this->h, this->length);
}

bool ArpHeader::StorePacket(const unsigned char *buf, size_t len)
{
    if (buf == NULL || len<ARP_HEADER_LEN) {
        return false;
    }

    this->length = ARP_HEADER_LEN;
    memcpy(&(this->h), buf, ARP_HEADER_LEN);
    return true;
}

void ArpHeader::SetHardwareType(unsigned short t)
{
    this->h.ar_hrd = htons(t);
}

unsigned short ArpHeader::GetHardwareType() const
{
    return ntohs(this->h.ar_hrd);
}

void ArpHeader::SetProtocolType(unsigned short t)
{
    this->h.ar_pro = htons(t);
}

unsigned short ArpHeader::GetProtocolType() const
{
    return ntohs(this->h.ar_pro);
}

void ArpHeader::SetHwAddrLen(unsigned char v)
{
    this->h.ar_hln = v;
}

unsigned char ArpHeader::GetHwAddrLen() const
{
    return this->h.ar_hln;
}

void ArpHeader::SetProtoAddrLen(unsigned char v)
{
    this->h.ar_pln = v;
}

unsigned char ArpHeader::GetProtoAddrLen() const
{
    return this->h.ar_pln;
}

void ArpHeader::SetOpCode(unsigned short c)
{
    this->h.ar_op = htons(c);
}

unsigned short ArpHeader::GetOpCode() const
{
    return htons(this->h.ar_op);
}

bool ArpHeader::SetSenderMAC(const unsigned char *m, size_t len)
{
    if (m == NULL || len<sizeof(this->h.ar_sha)) {
        return false;
    }
    memcpy(this->h.ar_sha, m, sizeof(this->h.ar_sha));
    return true;
}

bool ArpHeader::GetSenderMAC(unsigned char *m, size_t len) const
{ 
    if (m == NULL || len<sizeof(this->h.ar_sha)) {
        return false;
    }
    memcpy(m, this->h.ar_sha, sizeof(this->h.ar_sha));
    return true;
}

void ArpHeader::SetSenderIP(struct in_addr i)
{
    this->SetSenderIP(i.s_addr);
}

void ArpHeader::SetSenderIP(u_int i)
{
    this->h.ar_sip = i;
}

struct in_addr ArpHeader::GetSenderIP() const
{
    return *(struct in_addr*)&this->h.ar_sip;
}

bool ArpHeader::SetTargetMAC(const unsigned char *m, size_t len)
{
    if (m == NULL || len<sizeof(this->h.ar_tha)) {
        return false;
    }
    memcpy(this->h.ar_tha, m, sizeof(this->h.ar_tha));
    return true;
}

bool ArpHeader::GetTargetMAC(unsigned char *m, size_t len) const
{
    if (m == NULL || len<sizeof(this->h.ar_tha)) {
        return false;
    }
    memcpy(m, this->h.ar_tha, sizeof(this->h.ar_tha));
    return true;
}

void ArpHeader::SetTargetIP(struct in_addr i)
{
    this->SetTargetIP(i.s_addr);
}

void ArpHeader::SetTargetIP(u_int i)
{
    this->h.ar_tip = i;
}

struct in_addr ArpHeader::GetTargetIP() const
{
    return *(struct in_addr*)&this->h.ar_tip;
}

Json::Value ArpHeader::Serialize() const
{
    Json::Value root;
    unsigned char mac_buf[ETH_ADDRESS_LEN] = { 0 };

    root[ARP_SERIA_NAME_HARDWARE_TYPE] = (int)this->GetHardwareType();
    root[ARP_SERIA_NAME_PROTOCAL_TYPE] = (int)this->GetProtocolType();
    root[ARP_SERIA_NAME_HARDWARE_ADDR_LEN] = (int)this->GetHwAddrLen();
    root[ARP_SERIA_NAME_PROTOCAL_ADDR_LEN] = (int)this->GetProtoAddrLen();
    root[ARP_SERIA_NAME_OP_CODE] = (int)this->GetOpCode();
    this->GetSenderMAC(mac_buf, sizeof(mac_buf));
    root[ARP_SERIA_NAME_SENDER_MAC] = StringHelper::byte2basestr(mac_buf, sizeof(mac_buf), ":", StringHelper::hex, 2);
    in_addr send_ip = this->GetSenderIP();
    root[ARP_SERIA_NAME_SENDER_IP] = StringHelper::byte2basestr((const unsigned char *)&send_ip, IPv4_ADDRESS_LEN, ".", StringHelper::dec);
    this->GetTargetMAC(mac_buf, sizeof(mac_buf));
    root[ARP_SERIA_NAME_TARGET_MAC] = StringHelper::byte2basestr(mac_buf, sizeof(mac_buf), ":", StringHelper::hex, 2);
    in_addr target_ip = this->GetTargetIP();
    root[ARP_SERIA_NAME_TARGET_IP] = StringHelper::byte2basestr((const unsigned char *)&target_ip, IPv4_ADDRESS_LEN, ".", StringHelper::dec);
    return root;
}

bool ArpHeader::UnSerialize(const Json::Value &in)
{
    unsigned char mac_buf[6];

    if (in.isMember(ARP_SERIA_NAME_HARDWARE_TYPE) && in[ARP_SERIA_NAME_HARDWARE_TYPE].isInt()) {
        this->SetHardwareType(in[ARP_SERIA_NAME_HARDWARE_TYPE].asInt());
    }

    if (in.isMember(ARP_SERIA_NAME_PROTOCAL_TYPE) && in[ARP_SERIA_NAME_PROTOCAL_TYPE].isInt()) {
        this->SetProtocolType(in[ARP_SERIA_NAME_PROTOCAL_TYPE].asInt());
    }

    if (in.isMember(ARP_SERIA_NAME_HARDWARE_ADDR_LEN) && in[ARP_SERIA_NAME_HARDWARE_ADDR_LEN].isInt()) {
        this->SetHwAddrLen(in[ARP_SERIA_NAME_HARDWARE_ADDR_LEN].asInt());
    }

    if (in.isMember(ARP_SERIA_NAME_PROTOCAL_ADDR_LEN) && in[ARP_SERIA_NAME_PROTOCAL_ADDR_LEN].isInt()) {
        this->SetProtoAddrLen(in[ARP_SERIA_NAME_PROTOCAL_ADDR_LEN].asInt());
    }

    if (in.isMember(ARP_SERIA_NAME_OP_CODE) && in[ARP_SERIA_NAME_OP_CODE].isInt()) {
        this->SetOpCode(in[ARP_SERIA_NAME_OP_CODE].asInt());
    }

    if (in.isMember(ARP_SERIA_NAME_SENDER_MAC) && in[ARP_SERIA_NAME_SENDER_MAC].isString()) {
        std::string mac = StringHelper::replace(in[ARP_SERIA_NAME_SENDER_MAC].asString(), ":", "");
        if (mac.size() == 12) {
            if (StringHelper::hex2byte(mac, (char *)mac_buf, sizeof(mac_buf))) {
                this->SetSenderMAC(mac_buf, sizeof(mac_buf));
            }
        }
    }

    if (in.isMember(ARP_SERIA_NAME_SENDER_IP) && in[ARP_SERIA_NAME_SENDER_IP].isString()) {
        struct in_addr addr = NetworkHelper::IPStr2Addr(in[ARP_SERIA_NAME_SENDER_IP].asString());
        this->SetSenderIP(addr);
    }

    if (in.isMember(ARP_SERIA_NAME_TARGET_MAC) && in[ARP_SERIA_NAME_TARGET_MAC].isString()) {
        std::string mac = StringHelper::replace(in[ARP_SERIA_NAME_TARGET_MAC].asString(), ":", "");
        if (mac.size() == 12) {
            if (StringHelper::hex2byte(mac, (char *)mac_buf, sizeof(mac_buf))) {
                this->SetTargetMAC(mac_buf, sizeof(mac_buf));
            }
        }
    }

    if (in.isMember(ARP_SERIA_NAME_TARGET_IP) && in[ARP_SERIA_NAME_TARGET_IP].isString()) {
        struct in_addr addr = NetworkHelper::IPStr2Addr(in[ARP_SERIA_NAME_TARGET_IP].asString());
        this->SetTargetIP(addr);
    }

    return true;
}