#include "EthernetHeader.h"
#if defined(_MSC_VER)
#include <string\StringHelper.h>
#include <network\NetworkHelper.h>
#elif defined(__GNUC__)
#include <string/StringHelper.h>
#include <network/NetworkHelper.h>
#else
#error unsupported compiler
#endif

EthernetHeader::EthernetHeader() : NetBase()
{
    this->Reset();
}

EthernetHeader::~EthernetHeader()
{

}

void EthernetHeader::Reset()
{
    memset(&this->h, 0, sizeof(this->h));
    this->length = ETH_HEADER_LEN;
}

int EthernetHeader::ProtocolId() const
{
    return HEADER_TYPE_ETHERNET;
}

std::string EthernetHeader::Data() const
{
    return std::string((char *)&this->h, this->length);
}

bool EthernetHeader::StorePacket(const unsigned char *buf, size_t len)
{
    if (buf==NULL || len<ETH_HEADER_LEN) {
        return false;
    }

    this->length = ETH_HEADER_LEN;
    memcpy(&(this->h), buf, ETH_HEADER_LEN);
    return true;
}

bool EthernetHeader::SetSrcMAC(const unsigned char *m, size_t len)
{
    if (m == NULL || len<sizeof(this->h.eth_smac)) {
        return false;
    }
    memcpy(this->h.eth_smac, m, sizeof(this->h.eth_smac));
    return true;
}

bool EthernetHeader::GetSrcMAC(unsigned char *m, size_t len) const
{
    if (m == NULL || len<sizeof(this->h.eth_smac)) {
        return false;
    }
    memcpy(m, this->h.eth_smac, sizeof(this->h.eth_smac));
    return true;
}

bool EthernetHeader::SetDstMAC(const unsigned char *m, size_t len)
{
    if (m == NULL || len<sizeof(this->h.eth_dmac)) {
        return false;
    }
    memcpy(this->h.eth_dmac, m, sizeof(this->h.eth_dmac));
    return true;
}

bool EthernetHeader::GetDstMAC(unsigned char *m, size_t len) const
{
    if (m == NULL || len<sizeof(this->h.eth_dmac)) {
        return false;
    }
    memcpy(m, this->h.eth_dmac, sizeof(this->h.eth_dmac));
    return true;
}

void EthernetHeader::SetEtherType(unsigned short val)
{
    this->h.eth_type = htons(val);
}

unsigned short EthernetHeader::GetEtherType() const
{
    return ntohs(this->h.eth_type);
}

Json::Value EthernetHeader::Serialize() const
{
    Json::Value root;
    unsigned char mac_buf[6] = { 0 };

    this->GetSrcMAC(mac_buf, sizeof(mac_buf));
    root[ETH_SERIA_NAME_SRC_MAC] = StringHelper::byte2basestr(mac_buf, sizeof(mac_buf), ":", StringHelper::hex, 2);
    this->GetDstMAC(mac_buf, sizeof(mac_buf));
    root[ETH_SERIA_NAME_DST_MAC] = StringHelper::byte2basestr(mac_buf, sizeof(mac_buf), ":", StringHelper::hex, 2);
    root[ETH_SERIA_NAME_ETH_TYPE] = (int)this->GetEtherType();
    return root;
}

bool EthernetHeader::UnSerialize(const Json::Value &in)
{
    unsigned char mac_buf[6];
    if (in.isMember(ETH_SERIA_NAME_SRC_MAC) && in[ETH_SERIA_NAME_SRC_MAC].isString()) {
        std::string mac = StringHelper::replace(in[ETH_SERIA_NAME_SRC_MAC].asString(), ":", "");
        if (mac.size() == 12) {
            if (StringHelper::hex2byte(mac, (char *)mac_buf, sizeof(mac_buf))) {
                this->SetSrcMAC(mac_buf, sizeof(mac_buf));
            }
        }
    }

    if (in.isMember(ETH_SERIA_NAME_DST_MAC) && in[ETH_SERIA_NAME_DST_MAC].isString()) {
        std::string mac = StringHelper::replace(in[ETH_SERIA_NAME_DST_MAC].asString(), ":", "");
        if (mac.size() == 12) {
            if (StringHelper::hex2byte(mac, (char *)mac_buf, sizeof(mac_buf))) {
                this->SetDstMAC(mac_buf, sizeof(mac_buf));
            }
        }
    }

    if (in.isMember(ETH_SERIA_NAME_ETH_TYPE) && in[ETH_SERIA_NAME_ETH_TYPE].isInt()) {
        this->SetEtherType(in[ETH_SERIA_NAME_ETH_TYPE].asInt());
    }

    return true;
}